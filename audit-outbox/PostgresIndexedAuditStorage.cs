using System.Data;
using System.Text.RegularExpressions;
using Cehpalon.Engine.Tenancy;
using Npgsql;
using NpgsqlTypes;

namespace AuditOutbox;

public sealed record IndexedAuditStorageColumn(string Name, string Type, bool NotNull, string Collation);
public sealed record IndexedAuditStorageIndex(string Name, bool Primary, bool Unique, string Method,
    IReadOnlyList<string> Keys, IReadOnlyList<string> Collations, IReadOnlyList<string> OperatorClasses);
public sealed record IndexedAuditStorageInventory(string Version, string Schema, string TableName,
    IReadOnlyList<IndexedAuditStorageColumn> Columns, IReadOnlyList<IndexedAuditStorageIndex> Indexes);

// Explicit sample profile only. Catalog validation is a coherent point-in-time check,
// not protection against later trusted-administrator DDL or continuous data attestation.
public sealed class PostgresIndexedAuditStorage : ITenantChangeAuditIdempotentSink,
    ITenantChangeAuditLookupSource, ITenantChangeAuditResourceHistorySource, IAsyncDisposable
{
    public const string StorageTable = "audit_sink_indexed_v1";
    public const string ResourceIndex = "audit_sink_indexed_v1_resource_idx";
    public const string PrimaryKey = "audit_sink_indexed_v1_pkey";
    public const string VersionMarker = "cehpalon.audit.indexed.v1";
    public const string AppendTag = "owned-indexed-audit-append-v1";
    public const string LookupTag = "owned-indexed-audit-lookup-v1";
    public const string ResourceTag = "owned-indexed-audit-resource-v1";
    public const string InventoryTag = "owned-indexed-audit-inventory-v1";
    private readonly string connection;
    private readonly object gate = new();
    private NpgsqlDataSource? dataSource;
    private Task? disposal;
    private TaskCompletionSource? drained;
    // 0 constructed, 1 initializing, 2 ready, 3 disposed, 4 initialization faulted.
    private int state, active, connections, initializations, ddl, inventories, appends, lookups, reads,
        explains, lastPid, lastCandidates, lastDecoded, clientCreations, clientDisposals;
    public string Schema { get; }
    public string TableName => Schema + "." + StorageTable;
    public string IndexName => Schema + "." + ResourceIndex;
    public string ApplicationName { get; } = "owned-indexed-audit-" + Guid.NewGuid().ToString("N");
    public bool IsReady => Volatile.Read(ref state) == 2;
    public bool IsDisposed => Volatile.Read(ref state) == 3;
    public int ActiveOperations => Volatile.Read(ref active);
    public int Connections => Volatile.Read(ref connections);
    public int InitializationAttempts => Volatile.Read(ref initializations);
    public int DdlCommands => Volatile.Read(ref ddl);
    public int InventoryChecks => Volatile.Read(ref inventories);
    public int AppendCalls => Volatile.Read(ref appends);
    public int LookupQueries => Volatile.Read(ref lookups);
    public int ResourceQueries => Volatile.Read(ref reads);
    public int ExplainQueries => Volatile.Read(ref explains);
    public int QueryAttempts => AppendCalls + LookupQueries + ResourceQueries + ExplainQueries;
    public int LastBackendPid => Volatile.Read(ref lastPid);
    public int LastCandidateRows => Volatile.Read(ref lastCandidates);
    public int LastDecodedRows => Volatile.Read(ref lastDecoded);
    public int DataSourceCreations => Volatile.Read(ref clientCreations);
    public int DataSourceDisposals => Volatile.Read(ref clientDisposals);

    public PostgresIndexedAuditStorage(string connectionString, string ownedSchema)
    {
        ArgumentNullException.ThrowIfNull(connectionString);
        ArgumentNullException.ThrowIfNull(ownedSchema);
        if (!Regex.IsMatch(ownedSchema, "\\Aao_[a-f0-9]{32}\\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("An exact owned schema identifier is required.", nameof(ownedSchema));
        Schema = ownedSchema;
        connection = new NpgsqlConnectionStringBuilder(connectionString) { ApplicationName = ApplicationName }.ConnectionString;
        // Even DataSource construction is deferred to explicit initialization.
    }

    private sealed class Operation(PostgresIndexedAuditStorage owner) : IDisposable
    {
        private PostgresIndexedAuditStorage? current = owner;
        public void Dispose() => Interlocked.Exchange(ref current, null)?.End();
    }
    private Operation Enter(bool initialize, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (gate)
        {
            if (state == 3) throw new ObjectDisposedException(nameof(PostgresIndexedAuditStorage));
            if (initialize ? state != 0 : state != 2)
                throw new InvalidOperationException(initialize ? "Storage initialization is explicit and single-use." : "Indexed audit storage is not ready.");
            if (initialize) state = 1;
            active++;
            return new(this);
        }
    }
    private void End()
    {
        lock (gate)
        {
            active--;
            if (active == 0 && state == 3) drained?.TrySetResult();
        }
    }
    private async ValueTask<NpgsqlConnection> Open(CancellationToken token)
    {
        Interlocked.Increment(ref connections);
        var result = await dataSource!.OpenConnectionAsync(token).ConfigureAwait(false);
        try { Volatile.Write(ref lastPid, result.ProcessID); return result; }
        catch { await result.DisposeAsync().ConfigureAwait(false); throw; }
    }
    public Task CreateNewAsync(CancellationToken token = default) => Initialize(create: true, token);
    public Task OpenExistingAsync(CancellationToken token = default) => Initialize(create: false, token);
    private async Task Initialize(bool create, CancellationToken token)
    {
        using var operation = Enter(initialize: true, token);
        Interlocked.Increment(ref initializations);
        try
        {
            dataSource = NpgsqlDataSource.Create(connection);
            Interlocked.Increment(ref clientCreations);
            await using var c = await Open(token).ConfigureAwait(false);
            await using var transaction = await c.BeginTransactionAsync(IsolationLevel.RepeatableRead, token).ConfigureAwait(false);
            if (create)
            {
                await using var command = new NpgsqlCommand($"""
                    /* owned-indexed-audit-create-v1 */
                    CREATE TABLE {TableName}(
                        tenant text COLLATE "C" NOT NULL,
                        receipt uuid NOT NULL,
                        resource_kind text COLLATE "C" NOT NULL,
                        resource_id text COLLATE "C" NOT NULL,
                        payload text COLLATE "C" NOT NULL,
                        CONSTRAINT {PrimaryKey} PRIMARY KEY(tenant,receipt));
                    CREATE INDEX {ResourceIndex} ON {TableName} USING btree(tenant,resource_kind,resource_id,receipt);
                    COMMENT ON TABLE {TableName} IS '{VersionMarker}';
                    """, c, transaction);
                Interlocked.Increment(ref ddl);
                await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
            }
            else
            {
                await using var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY", c, transaction);
                await readOnly.ExecuteNonQueryAsync(token).ConfigureAwait(false);
                await using var held = new NpgsqlCommand($"LOCK TABLE {TableName} IN ACCESS SHARE MODE", c, transaction);
                await held.ExecuteNonQueryAsync(token).ConfigureAwait(false);
            }
            _ = await ValidateInventory(c, transaction, token).ConfigureAwait(false);
            await transaction.CommitAsync(token).ConfigureAwait(false);
            lock (gate)
            {
                if (state == 3) throw new ObjectDisposedException(nameof(PostgresIndexedAuditStorage));
                state = 2;
            }
        }
        catch (Exception primary)
        {
            lock (gate) { if (state != 3) state = 4; }
            try { await DisposeClient().ConfigureAwait(false); }
            catch (Exception cleanup) { throw new AggregateException("Indexed audit initialization and owned client cleanup failed.", primary, cleanup); }
            throw;
        }
    }

    public async Task<IndexedAuditStorageInventory> ReadInventoryAsync(CancellationToken token = default)
    {
        using var operation = Enter(initialize: false, token);
        await using var c = await Open(token).ConfigureAwait(false);
        await using var transaction = await c.BeginTransactionAsync(IsolationLevel.RepeatableRead, token).ConfigureAwait(false);
        await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY", c, transaction))
            await readOnly.ExecuteNonQueryAsync(token).ConfigureAwait(false);
        await using (var held = new NpgsqlCommand($"LOCK TABLE {TableName} IN ACCESS SHARE MODE", c, transaction))
            await held.ExecuteNonQueryAsync(token).ConfigureAwait(false);
        var snapshot = await ValidateInventory(c, transaction, token).ConfigureAwait(false);
        await transaction.CommitAsync(token).ConfigureAwait(false);
        return snapshot;
    }
    private static void Require(bool condition)
    { if (!condition) throw new InvalidOperationException("Indexed audit storage does not match the exact v1 catalog profile."); }
    private async Task<IndexedAuditStorageInventory> ValidateInventory(NpgsqlConnection c, NpgsqlTransaction tx, CancellationToken token)
    {
        Interlocked.Increment(ref inventories);
        uint tableOid;
        await using (var command = new NpgsqlCommand($"""
            /* {InventoryTag} */
            SELECT c.oid,c.relkind::text,c.relpersistence::text,c.relispartition,c.relrowsecurity,c.relforcerowsecurity,
                pg_catalog.obj_description(c.oid,'pg_class'),
                (SELECT count(*) FROM pg_catalog.pg_inherits WHERE inhrelid=c.oid OR inhparent=c.oid),
                (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgrelid=c.oid),
                (SELECT count(*) FROM pg_catalog.pg_rewrite WHERE ev_class=c.oid),
                (SELECT count(*) FROM pg_catalog.pg_policy WHERE polrelid=c.oid)
            FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname=$1 AND c.relname=$2
            """, c, tx))
        {
            command.Parameters.AddWithValue(Schema); command.Parameters.AddWithValue(StorageTable);
            await using var rows = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            Require(await rows.ReadAsync(token).ConfigureAwait(false));
            tableOid = rows.GetFieldValue<uint>(0);
            Require(rows.GetString(1) == "r" && rows.GetString(2) == "p" && !rows.GetBoolean(3) && !rows.GetBoolean(4) && !rows.GetBoolean(5)
                && !rows.IsDBNull(6) && rows.GetString(6) == VersionMarker && Enumerable.Range(7, 4).All(i => rows.GetInt64(i) == 0));
            Require(!await rows.ReadAsync(token).ConfigureAwait(false));
        }
        var columns = new List<IndexedAuditStorageColumn>();
        await using (var command = new NpgsqlCommand($"""
            /* {InventoryTag} */
            SELECT a.attnum::integer,a.attname::text,tn.nspname||'.'||t.typname,a.attnotnull,
                COALESCE(cn.nspname||'.'||co.collname,''),a.atttypmod,a.attndims,a.attisdropped,
                a.atthasdef,a.attidentity::text,a.attgenerated::text,a.attinhcount::integer,a.attislocal,t.typtype::text,a.atthasmissing
            FROM pg_catalog.pg_attribute a LEFT JOIN pg_catalog.pg_type t ON t.oid=a.atttypid
            LEFT JOIN pg_catalog.pg_namespace tn ON tn.oid=t.typnamespace
            LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid=co.collnamespace
            WHERE a.attrelid=$1 AND a.attnum>0 ORDER BY a.attnum
            """, c, tx))
        {
            command.Parameters.AddWithValue(NpgsqlDbType.Oid, tableOid);
            await using var rows = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            string[] names = ["tenant", "receipt", "resource_kind", "resource_id", "payload"];
            while (await rows.ReadAsync(token).ConfigureAwait(false))
            {
                var ordinal = columns.Count; Require(ordinal < 5);
                var type = ordinal == 1 ? "pg_catalog.uuid" : "pg_catalog.text"; var collation = ordinal == 1 ? "" : "pg_catalog.C";
                Require(rows.GetInt32(0) == ordinal + 1 && rows.GetString(1) == names[ordinal] && rows.GetString(2) == type && rows.GetBoolean(3)
                    && rows.GetString(4) == collation && rows.GetInt32(5) == -1 && rows.GetInt16(6) == 0 && !rows.GetBoolean(7)
                    && !rows.GetBoolean(8) && rows.GetString(9) == "" && rows.GetString(10) == "" && rows.GetInt32(11) == 0
                    && rows.GetBoolean(12) && rows.GetString(13) == "b" && !rows.GetBoolean(14));
                columns.Add(new(names[ordinal], type, true, collation));
            }
            Require(columns.Count == 5);
        }
        await using (var command = new NpgsqlCommand($"""
            /* {InventoryTag} */
            SELECT conname::text,contype::text,conkey::smallint[],condeferrable,condeferred,convalidated,conenforced,
                conislocal,coninhcount::integer,conparentid,connoinherit
            FROM pg_catalog.pg_constraint WHERE conrelid=$1
            """, c, tx))
        {
            command.Parameters.AddWithValue(NpgsqlDbType.Oid, tableOid);
            await using var rows = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            var primaryCount = 0; var notNull = new HashSet<short>(); var total = 0;
            while (await rows.ReadAsync(token).ConfigureAwait(false))
            {
                total++; var keys = rows.GetFieldValue<short[]>(2);
                Require(!rows.GetBoolean(3) && !rows.GetBoolean(4) && rows.GetBoolean(5) && rows.GetBoolean(6)
                    && rows.GetBoolean(7) && rows.GetInt32(8) == 0 && rows.GetFieldValue<uint>(9) == 0);
                if (rows.GetString(1) == "p")
                { Require(rows.GetString(0) == PrimaryKey && keys.SequenceEqual(new short[] { 1, 2 }) && rows.GetBoolean(10)); primaryCount++; }
                else
                { Require(rows.GetString(1) == "n" && keys.Length == 1 && keys[0] is >= 1 and <= 5 && !rows.GetBoolean(10) && notNull.Add(keys[0])); }
            }
            Require(total == 6 && primaryCount == 1 && notNull.Count == 5);
        }
        var indexes = new List<IndexedAuditStorageIndex>();
        await using (var command = new NpgsqlCommand($"""
            /* {InventoryTag} */
            SELECT ic.relname::text,am.amname,i.indisprimary,i.indisunique,i.indisvalid,i.indisready,i.indislive,i.indimmediate,
                i.indnkeyatts::integer,i.indnatts::integer,i.indexprs IS NULL,i.indpred IS NULL,
                ARRAY(SELECT a.attname::text FROM unnest(i.indkey::smallint[]) WITH ORDINALITY k(num,ord)
                    LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.num ORDER BY k.ord),
                ARRAY(SELECT COALESCE(n.nspname||'.'||co.collname,'') FROM unnest(i.indcollation::oid[]) WITH ORDINALITY k(num,ord)
                    LEFT JOIN pg_catalog.pg_collation co ON co.oid=k.num LEFT JOIN pg_catalog.pg_namespace n ON n.oid=co.collnamespace ORDER BY k.ord),
                ARRAY(SELECT n.nspname||'.'||o.opcname FROM unnest(i.indclass::oid[]) WITH ORDINALITY k(num,ord)
                    JOIN pg_catalog.pg_opclass o ON o.oid=k.num JOIN pg_catalog.pg_namespace n ON n.oid=o.opcnamespace ORDER BY k.ord),
                ARRAY(SELECT k.num::integer FROM unnest(i.indoption::smallint[]) WITH ORDINALITY k(num,ord) ORDER BY k.ord),
                ic.relpersistence::text,ic.relispartition,i.indisexclusion,i.indnullsnotdistinct
            FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class ic ON ic.oid=i.indexrelid
            JOIN pg_catalog.pg_am am ON am.oid=ic.relam WHERE i.indrelid=$1 ORDER BY ic.relname
            """, c, tx))
        {
            command.Parameters.AddWithValue(NpgsqlDbType.Oid, tableOid);
            await using var rows = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            while (await rows.ReadAsync(token).ConfigureAwait(false))
            {
                var name = rows.GetString(0); var primary = name == PrimaryKey; Require(primary || name == ResourceIndex);
                string[] keys = primary ? ["tenant", "receipt"] : ["tenant", "resource_kind", "resource_id", "receipt"];
                string[] collations = primary ? ["pg_catalog.C", ""] : ["pg_catalog.C", "pg_catalog.C", "pg_catalog.C", ""];
                string[] classes = primary ? ["pg_catalog.text_ops", "pg_catalog.uuid_ops"] : ["pg_catalog.text_ops", "pg_catalog.text_ops", "pg_catalog.text_ops", "pg_catalog.uuid_ops"];
                Require(rows.GetString(1) == "btree" && rows.GetBoolean(2) == primary && rows.GetBoolean(3) == primary
                    && Enumerable.Range(4, 4).All(rows.GetBoolean) && rows.GetInt32(8) == keys.Length && rows.GetInt32(9) == keys.Length
                    && rows.GetBoolean(10) && rows.GetBoolean(11) && rows.GetFieldValue<string[]>(12).SequenceEqual(keys)
                    && rows.GetFieldValue<string[]>(13).SequenceEqual(collations) && rows.GetFieldValue<string[]>(14).SequenceEqual(classes)
                    && rows.GetFieldValue<int[]>(15).Length == keys.Length && rows.GetFieldValue<int[]>(15).All(x => x == 0)
                    && rows.GetString(16) == "p" && !rows.GetBoolean(17) && !rows.GetBoolean(18) && !rows.GetBoolean(19));
                indexes.Add(new(name, primary, primary, "btree", Array.AsReadOnly(keys), Array.AsReadOnly(collations), Array.AsReadOnly(classes)));
            }
            Require(indexes.Count == 2 && indexes.Select(i => i.Name).Distinct().Count() == 2);
        }
        return new(VersionMarker, Schema, TableName, columns.AsReadOnly(), indexes.AsReadOnly());
    }

    public async ValueTask AppendOnceAsync(TenantChangeAuditRecord record, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(record);
        using var operation = Enter(initialize: false, token);
        var receipt = record.Receipt; var payload = PayloadCodec.Encode(record);
        Interlocked.Increment(ref appends);
        await using var c = await Open(token).ConfigureAwait(false);
        await using var command = new NpgsqlCommand($"""
            /* {AppendTag} */
            INSERT INTO {TableName} AS existing_row(tenant,receipt,resource_kind,resource_id,payload) VALUES($1,$2,$3,$4,$5)
            ON CONFLICT(tenant,receipt) DO UPDATE SET receipt=existing_row.receipt
            WHERE existing_row.tenant COLLATE "C"=excluded.tenant COLLATE "C" AND existing_row.receipt=excluded.receipt
              AND existing_row.resource_kind COLLATE "C"=excluded.resource_kind COLLATE "C"
              AND existing_row.resource_id COLLATE "C"=excluded.resource_id COLLATE "C"
              AND existing_row.payload COLLATE "C"=excluded.payload COLLATE "C"
            RETURNING 1
            """, c);
        command.Parameters.AddWithValue(receipt.Tenant.Value); command.Parameters.AddWithValue(receipt.ReceiptId);
        command.Parameters.AddWithValue(receipt.ResourceKind); command.Parameters.AddWithValue(receipt.ResourceId); command.Parameters.AddWithValue(payload);
        if (await command.ExecuteScalarAsync(token).ConfigureAwait(false) is not int value || value != 1)
            throw new InvalidOperationException("Indexed audit receipt conflicts with persisted metadata or payload.");
        // Exact replays may still create MVCC versions; only one visible key row is promised.
    }
    private static TenantChangeAuditRecord Decode(NpgsqlDataReader row, TenantId tenant, Guid? receipt = null,
        TenantChangeAuditResourceQuery? query = null)
    {
        var physicalTenant = row.GetString(0); var physicalReceipt = row.GetGuid(1); var kind = row.GetString(2); var id = row.GetString(3);
        var record = PayloadCodec.Decode(row.GetString(4)); var data = record.Receipt;
        if (!StringComparer.Ordinal.Equals(physicalTenant, tenant.Value) || !StringComparer.Ordinal.Equals(data.Tenant.Value, physicalTenant)
            || data.ReceiptId != physicalReceipt || !StringComparer.Ordinal.Equals(data.ResourceKind, kind) || !StringComparer.Ordinal.Equals(data.ResourceId, id)
            || receipt is { } requested && requested != physicalReceipt
            || query is not null && (!StringComparer.Ordinal.Equals(kind, query.ResourceKind) || !StringComparer.Ordinal.Equals(id, query.ResourceId)))
            throw new InvalidOperationException("Indexed audit physical metadata and decoded record differ.");
        return record;
    }
    public async ValueTask<TenantChangeAuditRecord?> FindAsync(TenantId authorizedTenant, Guid receiptId, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(authorizedTenant);
        if (receiptId == Guid.Empty) throw new ArgumentException("Receipt cannot be empty.", nameof(receiptId));
        using var operation = Enter(initialize: false, token); Interlocked.Increment(ref lookups);
        await using var c = await Open(token).ConfigureAwait(false);
        await using var command = new NpgsqlCommand($"/* {LookupTag} */ SELECT tenant,receipt,resource_kind,resource_id,payload FROM {TableName} WHERE tenant COLLATE \"C\"=($1::text COLLATE \"C\") AND receipt=$2", c);
        command.Parameters.AddWithValue(authorizedTenant.Value); command.Parameters.AddWithValue(receiptId);
        await using var rows = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
        if (!await rows.ReadAsync(token).ConfigureAwait(false)) return null;
        var result = Decode(rows, authorizedTenant, receiptId);
        if (await rows.ReadAsync(token).ConfigureAwait(false)) throw new InvalidOperationException("Indexed audit lookup returned duplicate physical keys.");
        return result;
    }
    public string ResourceSelectSql => $"""
        /* {ResourceTag} */
        SELECT tenant,receipt,resource_kind,resource_id,payload FROM {TableName}
        WHERE tenant COLLATE "C"=($1::text COLLATE "C")
          AND resource_kind COLLATE "C"=($2::text COLLATE "C") AND resource_id COLLATE "C"=($3::text COLLATE "C")
          AND ($4::uuid IS NULL OR receipt>$4::uuid) ORDER BY receipt LIMIT $5
        """;
    private static void BindResource(NpgsqlCommand command, TenantId tenant, TenantChangeAuditResourceQuery query)
    {
        ArgumentNullException.ThrowIfNull(tenant); ArgumentNullException.ThrowIfNull(query);
        if (query.Continuation is { } cursor && (!tenant.Equals(cursor.Tenant) || !StringComparer.Ordinal.Equals(query.ResourceKind, cursor.ResourceKind) || !StringComparer.Ordinal.Equals(query.ResourceId, cursor.ResourceId)))
            throw new ArgumentException("Continuation does not match the selected tenant/resource.", nameof(query));
        command.Parameters.AddWithValue(tenant.Value); command.Parameters.AddWithValue(query.ResourceKind); command.Parameters.AddWithValue(query.ResourceId);
        command.Parameters.AddWithValue(NpgsqlDbType.Uuid, (object?)query.Continuation?.AfterReceiptId ?? DBNull.Value);
        command.Parameters.AddWithValue(query.Limit + 1);
    }
    public async ValueTask<TenantChangeAuditResourcePage> ReadAsync(TenantId authorizedTenant, TenantChangeAuditResourceQuery query, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(authorizedTenant); ArgumentNullException.ThrowIfNull(query);
        using var operation = Enter(initialize: false, token);
        await using var command = new NpgsqlCommand(ResourceSelectSql); BindResource(command, authorizedTenant, query);
        Interlocked.Increment(ref reads); var candidates = 0; var decoded = 0;
        try
        {
            await using var c = await Open(token).ConfigureAwait(false); command.Connection = c;
            var records = new List<TenantChangeAuditRecord>();
            await using (var rows = await command.ExecuteReaderAsync(token).ConfigureAwait(false))
                while (await rows.ReadAsync(token).ConfigureAwait(false))
                { candidates++; var record = Decode(rows, authorizedTenant, query: query); decoded++; records.Add(record); }
            var selected = records.Take(query.Limit).ToArray();
            var next = records.Count > query.Limit ? new TenantChangeAuditResourceCursor(authorizedTenant, query.ResourceKind, query.ResourceId, selected[^1].Receipt.ReceiptId) : null;
            return new(selected, next);
        }
        finally { Volatile.Write(ref lastCandidates, candidates); Volatile.Write(ref lastDecoded, decoded); }
    }
    public async Task<string> ExplainResourceQueryAsync(TenantId authorizedTenant, TenantChangeAuditResourceQuery query, CancellationToken token = default)
    {
        using var operation = Enter(initialize: false, token);
        await using var command = new NpgsqlCommand("EXPLAIN(ANALYZE,BUFFERS,FORMAT JSON,TIMING OFF) " + ResourceSelectSql);
        BindResource(command, authorizedTenant, query); Interlocked.Increment(ref explains);
        await using var c = await Open(token).ConfigureAwait(false); command.Connection = c;
        return (string)(await command.ExecuteScalarAsync(token).ConfigureAwait(false) ?? throw new InvalidOperationException("Missing indexed audit plan."));
    }
    public ValueTask DisposeAsync()
    {
        lock (gate)
        {
            if (disposal is not null) return new(disposal);
            state = 3; // Reject new work before awaiting any in-flight caller-owned operations.
            var wait = active == 0 ? Task.CompletedTask : (drained = new(TaskCreationOptions.RunContinuationsAsynchronously)).Task;
            disposal = DisposeAfter(wait);
            return new(disposal);
        }
    }
    private async Task DisposeAfter(Task wait) { await wait.ConfigureAwait(false); await DisposeClient().ConfigureAwait(false); }
    private async Task DisposeClient()
    {
        var owned = Interlocked.Exchange(ref dataSource, null);
        if (owned is null) return;
        Interlocked.Increment(ref clientDisposals);
        await owned.DisposeAsync().ConfigureAwait(false);
    }
}
