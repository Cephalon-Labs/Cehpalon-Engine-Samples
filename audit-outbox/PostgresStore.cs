using System.Globalization;
using System.Text.RegularExpressions;
using Cehpalon.Engine.Tenancy;
using Npgsql;

namespace AuditOutbox;

public enum ProviderFault { None,StageAfterInsert,CommitBefore,CommitAfter,Rollback,Dispose,Sink,Ack }
public sealed record DomainRow(string Title,decimal Amount,string Secret,int Revision);

// Local consumer adapter, not a provider installed by Engine activation.
public sealed class PostgresStore(string connectionString,string schema):ITenantChangeAuditTransactionProvider<DomainSession>,ITenantChangeAuditOutboxSource,ITenantChangeAuditIdempotentSink,ITenantChangeAuditHistorySource,ITenantChangeAuditOutboxStatusSource
{
    private readonly string schema=Regex.IsMatch(schema,"^ao_[a-f0-9]{32}$",RegexOptions.CultureInvariant)?schema:throw new ArgumentException("Owned schema identifier required.");
    public ProviderFault Fault;public int HistoryReads,StatusReads,LastStatusBackendPid;
    public Func<CancellationToken,Task>? BeforeStatusQuery,AfterStatusQuery;public TenantId? StatusOwnerOverride;public int Connections,Begins,Stages,Commits,Rollbacks,Disposals,Claims,Acks,Releases,SinkCalls;
    public DomainSession? RetainedSession;public TenantChangeAuditRecord? LastRecord;public TenantChangeAuditOutboxLease? LastLease;
    public Action? AfterCommit;public bool ShortLease;public Func<Task>? AfterSink;
    public string Schema=>schema;
    private string Table(string table)=>schema+"."+table;
    private async Task<NpgsqlConnection> Open(CancellationToken token)
    {
        Interlocked.Increment(ref Connections);var connection=new NpgsqlConnection(connectionString);
        try{await connection.OpenAsync(token);return connection;}catch{await connection.DisposeAsync();throw;}
    }
    public async Task Initialize(CancellationToken token=default)
    {
        await using var c=await Open(token);await using var cmd=new NpgsqlCommand($"""
            CREATE SCHEMA {schema};
            CREATE TABLE {Table("domain_rows")}(tenant text NOT NULL,id text NOT NULL,title text NOT NULL,amount numeric NOT NULL,secret text NOT NULL,revision integer NOT NULL,PRIMARY KEY(tenant,id));
            CREATE TABLE {Table("audit_outbox")}(tenant text NOT NULL,receipt uuid NOT NULL,payload text NOT NULL,lease uuid NULL,expires timestamptz NULL,delivered boolean NOT NULL DEFAULT false,enqueued_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant,receipt));
            CREATE TABLE {Table("audit_sink")}(tenant text NOT NULL,receipt uuid NOT NULL,payload text NOT NULL,PRIMARY KEY(tenant,receipt));
            INSERT INTO {Table("domain_rows")} VALUES('A','shared','original-A',1,'private-domain-A',0),('B','shared','original-B',1,'private-domain-B',0);
            """,c);await cmd.ExecuteNonQueryAsync(token);
    }
    public async ValueTask<ITenantChangeAuditTransaction<DomainSession>> BeginAsync(TenantId tenant,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();Interlocked.Increment(ref Begins);var c=await Open(token);
        try{return new Transaction(this,c,await c.BeginTransactionAsync(token),tenant);}catch{await c.DisposeAsync();throw;}
    }
    private sealed class Transaction:ITenantChangeAuditTransaction<DomainSession>
    {
        private readonly PostgresStore owner;private readonly NpgsqlConnection connection;private readonly NpgsqlTransaction transaction;private readonly TenantId tenant;
        private bool active=true,finished;
        public Transaction(PostgresStore owner,NpgsqlConnection connection,NpgsqlTransaction transaction,TenantId tenant)
        {this.owner=owner;this.connection=connection;this.transaction=transaction;this.tenant=tenant;Session=new DomainSession(this);owner.RetainedSession=Session;}
        public DomainSession Session{get;}
        public void Demand(TenantId requested){if(!active||finished||!requested.Equals(tenant))throw new InvalidOperationException("Transaction session is closed or belongs to another tenant.");}
        public async Task<(DomainRow Before,DomainRow After)> Mutate(TenantId requested,string id,string title,decimal amount,string secret,CancellationToken token)
        {
            Demand(requested);token.ThrowIfCancellationRequested();
            await using var read=new NpgsqlCommand($"SELECT title,amount,secret,revision FROM {owner.Table("domain_rows")} WHERE tenant=$1 AND id=$2 FOR UPDATE",connection,transaction);
            read.Parameters.AddWithValue(tenant.Value);read.Parameters.AddWithValue(id);
            DomainRow before;await using(var rows=await read.ExecuteReaderAsync(token)){if(!await rows.ReadAsync(token))throw new InvalidOperationException("Missing owned row.");before=new(rows.GetString(0),rows.GetDecimal(1),rows.GetString(2),rows.GetInt32(3));}
            await using var update=new NpgsqlCommand($"UPDATE {owner.Table("domain_rows")} SET title=$3,amount=$4,secret=$5,revision=revision+1 WHERE tenant=$1 AND id=$2",connection,transaction);
            update.Parameters.AddWithValue(tenant.Value);update.Parameters.AddWithValue(id);update.Parameters.AddWithValue(title);update.Parameters.AddWithValue(amount);update.Parameters.AddWithValue(secret);
            if(await update.ExecuteNonQueryAsync(token)!=1)throw new InvalidOperationException("Missing owned update.");
            return(before,new(title,amount,secret,before.Revision+1));
        }
        public async ValueTask StageAsync(TenantChangeAuditRecord record,CancellationToken token)
        {
            Demand(record.Receipt.Tenant);Interlocked.Increment(ref owner.Stages);owner.LastRecord=record;
            await using var insert=new NpgsqlCommand($"INSERT INTO {owner.Table("audit_outbox")}(tenant,receipt,payload) VALUES($1,$2,$3)",connection,transaction);
            insert.Parameters.AddWithValue(tenant.Value);insert.Parameters.AddWithValue(record.Receipt.ReceiptId);insert.Parameters.AddWithValue(PayloadCodec.Encode(record));await insert.ExecuteNonQueryAsync(token);
            if(owner.Fault==ProviderFault.StageAfterInsert)throw new IOException("Controlled stage failure after actual insert.");
        }
        public async ValueTask CommitAsync(CancellationToken token)
        {
            Demand(tenant);Interlocked.Increment(ref owner.Commits);if(owner.Fault==ProviderFault.CommitBefore)throw new IOException("Controlled unknown commit before physical commit.");
            await transaction.CommitAsync(token);finished=true;owner.AfterCommit?.Invoke();
            if(owner.Fault==ProviderFault.CommitAfter)throw new IOException("Controlled lost commit acknowledgement.");
        }
        public async ValueTask RollbackAsync(CancellationToken token)
        {
            Demand(tenant);Interlocked.Increment(ref owner.Rollbacks);if(owner.Fault==ProviderFault.Rollback)throw new IOException("Controlled rollback acknowledgement failure.");
            await transaction.RollbackAsync(token);finished=true;
        }
        public async ValueTask DisposeAsync()
        {
            if(!active)return;active=false;Interlocked.Increment(ref owner.Disposals);
            try{await transaction.DisposeAsync();}finally{await connection.DisposeAsync();}
            if(owner.Fault==ProviderFault.Dispose)throw new IOException("Controlled disposal failure after physical cleanup.");
        }
    }
    // A consuming callback cannot commit/rollback through this public domain-only session.
    public sealed class SessionBridge
    {
        public static Task<(DomainRow Before,DomainRow After)> Change(object transaction,TenantId tenant,string id,string title,decimal amount,string secret,CancellationToken token)
            =>((Transaction)transaction).Mutate(tenant,id,title,amount,secret,token);
    }
    public async Task<DomainRow> Row(string tenant="A")
    {
        await using var c=await Open(default);await using var cmd=new NpgsqlCommand($"SELECT title,amount,secret,revision FROM {Table("domain_rows")} WHERE tenant=$1 AND id='shared'",c);cmd.Parameters.AddWithValue(tenant);
        await using var rows=await cmd.ExecuteReaderAsync();if(!await rows.ReadAsync())throw new InvalidOperationException();return new(rows.GetString(0),rows.GetDecimal(1),rows.GetString(2),rows.GetInt32(3));
    }
    public async Task<(int Outbox,int Delivered,int Sink)> Counts(string tenant="A")
    {
        await using var c=await Open(default);await using var cmd=new NpgsqlCommand($"SELECT (SELECT count(*) FROM {Table("audit_outbox")} WHERE tenant=$1),(SELECT count(*) FROM {Table("audit_outbox")} WHERE tenant=$1 AND delivered),(SELECT count(*) FROM {Table("audit_sink")} WHERE tenant=$1)",c);cmd.Parameters.AddWithValue(tenant);
        await using var rows=await cmd.ExecuteReaderAsync();await rows.ReadAsync();return(checked((int)rows.GetInt64(0)),checked((int)rows.GetInt64(1)),checked((int)rows.GetInt64(2)));
    }
    public async Task<string[]> Payloads(string table="audit_outbox",string tenant="A")
    {
        if(table is not("audit_outbox" or "audit_sink"))throw new ArgumentException();await using var c=await Open(default);await using var cmd=new NpgsqlCommand($"SELECT payload FROM {Table(table)} WHERE tenant=$1 ORDER BY receipt",c);cmd.Parameters.AddWithValue(tenant);
        var result=new List<string>();await using var rows=await cmd.ExecuteReaderAsync();while(await rows.ReadAsync())result.Add(rows.GetString(0));return result.ToArray();
    }
    public async ValueTask<TenantChangeAuditOutboxLease?> ClaimAsync(TenantId tenant,int maximum,TimeSpan duration,CancellationToken token)
    {
        Interlocked.Increment(ref Claims);var id=Guid.NewGuid();await using var c=await Open(token);await using var tx=await c.BeginTransactionAsync(token);
        await using var cmd=new NpgsqlCommand($"""
            WITH selected AS (SELECT tenant,receipt FROM {Table("audit_outbox")} WHERE tenant=$1 AND NOT delivered AND (lease IS NULL OR expires<=clock_timestamp()) ORDER BY receipt LIMIT $2 FOR UPDATE SKIP LOCKED)
            UPDATE {Table("audit_outbox")} AS a SET lease=$3,expires=clock_timestamp()+$4 FROM selected s WHERE a.tenant=s.tenant AND a.receipt=s.receipt RETURNING a.payload,a.expires
            """,c,tx);
        cmd.Parameters.AddWithValue(tenant.Value);cmd.Parameters.AddWithValue(maximum);cmd.Parameters.AddWithValue(id);cmd.Parameters.AddWithValue(ShortLease?TimeSpan.FromMilliseconds(100):duration);
        var records=new List<TenantChangeAuditRecord>();DateTimeOffset? expires=null;
        await using(var rows=await cmd.ExecuteReaderAsync(token)){while(await rows.ReadAsync(token)){records.Add(PayloadCodec.Decode(rows.GetString(0)));var rowExpiry=new DateTimeOffset(rows.GetDateTime(1));expires=expires is null||rowExpiry<expires?rowExpiry:expires;}}
        await tx.CommitAsync(token);if(records.Count==0)return null;
        return LastLease=new(tenant,id,expires!.Value,records);
    }
    public async ValueTask<bool> AcknowledgeAsync(TenantChangeAuditOutboxLease lease,Guid receiptId,CancellationToken token)
    {
        Interlocked.Increment(ref Acks);if(Fault==ProviderFault.Ack)throw new IOException("Controlled acknowledgement loss after sink publication.");
        await using var c=await Open(token);await using var cmd=new NpgsqlCommand($"UPDATE {Table("audit_outbox")} SET delivered=true,lease=NULL,expires=NULL WHERE tenant=$1 AND receipt=$2 AND lease=$3 AND expires>clock_timestamp() AND NOT delivered",c);
        cmd.Parameters.AddWithValue(lease.Tenant.Value);cmd.Parameters.AddWithValue(receiptId);cmd.Parameters.AddWithValue(lease.LeaseId);return await cmd.ExecuteNonQueryAsync(token)==1;
    }
    public async ValueTask ReleaseAsync(TenantChangeAuditOutboxLease lease,CancellationToken token)
    {
        Interlocked.Increment(ref Releases);await using var c=await Open(token);await using var cmd=new NpgsqlCommand($"UPDATE {Table("audit_outbox")} SET lease=NULL,expires=NULL WHERE tenant=$1 AND lease=$2 AND NOT delivered",c);cmd.Parameters.AddWithValue(lease.Tenant.Value);cmd.Parameters.AddWithValue(lease.LeaseId);await cmd.ExecuteNonQueryAsync(token);
    }
    public async ValueTask AppendOnceAsync(TenantChangeAuditRecord record,CancellationToken token)
    {
        Interlocked.Increment(ref SinkCalls);if(Fault==ProviderFault.Sink)throw new IOException("Controlled unavailable audit sink.");
        var payload=PayloadCodec.Encode(record);await using var c=await Open(token);await using var cmd=new NpgsqlCommand($"INSERT INTO {Table("audit_sink")}(tenant,receipt,payload) VALUES($1,$2,$3) ON CONFLICT(tenant,receipt) DO UPDATE SET payload={Table("audit_sink")}.payload WHERE {Table("audit_sink")}.payload=EXCLUDED.payload RETURNING payload",c);
        cmd.Parameters.AddWithValue(record.Receipt.Tenant.Value);cmd.Parameters.AddWithValue(record.Receipt.ReceiptId);cmd.Parameters.AddWithValue(payload);
        if(await cmd.ExecuteScalarAsync(token) is not string)throw new InvalidOperationException("Conflicting payload for tenant/receipt identity.");
        if(AfterSink is not null)await AfterSink();
    }
    public async ValueTask<TenantChangeAuditPage> ReadAsync(TenantId tenant,int limit,string? cursor,CancellationToken token)
    {
        Interlocked.Increment(ref HistoryReads);var offset=cursor is null?0:int.Parse(cursor,CultureInfo.InvariantCulture);
        if(offset<0)throw new ArgumentException("Invalid owned cursor.");await using var c=await Open(token);
        await using var cmd=new NpgsqlCommand($"SELECT payload FROM {Table("audit_sink")} WHERE tenant=$1 ORDER BY receipt LIMIT $2 OFFSET $3",c);
        cmd.Parameters.AddWithValue(tenant.Value);cmd.Parameters.AddWithValue(limit+1);cmd.Parameters.AddWithValue(offset);
        var rows=new List<TenantChangeAuditRecord>();await using(var reader=await cmd.ExecuteReaderAsync(token)){while(await reader.ReadAsync(token))rows.Add(PayloadCodec.Decode(reader.GetString(0)));}
        return new(rows.Take(limit),rows.Count>limit?(offset+limit).ToString(CultureInfo.InvariantCulture):null);
    }
    public async ValueTask<TenantChangeAuditOutboxStatus> ReadAsync(TenantId tenant,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();Interlocked.Increment(ref StatusReads);
        if(BeforeStatusQuery is not null)await BeforeStatusQuery(token);
        TenantChangeAuditOutboxStatus snapshot;
        await using(var c=await Open(token))
        {
            LastStatusBackendPid=c.ProcessID;
            await using var cmd=new NpgsqlCommand($"""
                /* owned-outbox-status-read */
                WITH snapshot_clock AS MATERIALIZED (SELECT clock_timestamp() AS observed)
                SELECT snapshot_clock.observed,
                    count(o.receipt) FILTER(WHERE NOT o.delivered),
                    count(o.receipt) FILTER(WHERE NOT o.delivered AND (o.lease IS NULL OR o.expires<=snapshot_clock.observed)),
                    count(o.receipt) FILTER(WHERE NOT o.delivered AND o.lease IS NOT NULL AND o.expires>snapshot_clock.observed),
                    count(o.receipt) FILTER(WHERE NOT o.delivered AND o.lease IS NOT NULL AND o.expires<=snapshot_clock.observed),
                    count(o.receipt) FILTER(WHERE o.delivered),min(o.enqueued_at) FILTER(WHERE NOT o.delivered)
                FROM snapshot_clock LEFT JOIN {Table("audit_outbox")} o ON o.tenant=$1
                GROUP BY snapshot_clock.observed
                """,c);
            cmd.Parameters.AddWithValue(tenant.Value);await using var rows=await cmd.ExecuteReaderAsync(token);if(!await rows.ReadAsync(token))throw new InvalidOperationException("Status aggregate returned no snapshot.");
            snapshot=new(StatusOwnerOverride??tenant,new DateTimeOffset(rows.GetDateTime(0)),rows.GetInt64(1),rows.GetInt64(2),rows.GetInt64(3),rows.GetInt64(4),rows.GetInt64(5),rows.IsDBNull(6)?null:new DateTimeOffset(rows.GetDateTime(6)));
        }
        if(AfterStatusQuery is not null)await AfterStatusQuery(token);
        return snapshot;
    }
    public async Task ExpireLease(TenantChangeAuditOutboxLease lease)
    {
        await using var c=await Open(default);await using var cmd=new NpgsqlCommand($"UPDATE {Table("audit_outbox")} SET expires=clock_timestamp()-interval '1 second' WHERE tenant=$1 AND lease=$2",c);cmd.Parameters.AddWithValue(lease.Tenant.Value);cmd.Parameters.AddWithValue(lease.LeaseId);await cmd.ExecuteNonQueryAsync();
    }
    public async Task ExpireClaimReceipt(TenantChangeAuditOutboxLease lease,Guid receipt)
    {
        await using var c=await Open(default);await using var cmd=new NpgsqlCommand($"UPDATE {Table("audit_outbox")} SET expires=clock_timestamp()-interval '1 second' WHERE tenant=$1 AND lease=$2 AND receipt=$3",c);cmd.Parameters.AddWithValue(lease.Tenant.Value);cmd.Parameters.AddWithValue(lease.LeaseId);cmd.Parameters.AddWithValue(receipt);await cmd.ExecuteNonQueryAsync();
    }
    public async Task<(Guid Receipt,DateTimeOffset Enqueued)[]> PendingEnqueueTimes(string tenant="A")
    {
        await using var c=await Open(default);await using var cmd=new NpgsqlCommand($"SELECT receipt,enqueued_at FROM {Table("audit_outbox")} WHERE tenant=$1 AND NOT delivered ORDER BY enqueued_at,receipt",c);cmd.Parameters.AddWithValue(tenant);var result=new List<(Guid,DateTimeOffset)>();await using var rows=await cmd.ExecuteReaderAsync();while(await rows.ReadAsync())result.Add((rows.GetGuid(0),new DateTimeOffset(rows.GetDateTime(1))));return result.ToArray();
    }
    public async Task<IAsyncDisposable> HoldStatusTableLock()
    {
        var c=await Open(default);var tx=await c.BeginTransactionAsync();try{await using var command=new NpgsqlCommand($"LOCK TABLE {Table("audit_outbox")} IN ACCESS EXCLUSIVE MODE",c,tx);await command.ExecuteNonQueryAsync();return new StatusLock(c,tx);}catch{await tx.DisposeAsync();await c.DisposeAsync();throw;}
    }
    private sealed class StatusLock(NpgsqlConnection connection,NpgsqlTransaction transaction):IAsyncDisposable
    {
        public async ValueTask DisposeAsync(){try{await transaction.RollbackAsync();}finally{await transaction.DisposeAsync();await connection.DisposeAsync();}}
    }
    public async Task<bool> StatusQueryIsLockBlocked()
    {
        await using var c=await Open(default);await using var cmd=new NpgsqlCommand("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND query LIKE '%owned-outbox-status-read%')",c);cmd.Parameters.AddWithValue(LastStatusBackendPid);return (bool)(await cmd.ExecuteScalarAsync())!;
    }
    public async Task<bool> StatusBackendQuiescent(int backendPid)
    {
        await using var c=await Open(default);if(c.ProcessID==backendPid)return true;
        await using var cmd=new NpgsqlCommand("SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND (state='active' OR wait_event_type='Lock'))",c);cmd.Parameters.AddWithValue(backendPid);return (bool)(await cmd.ExecuteScalarAsync())!;
    }
    public async Task<string> VersionSettings()
    {
        await using var c=await Open(default);await using var cmd=new NpgsqlCommand("SELECT version(),current_setting('fsync'),current_setting('synchronous_commit'),current_setting('full_page_writes')",c);
        await using var r=await cmd.ExecuteReaderAsync();await r.ReadAsync();return System.Text.Json.JsonSerializer.Serialize(new{server_version=r.GetString(0),fsync=r.GetString(1),synchronous_commit=r.GetString(2),full_page_writes=r.GetString(3)});
    }
    public static TenantChangeReceipt ReplaceTenant(TenantChangeReceipt r,TenantId tenant)=>new(r.ReceiptId,r.Principal,r.AuthenticationScheme,tenant,r.OperationId,r.Action,r.ResourceKind,r.ResourceId,r.AuthorizationResourceVersion,r.Kind,r.BeforeEntityVersion,r.AfterEntityVersion,r.ReportedAtUtc);
}

public sealed class DomainSession
{
    private readonly object transaction;
    internal DomainSession(object transaction)=>this.transaction=transaction;
    public Task<(DomainRow Before,DomainRow After)> Change(TenantId tenant,string id,string title,decimal amount,string secret,CancellationToken token=default)
        =>PostgresStore.SessionBridge.Change(transaction,tenant,id,title,amount,secret,token);
}
