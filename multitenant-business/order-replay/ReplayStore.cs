using System.Data;
using Cehpalon.Engine.Tenancy;
using Npgsql;
using static Business.OrderReplay.ReplayFixture;

namespace Business.OrderReplay;

internal sealed record Ledger(int Stock, string Status, int Revision, long Outbox, long Published, long Inbox);

internal sealed class ReplayStore(NpgsqlDataSource source)
{
    internal int OpenAttempts { get; private set; }
    private int lastBackend;

    internal Task<bool> CreateAsync(TenantOperationContext context, CancellationToken token) =>
        InTransactionAsync(context, Place, async (connection, transaction) =>
        {
            RequireProducer(context);
            await using var order = Command(connection, transaction, """
                INSERT INTO cephalon_replay.orders(tenant_id, order_id, sku, quantity, status, revision)
                VALUES ($1, $2, $3, $4, 'pending', 0)
                """, context.Tenant.Value, Expected.OrderId, Expected.Sku, Expected.Quantity);
            Require(await order.ExecuteNonQueryAsync(token) == 1, "Expected one inserted order.");

            await using var outbox = Command(connection, transaction, """
                INSERT INTO cephalon_replay.outbox(tenant_id, event_id, order_id, sku, quantity,
                    event_type, schema_version, aggregate_version, trace_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                """, context.Tenant.Value, Expected.EventId, Expected.OrderId, Expected.Sku, Expected.Quantity,
                Expected.EventType, Expected.SchemaVersion, Expected.AggregateVersion, Expected.TraceId);
            Require(await outbox.ExecuteNonQueryAsync(token) == 1, "Expected one inserted outbox event.");
            return true;
        }, token);

    internal Task<Envelope> LoadUnpublishedAsync(TenantOperationContext context, CancellationToken token) =>
        InTransactionAsync(context, Publish, async (connection, transaction) =>
        {
            RequireProducer(context);
            var row = await LoadEventAsync(context.Tenant, connection, transaction, token);
            Require(!row.Published && row.Event == Expected, "Expected the selected immutable event to be unpublished.");
            return row.Event;
        }, token);

    internal Task<bool> MarkPublishedAsync(TenantOperationContext context, Envelope published, CancellationToken token) =>
        InTransactionAsync(context, Publish, async (connection, transaction) =>
        {
            RequireProducer(context);
            var row = await LoadEventAsync(context.Tenant, connection, transaction, token);
            Require(!row.Published && row.Event == published, "The confirmed event did not match the unpublished row.");
            await using var command = Command(connection, transaction, """
                UPDATE cephalon_replay.outbox SET published = true
                WHERE tenant_id = $1 AND event_id = $2 AND order_id = $3 AND NOT published
                """, context.Tenant.Value, published.EventId, published.OrderId);
            Require(await command.ExecuteNonQueryAsync(token) == 1, "Expected to mark one confirmed event.");
            return true;
        }, token);

    internal Task<bool> ApplyAsync(TenantOperationContext context, Envelope delivered, CancellationToken token) =>
        InTransactionAsync(context, Reserve, async (connection, transaction) =>
        {
            RequireProducer(context);
            var row = await LoadEventAsync(context.Tenant, connection, transaction, token);
            Require(delivered == row.Event && delivered == Expected,
                "The delivery did not match the durable event and authorized scope.");

            await using var inbox = Command(connection, transaction, """
                INSERT INTO cephalon_replay.inbox(tenant_id, event_id, order_id)
                VALUES ($1, $2, $3) ON CONFLICT (tenant_id, event_id) DO NOTHING
                """, context.Tenant.Value, delivered.EventId, delivered.OrderId);
            var inserted = await inbox.ExecuteNonQueryAsync(token);
            if (inserted == 0) return false;
            Require(inserted == 1, "Expected one new inbox marker.");

            await using var stock = Command(connection, transaction, """
                UPDATE cephalon_replay.stock SET available = available - $3
                WHERE tenant_id = $1 AND sku = $2 AND available >= $3
                """, context.Tenant.Value, delivered.Sku, delivered.Quantity);
            Require(await stock.ExecuteNonQueryAsync(token) == 1, "Expected one successful stock decrement.");

            await using var order = Command(connection, transaction, """
                UPDATE cephalon_replay.orders SET status = 'reserved', revision = revision + 1
                WHERE tenant_id = $1 AND order_id = $2 AND sku = $3 AND quantity = $4
                    AND revision = $5 AND status = 'pending'
                """, context.Tenant.Value, delivered.OrderId, delivered.Sku, delivered.Quantity, delivered.AggregateVersion);
            Require(await order.ExecuteNonQueryAsync(token) == 1, "Expected one eligible order transition.");
            return true;
        }, token);

    internal Task<Ledger> InspectAsync(TenantOperationContext context, CancellationToken token) =>
        InTransactionAsync(context, Inspect, async (connection, transaction) =>
        {
            await using var command = Command(connection, transaction, """
                SELECT stock.available, orders.status, orders.revision,
                    (SELECT count(*) FROM cephalon_replay.outbox WHERE tenant_id = $1),
                    (SELECT count(*) FROM cephalon_replay.outbox WHERE tenant_id = $1 AND published),
                    (SELECT count(*) FROM cephalon_replay.inbox WHERE tenant_id = $1)
                FROM cephalon_replay.orders AS orders JOIN cephalon_replay.stock AS stock
                    ON stock.tenant_id = orders.tenant_id AND stock.sku = orders.sku
                WHERE orders.tenant_id = $1 AND orders.order_id = $2 AND orders.sku = $3 AND orders.quantity = $4
                """, context.Tenant.Value, Expected.OrderId, Expected.Sku, Expected.Quantity);
            await using var rows = await command.ExecuteReaderAsync(token);
            Require(await rows.ReadAsync(token), "The scoped ledger was missing.");
            return new Ledger(rows.GetInt32(0), rows.GetString(1), rows.GetInt32(2), rows.GetInt64(3),
                rows.GetInt64(4), rows.GetInt64(5));
        }, token);

    internal async Task VerifyBoundaryAsync(CancellationToken token)
    {
        await using var connection = await source.OpenConnectionAsync(token);
        Require(lastBackend == connection.ProcessID, "Expected to reuse the same PostgreSQL backend.");
        await using var command = new NpgsqlCommand("""
            SELECT NULLIF(current_setting('cephalon_replay.tenant_id', true), '') IS NULL
                AND NOT EXISTS (SELECT 1 FROM cephalon_replay.orders)
                AND NOT EXISTS (SELECT 1 FROM cephalon_replay.stock)
                AND NOT EXISTS (SELECT 1 FROM cephalon_replay.outbox)
                AND NOT EXISTS (SELECT 1 FROM cephalon_replay.inbox)
            """, connection);
        Require(await command.ExecuteScalarAsync(token) is true, "An unscoped backend exposed scoped state.");
    }

    internal async Task VerifyRoleAsync(CancellationToken token)
    {
        await using var connection = await source.OpenConnectionAsync(token);
        await using var command = new NpgsqlCommand("""
            SELECT current_setting('server_version_num') = '180006'
                AND current_user = session_user AND current_user = 'cephalon_replay_runtime'
                AND role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolbypassrls
                AND NOT has_database_privilege(role.rolname, current_database(), 'CREATE')
                AND EXISTS (
                    SELECT 1 FROM pg_namespace WHERE nspname = 'cephalon_replay'
                        AND NOT has_schema_privilege(role.rolname, oid, 'CREATE'))
                AND (SELECT count(*) = 4 AND bool_and(t.relrowsecurity AND t.relforcerowsecurity
                        AND NOT pg_has_role(role.oid, t.relowner, 'MEMBER'))
                    FROM pg_class AS t JOIN pg_namespace AS n ON n.oid = t.relnamespace
                    WHERE n.nspname = 'cephalon_replay' AND t.relname IN ('orders','stock','outbox','inbox'))
            FROM pg_roles AS role WHERE role.rolname = current_user
            """, connection);
        Require(await command.ExecuteScalarAsync(token) is true, "Unexpected PostgreSQL version or runtime privileges.");
    }

    private async Task<T> InTransactionAsync<T>(TenantOperationContext context, string operation,
        Func<NpgsqlConnection, NpgsqlTransaction, Task<T>> work, CancellationToken token)
    {
        void Demand()
        {
            token.ThrowIfCancellationRequested();
            Require(context.OperationId == operation, "Unexpected checked operation.");
            context.DemandAccess(context.Tenant, Resource, OrderKey, operation);
        }

        Demand();
        OpenAttempts++;
        await using var connection = await source.OpenConnectionAsync(token);
        lastBackend = connection.ProcessID;
        Demand();
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, token);
        Demand();
        await using (var scope = Command(connection, transaction,
            "SELECT set_config('cephalon_replay.tenant_id', $1, true)", context.Tenant.Value))
            await scope.ExecuteScalarAsync(token);
        Demand();
        var result = await work(connection, transaction);
        Demand();
        using var commitDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await transaction.CommitAsync(commitDeadline.Token);
        Demand();
        return result;
    }

    private static async Task<(Envelope Event, bool Published)> LoadEventAsync(TenantId tenant, NpgsqlConnection connection,
        NpgsqlTransaction transaction, CancellationToken token)
    {
        await using var command = Command(connection, transaction, """
            SELECT event_id, order_id, sku, quantity, event_type, schema_version, aggregate_version, trace_id, published
            FROM cephalon_replay.outbox WHERE tenant_id = $1 AND event_id = $2 AND order_id = $3
            """, tenant.Value, Expected.EventId, Expected.OrderId);
        await using var rows = await command.ExecuteReaderAsync(token);
        Require(await rows.ReadAsync(token), "The authorized immutable outbox event was missing.");
        return (new Envelope(tenant.Value, rows.GetGuid(0), rows.GetGuid(1), rows.GetString(2), rows.GetInt32(3),
            rows.GetString(4), rows.GetInt32(5), rows.GetInt32(6), rows.GetString(7)), rows.GetBoolean(8));
    }

    private static void RequireProducer(TenantOperationContext context) =>
        Require(context.Tenant.Equals(Alpha), "The selected replay action lacks fixture tenant authority.");

    private static NpgsqlCommand Command(NpgsqlConnection connection, NpgsqlTransaction transaction, string sql,
        params object[] parameters)
    {
        var command = new NpgsqlCommand(sql, connection, transaction);
        foreach (var parameter in parameters)
            command.Parameters.AddWithValue(parameter);
        return command;
    }
}
