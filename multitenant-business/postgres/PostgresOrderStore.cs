using System.Data;
using System.Globalization;
using System.Runtime.ExceptionServices;
using Cehpalon.Engine.Tenancy;
using Npgsql;

namespace Business.Postgres;

internal sealed record OrderRow(int OrderId, string Status, int Revision);

internal sealed class CommitUncertainException(Exception inner)
    : Exception("The order transaction commit was attempted without a confirmed outcome.", inner);

internal sealed class CommittedWithoutResultException(Exception inner)
    : Exception("The order transaction committed and its result could not be returned.", inner);

internal sealed class PostgresOrderStore(NpgsqlDataSource source,
    Func<int, CancellationToken, ValueTask>? afterUpdate = null, Action<int>? beforeUpdate = null)
{
    internal const string ReadOperation = "orders.read";
    internal const string UpdateOperation = "orders.complete";
    internal const string ResourceKind = "order";
    private int openAttempts;
    private int commandAttempts;
    private int acknowledgedRollbacks;

    internal int OpenAttempts => Volatile.Read(ref openAttempts);
    internal int CommandAttempts => Volatile.Read(ref commandAttempts);
    internal int AcknowledgedRollbacks => Volatile.Read(ref acknowledgedRollbacks);
    internal int LastBackend { get; private set; }

    internal static string ResourceId(int orderId)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(orderId);
        return orderId.ToString(CultureInfo.InvariantCulture);
    }

    internal ValueTask<OrderRow?> FindAsync(TenantOperationContext context, int orderId, CancellationToken token) =>
        ExecuteAsync<OrderRow?>(context, orderId, ReadOperation, async (connection, transaction) =>
        {
            await using var command = new NpgsqlCommand("""
                SELECT order_id, status, revision FROM cephalon_orders.orders
                WHERE tenant_id = $1 AND order_id = $2
                """, connection, transaction);
            BindOrder(command, context.Tenant, orderId);
            Interlocked.Increment(ref commandAttempts);
            await using var rows = await command.ExecuteReaderAsync(token);
            return await rows.ReadAsync(token) ? ReadOrder(rows) : null;
        }, token);

    internal ValueTask<OrderRow?> CompleteAsync(TenantOperationContext context, int orderId,
        int expectedRevision, CancellationToken token) =>
        ExecuteAsync<OrderRow?>(context, orderId, UpdateOperation, async (connection, transaction) =>
        {
            await using var command = new NpgsqlCommand("""
                UPDATE cephalon_orders.orders SET status = 'complete', revision = revision + 1
                WHERE tenant_id = $1 AND order_id = $2 AND revision = $3 AND status <> 'complete'
                RETURNING order_id, status, revision
                """, connection, transaction);
            BindOrder(command, context.Tenant, orderId);
            command.Parameters.Add(new NpgsqlParameter<int> { TypedValue = expectedRevision });
            Interlocked.Increment(ref commandAttempts);
            beforeUpdate?.Invoke(connection.ProcessID);
            OrderRow? updated;
            await using (var rows = await command.ExecuteReaderAsync(token))
                updated = await rows.ReadAsync(token) ? ReadOrder(rows) : null;
            if (updated is not null && afterUpdate is not null)
                await afterUpdate(connection.ProcessID, token);
            return updated;
        }, token);

    private async ValueTask<T> ExecuteAsync<T>(TenantOperationContext context, int orderId, string operation,
        Func<NpgsqlConnection, NpgsqlTransaction, Task<T>> work, CancellationToken token)
    {
        var resource = ResourceId(orderId);
        void Demand()
        {
            token.ThrowIfCancellationRequested();
            if (!StringComparer.Ordinal.Equals(context.OperationId, operation))
                throw new TenantAccessDeniedException();
            context.DemandAccess(context.Tenant, ResourceKind, resource, operation);
        }

        Demand();
        Interlocked.Increment(ref openAttempts);
        var connection = await source.OpenConnectionAsync(token);
        NpgsqlTransaction? transaction = null;
        var commitStarted = false;
        var commitAcknowledged = false;
        T result = default!;
        Exception? failure = null;
        try
        {
            Demand();
            LastBackend = connection.ProcessID;
            transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, token);
            Demand();
            await using (var scope = new NpgsqlCommand(
                "SELECT set_config('cephalon_orders.tenant_id', $1, true)", connection, transaction))
            {
                scope.Parameters.Add(new NpgsqlParameter<string> { TypedValue = context.Tenant.Value });
                Interlocked.Increment(ref commandAttempts);
                await scope.ExecuteScalarAsync(token);
            }

            Demand();
            result = await work(connection, transaction);
            Demand();

            using var commitDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            commitStarted = true;
            await transaction.CommitAsync(commitDeadline.Token);
            commitAcknowledged = true;
        }
        catch (Exception error)
        {
            failure = error;
            if (transaction is not null && !commitStarted)
            {
                try
                {
                    using var rollbackDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                    await transaction.RollbackAsync(rollbackDeadline.Token);
                    Interlocked.Increment(ref acknowledgedRollbacks);
                }
                catch (Exception rollbackFailure)
                {
                    failure = new AggregateException("Rollback was attempted without a confirmed outcome.", failure, rollbackFailure);
                }
            }
        }
        finally
        {
            try
            {
                if (transaction is not null) await transaction.DisposeAsync();
            }
            catch (Exception cleanupFailure)
            {
                failure = Combine(failure, cleanupFailure);
            }
            try
            {
                await connection.DisposeAsync();
            }
            catch (Exception cleanupFailure)
            {
                failure = Combine(failure, cleanupFailure);
            }
        }

        if (commitAcknowledged && failure is null)
        {
            try { Demand(); }
            catch (Exception completionFailure) { failure = completionFailure; }
        }
        if (failure is not null)
        {
            if (commitAcknowledged) throw new CommittedWithoutResultException(failure);
            if (commitStarted) throw new CommitUncertainException(failure);
            ExceptionDispatchInfo.Capture(failure).Throw();
        }
        return result;
    }

    private static Exception Combine(Exception? earlier, Exception cleanup) =>
        earlier is null ? cleanup : new AggregateException("Transaction cleanup failed.", earlier, cleanup);

    private static OrderRow ReadOrder(NpgsqlDataReader rows) => new(rows.GetInt32(0), rows.GetString(1), rows.GetInt32(2));

    private static void BindOrder(NpgsqlCommand command, TenantId tenant, int orderId)
    {
        command.Parameters.Add(new NpgsqlParameter<string> { TypedValue = tenant.Value });
        command.Parameters.Add(new NpgsqlParameter<int> { TypedValue = orderId });
    }
}
