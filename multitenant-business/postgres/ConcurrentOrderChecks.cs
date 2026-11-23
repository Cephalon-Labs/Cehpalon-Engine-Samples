using Business.Postgres;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Tenancy;
using Npgsql;
using static OrderFixture;

internal static class ConcurrentOrderChecks
{
    internal static async Task RunAsync(NpgsqlConnectionStringBuilder settings, TenantId alpha, TenantId beta,
        OperationContext correlation, CancellationToken token)
    {
        var concurrent = new NpgsqlConnectionStringBuilder(settings.ConnectionString) { MaxPoolSize = 2 };
        await using var source = NpgsqlDataSource.Create(concurrent.ConnectionString);
        var observerSettings = new NpgsqlConnectionStringBuilder(settings.ConnectionString) { Pooling = false };
        await using var observer = new NpgsqlConnection(observerSettings.ConnectionString);
        await observer.OpenAsync(token);

        await DistinctTenantsAsync(source, observer, alpha, beta, correlation, token);
        await SameOrderAsync(source, observer, alpha, 3, correlation, cancelWaiter: false, token);
        await SameOrderAsync(source, observer, alpha, 4, correlation, cancelWaiter: true, token);
    }

    private static async Task DistinctTenantsAsync(NpgsqlDataSource source, NpgsqlConnection observer,
        TenantId alpha, TenantId beta, OperationContext correlation, CancellationToken token)
    {
        const int orderId = 2;
        var alphaHold = new UpdateHold();
        var betaHold = new UpdateHold();
        var alphaStore = new PostgresOrderStore(source, alphaHold.WaitAsync);
        var betaStore = new PostgresOrderStore(source, betaHold.WaitAsync);
        var first = CompleteAsync(alpha, alphaStore, orderId, correlation, token);
        Task<OperationResult<OrderRow>>? second = null;
        try
        {
            var alphaPid = await alphaHold.Reached.WaitAsync(token);
            second = CompleteAsync(beta, betaStore, orderId, correlation, token);
            var betaPid = await betaHold.Reached.WaitAsync(token);
            Check(alphaPid != betaPid && observer.ProcessID != alphaPid && observer.ProcessID != betaPid,
                "The two tenant writes and observer did not have distinct backends.");
            await ObserveAsync(observer, """
                SELECT count(*) = 2 FROM pg_stat_activity
                WHERE pid IN ($1, $2) AND state = 'idle in transaction' AND xact_start IS NOT NULL
                """, alphaPid, betaPid, token);

            betaHold.Release();
            CheckCommitted(await second, orderId);
            Check(!first.IsCompleted && Work(betaStore) == (1, 2),
                "Tenant B did not commit independently while tenant A was held.");
            await CheckReturnAsync(source, betaPid, token);
            alphaHold.Release();
            CheckCommitted(await first, orderId);
            Check(Work(alphaStore) == (1, 2), "Tenant A did not complete in one transaction attempt.");
            await CheckReadbackAsync(alpha, alphaStore, orderId, correlation, token);
            await CheckReadbackAsync(beta, betaStore, orderId, correlation, token);
            Console.WriteLine("Distinct tenant updates overlapped on separate PostgreSQL backends and committed independently.");
        }
        finally
        {
            alphaHold.Release();
            betaHold.Release();
            await ObserveCompletionAsync(first, second);
        }
    }

    private static async Task SameOrderAsync(NpgsqlDataSource source, NpgsqlConnection observer, TenantId tenant,
        int orderId, OperationContext correlation, bool cancelWaiter, CancellationToken token)
    {
        var hold = new UpdateHold();
        var holderStore = new PostgresOrderStore(source, hold.WaitAsync);
        var waiterStarting = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        var waiterStore = new PostgresOrderStore(source, beforeUpdate: pid => waiterStarting.TrySetResult(pid));
        using var waiterCancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        var holder = CompleteAsync(tenant, holderStore, orderId, correlation, token);
        Task<OperationResult<OrderRow>>? waiter = null;
        try
        {
            var holderPid = await hold.Reached.WaitAsync(token);
            waiter = CompleteAsync(tenant, waiterStore, orderId, correlation, waiterCancellation.Token);
            var waiterPid = await waiterStarting.Task.WaitAsync(token);
            Check(holderPid != waiterPid && observer.ProcessID != holderPid && observer.ProcessID != waiterPid,
                "The lock holder, waiter and observer did not have distinct backends.");
            await ObserveAsync(observer, """
                SELECT state = 'active' AND wait_event_type = 'Lock'
                    AND query LIKE 'UPDATE cephalon_orders.orders%'
                    AND pg_blocking_pids(pid) = ARRAY[$2]
                FROM pg_stat_activity WHERE pid = $1
                """, waiterPid, holderPid, token);

            if (cancelWaiter)
            {
                waiterCancellation.Cancel();
                var canceled = await RejectAsync<OperationCanceledException>(() => waiter);
                Check(canceled.CancellationToken == waiterCancellation.Token &&
                    canceled.InnerException is PostgresException { SqlState: PostgresErrorCodes.QueryCanceled } &&
                    waiterStore.AcknowledgedRollbacks == 1 && !holder.IsCompleted,
                    "The blocked PostgreSQL update did not acknowledge cancellation and rollback while the holder was open.");
                await CheckReturnAsync(source, waiterPid, token);
            }

            hold.Release();
            CheckCommitted(await holder, orderId);
            if (!cancelWaiter)
            {
                var result = await waiter;
                Check(!result.IsSuccess && result.Error.Code == "order.not_changed",
                    "The second conditional write should have affected zero rows.");
                Check(waiterStore.AcknowledgedRollbacks == 0, "The zero-row write should have completed normally.");
            }
            Check(Work(holderStore) == (1, 2) && Work(waiterStore) == (1, 2),
                "The contention case used more than one transaction or update attempt per dispatch.");
            await CheckReadbackAsync(tenant, holderStore, orderId, correlation, token);
            Console.WriteLine(cancelWaiter
                ? "PostgreSQL lock-wait cancellation rolled back and the same backend returned without tenant scope."
                : "Same-order contention had one committed update and one zero-row conditional outcome.");
        }
        finally
        {
            hold.Release();
            await ObserveCompletionAsync(holder, waiter);
        }
    }

    private static async Task ObserveAsync(NpgsqlConnection observer, string sql, int firstPid, int secondPid, CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        await using var command = new NpgsqlCommand(sql, observer);
        command.Parameters.Add(new NpgsqlParameter<int> { TypedValue = firstPid });
        command.Parameters.Add(new NpgsqlParameter<int> { TypedValue = secondPid });
        // The receipt is a server observation, not a timed estimate of which statement went first.
        while (await command.ExecuteScalarAsync(timeout.Token) is not true)
            timeout.Token.ThrowIfCancellationRequested();
    }

    private static Task<OperationResult<OrderRow>> CompleteAsync(TenantId tenant, PostgresOrderStore store,
        int orderId, OperationContext correlation, CancellationToken token) =>
        CreateDispatcher(tenant, store).DispatchAsync<CompleteOrderRequest, OrderRow>(
            PostgresOrderStore.UpdateOperation, new(tenant, orderId, 0), correlation, token).AsTask();

    private static void CheckCommitted(OperationResult<OrderRow> result, int orderId) =>
        Check(result.IsSuccess && result.Value == new OrderRow(orderId, "complete", 1),
            "A committed write did not advance exactly one revision.");

    private static async Task CheckReadbackAsync(TenantId tenant, PostgresOrderStore store, int orderId,
        OperationContext correlation, CancellationToken token)
    {
        var result = await CreateDispatcher(tenant, store).DispatchAsync<OrderRequest, OrderRow>(
            PostgresOrderStore.ReadOperation, new(tenant, orderId), correlation, token);
        CheckCommitted(result, orderId);
    }

    private static async Task ObserveCompletionAsync(Task first, Task? second)
    {
        await (second is null ? first : Task.WhenAll(first, second))
            .ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
    }

    private sealed class UpdateHold
    {
        private readonly TaskCompletionSource<int> reached = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal Task<int> Reached => reached.Task;

        internal async ValueTask WaitAsync(int pid, CancellationToken token)
        {
            Check(reached.TrySetResult(pid), "The held update was called more than once.");
            await release.Task.WaitAsync(token);
        }

        internal void Release() => release.TrySetResult();
    }
}
