using Business.Postgres;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Tenancy;
using Npgsql;
using static OrderFixture;

internal static class OrderCrashChecks
{
    private const int OrderId = 5;
    private static readonly TenantId Alpha = new("A");
    private static readonly TenantId Beta = new("B");
    private static readonly OperationContext Correlation = new("postgresql-crash-fixture");

    internal static async Task StageAsync(NpgsqlConnectionStringBuilder settings, string stoppedSignal)
    {
        Check(Path.IsPathFullyQualified(stoppedSignal) && !File.Exists(stoppedSignal),
            "The crash-stage stop signal must be a new owned path.");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var token = deadline.Token;
        await using var source = NpgsqlDataSource.Create(settings.ConnectionString);
        await CheckRuntimeRoleAsync(source, token);
        var store = new PostgresOrderStore(source);
        var committed = await CompleteAsync(Alpha, store, token);
        Check(committed.IsSuccess && committed.Value == new OrderRow(OrderId, "complete", 1) &&
            Work(store) == (1, 2), "The acknowledged crash-stage update did not commit exactly once.");
        await CheckReturnAsync(source, store.LastBackend, token);

        using var stageLifetime = CancellationTokenSource.CreateLinkedTokenSource(token);
        var updateReturned = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        var pendingStore = new PostgresOrderStore(source, HoldUpdateAsync);
        var pending = CompleteAsync(Beta, pendingStore, stageLifetime.Token);
        try
        {
            var backend = await updateReturned.Task.WaitAsync(token);
            Check(Work(pendingStore) == (1, 2) && !pending.IsCompleted,
                "The crash-stage update was not held before commit.");
            await ConfirmHeldAsync(settings, backend, token);
            Console.WriteLine("Crash stage ready with one acknowledged commit and one held update.");

            using var check = new PeriodicTimer(TimeSpan.FromMilliseconds(25));
            while (!File.Exists(stoppedSignal))
            {
                Check(!pending.IsCompleted, "The held dispatch ended before the fixture stop signal.");
                await check.WaitForNextTickAsync(token);
            }
            Check(!pending.IsCompleted, "The held dispatch ended before the crash gate was closed.");
        }
        finally
        {
            // Cancel the gate. It never releases the update toward commit, including on runner failure.
            stageLifetime.Cancel();
            await ((Task)pending).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        }
        Console.WriteLine("Crash stage application joined after the stop signal.");

        async ValueTask HoldUpdateAsync(int pid, CancellationToken cancellationToken)
        {
            Check(updateReturned.TrySetResult(pid), "The crash stage submitted another update.");
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }
    }

    internal static async Task VerifyAsync(NpgsqlConnectionStringBuilder settings)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var token = deadline.Token;
        await using var source = NpgsqlDataSource.Create(settings.ConnectionString);
        await CheckRuntimeRoleAsync(source, token);
        var store = new PostgresOrderStore(source);

        var alpha = CreateDispatcher(Alpha, store);
        var beta = CreateDispatcher(Beta, store);
        var committed = await alpha.DispatchAsync<OrderRequest, OrderRow>(
            PostgresOrderStore.ReadOperation, new(Alpha, OrderId), Correlation, token);
        Check(committed.IsSuccess && committed.Value == new OrderRow(OrderId, "complete", 1),
            "The acknowledged write was missing after PostgreSQL recovery.");
        await CheckReturnAsync(source, store.LastBackend, token);

        var prior = await beta.DispatchAsync<OrderRequest, OrderRow>(
            PostgresOrderStore.ReadOperation, new(Beta, OrderId), Correlation, token);
        Check(prior.IsSuccess && prior.Value == new OrderRow(OrderId, "review", 0),
            "The held pre-commit update survived PostgreSQL recovery.");
        await CheckReturnAsync(source, store.LastBackend, token);

        var beforeDenial = Work(store);
        var denied = await alpha.DispatchAsync<OrderRequest, OrderRow>(
            PostgresOrderStore.ReadOperation, new(Beta, OrderId), Correlation, token);
        Check(!denied.IsSuccess && denied.Error.Code == "access.denied" && Work(store) == beforeDenial,
            "Cross-tenant recovery verification reached the runtime store.");
        Console.WriteLine("Fresh application saw only the acknowledged update and preserved tenant isolation after restart.");
    }

    private static async Task ConfirmHeldAsync(NpgsqlConnectionStringBuilder settings, int backend, CancellationToken token)
    {
        var observerSettings = new NpgsqlConnectionStringBuilder(settings.ConnectionString) { Pooling = false };
        await using var observer = new NpgsqlConnection(observerSettings.ConnectionString);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        await observer.OpenAsync(deadline.Token);
        Check(observer.ProcessID != backend, "The observer used the held update's backend.");
        await using var command = new NpgsqlCommand("""
            SELECT state = 'idle in transaction' AND xact_start IS NOT NULL
                AND query LIKE 'UPDATE cephalon_orders.orders%'
            FROM pg_stat_activity WHERE pid = $1 AND usename = current_user
            """, observer);
        command.Parameters.Add(new NpgsqlParameter<int> { TypedValue = backend });
        while (await command.ExecuteScalarAsync(deadline.Token) is not true)
            deadline.Token.ThrowIfCancellationRequested();
    }

    private static Task<OperationResult<OrderRow>> CompleteAsync(TenantId tenant, PostgresOrderStore store,
        CancellationToken token) =>
        CreateDispatcher(tenant, store).DispatchAsync<CompleteOrderRequest, OrderRow>(
            PostgresOrderStore.UpdateOperation, new(tenant, OrderId, 0), Correlation, token).AsTask();
}
