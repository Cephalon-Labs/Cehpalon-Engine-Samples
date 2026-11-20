using System.Diagnostics.Metrics;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Tenancy;

internal sealed class HoldingOperation(Task cleanup) : IOperationHandler<int, int>, IAsyncDisposable
{
    public ValueTask<OperationResult<int>> HandleAsync(int request, OperationContext context, CancellationToken token)
        => new(OperationResult<int>.Success(request));

    public ValueTask DisposeAsync() => new(cleanup);
}

internal static class BudgetChecks
{
    private static readonly OperationContext Context = new("test-budget");

    internal static async Task ConcurrentCleanup()
    {
        var budget = new OperationConcurrencyBudget(2);
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var created = 0;
        var registry = new OperationRegistryBuilder().Register<int, int>("capacity.hold", () =>
        {
            Interlocked.Increment(ref created);
            return new HoldingOperation(release.Task);
        }).Build();
        var dispatcher = new OperationDispatcher(registry);
        var otherDispatcher = new OperationDispatcher(registry);
        var drivers = Enumerable.Range(0, 32).Select(i => Task.Run(async () =>
        {
            await start.Task;
            return budget.DispatchAsync<int, int>(i % 2 == 0 ? dispatcher : otherDispatcher, "capacity.hold", i, Context);
        })).ToArray();
        start.SetResult();
        try
        {
            var calls = await Task.WhenAll(drivers).WaitAsync(TimeSpan.FromSeconds(5));
            Verify(created == 2 && calls.Count(x => !x.IsCompleted) == 2);
            using var ac = new CancellationTokenSource();
            ac.Cancel();
            await Throws<OperationCanceledException>(() => budget.DispatchAsync<int, int>(dispatcher, "capacity.hold", 50, Context, ac.Token));
            release.SetResult();
            var results = await Task.WhenAll(calls.Select(call => call.AsTask()));
            Verify(results.Count(row => row.IsSuccess) == 2
                   && results.Where(row => !row.IsSuccess).All(row => row.Error.Code == OperationConcurrencyBudget.CapacityExceededCode)
                   && created == 2);
            Verify((await budget.DispatchAsync<int, int>(otherDispatcher, "capacity.hold", 51, Context)).Value == 51);
        }
        finally { release.TrySetResult(); }
    }

    internal static async Task FailureRecovery()
    {
        try { _ = new OperationConcurrencyBudget(0); throw new InvalidOperationException("Expected invalid capacity"); }
        catch (ArgumentOutOfRangeException) { }

        using var cancel = new CancellationTokenSource();
        var dispatcher = new OperationDispatcher(new OperationRegistryBuilder()
            .Register<int, int>("capacity.factory", () => throw new IOException("factory"))
            .Register<int, int>("capacity.cleanup", () => new HoldingOperation(Task.FromException(new InvalidDataException("cleanup"))))
            .Register<int, int>("capacity.cancel", () => { cancel.Cancel(); return new HoldingOperation(Task.CompletedTask); })
            .Register<int, int>("capacity.ok", () => new HoldingOperation(Task.CompletedTask)).Build());
        var budget = new OperationConcurrencyBudget(1);
        await Throws<IOException>(() => budget.DispatchAsync<int, int>(dispatcher, "capacity.factory", 0, Context));
        await Throws<InvalidDataException>(() => budget.DispatchAsync<int, int>(dispatcher, "capacity.cleanup", 0, Context));
        await Throws<OperationCanceledException>(() => budget.DispatchAsync<int, int>(dispatcher, "capacity.cancel", 0, Context, cancel.Token));
        Verify((await budget.DispatchAsync<int, int>(dispatcher, "capacity.ok", 42, Context)).Value == 42);
    }

    internal static async Task TenantLimits()
    {
        var budget = new TenantOperationConcurrencyBudget(2, 1);
        Verify(budget.GetSnapshot() == new TenantOperationConcurrencySnapshot(new(2, 0, false), 1, 0));
        var a = HeldFixture();
        var b = HeldFixture();
        var fa = a.Build(tenantBudget: budget);
        var fb = b.Build(tenantBudget: budget);
        var outsider = new Fixture();
        var noMembershipB = outsider.Build(tenantBudget: budget);
        var pendingA = TenantCall(fa, "A").AsTask();
        Task<OperationResult<int>>? pendingB = null;
        try
        {
            await a.CleanupEntered!.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Verify((await TenantCall(fb, "A")).Error.Code == OperationConcurrencyBudget.CapacityExceededCode);
            Verify(b.Created == 0 && a.Reads == 1 && a.Disposed == 0);

            pendingB = TenantCall(fb, "B").AsTask();
            await b.CleanupEntered!.Task.WaitAsync(TimeSpan.FromSeconds(5));
            var full = budget.GetSnapshot();
            Verify(full == new TenantOperationConcurrencySnapshot(new(2, 2, false), 1, 2));
            Verify((await TenantCall(noMembershipB, "B")).Error.Code == "access.denied");
            Verify((await TenantCall(noMembershipB, "C")).Error.Code == OperationConcurrencyBudget.CapacityExceededCode);
            var rejected = await Task.WhenAll(Enumerable.Range(0, 32).Select(i =>
                Task.Run(async () => await TenantCall(i % 2 == 0 ? fa : fb, i % 2 == 0 ? "B" : "A"))));
            Verify(rejected.All(x => x.Error.Code == OperationConcurrencyBudget.CapacityExceededCode));
            Verify(a.Created == 1 && b.Created == 1 && outsider.Created == 0);

            a.CleanupRelease!.SetResult();
            Verify((await pendingA).IsSuccess && a.Disposed == 1);
            Verify(budget.GetSnapshot() == new TenantOperationConcurrencySnapshot(new(2, 1, false), 1, 1));
            Verify(full == new TenantOperationConcurrencySnapshot(new(2, 2, false), 1, 2));
            Verify((await TenantCall(noMembershipB, "C")).IsSuccess && outsider.Disposed == 1);
            Verify((await TenantCall(fa, "B")).Error.Code == OperationConcurrencyBudget.CapacityExceededCode);
        }
        finally
        {
            a.CleanupRelease!.TrySetResult();
            b.CleanupRelease!.TrySetResult();
        }
        Verify((await pendingB!).IsSuccess && b.Disposed == 1);
        Verify((await TenantCall(fa, "B")).IsSuccess && a.Disposed == 2);
        Verify(budget.GetSnapshot() == new TenantOperationConcurrencySnapshot(new(2, 0, false), 1, 0));
    }

    internal static async Task TenantFailureRecovery()
    {
        foreach (var (total, tenant) in new[] { (0, 1), (1, 0), (1, 2) })
        {
            try { _ = new TenantOperationConcurrencyBudget(total, tenant); throw new InvalidOperationException("Expected invalid limits"); }
            catch (ArgumentOutOfRangeException) { }
        }

        var budget = new TenantOperationConcurrencyBudget(1, 1);
        var fixture = new Fixture();
        var dispatcher = fixture.Build(tenantBudget: budget);
        using var cancel = new CancellationTokenSource();
        fixture.Hooks["factory"] = cancel.Cancel;
        await Throws<OperationCanceledException>(() => TenantCall(dispatcher, "A", cancel.Token));
        Verify(fixture.Created == 1 && fixture.Disposed == 1 && fixture.Reads == 0);
        fixture.Hooks.Clear();

        fixture.CleanupFailure = true;
        await Throws<InvalidDataException>(() => TenantCall(dispatcher, "A"));
        fixture.CleanupFailure = false;
        Verify((await TenantCall(dispatcher, "A")).IsSuccess);
        Verify(fixture.Created == 3 && fixture.Disposed == 3);
    }

    internal static async Task DrainCore()
    {
        var releaseSuccess = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFault = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var factories = 0;
        var registry = new OperationRegistryBuilder().Register<int, int>("drain.own", () =>
            new HoldingOperation(Interlocked.Increment(ref factories) == 1 ? releaseSuccess.Task : releaseFault.Task)).Build();
        var dispatcher = new OperationDispatcher(registry);
        var other = new OperationDispatcher(registry);
        var idle = new OperationConcurrencyBudget(int.MaxValue);
        Verify(idle.DrainAsync().IsCompletedSuccessfully);
        Verify((await idle.DispatchAsync<int, int>(dispatcher, "drain.own", 0, Context)).Error.Code
               == OperationConcurrencyBudget.CapacityExceededCode && factories == 0);

        var budget = new OperationConcurrencyBudget(3);
        Verify(budget.GetSnapshot() == new OperationConcurrencySnapshot(3, 0, false));
        var success = budget.DispatchAsync<int, int>(dispatcher, "drain.own", 1, Context).AsTask();
        var fault = budget.DispatchAsync<int, int>(other, "drain.own", 2, Context).AsTask();
        try
        {
            using var cancel = new CancellationTokenSource();
            var canceledWait = budget.DrainAsync(cancel.Token);
            var first = budget.DrainAsync();
            var second = budget.DrainAsync();
            Verify(budget.GetSnapshot() == new OperationConcurrencySnapshot(3, 2, true));
            Verify(!first.IsCompleted && !second.IsCompleted);
            Verify((await budget.DispatchAsync<int, int>(other, "drain.own", 3, Context)).Error.Code
                   == OperationConcurrencyBudget.CapacityExceededCode && factories == 2);
            cancel.Cancel();
            await VerifyCanceled(canceledWait);
            Verify(!first.IsCompleted && !second.IsCompleted && !success.IsCompleted);
            releaseSuccess.SetResult();
            Verify((await success.WaitAsync(TimeSpan.FromSeconds(5))).Value == 1 && !first.IsCompleted);
            Verify(budget.GetSnapshot() == new OperationConcurrencySnapshot(3, 1, true));
            releaseFault.SetException(new InvalidDataException("cleanup"));
            await Throws<InvalidDataException>(() => new ValueTask<OperationResult<int>>(fault));
            await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(5));
            Verify(budget.DrainAsync().IsCompletedSuccessfully);
            Verify(budget.GetSnapshot() == new OperationConcurrencySnapshot(3, 0, true));
            Verify((await budget.DispatchAsync<int, int>(dispatcher, "drain.own", 4, Context)).Error.Code
                   == OperationConcurrencyBudget.CapacityExceededCode && factories == 2);
        }
        finally
        {
            releaseSuccess.TrySetResult();
            releaseFault.TrySetResult();
        }
    }

    internal static async Task DrainTenants()
    {
        var budget = new TenantOperationConcurrencyBudget(2, 1);
        var holder = HeldFixture();
        var other = new Fixture();
        var holderDispatch = holder.Build(tenantBudget: budget);
        var otherDispatch = other.Build(tenantBudget: budget);
        var pending = TenantCall(holderDispatch, "A").AsTask();
        try
        {
            await holder.CleanupEntered!.Task.WaitAsync(TimeSpan.FromSeconds(5));
            using var cancel = new CancellationTokenSource();
            cancel.Cancel();
            await VerifyCanceled(budget.DrainAsync(cancel.Token));
            var first = budget.DrainAsync();
            var second = budget.DrainAsync();
            Verify(!first.IsCompleted && !second.IsCompleted);
            Verify(budget.GetSnapshot() == new TenantOperationConcurrencySnapshot(new(2, 1, true), 1, 1));
            Verify((await TenantCall(otherDispatch, "C")).Error.Code == OperationConcurrencyBudget.CapacityExceededCode);
            Verify((await TenantCall(otherDispatch, "B")).Error.Code == "access.denied");
            Verify(other.Created == 0 && other.IdentityCalls == 2 && holder.Disposed == 0);
            holder.CleanupRelease!.SetResult();
            Verify((await pending.WaitAsync(TimeSpan.FromSeconds(5))).IsSuccess && holder.Disposed == 1);
            await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(5));
            Verify(budget.DrainAsync().IsCompletedSuccessfully);
            Verify(budget.GetSnapshot() == new TenantOperationConcurrencySnapshot(new(2, 0, true), 1, 0));
            Verify((await TenantCall(otherDispatch, "A")).Error.Code == OperationConcurrencyBudget.CapacityExceededCode);
            Verify(new TenantOperationConcurrencyBudget(1, 1).DrainAsync().IsCompletedSuccessfully);
        }
        finally
        {
            holder.CleanupRelease!.TrySetResult();
        }
    }

    internal static async Task SnapshotRace()
    {
        var budget = new OperationConcurrencyBudget(4);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var factories = 0;
        var dispatcher = new OperationDispatcher(new OperationRegistryBuilder()
            .Register<int, int>("snapshot.race", () =>
            {
                Interlocked.Increment(ref factories);
                entered.TrySetResult();
                return new HoldingOperation(release.Task);
            }).Build());
        var workers = Enumerable.Range(0, 32).Select(i => Task.Run(async () =>
        {
            await start.Task;
            var call = budget.DispatchAsync<int, int>(dispatcher, "snapshot.race", i, Context);
            var snapshot = budget.GetSnapshot();
            Verify(snapshot.MaximumConcurrentOperations == 4 && snapshot.ActiveOperations is >= 0 and <= 4);
            return await call;
        })).ToArray();
        start.SetResult();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            var drain = budget.DrainAsync();
            var held = budget.GetSnapshot();
            Verify(held.IsAdmissionClosed && held.ActiveOperations is >= 1 and <= 4);
            release.SetResult();
            var results = await Task.WhenAll(workers).WaitAsync(TimeSpan.FromSeconds(5));
            await drain.WaitAsync(TimeSpan.FromSeconds(5));
            Verify(results.Count(result => result.IsSuccess) == factories && factories is >= 1 and <= 4);
            Verify(results.Where(result => !result.IsSuccess).All(result =>
                result.Error.Code == OperationConcurrencyBudget.CapacityExceededCode));
            Verify(budget.GetSnapshot() == new OperationConcurrencySnapshot(4, 0, true));
            Verify(held.IsAdmissionClosed && held.ActiveOperations is >= 1 and <= 4);
        }
        finally { release.TrySetResult(); }
    }

    internal static async Task MetricsLifecycle()
    {
        var core = new OperationConcurrencyBudget(2);
        var tenant = new TenantOperationConcurrencyBudget(2, 1);
        var fixture = HeldFixture();
        var tenantWork = TenantCall(fixture.Build(tenantBudget: tenant), "A").AsTask();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var factories = 0;
        var dispatcher = new OperationDispatcher(new OperationRegistryBuilder()
            .Register<int, int>("metrics.hold", () => { factories++; return new HoldingOperation(release.Task); })
            .Register<int, int>("metrics.ok", () => { factories++; return new HoldingOperation(Task.CompletedTask); }).Build());
        var coreWork = core.DispatchAsync<int, int>(dispatcher, "metrics.hold", 1, Context).AsTask();
        using var listener = new MeterListener();
        var values = new Dictionary<string, int>(StringComparer.Ordinal);
        var callbackFault = false;
        listener.InstrumentPublished = (instrument, observer) =>
        {
            if (instrument.Meter.Name is "Cehpalon.Engine.Core.Budget" or "Cehpalon.Engine.Test.TenantBudget")
                observer.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<int>((instrument, value, tags, _) =>
        {
            Verify(tags.IsEmpty);
            if (callbackFault) throw new IOException("observer failed");
            Verify(values.TryAdd(instrument.Meter.Name + "/" + instrument.Name, value));
        });
        listener.Start();
        using var coreMeter = core.CreateMetrics();
        using var tenantMeter = tenant.CreateMetrics("Cehpalon.Engine.Test.TenantBudget");
        void Collect(int active, int closed)
        {
            values.Clear();
            listener.RecordObservableInstruments();
            Verify(values.Count == 8);
            foreach (var name in new[] { coreMeter.Name, tenantMeter.Name })
            {
                Verify(values[name + "/cehpalon.operation_budget.active"] == active);
                Verify(values[name + "/cehpalon.operation_budget.capacity"] == 2);
                Verify(values[name + "/cehpalon.operation_budget.closed"] == closed);
            }
            Verify(values[tenantMeter.Name + "/cehpalon.operation_budget.active_tenants"] == active);
            Verify(values[tenantMeter.Name + "/cehpalon.operation_budget.tenant_capacity"] == 1);
        }
        try
        {
            await fixture.CleanupEntered!.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Verify(factories == 1 && fixture.Created == 1 && values.Count == 0);
            Collect(1, 0);
            callbackFault = true;
            Exception? observed = null;
            try { listener.RecordObservableInstruments(); }
            catch (Exception error) { observed = error; }
            Verify(observed is IOException or AggregateException);
            Verify((await core.DispatchAsync<int, int>(dispatcher, "metrics.ok", 2, Context)).Value == 2);
            callbackFault = false;
            var coreDrain = core.DrainAsync();
            var tenantDrain = tenant.DrainAsync();
            Collect(1, 1);
            release.SetResult();
            fixture.CleanupRelease!.SetResult();
            await Task.WhenAll(coreWork, tenantWork, coreDrain, tenantDrain).WaitAsync(TimeSpan.FromSeconds(5));
            Collect(0, 1);
            Verify(factories == 2 && fixture.Created == 1 && fixture.Disposed == 1);
            coreMeter.Dispose();
            tenantMeter.Dispose();
            values.Clear();
            listener.RecordObservableInstruments();
            Verify(values.Count == 0);
        }
        finally
        {
            release.TrySetResult();
            fixture.CleanupRelease!.TrySetResult();
            await Task.WhenAll(coreWork, tenantWork).WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    private static async Task VerifyCanceled(Task task)
    {
        try { await task.WaitAsync(TimeSpan.FromSeconds(5)); }
        catch (OperationCanceledException) { return; }
        throw new InvalidOperationException("Expected the drain waiter to cancel.");
    }

    private static Fixture HeldFixture() => new()
    {
        MemberB = true,
        CleanupEntered = new(TaskCreationOptions.RunContinuationsAsynchronously),
        CleanupRelease = new(TaskCreationOptions.RunContinuationsAsynchronously)
    };

    private static ValueTask<OperationResult<int>> TenantCall(
        TenantOperationDispatcher dispatcher, string tenant, CancellationToken token = default) =>
        dispatcher.DispatchAsync<Request, int>("document.read", new(tenant, "shared"), Context, token);

    private static async ValueTask Throws<T>(Func<ValueTask<OperationResult<int>>> action) where T : Exception
    {
        try { await action(); }
        catch (T) { return; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}");
    }

    private static void Verify(bool condition)
    {
        if (!condition)
            throw new InvalidOperationException("Unexpected dispatch budget result");
    }
}
