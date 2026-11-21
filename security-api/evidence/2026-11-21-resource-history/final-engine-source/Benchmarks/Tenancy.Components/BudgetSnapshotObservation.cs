using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;

internal static class BudgetSnapshotObservation
{
    private const int Warmup = 10_000;
    private const int Iterations = 1_000_000;
    private const int Repetitions = 5;

    internal static async Task<int> RunAsync(string output, bool observeMetrics = false)
    {
        if (File.Exists(output))
            throw new IOException("Retain previous results; use a new file.");

        var core = new OperationConcurrencyBudget(2);
        var tenant = new TenantOperationConcurrencyBudget(2, 1);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var owned = new Ownership();
        var coreDispatcher = new OperationDispatcher(new OperationRegistryBuilder()
            .Register<int, int>("snapshots.read", () => new CoreHandler(release.Task, owned)).Build());
        var authority = new FixtureAuthority();
        var tenantRegistry = new TenantOperationRegistryBuilder()
            .Register<ReadRequest, int>("documents.read", "documents.read", "document",
                request => new(request.Tenant, request.Value), request => new(request.Tenant, "shared"),
                () => new TenantHandler(release.Task, owned)).Build();
        var services = new TenantSecurityServices(authority,
            new IdentityTrustPolicy([FixtureAuthority.Issuer], ["fixture"]), authority, authority,
            TimeSpan.FromHours(1), authority, new FixedClock());
        var tenantDispatcher = TenantOperationDispatcher.WithTenantConcurrencyBudget(tenantRegistry, services, tenant);
        var context = new OperationContext("snapshot-observer");
        var stages = new List<object>();
        object ObserveStage(string name, int active, bool closed) => observeMetrics
            ? BudgetMetricsObservation.Observe(name, core, tenant, active, closed)
            : Observe(name, core, tenant, active, closed);
        stages.Add(ObserveStage("idle-open", 0, false));

        var coreWork = core.DispatchAsync<int, int>(coreDispatcher, "snapshots.read", 7, context).AsTask();
        var tenantWork = tenantDispatcher.DispatchAsync<ReadRequest, int>(
            "documents.read", new(authority.A, 11), context).AsTask();
        try
        {
            if (coreWork.IsCompleted || tenantWork.IsCompleted || owned.Created != 2 || owned.Disposed != 0)
                throw new InvalidOperationException("Both operations must be waiting in owned cleanup.");

            stages.Add(ObserveStage("cleanup-open", 1, false));
            var coreDrain = core.DrainAsync();
            var tenantDrain = tenant.DrainAsync();
            if (coreDrain.IsCompleted || tenantDrain.IsCompleted)
                throw new InvalidOperationException("Drain completed before cleanup release.");

            stages.Add(ObserveStage("cleanup-closed", 1, true));
            release.SetResult();
            await Task.WhenAll(coreDrain, tenantDrain).WaitAsync(TimeSpan.FromSeconds(10));
            if ((await coreWork).Value != 7 || (await tenantWork).Value != 11
                || owned.Created != 2 || owned.Disposed != 2)
                throw new InvalidOperationException("Operation results or cleanup ownership differed.");

            stages.Add(ObserveStage("drained", 0, true));
        }
        finally
        {
            release.TrySetResult();
            await Task.WhenAll(coreWork, tenantWork).WaitAsync(TimeSpan.FromSeconds(10));
        }

        var report = new
        {
            observedAtUtc = DateTimeOffset.UtcNow,
            framework = RuntimeInformation.FrameworkDescription,
            os = RuntimeInformation.OSDescription,
            scope = observeMetrics ? "Periodic MeterListener collection including eight validation callbacks"
                : "Serial aggregate snapshot observation including typed delegate and checksum cost",
            warmup = observeMetrics ? 0 : Warmup,
            iterations = observeMetrics ? BudgetMetricsObservation.Collections : Iterations,
            repetitions = observeMetrics ? 1 : Repetitions,
            stopwatchFrequency = Stopwatch.Frequency,
            created = owned.Created, disposed = owned.Disposed, stages
        };
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        await using var file = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await JsonSerializer.SerializeAsync(file, report, new JsonSerializerOptions { WriteIndented = true });
        return 0;
    }

    private static Stage Observe(string name, OperationConcurrencyBudget core,
        TenantOperationConcurrencyBudget tenant, int active, bool closed)
    {
        var coreSnapshot = core.GetSnapshot();
        var tenantSnapshot = tenant.GetSnapshot();
        if (coreSnapshot != new OperationConcurrencySnapshot(2, active, closed)
            || tenantSnapshot != new TenantOperationConcurrencySnapshot(coreSnapshot, 1, active))
            throw new InvalidOperationException("Snapshot does not match the controlled stage.");

        Lane[] lanes =
        [
            new("cached-core", () => Fingerprint(coreSnapshot), Fingerprint(coreSnapshot)),
            new("core", () => Fingerprint(core.GetSnapshot()), Fingerprint(coreSnapshot)),
            new("cached-tenant", () => Fingerprint(tenantSnapshot), Fingerprint(tenantSnapshot)),
            new("tenant", () => Fingerprint(tenant.GetSnapshot()), Fingerprint(tenantSnapshot))
        ];
        foreach (var lane in lanes)
            for (var i = 0; i < Warmup; i++)
                if (lane.Read() != lane.Expected)
                    throw new InvalidOperationException("Warmup snapshot differed.");

        var measurements = new List<Measurement>();
        for (var repetition = 0; repetition < Repetitions; repetition++)
        {
            for (var offset = 0; offset < lanes.Length; offset++)
            {
                var lane = lanes[(repetition + offset) % lanes.Length];
                long checksum = 0;
                var before = GC.GetAllocatedBytesForCurrentThread();
                var started = Stopwatch.GetTimestamp();
                for (var i = 0; i < Iterations; i++)
                    checksum += lane.Read();
                var elapsed = Stopwatch.GetTimestamp() - started;
                var bytes = GC.GetAllocatedBytesForCurrentThread() - before;
                if (checksum != lane.Expected * Iterations)
                    throw new InvalidOperationException("Measured snapshot checksum differed.");

                measurements.Add(new(repetition, offset, lane.Name, elapsed, bytes, checksum));
            }
        }

        if (core.GetSnapshot() != coreSnapshot || tenant.GetSnapshot() != tenantSnapshot)
            throw new InvalidOperationException("The controlled stage changed during observation.");

        return new(name, coreSnapshot, tenantSnapshot, measurements);
    }

    private static long Fingerprint(OperationConcurrencySnapshot snapshot) =>
        snapshot.MaximumConcurrentOperations * 100L + snapshot.ActiveOperations * 10L
        + (snapshot.IsAdmissionClosed ? 1 : 0);

    private static long Fingerprint(TenantOperationConcurrencySnapshot snapshot) =>
        Fingerprint(snapshot.Total) * 100L + snapshot.MaximumConcurrentOperationsPerTenant * 10L
        + snapshot.ActiveTenants;

    private sealed record Lane(string Name, Func<long> Read, long Expected);
    private sealed record Measurement(int Repetition, int Order, string Lane, long ElapsedTicks,
        long AllocatedBytes, long Checksum);
    private sealed record Stage(string Name, OperationConcurrencySnapshot Core,
        TenantOperationConcurrencySnapshot Tenant, IReadOnlyList<Measurement> Measurements);

    private sealed class Ownership
    {
        internal int Created;
        internal int Disposed;
    }

    private sealed class CoreHandler : IOperationHandler<int, int>, IAsyncDisposable
    {
        private readonly Task release;
        private readonly Ownership owned;

        internal CoreHandler(Task release, Ownership owned)
        {
            this.release = release;
            this.owned = owned;
            owned.Created++;
        }

        public ValueTask<OperationResult<int>> HandleAsync(int request, OperationContext context, CancellationToken token)
            => ValueTask.FromResult(OperationResult<int>.Success(request));

        public async ValueTask DisposeAsync()
        {
            await release;
            Interlocked.Increment(ref owned.Disposed);
        }
    }

    private sealed class TenantHandler : ITenantOperationHandler<ReadRequest, int>, IAsyncDisposable
    {
        private readonly Task release;
        private readonly Ownership owned;

        internal TenantHandler(Task release, Ownership owned)
        {
            this.release = release;
            this.owned = owned;
            owned.Created++;
        }

        public ValueTask<OperationResult<int>> HandleAsync(ReadRequest request, TenantOperationContext context, CancellationToken token)
        {
            context.DemandAccess(request.Tenant, "document", "shared", "documents.read");
            return ValueTask.FromResult(OperationResult<int>.Success(request.Value));
        }

        public async ValueTask DisposeAsync()
        {
            await release;
            Interlocked.Increment(ref owned.Disposed);
        }
    }
}
