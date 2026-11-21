using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;

internal static class BudgetContentionObservation
{
    private const int Producers = 4;
    private const int Warmup = 1_000;
    private const int Iterations = 25_000;
    private const int Repetitions = 5;

    internal static async Task<int> RunAsync(string output)
    {
        if (File.Exists(output)) throw new IOException("Use a new output file.");
        var pairs = new List<Pair>();
        string? failure = null;
        try
        {
            for (var repetition = 0; repetition < Repetitions; repetition++)
            {
                var observedFirst = repetition % 2 == 1;
                var first = await RunLane(observedFirst);
                var second = await RunLane(!observedFirst);
                pairs.Add(new(repetition, observedFirst, observedFirst ? second : first,
                    observedFirst ? first : second));
            }
        }
        catch (Exception error)
        {
            failure = error.ToString();
        }

        var report = new
        {
            status = failure is null ? "passed" : "failed", failure,
            observedAtUtc = DateTimeOffset.UtcNow, framework = RuntimeInformation.FrameworkDescription,
            os = RuntimeInformation.OSDescription, logicalProcessors = Environment.ProcessorCount,
            scope = "Shared-host concurrent fixture dispatch with one waiting or continuous aggregate observer",
            producers = Producers, warmup = Warmup, iterations = Iterations, repetitions = Repetitions,
            stopwatchFrequency = Stopwatch.Frequency, pairs
        };
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        await using var file = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await JsonSerializer.SerializeAsync(file, report, new JsonSerializerOptions { WriteIndented = true });
        return failure is null ? 0 : 1;
    }

    private static async Task<Lane> RunLane(bool observe)
    {
        var budget = new TenantOperationConcurrencyBudget(8, 2);
        var fixtures = Enumerable.Range(0, Producers).Select(index => new Worker(index, budget)).ToArray();
        foreach (var worker in fixtures)
        {
            for (var i = 0; i < Warmup; i++) _ = worker.Invoke(i);
            worker.Reset();
        }

        using var ready = new CountdownEvent(Producers + 1);
        using var start = new ManualResetEventSlim();
        using var done = new ManualResetEventSlim();
        var workers = fixtures.Select(worker => Task.Factory.StartNew(() =>
        {
            ready.Signal();
            start.Wait();
            var allocated = GC.GetAllocatedBytesForCurrentThread();
            long checksum = 0;
            for (var i = 0; i < Iterations; i++) checksum += worker.Invoke(i);
            var bytes = GC.GetAllocatedBytesForCurrentThread() - allocated;
            if (checksum != (long)Iterations * (Iterations - 1) / 2
                || worker.GetCounts() != new Counts(Iterations, Iterations, Iterations, Iterations, Iterations, Iterations))
                throw new InvalidOperationException("Producer checksum or authority/ownership counts differed.");
            return new Producer(Environment.CurrentManagedThreadId, checksum, bytes, worker.GetCounts());
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default)).ToArray();
        var observer = Task.Factory.StartNew(() =>
        {
            ready.Signal();
            start.Wait();
            long reads = 0;
            var allocated = GC.GetAllocatedBytesForCurrentThread();
            var started = Stopwatch.GetTimestamp();
            if (observe)
            {
                // At least one read is retained even if producers finish before this thread runs.
                do
                {
                    var state = budget.GetSnapshot();
                    if (state.Total.MaximumConcurrentOperations != 8 || state.MaximumConcurrentOperationsPerTenant != 2
                        || state.Total.IsAdmissionClosed || state.Total.ActiveOperations is < 0 or > 8
                        || state.ActiveTenants is < 0 or > Producers
                        || state.ActiveTenants > state.Total.ActiveOperations
                        || state.Total.ActiveOperations > state.ActiveTenants * 2)
                        throw new InvalidOperationException("An aggregate snapshot violated admission invariants.");
                    reads++;
                }
                while (!done.IsSet);
            }
            else done.Wait();
            var elapsed = Stopwatch.GetTimestamp() - started;
            var bytes = GC.GetAllocatedBytesForCurrentThread() - allocated;
            return new Observer(Environment.CurrentManagedThreadId, reads, elapsed, bytes);
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

        Producer[] results;
        Observer observation;
        long elapsed;
        try
        {
            if (!ready.Wait(TimeSpan.FromSeconds(10)))
                throw new TimeoutException("The dedicated actors did not acknowledge readiness.");
            var started = Stopwatch.GetTimestamp();
            start.Set();
            results = await Task.WhenAll(workers).WaitAsync(TimeSpan.FromSeconds(60));
            done.Set();
            observation = await observer.WaitAsync(TimeSpan.FromSeconds(10));
            elapsed = Stopwatch.GetTimestamp() - started;
        }
        finally
        {
            start.Set();
            done.Set();
            await Task.WhenAll(workers.Cast<Task>().Append(observer)).WaitAsync(TimeSpan.FromSeconds(60));
        }

        if (results.Select(result => result.ThreadId).Append(observation.ThreadId).Distinct().Count() != Producers + 1)
            throw new InvalidOperationException("Actor threads were not distinct.");
        var beforeDrain = budget.GetSnapshot();
        await budget.DrainAsync().WaitAsync(TimeSpan.FromSeconds(10));
        var drained = budget.GetSnapshot();
        if (beforeDrain != new TenantOperationConcurrencySnapshot(new(8, 0, false), 2, 0)
            || drained != new TenantOperationConcurrencySnapshot(new(8, 0, true), 2, 0))
            throw new InvalidOperationException("Terminal ownership or drain state differed.");
        return new(observe, elapsed, results, observation, beforeDrain, drained);
    }

    private sealed record Pair(int Repetition, bool ObservedFirst, Lane Control, Lane Observed);
    private sealed record Lane(bool Observe, long ElapsedTicks, IReadOnlyList<Producer> Producers,
        Observer Observer, TenantOperationConcurrencySnapshot BeforeDrain, TenantOperationConcurrencySnapshot Drained);
    private sealed record Producer(int ThreadId, long Checksum, long AllocatedBytes, Counts Counts);
    private sealed record Observer(int ThreadId, long Reads, long ElapsedTicks, long AllocatedBytes);
    private readonly record struct Counts(int Identities, int Memberships, int Resources, int Policies, int Factories, int Disposals);
    private sealed record Request(TenantId Tenant, int Value);

    private sealed class Worker : IIdentitySource, ITenantMembershipSource, IResourceScopeSource, ITenantAccessPolicy
    {
        private const string Issuer = "urn:cehpalon:observer-fixture";
        private readonly TenantId tenant;
        private readonly IdentitySnapshot identity;
        private readonly TenantOperationDispatcher dispatcher;
        private readonly OperationContext context = new("concurrent-snapshot-observer");
        private int identities, memberships, resources, policies, factories, disposals;

        internal Worker(int index, TenantOperationConcurrencyBudget budget)
        {
            tenant = new("tenant-" + index);
            identity = new(new(Issuer, "producer-" + index), "fixture", FixtureAuthority.Now.AddMinutes(-1), FixtureAuthority.Now.AddHours(1));
            var registry = new TenantOperationRegistryBuilder().Register<Request, int>("observer.read", "observer.read", "document",
                request => new(request.Tenant, request.Value), request => new(request.Tenant, "shared"), () =>
                {
                    factories++;
                    return new Handler(this);
                }).Build();
            var services = new TenantSecurityServices(this, new IdentityTrustPolicy([Issuer], ["fixture"]),
                this, this, TimeSpan.FromHours(1), this, new FixedClock());
            dispatcher = TenantOperationDispatcher.WithTenantConcurrencyBudget(registry, services, budget);
        }

        internal int Invoke(int value)
        {
            var pending = dispatcher.DispatchAsync<Request, int>("observer.read", new(tenant, value), context);
            if (!pending.IsCompletedSuccessfully)
                throw new InvalidOperationException("The measured producer requires a synchronous fixture operation.");
            var result = pending.GetAwaiter().GetResult();
            if (!result.IsSuccess || result.Value != value)
                throw new InvalidOperationException("Authorized producer dispatch failed.");
            return result.Value;
        }

        internal void Reset() => identities = memberships = resources = policies = factories = disposals = 0;
        internal Counts GetCounts() => new(identities, memberships, resources, policies, factories, disposals);

        public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            identities++;
            return ValueTask.FromResult<IdentitySnapshot?>(identity);
        }

        public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot current, TenantId requested, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            memberships++;
            return ValueTask.FromResult<TenantMembershipSnapshot?>(requested.Equals(tenant) && current.Principal.Equals(identity.Principal)
                ? new(identity.Principal, tenant, true, identity.NotBeforeUtc, identity.ExpiresAtUtc, "v1") : null);
        }

        public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId requested, string kind, string id, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            resources++;
            return ValueTask.FromResult<ResourceScopeSnapshot?>(requested.Equals(tenant) && kind == "document" && id == "shared"
                ? new(tenant, kind, id, "v1") : null);
        }

        public ValueTask<bool> IsAllowedAsync(TenantAccessRequest request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            policies++;
            return ValueTask.FromResult(request.OperationId == "observer.read" && request.Action == "observer.read");
        }

        private sealed class Handler(Worker owner) : ITenantOperationHandler<Request, int>, IDisposable
        {
            public ValueTask<OperationResult<int>> HandleAsync(Request request, TenantOperationContext context, CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                context.DemandAccess(request.Tenant, "document", "shared", "observer.read");
                return ValueTask.FromResult(OperationResult<int>.Success(request.Value));
            }

            public void Dispose() => owner.disposals++;
        }
    }
}
