using System.Diagnostics;
using System.Diagnostics.Metrics;
using PortableConsumers.Generated;

namespace MetricsOverhead;

public static class Host
{
    private readonly record struct Sample(int Index, string Phase, long StartedTicks, long ElapsedTicks, long AllocatedBytes,
        int Callbacks, int Active, int Capacity, int Closed, int ActiveTenants, int TenantCapacity);

    public static async Task<int> Run(Dictionary<string, string> options)
    {
        var enabled = bool.Parse(options["--listener"]);
        var tenant = bool.Parse(options["--tenant"]);
        var samples = new Sample[8192];
        var values = new int[5];
        var count = 0;
        var totalCallbacks = 0;
        var callbacks = 0;
        var invalid = 0;
        var published = 0;
        var gate = new object();
        var observations = new Dictionary<string, object?>();
        using var process = Process.GetCurrentProcess();
        using var tls = new TlsFixture();
        using var jwt = new JwtFixture();
        await using var host = new FixtureHost();
        Meter? meter = null;
        MeterListener? listener = null;
        using var cancel = new CancellationTokenSource();
        Task? sampler = null;
        var status = "failed";
        var postDisposalCallbacks = 0;

        void Collect(string phase)
        {
            lock (gate)
            {
                if (count == samples.Length) throw new InvalidOperationException();
                callbacks = 0;
                var allocated = GC.GetAllocatedBytesForCurrentThread();
                var started = Entry.Now;
                listener!.RecordObservableInstruments();
                var elapsed = Entry.Now - started;
                var bytes = GC.GetAllocatedBytesForCurrentThread() - allocated;
                samples[count] = new(count, phase, started, elapsed, bytes, callbacks,
                    values[0], values[1], values[2], values[3], values[4]);
                count++;
                totalCallbacks += callbacks;
                if (invalid != 0 || callbacks != (tenant ? 5 : 3) || published != (tenant ? 31 : 7))
                    throw new InvalidOperationException();
            }
        }

        object Snapshot()
        {
            var ticks = Entry.Now;
            var allocated = GC.GetTotalAllocatedBytes(precise: true);
            var cpu = process.TotalProcessorTime.Ticks;
            var store = host.Store;
            return new { ticks, allocatedBytes = allocated, cpuTicks = cpu,
                gc = new[] { GC.CollectionCount(0), GC.CollectionCount(1), GC.CollectionCount(2) },
                factories = Volatile.Read(ref store.Factories), constructors = Volatile.Read(ref store.Constructors),
                reads = Volatile.Read(ref store.Reads), writes = Volatile.Read(ref store.Writes),
                disposals = Volatile.Read(ref store.Disposals) };
        }

        try
        {
            await host.Start(FixtureHost.Config(true, true), tls, jwt, 64, tenant ? 32 : null);
            if (enabled)
            {
                const string meterName = "Cehpalon.HttpsOverhead";
                meter = host.CreateBudgetMetrics(meterName) ?? throw new InvalidOperationException();
                listener = new MeterListener();
                listener.InstrumentPublished = (instrument, observer) =>
                {
                    if (instrument.Meter.Name != meterName) return;
                    var index = Index(instrument.Name);
                    if (index < 0 || (published & (1 << index)) != 0) throw new InvalidOperationException();
                    published |= 1 << index;
                    observer.EnableMeasurementEvents(instrument);
                };
                listener.SetMeasurementEventCallback<int>((instrument, value, tags, _) =>
                {
                    var index = Index(instrument.Name);
                    if (index < 0 || !tags.IsEmpty) { invalid++; return; }
                    values[index] = value;
                    callbacks++;
                    if (index == 0 && value is < 0 or > 64 || index == 1 && value != 64
                        || index == 2 && value is not (0 or 1) || index == 3 && value is < 0 or > 2
                        || index == 4 && value != 32) invalid++;
                });
                listener.Start();
                Collect("initial");
                sampler = Task.Run(async () =>
                {
                    try
                    {
                        while (true)
                        {
                            await Task.Delay(10, cancel.Token);
                            Collect("periodic");
                        }
                    }
                    catch (OperationCanceledException) when (cancel.IsCancellationRequested) { }
                });
            }
            // Private handshake: the controller never persists this line or sends it as argv.
            Entry.Signal(new { kind = "ready", address = host.Address.ToString(),
                root = Convert.ToBase64String(tls.Root.RawData), alice = jwt.Token(), bob = jwt.Token("bob"),
                environment = Entry.EnvironmentInfo(), listener = enabled, tenant });
            var begun = false;
            var ended = false;
            while (await Console.In.ReadLineAsync() is { } command)
            {
                if (command == "BEGIN" && !begun)
                {
                    begun = true;
                    observations["begin"] = Snapshot();
                    Entry.Signal(new { kind = "begin", snapshot = observations["begin"] });
                }
                else if (command == "END" && begun && !ended)
                {
                    ended = true;
                    observations["end"] = Snapshot();
                    Entry.Signal(new { kind = "end", snapshot = observations["end"] });
                }
                else if (command == "STOP") { status = begun && ended ? "passed" : "failed"; break; }
                else throw new InvalidOperationException();
            }
        }
        catch (Exception error) { observations["failureType"] = error.GetType().Name; }
        finally
        {
            try
            {
                cancel.Cancel();
                if (sampler is not null) await sampler.WaitAsync(TimeSpan.FromSeconds(5));
                await host.DisposeAsync();
                if (enabled && listener is not null)
                {
                    Collect("closed");
                    if (values[0] != 0 || values[2] != 1 || tenant && values[3] != 0) status = "failed";
                    meter!.Dispose();
                    callbacks = 0;
                    listener.RecordObservableInstruments();
                    postDisposalCallbacks = callbacks;
                    if (callbacks != 0) status = "failed";
                }
            }
            catch (Exception error) { status = "failed"; observations["cleanupFailureType"] = error.GetType().Name; }
            finally { meter?.Dispose(); listener?.Dispose(); }
            var store = host.Store;
            await Entry.Save(options["--output"], new { status, listener = enabled, tenant,
                environment = Entry.EnvironmentInfo(), requestedDelayMilliseconds = enabled ? 10 : 0,
                meterCreated = meter is not null, listenerCreated = listener is not null, samplerCreated = sampler is not null,
                observations, sampleCount = count, totalCallbacks, samples = samples.Take(count).ToArray(), invalidCallbacks = invalid, postDisposalCallbacks,
                store = new { store.Factories, store.Constructors, store.Reads, store.Writes, store.Disposals },
                counters = host.Counters, snapshot = host.CapacitySnapshot, tenantSnapshot = host.TenantCapacitySnapshot });
        }
        Entry.Signal(new { kind = "stopped", status });
        return status == "passed" ? 0 : 1;
    }

    private static int Index(string name) => name switch
    {
        "cehpalon.operation_budget.active" => 0, "cehpalon.operation_budget.capacity" => 1,
        "cehpalon.operation_budget.closed" => 2, "cehpalon.operation_budget.active_tenants" => 3,
        "cehpalon.operation_budget.tenant_capacity" => 4, _ => -1
    };
}
