using System.Diagnostics;
using System.Diagnostics.Metrics;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Tenancy;

internal static class BudgetMetricsObservation
{
    internal const int Collections = 20;
    internal const int DelayMilliseconds = 10;

    internal static object Observe(string name, OperationConcurrencyBudget core,
        TenantOperationConcurrencyBudget tenant, int active, bool closed)
    {
        var total = core.GetSnapshot();
        var partitioned = tenant.GetSnapshot();
        if (total != new OperationConcurrencySnapshot(2, active, closed)
            || partitioned != new TenantOperationConcurrencySnapshot(total, 1, active))
            throw new InvalidOperationException("Budget state differs from the controlled metrics stage.");

        var expected = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["cehpalon.operation_budget.active"] = active,
            ["cehpalon.operation_budget.capacity"] = 2,
            ["cehpalon.operation_budget.closed"] = closed ? 1 : 0,
            ["cehpalon.operation_budget.active_tenants"] = active,
            ["cehpalon.operation_budget.tenant_capacity"] = 1
        };
        using var listener = new MeterListener();
        var publications = 0;
        var callbacks = 0;
        var invalid = 0;
        listener.InstrumentPublished = (instrument, observer) =>
        {
            if (instrument.Meter.Name is "Cehpalon.Engine.Core.Budget" or "Cehpalon.Engine.Tenancy.Budget")
            {
                observer.EnableMeasurementEvents(instrument, expected[instrument.Name]);
                publications++;
            }
        };
        listener.SetMeasurementEventCallback<int>((_, value, tags, state) =>
        {
            if (value != (int)state! || !tags.IsEmpty) invalid++;
            callbacks++;
        });
        listener.Start();
        using var coreMeter = core.CreateMetrics();
        using var tenantMeter = tenant.CreateMetrics();
        if (publications != 8 || callbacks != 0)
            throw new InvalidOperationException("Metric registration must publish eight uncollected instruments.");

        var samples = new List<Sample>();
        for (var i = 0; i < Collections; i++)
        {
            Thread.Sleep(DelayMilliseconds);
            callbacks = 0;
            var allocated = GC.GetAllocatedBytesForCurrentThread();
            var started = Stopwatch.GetTimestamp();
            listener.RecordObservableInstruments();
            var elapsed = Stopwatch.GetTimestamp() - started;
            var bytes = GC.GetAllocatedBytesForCurrentThread() - allocated;
            if (callbacks != 8 || invalid != 0)
                throw new InvalidOperationException("Collection did not emit the expected aggregate gauges.");
            samples.Add(new(i, started, elapsed, bytes, callbacks));
        }

        if (core.GetSnapshot() != total || tenant.GetSnapshot() != partitioned)
            throw new InvalidOperationException("Budget state changed during metrics collection.");

        return new { Name = name, Core = total, Tenant = partitioned,
            Publications = publications, DelayMilliseconds, samples };
    }

    private sealed record Sample(int Index, long StartedTicks, long ElapsedTicks, long AllocatedBytes, int Callbacks);
}
