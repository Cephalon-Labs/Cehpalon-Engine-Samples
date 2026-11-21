using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Cehpalon.Engine.Core;

internal static class DispatchBudgetObservation
{
    private const int Iterations = 100_000;
    private const int Warmup = 10_000;
    private const int Repetitions = 5;

    internal static async Task<int> RunAsync(string output)
    {
        var context = new OperationContext("budget-component-observation");
        var dispatcher = new OperationDispatcher(new OperationRegistryBuilder()
            .Register<int, int>("bench.echo", () => new EchoHandler()).Build());
        var budget = new OperationConcurrencyBudget(2);
        int Direct(int value) => dispatcher.DispatchAsync<int, int>("bench.echo", value, context).GetAwaiter().GetResult().Value;
        int Bounded(int value) => budget.DispatchAsync<int, int>(dispatcher, "bench.echo", value, context).GetAwaiter().GetResult().Value;
        for (var i = 0; i < Warmup; i++)
        {
            _ = Direct(i);
            _ = Bounded(i);
        }
        EchoHandler.Created = EchoHandler.Disposed = 0;
        var runs = new List<object>();
        for (var repetition = 0; repetition < Repetitions; repetition++)
        {
            var boundedFirst = repetition % 2 == 1;
            var first = Measure(boundedFirst ? Bounded : Direct);
            var second = Measure(boundedFirst ? Direct : Bounded);
            runs.Add(new { repetition, boundedFirst, baseline = boundedFirst ? second : first,
                budget = boundedFirst ? first : second });
        }
        if (EchoHandler.Created != 2L * Iterations * Repetitions || EchoHandler.Disposed != EchoHandler.Created)
            throw new InvalidOperationException("Unexpected handler ownership counts.");
        var report = new { sdk = RuntimeInformation.FrameworkDescription, os = RuntimeInformation.OSDescription,
            stopwatchFrequency = Stopwatch.Frequency, warmup = Warmup, iterations = Iterations,
            created = EchoHandler.Created, disposed = EchoHandler.Disposed, runs };
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        await using var file = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await JsonSerializer.SerializeAsync(file, report, new JsonSerializerOptions { WriteIndented = true });
        return 0;
    }

    private static Observation Measure(Func<int, int> dispatch)
    {
        long checksum = 0;
        var allocated = GC.GetAllocatedBytesForCurrentThread();
        var started = Stopwatch.GetTimestamp();
        for (var i = 0; i < Iterations; i++)
            checksum += dispatch(i);
        var elapsed = Stopwatch.GetTimestamp() - started;
        var bytes = GC.GetAllocatedBytesForCurrentThread() - allocated;
        if (checksum != (long)Iterations * (Iterations - 1) / 2)
            throw new InvalidOperationException("Observation changed the operation result.");
        return new(elapsed, bytes, checksum);
    }

    private sealed record Observation(long ElapsedTicks, long AllocatedBytes, long Checksum);
}
