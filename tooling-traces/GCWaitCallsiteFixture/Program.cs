using System.Runtime.InteropServices;

internal static class Program
{
    private static readonly AutoResetEvent Run = new(false);
    private static readonly AutoResetEvent Ready = new(false);
    private static readonly AutoResetEvent Done = new(false);
    private static int iterations;

    [DllImport("libc", EntryPoint = "gettid")]
    private static extern int GetTid();

    [DllImport("libc", EntryPoint = "usleep")]
    private static extern int SleepMicroseconds(uint usec);

    private static void Worker()
    {
        // Pre-JIT the P/Invoke path before reporting readiness.
        if (SleepMicroseconds(10) != 0)
            throw new InvalidOperationException("Warm-up sleep failed");
        Console.WriteLine($"worker {Environment.ProcessId} {GetTid()}");
        for (var arm = 0; arm < 2; arm++)
        {
            Run.WaitOne();
            Ready.Set();
            for (var i = 0; i < iterations; i++)
                if (SleepMicroseconds(500) != 0)
                    throw new InvalidOperationException("Worker sleep failed");
            Done.Set();
        }
        // Hold the exact TID through the second drain.
        Run.WaitOne();
    }

    public static void Main()
    {
        if (System.Runtime.GCSettings.IsServerGC)
            throw new InvalidOperationException("Fixture requires workstation GC");
        var roots = new object[700_000];
        for (var i = 0; i < roots.Length; i++)
            roots[i] = new byte[88];
        GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
        var worker = new Thread(Worker) { IsBackground = true };
        worker.Start();

        foreach (var collect in new[] { false, true })
        {
            var name = collect ? "positive" : "negative";
            if (Console.ReadLine() != name)
                throw new InvalidOperationException($"Unexpected fixture command for {name}");
            var before = (GC.CollectionCount(0), GC.CollectionCount(1), GC.CollectionCount(2));
            iterations = collect ? 2048 : 64;
            Run.Set();
            Ready.WaitOne();
            if (collect)
                for (var i = 0; i < 12; i++)
                    GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
            Done.WaitOne();
            var after = (GC.CollectionCount(0), GC.CollectionCount(1), GC.CollectionCount(2));
            Console.WriteLine($"{name} {after.Item1 - before.Item1} {after.Item2 - before.Item2} {after.Item3 - before.Item3}");
        }
        if (Console.ReadLine() != "close")
            throw new InvalidOperationException("Expected cleanup command");
        Run.Set();
        worker.Join();
        GC.KeepAlive(roots);
    }
}
