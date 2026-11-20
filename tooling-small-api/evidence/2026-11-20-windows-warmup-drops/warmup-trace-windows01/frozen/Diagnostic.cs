using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Http;

namespace MetricsOverhead;

public static class Diagnostic
{
    public static bool Enabled;
    private static readonly Receipt[] Records = new Receipt[65536];
    private static long sequence;
    private static int active, closed, overflow, late;
    private static string role = "", output = "";
    private static HostingObserver? hosting;
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, long> HostingEvents = new();
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> HostingShapes = new();
    private readonly record struct Receipt(long Sequence, int Kind, int Phase, int Index, int Lane,
        int Pid, int NativeTid, int ManagedTid, long BeforeTicks, long AfterTicks);
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();

    public static async Task Begin(string name, string path)
    {
        role = name; output = path;
        Entry.Signal(new { kind = "trace-ready", pid = Environment.ProcessId, role, frequency = Stopwatch.Frequency });
        if (await Console.In.ReadLineAsync() != "CAPTURE") throw new InvalidOperationException();
        if (!Log.Instance.IsEnabled()) throw new InvalidOperationException("Marker provider not enabled.");
        if (name == "host") hosting = new HostingObserver();
        Mark(1);
    }

    public static void Mark(int kind, int phase = 0, int index = -1, int lane = -1)
    {
        if (!Enabled) return;
        Interlocked.Increment(ref active);
        try
        {
            if (Volatile.Read(ref closed) != 0) { Interlocked.Increment(ref late); return; }
            Emit(kind, phase, index, lane);
        }
        finally { Interlocked.Decrement(ref active); }
    }

    private static void Emit(int kind, int phase, int index, int lane)
    {
        var id = Interlocked.Increment(ref sequence);
        var pid = Environment.ProcessId;
        var native = checked((int)GetCurrentThreadId());
        var managed = Environment.CurrentManagedThreadId;
        var pending = ThreadPool.PendingWorkItemCount;
        var threads = ThreadPool.ThreadCount;
        var before = Entry.Now;
        Log.Instance.Point(id, before, pid, native, managed, kind, phase, index, lane, pending, threads);
        var after = Entry.Now;
        if (id <= Records.Length) Records[id - 1] = new(id, kind, phase, index, lane, pid, native, managed, before, after);
        else Interlocked.Increment(ref overflow);
    }

    public static async Task Finish()
    {
        hosting?.Dispose();
        Volatile.Write(ref closed, 1);
        var deadline = Entry.Now + Stopwatch.Frequency;
        while (Volatile.Read(ref active) != 0)
        {
            if (Entry.Now > deadline) throw new TimeoutException();
            Thread.Yield();
        }
        Emit(2, 0, -1, -1);
        await Entry.Save(output + ".receipts.json", new { role, pid = Environment.ProcessId,
            frequency = Stopwatch.Frequency, markerCount = sequence, capacity = Records.Length, overflow, late,
            hostingEvents = HostingEvents, hostingShapes = HostingShapes,
            receipts = Records.Take((int)Math.Min(sequence, Records.Length)).ToArray() });
        Entry.Signal(new { kind = "trace-finished", role, pid = Environment.ProcessId, markers = sequence, overflow, late });
        if (await Console.In.ReadLineAsync() != "RELEASE") throw new InvalidOperationException();
    }

    public static async Task<int> Fixture(Dictionary<string, string> options)
    {
        var allocated = GC.GetAllocatedBytesForCurrentThread();
        var start = Entry.Now;
        long checksum = 0;
        for (var i = 0; i < 10000; i++) { Mark(50, 0, i); checksum += i; }
        var end = Entry.Now;
        var bytes = GC.GetAllocatedBytesForCurrentThread() - allocated;
        Mark(51); Thread.Sleep(40); Mark(52);
        Mark(53); GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true); GC.WaitForPendingFinalizers(); Mark(54);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Mark(55);
        var work = Task.Run(async () => { Mark(56); Mark(57); await gate.Task; Mark(59); });
        await Task.Delay(40);
        Mark(58); gate.SetResult(); await work;
        await Entry.Save(options["--output"], new { status = "passed", observed = Enabled, iterations = 10000,
            loopWallTicks = end - start, loopAllocatedBytes = bytes, checksum, environment = Entry.EnvironmentInfo() });
        return 0;
    }

    private sealed class HostingObserver : IObserver<DiagnosticListener>, IObserver<KeyValuePair<string, object?>>, IDisposable
    {
        private readonly List<IDisposable> subscriptions = new();
        private readonly IDisposable all;
        public HostingObserver() => all = DiagnosticListener.AllListeners.Subscribe(this);
        public void OnNext(DiagnosticListener listener)
        {
            if (listener.Name == "Microsoft.AspNetCore")
                lock (subscriptions) subscriptions.Add(listener.Subscribe(this,
                    name => name.StartsWith("Microsoft.AspNetCore.Hosting.HttpRequestIn", StringComparison.Ordinal)));
        }
        public void OnNext(KeyValuePair<string, object?> value)
        {
            HostingEvents.AddOrUpdate(value.Key, 1, (_, count) => count + 1);
            HostingShapes.TryAdd(value.Key, (value.Value?.GetType().FullName ?? "null") + ":" +
                string.Join(',', value.Value?.GetType().GetProperties().Select(p => p.Name) ?? []));
            if (value.Key is not ("Microsoft.AspNetCore.Hosting.HttpRequestIn.Start" or "Microsoft.AspNetCore.Hosting.HttpRequestIn.Stop")) return;
            var context = value.Value as HttpContext ?? value.Value?.GetType().GetProperty("HttpContext")?.GetValue(value.Value) as HttpContext;
            if (context is not null && int.TryParse(context.Request.Headers["X-Cehpalon-Trace"], out var id) && id >= 0)
                Mark(value.Key.EndsWith(".Start", StringComparison.Ordinal) ? 30 : 31, id / 10000, id % 10000, id % 10000 % 32);
        }
        public void OnCompleted() { }
        public void OnError(Exception _) { }
        public void Dispose() { all.Dispose(); lock (subscriptions) foreach (var item in subscriptions) item.Dispose(); }
    }
}

[EventSource(Name = "Cehpalon-Https-Warmup")]
public sealed class Log : EventSource
{
    public static readonly Log Instance = new();
    [Event(1, Level = EventLevel.Informational)]
    public unsafe void Point(long sequence, long ticks, int pid, int nativeTid, int managedTid,
        int kind, int phase, int index, int lane, long pending, int threads)
    {
        EventData* data = stackalloc EventData[11];
        for (var i = 0; i < 11; i++) data[i] = default;
        data[0].DataPointer = (IntPtr)(&sequence); data[0].Size = 8;
        data[1].DataPointer = (IntPtr)(&ticks); data[1].Size = 8;
        data[2].DataPointer = (IntPtr)(&pid); data[2].Size = 4;
        data[3].DataPointer = (IntPtr)(&nativeTid); data[3].Size = 4;
        data[4].DataPointer = (IntPtr)(&managedTid); data[4].Size = 4;
        data[5].DataPointer = (IntPtr)(&kind); data[5].Size = 4;
        data[6].DataPointer = (IntPtr)(&phase); data[6].Size = 4;
        data[7].DataPointer = (IntPtr)(&index); data[7].Size = 4;
        data[8].DataPointer = (IntPtr)(&lane); data[8].Size = 4;
        data[9].DataPointer = (IntPtr)(&pending); data[9].Size = 8;
        data[10].DataPointer = (IntPtr)(&threads); data[10].Size = 4;
        WriteEventCore(1, 11, data);
    }
}
