using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

if (!OperatingSystem.IsLinux() || RuntimeInformation.ProcessArchitecture != Architecture.X64)
    throw new PlatformNotSupportedException("This synthetic syscall fixture is Linux x64 only.");
var output = Path.GetFullPath(args.Single());
DiagnosticSpans.Initialize(output + ".spans.jsonl");
DiagnosticSpans.Case(1, "wait-collector-conformance", -2, 0, "conformance");
DiagnosticSpans.Variant("synthetic");
var mainTid = Native.GetTid();
try
{
    var start = Stopwatch.GetTimestamp();
    DiagnosticSpans.Span("fixture.startup", start, Stopwatch.GetTimestamp());
    start = Stopwatch.GetTimestamp();
    var watch = Stopwatch.StartNew(); double checksum = 0;
    while (watch.ElapsedMilliseconds < 75)
        for (var i = 1; i < 1000; i++) checksum += Math.Sqrt(i);
    DiagnosticSpans.Span("fixture.cpu", start, Stopwatch.GetTimestamp());

    using var unsignalled = new ManualResetEvent(false);
    using var armed = new ManualResetEvent(false);
    var workerTid = 0; double workerChecksum = 0;
    var worker = new Thread(() =>
    {
        workerTid = Native.GetTid(); armed.Set();
        var work = Stopwatch.StartNew();
        while (work.ElapsedMilliseconds < 30)
            for (var i = 1; i < 1000; i++) workerChecksum += Math.Sqrt(i);
    });
    worker.Start();
    try
    {
        if (!armed.WaitOne(TimeSpan.FromSeconds(10))) throw new TimeoutException("Owned worker did not arm.");
        start = Stopwatch.GetTimestamp();
        if (unsignalled.WaitOne(TimeSpan.FromMilliseconds(80))) throw new InvalidOperationException("Unsignalled event was signalled.");
        DiagnosticSpans.Span("fixture.managed-wait", start, Stopwatch.GetTimestamp());
    }
    finally
    {
        if (!worker.Join(TimeSpan.FromSeconds(10))) throw new TimeoutException("Owned synthetic worker did not join.");
    }
    if (workerTid <= 0 || workerTid == mainTid || workerChecksum <= 0) throw new InvalidOperationException("Worker semantic proof.");

    var word = Marshal.AllocHGlobal(sizeof(int));
    int futexError;
    try
    {
        Marshal.WriteInt32(word, 0);
        var timeout = new Native.Timespec { Seconds = 0, Nanoseconds = 80_000_000 };
        start = Stopwatch.GetTimestamp();
        var result = Native.Futex(202, word, 128, 0, ref timeout, IntPtr.Zero, 0);
        futexError = Marshal.GetLastPInvokeError();
        var end = Stopwatch.GetTimestamp();
        if (result != -1 || futexError != 110) throw new InvalidOperationException("Expected synthetic futex ETIMEDOUT.");
        DiagnosticSpans.Span("fixture.native-futex-wait", start, end);
    }
    finally { Marshal.FreeHGlobal(word); }

    start = Stopwatch.GetTimestamp();
    var temporary = new List<byte[]>();
    for (var i = 0; i < 128; i++) temporary.Add(new byte[65536]);
    temporary.Clear();
    // Synthetic collector verification only; never real workload or benchmark.
    GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
    GC.WaitForPendingFinalizers();
    DiagnosticSpans.Span("fixture.explicit-gc-conformance-only", start, Stopwatch.GetTimestamp());
    start = Stopwatch.GetTimestamp();
    var bytes = Enumerable.Range(0, 4096).Select(i => (byte)(i % 251)).ToArray();
    var file = Path.Combine(Path.GetDirectoryName(output)!, "known.bin");
    File.WriteAllBytes(file, bytes);
    if (!File.ReadAllBytes(file).SequenceEqual(bytes) || checksum <= 0) throw new InvalidOperationException("Synthetic file/CPU semantics.");
    DiagnosticSpans.Span("fixture.file-write-read", start, Stopwatch.GetTimestamp());
    start = Stopwatch.GetTimestamp();
    File.WriteAllText(output, JsonSerializer.Serialize(new { status = "passed", role = "synthetic_wait_collector_not_acceptance", processId = Environment.ProcessId,
        mainNativeTid = mainTid, workerNativeTid = workerTid, workerJoined = true, managedWaitTimedOut = true,
        nativeFutexErrno = futexError, bytes = bytes.Length, sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)), forcedGcFixtureOnly = true }));
    DiagnosticSpans.Span("fixture.result", start, Stopwatch.GetTimestamp());
}
finally { DiagnosticSpans.Complete(); }
return 0;

static class Native
{
    [StructLayout(LayoutKind.Sequential)] internal struct Timespec { internal long Seconds; internal long Nanoseconds; }
    [DllImport("libc", EntryPoint = "gettid")] internal static extern int GetTid();
    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    internal static extern long Futex(long number, IntPtr address, int operation, int expected, ref Timespec timeout, IntPtr secondAddress, int thirdValue);
}
