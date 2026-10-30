using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

// Diagnostic-only observer. Every stage end is captured before this logger runs.
static class DiagnosticSpans
{
    static readonly List<SpanRecord> Records = new();
    static string? path;
    static long sequence, anchorBefore, anchorAfter, utcTicks;
    static int size, caseIndex = -1, pair = -1;
    static string state = "startup", phase = "startup", variant = "none";
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    [DllImport("libc", EntryPoint = "gettid")] static extern int GetTid();
    static int OsThreadId() => OperatingSystem.IsWindows() ? checked((int)GetCurrentThreadId()) : GetTid();
    internal static void Initialize(string output)
    {
        if (File.Exists(output)) throw new IOException("Diagnostic span sidecar must be new.");
        path = output;
        anchorBefore = Stopwatch.GetTimestamp();
        utcTicks = DateTimeOffset.UtcNow.UtcTicks;
        anchorAfter = Stopwatch.GetTimestamp();
    }
    internal static void Case(int operationCount, string caseState, int index, int pairSequence, string rowPhase)
    { size = operationCount; state = caseState; caseIndex = index; pair = pairSequence; phase = rowPhase; variant = "none"; }
    internal static void Variant(string value) => variant = value;
    internal static void Span(string stage, long startTicks, long endTicks)
    {
        if (path is null) return;
        var id = ++sequence;
        // Metadata acquisition and event/sidecar bookkeeping are AFTER body end.
        var tid = OsThreadId();
        var pid = Environment.ProcessId;
        var markerBefore = Stopwatch.GetTimestamp();
        ToolingDiagnosticEvents.Log.Span(id, stage, startTicks, endTicks, Stopwatch.Frequency,
            utcTicks, anchorBefore, anchorAfter, pid, tid, caseIndex, size, state, variant, pair, phase, markerBefore);
        var markerAfter = Stopwatch.GetTimestamp();
        Records.Add(new(id, stage, startTicks, endTicks, Stopwatch.Frequency, utcTicks,
            anchorBefore, anchorAfter, pid, tid, caseIndex, size, state, variant, pair, phase,
            markerBefore, markerAfter));
    }
    internal static void Complete()
    {
        if (path is null) return;
        using var writer = new StreamWriter(new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read), new UTF8Encoding(false));
        var json = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        foreach (var record in Records) writer.WriteLine(JsonSerializer.Serialize(record, json));
    }
    sealed record SpanRecord(long Sequence, string Stage, long StartTicks, long EndTicks, long Frequency,
        long UtcAnchorTicks, long AnchorBeforeTicks, long AnchorAfterTicks, int ProcessId, int OsThreadId,
        int CaseIndex, int Size, string State, string Variant, int PairSequence, string Phase,
        long MarkerBeforeTicks, long MarkerAfterTicks);
}

[EventSource(Name = "Cehpalon-Tooling-Diagnostic")]
sealed class ToolingDiagnosticEvents : EventSource
{
    internal static readonly ToolingDiagnosticEvents Log = new();
    public static class Keywords { public const EventKeywords Diagnostic = (EventKeywords)1; }
    [Event(1, Level = EventLevel.Informational, Keywords = Keywords.Diagnostic)]
    public void Span(long sequence, string stage, long startTicks, long endTicks, long frequency,
        long utcAnchorTicks, long anchorBeforeTicks, long anchorAfterTicks, int processId, int osThreadId,
        int caseIndex, int size, string state, string variant, int pairSequence, string phase, long markerBeforeTicks)
    {
        if (IsEnabled()) WriteEvent(1, sequence, stage, startTicks, endTicks, frequency,
            utcAnchorTicks, anchorBeforeTicks, anchorAfterTicks, processId, osThreadId,
            caseIndex, size, state, variant, pairSequence, phase, markerBeforeTicks);
    }
}
