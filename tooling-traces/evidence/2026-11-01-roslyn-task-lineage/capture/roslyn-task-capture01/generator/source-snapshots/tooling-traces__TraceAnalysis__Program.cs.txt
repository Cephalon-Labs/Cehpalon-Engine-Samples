using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Diagnostics.NETCore.Client;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Etlx;

return ProgramMain.Run(args);

static class ProgramMain
{
    internal static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };
    internal static readonly JsonSerializerOptions Lines = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    const string RuntimeProvider = "Microsoft-Windows-DotNETRuntime";
    const string MarkerProvider = "Cehpalon-Tooling-Diagnostic";
    const string SampleProvider = "Microsoft-DotNETCore-SampleProfiler";

    internal static int Run(string[] args)
    {
        if (args.Length == 2 && args[0] == "--resume" && int.TryParse(args[1], out var pid) && pid > 0)
        {
            try
            {
                new DiagnosticsClient(pid).ResumeRuntime();
                Console.WriteLine(JsonSerializer.Serialize(new { status = "command_acknowledged", processId = pid, acknowledgedUtc = DateTimeOffset.UtcNow,
                    endpointScope = "default_pid_port_only", executionResumed = (bool?)null, role = "acknowledgment does not release other suspended ports" }, Lines));
                return 0;
            }
            catch (Exception error)
            {
                Console.Error.WriteLine(JsonSerializer.Serialize(new { status = "failed", processId = pid, error = error.ToString() }, Lines));
                return 1;
            }
        }
        if (args.Length == 1 && args[0] == "--self-test") return SelfTest();
        var options = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 0; i < args.Length; i += 2)
            if (i + 1 >= args.Length || args[i] is not ("--trace" or "--output" or "--spans") || !options.TryAdd(args[i], args[i + 1])) return Usage();
        if (!options.TryGetValue("--trace", out var trace) || !options.TryGetValue("--output", out var output)) return Usage();
        trace = Path.GetFullPath(trace); output = Path.GetFullPath(output);
        if (!File.Exists(trace) || Directory.Exists(output) || File.Exists(output)) throw new IOException("Input trace must exist and output directory must be new.");
        Directory.CreateDirectory(output);
        var report = new AnalysisReport { Input = trace, InputSha256 = HashFile(trace), StartedUtc = DateTimeOffset.UtcNow };
        try
        {
            Analyze(trace, output, options.GetValueOrDefault("--spans"), report);
            report.Status = "completed";
        }
        catch (Exception error) { report.Status = "failed"; report.Failure = error.ToString(); }
        report.FinishedUtc = DateTimeOffset.UtcNow;
        File.WriteAllText(Path.Combine(output, "summary.json"), JsonSerializer.Serialize(report, Json) + "\n", new UTF8Encoding(false));
        Console.WriteLine(JsonSerializer.Serialize(new { report.Status, report.Events, report.EventsLost, report.MarkerEvents, output }, Lines));
        return report.Status == "completed" ? 0 : 1;
    }

    static int Usage()
    {
        Console.Error.WriteLine("Usage: TraceAnalysis --trace <nettrace> --output <new-directory> [--spans <sidecar.jsonl>] | --resume <owned-pid> | --self-test");
        return 2;
    }

    static void Analyze(string trace, string output, string? sidecar, AnalysisReport report)
    {
        var tracker = new Intervals();
        var markers = new Dictionary<long, Marker>();
        var sampled = new List<Sample>();
        using (var raw = new StreamWriter(Path.Combine(output, "events.jsonl"), false, new UTF8Encoding(false)))
        using (var source = new EventPipeEventSource(trace))
        {
            // Register known CLR templates and dynamic metadata. AllEvents fires once
            // for each dispatched event; Dynamic.All is deliberately a no-op listener.
            source.Clr.All += _ => { };
            source.Dynamic.All += _ => { };
            source.AllEvents += data =>
            {
                var payload = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                foreach (var name in data.PayloadNames)
                {
                    try { payload[name] = Safe(data.PayloadByName(name)); }
                    catch (Exception error) { report.PayloadReadErrors++; payload[name] = "unreadable:" + error.GetType().Name; }
                }
                var key = data.ProviderName + "/" + data.EventName;
                report.EventCounts[key] = report.EventCounts.GetValueOrDefault(key) + 1;
                report.Events++;
                var frame = new Frame(data.ProviderName, data.EventName, data.ProcessID, data.ThreadID, data.TimeStampRelativeMSec, payload,
                    (int)data.ID, (int)data.Opcode, data.Version, data.GetType().FullName ?? "unknown");
                raw.WriteLine(JsonSerializer.Serialize(frame, Lines));
                if (data.ProviderName == RuntimeProvider)
                {
                    var normalized = Regex.Replace(data.EventName, "[^A-Za-z0-9]", "");
                    if (normalized.StartsWith("GCSuspendEEStart", StringComparison.Ordinal)) tracker.SuspendStart(frame);
                    else if (normalized.StartsWith("GCSuspendEEStop", StringComparison.Ordinal)) tracker.SuspendStop(frame);
                    else if (normalized.StartsWith("GCRestartEEStart", StringComparison.Ordinal)) tracker.RestartStart(frame);
                    else if (normalized.StartsWith("GCRestartEEStop", StringComparison.Ordinal)) tracker.RestartStop(frame);
                    else if (normalized.StartsWith("MethodJittingStarted", StringComparison.Ordinal)) tracker.JitStart(frame);
                    else if (normalized.StartsWith("MethodLoadVerbose", StringComparison.Ordinal) || Regex.IsMatch(normalized, "^MethodLoad(V[0-9]+)?$"))
                    {
                        var property = data.GetType().GetProperty("IsJitted");
                        var isJitted = property?.GetValue(data) as bool? ?? (Number(payload, "MethodFlags", 0) & 8) != 0;
                        var tier = data.GetType().GetProperty("OptimizationTier")?.GetValue(data)?.ToString() ?? Text(payload, "OptimizationTier", "unavailable");
                        tracker.JitLoad(frame, isJitted, tier);
                    }
                }
                // Rundown provider/DC events are never sent to JitLoad.
                if (data.ProviderName == SampleProvider)
                {
                    report.SampledThreadEvents++;
                    sampled.Add(new(data.ProcessID, data.ThreadID, data.TimeStampRelativeMSec));
                }
                if (data.ProviderName == MarkerProvider && payload.ContainsKey("sequence"))
                {
                    report.MarkerEvents++;
                    var id = Number(payload, "sequence");
                    var marker = new Marker(id, data.ProcessID, data.ThreadID, data.TimeStampRelativeMSec, payload);
                    if (!markers.TryAdd(id, marker)) report.MarkerErrors.Add("duplicate marker sequence:" + id);
                    if (Number(payload, "processId") != data.ProcessID || Number(payload, "osThreadId") != data.ThreadID)
                        report.MarkerErrors.Add("header/payload PID or native TID mismatch:" + id);
                }
            };
            source.Process();
            report.EventsLost = source.EventsLost;
            report.Header = source.HeaderKeyValuePairs;
        }
        tracker.Finish();
        report.GcSuspensionEnvelopes = tracker.Suspensions.Count;
        report.GcRelatedEnvelopes = tracker.Suspensions.Count(s => s.GcRelated);
        report.JitStartToLoadIntervals = tracker.JitIntervals.Count;
        report.Unmatched = tracker.Unmatched;
        report.JitLoadWithoutUniqueStart = tracker.LoadWithoutStart;
        report.NonJittedMethodLoads = tracker.NonJittedLoads;
        report.EePairingErrors = tracker.EePairingErrors;
        report.EePairingStatus = tracker.EePairingErrors == 0 ? "complete_for_observed_episodes" : "partial_or_ambiguous";
        report.JitPairingErrors = tracker.JitPairingErrors;
        File.WriteAllText(Path.Combine(output, "intervals.json"), JsonSerializer.Serialize(new { tracker.Suspensions, tracker.JitIntervals, tracker.Unmatched, tracker.LoadWithoutStart, tracker.NonJittedLoads }, Json) + "\n", new UTF8Encoding(false));
        if (sidecar is not null)
        {
            sidecar = Path.GetFullPath(sidecar);
            report.SidecarSha256 = HashFile(sidecar);
            Correlate(sidecar, output, markers, tracker, sampled, report);
        }
        else report.AlignmentStatus = "no_sidecar; process-wide events only";
        ExtractStacks(trace, output, report);
        report.CorrelationStatus = report.EventsLost == 0 && report.MarkerErrors.Count == 0 && report.PayloadReadErrors == 0 && report.EePairingErrors == 0
            && report.StackExtractionStatus == "completed" && report.EtlxEventsLost == 0
            && (sidecar is null || report.AlignmentStatus == "bounded_consistent") ? "observed_with_declared_bounds" : "incomplete_or_uncertain";
        report.OutputSha256 = Directory.GetFiles(output).Order().ToDictionary(p => Path.GetFileName(p)!, HashFile);
    }

    static void Correlate(string sidecar, string output, Dictionary<long, Marker> markers, Intervals tracker, List<Sample> sampled, AnalysisReport report)
    {
        double lower = double.NegativeInfinity, upper = double.PositiveInfinity;
        var seen = new HashSet<long>();
        using var writer = new StreamWriter(Path.Combine(output, "spans-correlated.jsonl"), false, new UTF8Encoding(false));
        foreach (var line in File.ReadLines(sidecar))
        {
            using var document = JsonDocument.Parse(line);
            var span = document.RootElement;
            var id = span.GetProperty("sequence").GetInt64();
            report.SidecarSpans++;
            if (!seen.Add(id)) report.MarkerErrors.Add("duplicate sidecar sequence:" + id);
            if (!markers.TryGetValue(id, out var marker)) { report.MarkerErrors.Add("missing marker:" + id); continue; }
            foreach (var name in new[] { "startTicks", "endTicks", "frequency", "processId", "osThreadId", "caseIndex", "size", "pairSequence", "markerBeforeTicks", "utcAnchorTicks", "anchorBeforeTicks", "anchorAfterTicks" })
                if (Number(marker.Payload, name) != span.GetProperty(name).GetInt64()) report.MarkerErrors.Add("marker/sidecar differs:" + id + ":" + name);
            foreach (var name in new[] { "stage", "state", "variant", "phase" })
                if (Text(marker.Payload, name) != span.GetProperty(name).GetString()) report.MarkerErrors.Add("marker/sidecar differs:" + id + ":" + name);
            var frequency = span.GetProperty("frequency").GetDouble();
            var start = span.GetProperty("startTicks").GetInt64(); var end = span.GetProperty("endTicks").GetInt64();
            var before = span.GetProperty("markerBeforeTicks").GetInt64(); var after = span.GetProperty("markerAfterTicks").GetInt64();
            if (frequency <= 0 || end < start || before < end || after < before) { report.MarkerErrors.Add("invalid clock ordering:" + id); continue; }
            var lo = marker.TimeMsec - after * 1000.0 / frequency;
            var hi = marker.TimeMsec - before * 1000.0 / frequency;
            lower = Math.Max(lower, lo); upper = Math.Min(upper, hi);
            var startLo = start * 1000.0 / frequency + lo; var startHi = start * 1000.0 / frequency + hi;
            var endLo = end * 1000.0 / frequency + lo; var endHi = end * 1000.0 / frequency + hi;
            var pid = span.GetProperty("processId").GetInt32(); var tid = span.GetProperty("osThreadId").GetInt32();
            object Overlap(double a, double b) => new { minimumMsec = Math.Max(0, Math.Min(endLo, b) - Math.Max(startHi, a)),
                maximumMsec = Math.Min(Math.Min((end - start) * 1000.0 / frequency, b - a), Math.Max(0, Math.Min(endHi, b) - Math.Max(startLo, a))) };
            var gc = tracker.Suspensions.Where(g => g.ProcessId == pid && g.GcRelated && g.EndMsec >= startLo && g.StartMsec <= endHi)
                .Select(g => new { g.StartMsec, g.EndMsec, g.Reason, g.FullySuspendedStartMsec, g.RestartStartMsec, overlap = Overlap(g.StartMsec, g.EndMsec), meaning = "suspension envelope, not all-thread-stop CPU time" }).ToArray();
            var jit = tracker.JitIntervals.Where(j => j.ProcessId == pid && j.EndMsec >= startLo && j.StartMsec <= endHi)
                .Select(j => new { j.ThreadId, j.Method, j.Tier, j.StartMsec, j.EndMsec, sameCallerThread = j.ThreadId == tid, overlap = Overlap(j.StartMsec, j.EndMsec), meaning = "start-to-load elapsed interval, not JIT CPU duration or proven caller stall" }).ToArray();
            var samples = sampled.Where(s => s.ProcessId == pid && s.TimeMsec >= startLo && s.TimeMsec <= endHi).ToArray();
            writer.WriteLine(JsonSerializer.Serialize(new { span = span.Clone(), markerTimeRelativeMsec = marker.TimeMsec, offsetLowerMsec = lo, offsetUpperMsec = hi,
                startRelativeLowerMsec = startLo, startRelativeUpperMsec = startHi, endRelativeLowerMsec = endLo, endRelativeUpperMsec = endHi,
                loggerCallMsec = (after - before) * 1000.0 / frequency, gcSuspensionEnvelopes = gc, jitStartToLoadIntervals = jit,
                sampledThreadEvents = samples.Length, sameThreadSampleEvents = samples.Count(s => s.ThreadId == tid), sampleMeaning = "sampled thread observations; not OS on-CPU attribution" }, Lines));
        }
        foreach (var id in markers.Keys.Except(seen)) report.MarkerErrors.Add("marker missing sidecar:" + id);
        report.ClockOffsetIntersectionLowerMsec = double.IsFinite(lower) ? lower : null;
        report.ClockOffsetIntersectionUpperMsec = double.IsFinite(upper) ? upper : null;
        report.AlignmentStatus = report.SidecarSpans > 0 && lower <= upper && report.MarkerErrors.Count == 0 ? "bounded_consistent" : "uncertain_or_incomplete";
    }

    static void ExtractStacks(string trace, string output, AnalysisReport report)
    {
        var etlx = Path.Combine(output, "managed-stacks.etlx");
        try
        {
            TraceLog.CreateFromEventPipeDataFile(trace, etlx, new TraceLogOptions { KeepAllEvents = true });
            using var log = new TraceLog(etlx);
            using var writer = new StreamWriter(Path.Combine(output, "sampled-thread-stacks.jsonl"), false, new UTF8Encoding(false));
            foreach (var data in log.Events)
            {
                if (data.ProviderName != SampleProvider) continue;
                var frames = new List<string>(); var stack = data.CallStack();
                while (stack is not null && frames.Count < 4096) { frames.Add(stack.CodeAddress.FullMethodName); stack = stack.Caller; }
                if (stack is not null) report.TruncatedStacks++;
                if (frames.Count == 0) report.SamplesWithoutManagedFrames++;
                report.StackSamples++;
                writer.WriteLine(JsonSerializer.Serialize(new { processId = data.ProcessID, osThreadId = data.ThreadID, timeRelativeMsec = data.TimeStampRelativeMSec, frames,
                    truncated = stack is not null, meaning = "managed sampled-thread stack; not native/OS on-CPU trace or scheduler wait attribution" }, Lines));
            }
            report.StackExtractionStatus = "completed";
            report.EtlxEventsLost = log.EventsLost;
        }
        catch (Exception error) { report.StackExtractionStatus = "failed"; report.StackExtractionFailure = error.ToString(); }
    }

    static object? Safe(object? value) => value switch
    {
        null => null,
        Enum e => Convert.ToInt64(e, CultureInfo.InvariantCulture),
        string or bool or byte or sbyte or short or ushort or int or uint or long or ulong or decimal => value,
        double d when double.IsFinite(d) => d,
        float f when float.IsFinite(f) => f,
        byte[] b => Convert.ToHexString(b),
        Array a => a.Cast<object?>().Select(Safe).ToArray(),
        _ => value.ToString()
    };
    internal static string Text(Dictionary<string, object?> p, string key, string fallback = "") => p.TryGetValue(key, out var value) ? Convert.ToString(value, CultureInfo.InvariantCulture) ?? fallback : fallback;
    internal static long Number(Dictionary<string, object?> p, string key, long fallback = -1)
    { try { return p.TryGetValue(key, out var v) && v is not null ? Convert.ToInt64(v, CultureInfo.InvariantCulture) : fallback; } catch { return fallback; } }
    internal static string HashFile(string path) { using var stream = File.OpenRead(path); return Convert.ToHexStringLower(SHA256.HashData(stream)); }

    static int SelfTest()
    {
        var t = new Intervals();
        Frame F(string n, double ms, int pid = 1, int tid = 2, long method = 3) => new(RuntimeProvider, n, pid, tid, ms,
            new(StringComparer.OrdinalIgnoreCase) { ["ClrInstanceID"] = 1, ["Reason"] = 6, ["MethodID"] = method, ["ModuleID"] = 4 });
        t.SuspendStart(F("GC/SuspendEEStart", 10)); t.SuspendStop(F("GC/SuspendEEStop", 11)); t.RestartStart(F("GC/RestartEEStart", 12)); t.RestartStop(F("GC/RestartEEStop", 13));
        t.JitStart(F("Method/JittingStarted", 15)); t.JitLoad(F("Method/LoadVerbose", 17), true, "Tier0");
        t.JitLoad(F("Method/LoadVerbose", 18, method: 5), true, "Tier1");
        t.JitStart(F("Method/JittingStarted", 19, method: 6)); t.JitStart(F("Method/JittingStarted", 20, method: 6));
        t.JitLoad(F("Method/LoadVerbose", 21, method: 6), true, "Tier1");
        t.JitStart(F("Method/JittingStarted", 22, method: 6));
        t.JitLoad(F("Method/LoadVerbose", 23, method: 6), true, "Tier1"); t.JitLoad(F("Method/LoadVerbose", 24, method: 6), true, "Tier1");
        t.SuspendStart(F("GC/SuspendEEStart", 30)); t.SuspendStart(F("GC/SuspendEEStart", 31)); t.RestartStop(F("GC/RestartEEStop", 35));
        t.Finish();
        if (t.Suspensions.Count != 1 || !t.Suspensions[0].GcRelated || t.Suspensions[0].FullySuspendedStartMsec != 11 || t.Suspensions[0].RestartStartMsec != 12
            || t.JitIntervals.Count != 1 || t.JitIntervals[0].EndMsec != 17 || t.LoadWithoutStart.Count != 4 || t.EePairingErrors == 0 || t.JitPairingErrors == 0) throw new InvalidOperationException("Interval self-test failed.");
        Console.WriteLine("{\"status\":\"passed\",\"scope\":\"synthetic interval pairing only, not actual trace conformance\"}");
        return 0;
    }
}

sealed record Frame(string Provider, string Name, int ProcessId, int ThreadId, double TimeMsec, Dictionary<string, object?> Payload,
    int EventId = -1, int Opcode = -1, int Version = -1, string TemplateType = "synthetic");
sealed record Marker(long Sequence, int ProcessId, int ThreadId, double TimeMsec, Dictionary<string, object?> Payload);
sealed record Sample(int ProcessId, int ThreadId, double TimeMsec);
sealed record Suspension(int ProcessId, long ClrInstanceId, string Reason, bool GcRelated, double StartMsec, double? FullySuspendedStartMsec, double? RestartStartMsec, double EndMsec);
sealed record JitInterval(int ProcessId, int ThreadId, string Key, string Method, string Tier, double StartMsec, double EndMsec);

sealed class Intervals
{
    sealed record PendingGc(Frame Start, double? Stop = null, double? Restart = null);
    readonly Dictionary<string, PendingGc> gc = new();
    readonly HashSet<string> ambiguousGc = new();
    readonly Dictionary<string, Frame> jit = new();
    readonly HashSet<string> ambiguousJit = new();
    internal List<Suspension> Suspensions { get; } = new();
    internal List<JitInterval> JitIntervals { get; } = new();
    internal List<object> Unmatched { get; } = new();
    internal List<object> LoadWithoutStart { get; } = new();
    internal long NonJittedLoads { get; private set; }
    internal long EePairingErrors { get; private set; }
    internal long JitPairingErrors { get; private set; }
    static string GcKey(Frame f) => f.ProcessId + ":" + ProgramMain.Number(f.Payload, "ClrInstanceID");
    static string JitKey(Frame f) => GcKey(f) + ":" + f.ThreadId + ":" + ProgramMain.Text(f.Payload, "MethodID") + ":" + ProgramMain.Text(f.Payload, "ModuleID");
    internal void SuspendStart(Frame f)
    {
        if (ProgramMain.Number(f.Payload, "ClrInstanceID") < 0) { EePairingErrors++; Unmatched.Add(new { reason = "suspend start missing CLR identity", frame = f }); return; }
        var key = GcKey(f);
        if (gc.Remove(key, out var old)) { EePairingErrors++; ambiguousGc.Add(key); Unmatched.Add(new { reason = "ambiguous repeated suspension start", old.Start, replacement = f }); }
        gc[key] = new(f);
    }
    internal void SuspendStop(Frame f)
    {
        var key = GcKey(f);
        if (gc.TryGetValue(key, out var old) && old.Stop is null) gc[key] = old with { Stop = f.TimeMsec };
        else { EePairingErrors++; Unmatched.Add(new { reason = "suspend stop without unique open start", frame = f }); }
    }
    internal void RestartStart(Frame f)
    {
        var key = GcKey(f);
        if (gc.TryGetValue(key, out var old) && old.Restart is null) gc[key] = old with { Restart = f.TimeMsec };
        else { EePairingErrors++; Unmatched.Add(new { reason = "restart start without unique open suspension", frame = f }); }
    }
    internal void RestartStop(Frame f)
    {
        var key = GcKey(f);
        if (!gc.Remove(key, out var old)) { EePairingErrors++; Unmatched.Add(new { reason = "restart stop without suspend", frame = f }); return; }
        if (ambiguousGc.Remove(key)) { EePairingErrors++; Unmatched.Add(new { reason = "ambiguous suspension episode not promoted", start = old.Start, end = f }); return; }
        var reason = ProgramMain.Number(old.Start.Payload, "Reason");
        if (f.TimeMsec < old.Start.TimeMsec || old.Stop is double stop && (stop < old.Start.TimeMsec || stop > f.TimeMsec) || old.Restart is double restart && (restart < old.Start.TimeMsec || restart > f.TimeMsec || old.Stop is double s && restart < s))
        { EePairingErrors++; Unmatched.Add(new { reason = "invalid suspension ordering", start = old.Start, end = f }); return; }
        if (old.Stop is null || old.Restart is null) { EePairingErrors++; Unmatched.Add(new { reason = "incomplete suspension inner phases; envelope only", start = old.Start, end = f }); }
        Suspensions.Add(new(f.ProcessId, ProgramMain.Number(f.Payload, "ClrInstanceID"), reason.ToString(CultureInfo.InvariantCulture), reason is 1 or 6,
            old.Start.TimeMsec, old.Stop, old.Restart, f.TimeMsec));
    }
    internal void JitStart(Frame f)
    {
        if (!f.Payload.ContainsKey("MethodID") || !f.Payload.ContainsKey("ModuleID") || ProgramMain.Number(f.Payload, "ClrInstanceID") < 0)
        { JitPairingErrors++; Unmatched.Add(new { reason = "JIT start missing pairing identity", frame = f }); return; }
        var key = JitKey(f);
        if (ambiguousJit.Contains(key)) { JitPairingErrors++; Unmatched.Add(new { reason = "JIT key remains poisoned after ambiguity", frame = f }); return; }
        if (jit.Remove(key, out var old)) { JitPairingErrors++; Unmatched.Add(new { reason = "ambiguous repeated JIT start", old, replacement = f }); ambiguousJit.Add(key); }
        jit[key] = f;
    }
    internal void JitLoad(Frame f, bool isJitted, string tier)
    {
        if (!isJitted) { NonJittedLoads++; return; }
        var key = JitKey(f);
        if (ambiguousJit.Contains(key)) { jit.Remove(key); LoadWithoutStart.Add(new { reason = "ambiguous matching JIT starts; key poisoned for remainder", frame = f, tier }); return; }
        if (!jit.Remove(key, out var start) || f.TimeMsec < start.TimeMsec)
        { LoadWithoutStart.Add(new { reason = "actual runtime JIT load without unique matching start", frame = f, tier }); return; }
        var method = ProgramMain.Text(start.Payload, "MethodNamespace") + "." + ProgramMain.Text(start.Payload, "MethodName") + ProgramMain.Text(start.Payload, "MethodSignature");
        JitIntervals.Add(new(f.ProcessId, f.ThreadId, key, method, tier, start.TimeMsec, f.TimeMsec));
    }
    internal void Finish()
    {
        foreach (var p in gc.Values) { EePairingErrors++; Unmatched.Add(new { reason = "unfinished suspension", p.Start }); }
        foreach (var p in jit.Values) { JitPairingErrors++; Unmatched.Add(new { reason = "unfinished JIT start", frame = p }); }
    }
}

sealed class AnalysisReport
{
    public string Protocol { get; } = "cehpalon-managed-trace-analysis-v1";
    public bool Canonical { get; } = false;
    public string PerformanceStatus { get; } = "diagnostic_only_not_acceptance";
    public string QualificationStatus { get; } = "not_qualified";
    public string Status { get; set; } = "running";
    public string Input { get; set; } = "";
    public string InputSha256 { get; set; } = "";
    public DateTimeOffset StartedUtc { get; set; }
    public DateTimeOffset FinishedUtc { get; set; }
    public string? Failure { get; set; }
    public long Events { get; set; }
    public int EventsLost { get; set; }
    public long PayloadReadErrors { get; set; }
    public Dictionary<string, long> EventCounts { get; } = new();
    public Dictionary<string, string>? Header { get; set; }
    public long MarkerEvents { get; set; }
    public long SidecarSpans { get; set; }
    public string? SidecarSha256 { get; set; }
    public List<string> MarkerErrors { get; } = new();
    public string AlignmentStatus { get; set; } = "not_attempted";
    public double? ClockOffsetIntersectionLowerMsec { get; set; }
    public double? ClockOffsetIntersectionUpperMsec { get; set; }
    public string CorrelationStatus { get; set; } = "not_attempted";
    public long GcSuspensionEnvelopes { get; set; }
    public long GcRelatedEnvelopes { get; set; }
    public long JitStartToLoadIntervals { get; set; }
    public long EePairingErrors { get; set; }
    public string EePairingStatus { get; set; } = "not_attempted";
    public long JitPairingErrors { get; set; }
    public long NonJittedMethodLoads { get; set; }
    public List<object> Unmatched { get; set; } = new();
    public List<object> JitLoadWithoutUniqueStart { get; set; } = new();
    public long SampledThreadEvents { get; set; }
    public long StackSamples { get; set; }
    public long SamplesWithoutManagedFrames { get; set; }
    public long TruncatedStacks { get; set; }
    public int EtlxEventsLost { get; set; }
    public string StackExtractionStatus { get; set; } = "not_attempted";
    public string? StackExtractionFailure { get; set; }
    public Dictionary<string, string>? OutputSha256 { get; set; }
    public string[] Limits { get; } = [
        "Instrumented and traced work is perturbed and never performance acceptance.",
        "GC suspension start-to-restart-stop includes rendezvous/restart; stop-to-restart-start is the narrower all-suspended window. Background GC lifetime is not a pause.",
        "JIT start-to-load is an elapsed interval, not compiler CPU time; background-thread overlap is not proven caller stall. Rundown loads are excluded from matching.",
        "Sample profiler observes managed thread stacks, not OS on-CPU, native stacks, scheduling waits or physical file IO. Use separate OS tracing for those claims.",
        "Clock mapping assumes the event timestamp occurs during the recorded logging call. Every per-marker interval and their intersection are retained; inconsistent mapping is uncertain.",
        "Missing/unmatched events, payload errors, loss or failed stack extraction are retained rather than silently treated as complete evidence.",
        "No external symbol server is configured; available JIT/rundown managed names only. Native/PDB source line resolution is not claimed."
        ,"Unassigned diagnostic gaps include UTF8/source-string material construction, logger bookkeeping, pretty final report and final buffered sidecar serialization; a small SHA/hex span does not prove those costs absent."
    ];
}
