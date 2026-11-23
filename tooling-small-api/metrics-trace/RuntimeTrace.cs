using System.Diagnostics.Tracing;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Diagnostics.NETCore.Client;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;

if(args.Length==0 || args.Length==1 && args[0] is "--help" or "-h") {Console.WriteLine("Usage: RuntimeTrace collect/analyze <paired options including --output>. Use the owned metrics trace controller; no process was attached.");return;}
var json = new JsonSerializerOptions { WriteIndented = false };
var options = new Dictionary<string, string>();
for (var i = 1; i < args.Length; i += 2) options.Add(args[i], args[i + 1]);
var output = Path.GetFullPath(options["--output"]);
if (args[0] == "collect")
{
    var pid = int.Parse(options["--pid"]);
    var keywords = (long)(ClrTraceEventParser.Keywords.GC | ClrTraceEventParser.Keywords.Threading | ClrTraceEventParser.Keywords.ThreadTransfer);
    var providers = new[] {
        new EventPipeProvider("Microsoft-Windows-DotNETRuntime", EventLevel.Verbose, keywords),
        new EventPipeProvider("System.Threading.Tasks.TplEventSource", EventLevel.Verbose, -1),
        new EventPipeProvider("Cehpalon-Https-Warmup", EventLevel.Informational, -1) };
    using var session = new DiagnosticsClient(pid).StartEventPipeSession(providers, requestRundown: false, circularBufferMB: 128);
    await using var file = new FileStream(output, FileMode.CreateNew, FileAccess.Write);
    var copy = session.EventStream.CopyToAsync(file);
    Console.WriteLine(JsonSerializer.Serialize(new { kind = "attached", pid, keywords, bufferMB = 128, rundown = false }));
    if (await Console.In.ReadLineAsync() != "STOP") throw new InvalidOperationException();
    session.Stop();
    await copy.WaitAsync(TimeSpan.FromSeconds(20));
    await file.FlushAsync();
    Console.WriteLine(JsonSerializer.Serialize(new { kind = "collected", pid, bytes = file.Length }));
    return;
}
if (args[0] != "analyze") throw new ArgumentException();
Directory.CreateDirectory(output);
var trace = Path.GetFullPath(options["--trace"]);
var expectedPid = int.Parse(options["--pid"]);
var allow = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
    "sequence", "ticks", "pid", "nativeTid", "managedTid", "kind", "phase", "index", "lane", "pending", "threads",
    "ClrInstanceID", "Count", "Reason", "Type", "Depth", "Generation", "ActiveWorkerThreadCount", "RetiredWorkerThreadCount",
    "TaskID", "OriginatingTaskID", "OriginatingTaskSchedulerID", "TaskSchedulerID", "Behavior", "ContinuationID",
    "WorkID", "WorkId", "NativeOverlapped", "Overlapped", "MultiDequeues", "Throughput", "NewWorkerThreadCount", "AdjustmentReason" };
var pointers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "WorkID", "NativeOverlapped", "Overlapped" };
var counts = new Dictionary<string, long>();
long events = 0, exported = 0, errors = 0;
using var source = new EventPipeEventSource(trace);
using var raw = new StreamWriter(Path.Combine(output, "events.jsonl"), false, new UTF8Encoding(false));
source.Clr.All += _ => { };
source.Dynamic.All += _ => { };
source.AllEvents += data =>
{
    events++;
    var key = data.ProviderName + "/" + data.EventName;
    counts[key] = counts.GetValueOrDefault(key) + 1;
    if (data.ProviderName is not ("Microsoft-Windows-DotNETRuntime" or "System.Threading.Tasks.TplEventSource" or "Cehpalon-Https-Warmup")) return;
    var payload = new Dictionary<string, object?>();
    foreach (var name in data.PayloadNames)
    {
        if (!allow.Contains(name)) continue;
        try
        {
            var value = data.PayloadByName(name);
            if (pointers.Contains(name))
                payload[name] = "id:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(expectedPid + ":" + Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture)))).ToLowerInvariant();
            else if (value is byte or sbyte or short or ushort or int or uint or long or ulong or float or double or bool) payload[name] = value;
            else if (value is Enum) payload[name] = Convert.ToInt64(value);
        }
        catch { errors++; }
    }
    // Raw QPC is required for independent before/after application receipt validation.
    // Its clock basis is accepted only if that validation and relative-time slopes pass.
#pragma warning disable CS0618
    var qpc = data.TimeStampQPC;
#pragma warning restore CS0618
    raw.WriteLine(JsonSerializer.Serialize(new { provider = data.ProviderName, name = data.EventName,
        pid = data.ProcessID, tid = data.ThreadID, qpc, milliseconds = data.TimeStampRelativeMSec,
        id = (int)data.ID, opcode = (int)data.Opcode, version = data.Version,
        template = data.GetType().FullName, activity = data.ActivityID, relatedActivity = data.RelatedActivityID, payload }, json));
    exported++;
};
source.Process();
var summary = new { status = "decoded", expectedPid, events, exported,
    reportedEventsLost = source.EventsLost, payloadReadErrors = errors, eventCounts = counts,
    traceSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(trace))).ToLowerInvariant(),
    scope = "Allowlisted numeric metadata; pointer identities pseudonymized within PID. Private original nettrace retained locally. No kernel scheduling events." };
File.WriteAllText(Path.Combine(output, "summary.json"), JsonSerializer.Serialize(summary, new JsonSerializerOptions { WriteIndented = true }) + "\n", new UTF8Encoding(false));
Console.WriteLine(JsonSerializer.Serialize(new { status = "decoded", events, exported, lost = source.EventsLost, errors }));
