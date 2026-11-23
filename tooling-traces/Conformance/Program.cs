using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
if(args.Length==0 || args.Length==1 && args[0] is "--help" or "-h") {Console.WriteLine("Usage: Conformance <new-output.json>. Run through the owned collector controller for diagnostic evidence.");return 0;}
var output = Path.GetFullPath(args.Single());
DiagnosticSpans.Initialize(output + ".spans.jsonl");
DiagnosticSpans.Case(1, "collector-conformance", -2, 0, "conformance");
DiagnosticSpans.Variant("synthetic");
try
{
    var start = Stopwatch.GetTimestamp();
    DiagnosticSpans.Span("fixture.startup", start, Stopwatch.GetTimestamp());
    start = Stopwatch.GetTimestamp();
    var watch = Stopwatch.StartNew(); double checksum = 0;
    while(watch.ElapsedMilliseconds < 75) for(var i=1;i<1000;i++) checksum += Math.Sqrt(i);
    DiagnosticSpans.Span("fixture.cpu", start, Stopwatch.GetTimestamp());
    start = Stopwatch.GetTimestamp();
    var temporary = new List<byte[]>();
    for(var i=0;i<128;i++) temporary.Add(new byte[65536]);
    temporary.Clear();
    // Collector conformance ONLY. Never part of the real diagnostic workload/benchmark.
    GC.Collect(2, GCCollectionMode.Forced, blocking:true, compacting:true);
    GC.WaitForPendingFinalizers();
    DiagnosticSpans.Span("fixture.explicit-gc-conformance-only", start, Stopwatch.GetTimestamp());
    start = Stopwatch.GetTimestamp();
    var bytes = Enumerable.Range(0,4096).Select(i=>(byte)(i%251)).ToArray();
    var file = Path.Combine(Path.GetDirectoryName(output)!, "known.bin");
    File.WriteAllBytes(file,bytes);var observed=File.ReadAllBytes(file);
    if(!observed.SequenceEqual(bytes)||checksum<=0) throw new InvalidOperationException("Known conformance semantics");
    DiagnosticSpans.Span("fixture.file-write-read", start, Stopwatch.GetTimestamp());
    start = Stopwatch.GetTimestamp();
    File.WriteAllText(output,JsonSerializer.Serialize(new {status="passed",role="synthetic_collector_conformance_not_acceptance",processId=Environment.ProcessId,bytes=bytes.Length,sha256=Convert.ToHexStringLower(SHA256.HashData(bytes)),forcedGcFixtureOnly=true}));
    DiagnosticSpans.Span("fixture.result", start, Stopwatch.GetTimestamp());
}
finally { DiagnosticSpans.Complete(); }
return 0;
