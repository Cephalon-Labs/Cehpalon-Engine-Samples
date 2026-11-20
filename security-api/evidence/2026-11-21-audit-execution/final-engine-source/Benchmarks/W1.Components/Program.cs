using System.Diagnostics;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Text.Json;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Composition;

const int DispatchIterations = 100_000;
const int DispatchWarmup = 10_000;
const int Repetitions = 5;
var outputArgument = args.SingleOrDefault(a => a.StartsWith("--output=", StringComparison.Ordinal))
    ?? throw new ArgumentException("--output=<new-file.json> is required");
var outputPath = Path.GetFullPath(outputArgument[9..]);
if (File.Exists(outputPath)) throw new IOException("Preserve previous results; choose a new output path.");
if (args.Contains("--observe-dispatch-budget", StringComparer.Ordinal))
    return await DispatchBudgetObservation.RunAsync(outputPath);
var context = new OperationContext("w1-component-benchmark");
var dispatcher = new OperationDispatcher(new OperationRegistryBuilder()
    .Register<int,int>("bench.echo", () => new EchoHandler()).Build());
var token = CancellationToken.None;
for (var i = 0; i < DispatchWarmup; i++) { Direct(i); Dispatch(i); }
EchoHandler.Created = EchoHandler.Disposed = 0;
var dispatchRuns = new List<object>();
var overheads = new List<double>();
var extraAllocations = new List<double>();
for (var repetition = 0; repetition < Repetitions; repetition++)
{
    Measurement direct, engine;
    if (repetition % 2 == 0) { direct = Measure(DispatchIterations, Direct); engine = Measure(DispatchIterations, Dispatch); }
    else { engine = Measure(DispatchIterations, Dispatch); direct = Measure(DispatchIterations, Direct); }
    overheads.Add(engine.NanosecondsPerOperation-direct.NanosecondsPerOperation);
    extraAllocations.Add(engine.BytesPerOperation-direct.BytesPerOperation);
    dispatchRuns.Add(new { repetition, order = repetition % 2 == 0 ? "direct,dispatcher" : "dispatcher,direct", direct, dispatcher=engine });
}
var handlerOwnershipCorrect = EchoHandler.Created == 2L*DispatchIterations*Repetitions && EchoHandler.Disposed == EchoHandler.Created;
var smallCatalog = new[] { new ModuleDescriptor("core",ModuleRole.Support),new ModuleDescriptor("api",ModuleRole.EntryPoint,["core"]), new ModuleDescriptor("graphql",ModuleRole.EntryPoint,["core"]),new ModuleDescriptor("worker",ModuleRole.EntryPoint,["core"]) };
var smallJson = Config("api");
int Small(int _) { var p=CompositionCompiler.Compile(smallJson,smallCatalog); if (!p.IsSuccess || p.Plan!.ActivationOrder.Count!=2) throw new InvalidOperationException("Small plan changed."); return p.Plan.ActivationOrder.Count; }
var largeCatalog = Enumerable.Range(0,128).Select(i=>new ModuleDescriptor($"m{i:000}",i==127?ModuleRole.EntryPoint:ModuleRole.Support,i==0?[]:new[]{$"m{i-1:000}"})).ToArray();
var largeJson = Config("m127");
int Large(int _) { var p=CompositionCompiler.Compile(largeJson,largeCatalog); if(!p.IsSuccess || p.Plan!.ActivationOrder.Count!=128) throw new InvalidOperationException("Large plan changed."); return p.Plan.ActivationOrder.Count; }
if (!CompositionCompiler.Compile(smallJson,smallCatalog).Plan!.ActivationOrder.SequenceEqual(new[]{"core","api"}) || !CompositionCompiler.Compile(largeJson,largeCatalog).Plan!.ActivationOrder.SequenceEqual(Enumerable.Range(0,128).Select(i=>$"m{i:000}"))) throw new InvalidOperationException("Plan-order preflight failed.");
for (var i=0;i<100;i++) Small(i);
var smallRuns=Enumerable.Range(0,Repetitions).Select(_=>
{
    CheckPlanOrder(); var result=Measure(1_000,Small); CheckPlanOrder(); return result;
}).ToArray();
for (var i=0;i<10;i++) Large(i);
var largeRuns=Enumerable.Range(0,Repetitions).Select(_=>
{
    CheckPlanOrder(); var result=Measure(100,Large); CheckPlanOrder(); return result;
}).ToArray();
void CheckPlanOrder()
{
    if (!CompositionCompiler.Compile(smallJson,smallCatalog).Plan!.ActivationOrder.SequenceEqual(new[]{"core","api"}) || !CompositionCompiler.Compile(largeJson,largeCatalog).Plan!.ActivationOrder.SequenceEqual(Enumerable.Range(0,128).Select(i=>$"m{i:000}"))) throw new InvalidOperationException("Plan-order pre/postflight failed.");
}
var checks=new[] {
    new {name="owned handler counts",passed=handlerOwnershipCorrect},
    new {name="all per-run checksums exact",passed=smallRuns.All(x=>x.Checksum==2_000) && largeRuns.All(x=>x.Checksum==12_800)},
    new {name="median dispatch extra time <=20us/op",passed=Median(overheads)<=20_000},
    new {name="median dispatch extra allocation <=1024B/op",passed=Median(extraAllocations)<=1024},
    new {name="small median <=2ms/compile",passed=Median(smallRuns.Select(x=>x.NanosecondsPerOperation))<=2_000_000},
    new {name="small median <=128KiB/compile",passed=Median(smallRuns.Select(x=>x.BytesPerOperation))<=128*1024},
    new {name="128node median <=10ms/compile",passed=Median(largeRuns.Select(x=>x.NanosecondsPerOperation))<=10_000_000},
    new {name="128node median <=2MiB/compile",passed=Median(largeRuns.Select(x=>x.BytesPerOperation))<=2*1024*1024}
};
string? affinity=null;
try { if (OperatingSystem.IsWindows() || OperatingSystem.IsLinux()) affinity="0x"+Process.GetCurrentProcess().ProcessorAffinity.ToInt64().ToString("x",System.Globalization.CultureInfo.InvariantCulture); }
catch (PlatformNotSupportedException) { }
var report=new {
    observedAtUtc=DateTimeOffset.UtcNow,scope="Warm synchronous component regression smoke only; local WSL/shared host, no production/E2E/transport/tenant/generator-speed qualification.",
    protocol="Docs internal/validation/w1-component-protocol.md, declared before measurement; no outlier filtering",
    environment=new {os=RuntimeInformation.OSDescription,framework=RuntimeInformation.FrameworkDescription,architecture=RuntimeInformation.ProcessArchitecture.ToString(),logicalProcessors=Environment.ProcessorCount,affinity,gcTotalAvailableMemoryBytes=GC.GetGCMemoryInfo().TotalAvailableMemoryBytes,serverGC=GCSettings.IsServerGC,stopwatchFrequency=Stopwatch.Frequency},
    dispatch=new {iterations=DispatchIterations,warmup=DispatchWarmup,repetitions=Repetitions,runs=dispatchRuns,medianExtraNanoseconds=Median(overheads),medianExtraBytes=Median(extraAllocations),created=EchoHandler.Created,disposed=EchoHandler.Disposed},
    smallComposition=new {iterations=1000,warmup=100,repetitions=Repetitions,runs=smallRuns},
    largeComposition=new {nodes=128,iterations=100,warmup=10,repetitions=Repetitions,runs=largeRuns},checks,passed=checks.All(x=>x.passed)
};
Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
await using (var stream=new FileStream(outputPath,FileMode.CreateNew,FileAccess.Write,FileShare.None)) await JsonSerializer.SerializeAsync(stream,report,new JsonSerializerOptions {WriteIndented=true});
Console.WriteLine($"Component guardrails: {checks.Count(x=>x.passed)}/{checks.Length}; all raw repetitions retained in {outputPath}");
return checks.All(x=>x.passed)?0:1;

int Direct(int request)
{
    token.ThrowIfCancellationRequested();
    token.ThrowIfCancellationRequested();
    using var handler=new EchoHandler();
    token.ThrowIfCancellationRequested();
    var response=handler.HandleAsync(request,context,token).GetAwaiter().GetResult();
    if (!response.IsSuccess || response.Value!=request) throw new InvalidOperationException("Direct result changed.");
    return response.Value;
}
int Dispatch(int request)
{
    var response=dispatcher.DispatchAsync<int,int>("bench.echo",request,context,token).GetAwaiter().GetResult();
    if (!response.IsSuccess || response.Value!=request) throw new InvalidOperationException("Dispatch result changed.");
    return response.Value;
}
static Measurement Measure(int iterations,Func<int,int> action)
{
    long checksum=0;
    var before=GC.GetAllocatedBytesForCurrentThread();
    var started=Stopwatch.GetTimestamp();
    for (var i=0;i<iterations;i++) checksum+=action(i);
    var elapsed=Stopwatch.GetTimestamp()-started;
    var allocated=GC.GetAllocatedBytesForCurrentThread()-before;
    if(iterations==DispatchIterations && checksum!=(long)iterations*(iterations-1)/2) throw new InvalidOperationException("Dispatch/direct checksum changed.");
    return new(iterations,elapsed,allocated,checksum,elapsed*1_000_000_000d/Stopwatch.Frequency/iterations,(double)allocated/iterations);
}
static string Config(string root)=>JsonSerializer.Serialize(new {Cehpalon=new {SchemaVersion=1,Architecture="Modular",Topology="SingleProcess",Pattern="RequestReply",Modules=new Dictionary<string,object>{{root,new {Enabled=true}}}}});
static double Median(IEnumerable<double> values) { var a=values.Order().ToArray(); return a[a.Length/2]; }
sealed record Measurement(int Iterations,long ElapsedTicks,long AllocatedBytes,long Checksum,double NanosecondsPerOperation,double BytesPerOperation);
sealed class EchoHandler:IOperationHandler<int,int>,IDisposable
{
    public static long Created,Disposed;
    public EchoHandler()=>Created++;
    public ValueTask<OperationResult<int>> HandleAsync(int request,OperationContext context,CancellationToken token)=>ValueTask.FromResult(OperationResult<int>.Success(request));
    public void Dispose()=>Disposed++;
}
