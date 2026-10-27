using System.Runtime.InteropServices;
using System.Text.Json;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Composition;

var outputArgument=args.SingleOrDefault(a=>a.StartsWith("--output=",StringComparison.Ordinal)) ?? throw new ArgumentException("--output=<new-file.json> is required");
var outputPath=Path.GetFullPath(outputArgument[9..]);
if(File.Exists(outputPath)) throw new IOException("Preserve previous consumer results.");
var results=new List<object>(); var passed=0; var failed=0;
async Task Check(string name,Func<Task> test)
{
    try { await test(); results.Add(new {name,passed=true}); passed++; }
    catch(Exception error) { results.Add(new {name,passed=false,error=error.ToString()}); failed++; }
}
void Assert(bool value,string reason) { if(!value) throw new InvalidOperationException(reason); }
ModuleDescriptor[] Catalog()=>[new("core",ModuleRole.Support),new("api",ModuleRole.EntryPoint,["core"]),new("graphql",ModuleRole.EntryPoint,["core"]),new("worker",ModuleRole.EntryPoint,["core"])];
foreach(var (profile,entrypoints) in new[]{("api-only",new[]{"api"}),("api-graphql",new[]{"api","graphql"}),("worker-only",new[]{"worker"})})
{
    await Check(profile+": generated business operation reused and disabled work stays zero",async()=>
    {
        var compiled=CompositionCompiler.Compile(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory,"profiles",profile+".json")),Catalog());
        Assert(compiled.IsSuccess,"Profile must compile");
        var counters=Catalog().ToDictionary(d=>d.Id,_=>new ModuleCounters(),StringComparer.Ordinal);
        var factory=new BusinessFactory(); OperationDispatcher? dispatcher=null;
        var registrations=Catalog().Select(d=>new ModuleRegistration(d.Id,_=>
        {
            counters[d.Id].Factories++;
            if(d.Id=="core")
            {
                var builder=new OperationRegistryBuilder();
                Cehpalon.Engine.Generated.OperationRegistrations.RegisterAll(builder,factory);
                Assert(factory.Created==0,"Generated registration must be lazy");
                var registry=builder.Build();
                Assert(registry.OperationIds.SequenceEqual(new[]{"calculator.add"}),"Typed generated registry differs");
                dispatcher=new OperationDispatcher(registry);
            }
            return ValueTask.FromResult<IAsyncDisposable>(new RecorderModule(counters[d.Id]));
        })).ToArray();
        var lease=await PlanActivator.ActivateAsync(compiled.Plan!,registrations);
        var activeDispatcher=dispatcher ?? throw new InvalidOperationException("Core must activate before entrypoints");
        foreach(var entrypoint in entrypoints)
        {
            // These are in-process module callers, not HTTP/GraphQL/Worker adapters.
            var result=await activeDispatcher.DispatchAsync<AddNumbers,Sum>("calculator.add",new(20,22),new OperationContext(entrypoint));
            Assert(result.IsSuccess && result.Value.Value==42,"Shared handler result differs");
        }
        Assert(factory.Created==entrypoints.Length && factory.Disposed==factory.Created,"Every invocation must own/release a handler");
        var before=factory.Created;
        var unknown=await activeDispatcher.DispatchAsync<AddNumbers,Sum>("calculator.missing",new(1,2),new("unknown"));
        var mismatch=await activeDispatcher.DispatchAsync<string,Sum>("calculator.add","wrong contract",new("mismatch"));
        Assert(!unknown.IsSuccess && unknown.Error.Code=="operation.not_found" && !mismatch.IsSuccess && mismatch.Error.Code=="operation.contract_mismatch" && factory.Created==before,"Lookup/type guards must precede factory");
        using var cancelled=new CancellationTokenSource(); cancelled.Cancel();
        try { await activeDispatcher.DispatchAsync<AddNumbers,Sum>("calculator.add",new(1,2),new("cancelled"),cancelled.Token); throw new InvalidOperationException("Cancellation must propagate"); }
        catch(OperationCanceledException) { Assert(factory.Created==before,"Pre-cancel must not create handler"); }
        var businessError=await activeDispatcher.DispatchAsync<AddNumbers,Sum>("calculator.add",new(1001,0),new("business-error"));
        Assert(!businessError.IsSuccess && businessError.Error.Code=="input.out_of_range" && factory.Created==before+1 && factory.Disposed==factory.Created,"Business error and cleanup differ");
        await Task.WhenAll(lease.DisposeAsync().AsTask(),lease.DisposeAsync().AsTask());
        foreach(var (id,count) in counters)
        {
            var enabled=id=="core" || entrypoints.Contains(id,StringComparer.Ordinal);
            Assert(enabled ? count.Factories==1 && count.Constructors==1 && count.Connections==1 && count.Endpoints==1 && count.Background==1 && count.Disposed==1 : count.IsZero,"Owned recorder work differs: "+id);
        }
    });
}
await Check("explicit-false dependency rejects before activation",()=>
{
    const string json="""{"Cehpalon":{"SchemaVersion":1,"Architecture":"Modular","Topology":"SingleProcess","Pattern":"RequestReply","Modules":{"api":{"Enabled":true},"core":{"Enabled":false}}}}""";
    var compiled=CompositionCompiler.Compile(json,Catalog());
    Assert(!compiled.IsSuccess && compiled.Plan is null && compiled.Diagnostics.Any(d=>d.Code=="PLAN_FORBIDDEN"),"Explicitfalse must reject");
    return Task.CompletedTask;
});
await Check("unsupported topology fails closed",()=>
{
    const string json="""{"Cehpalon":{"SchemaVersion":1,"Architecture":"Modular","Topology":"Distributed","Pattern":"RequestReply","Modules":{}}}""";
    var compiled=CompositionCompiler.Compile(json,Catalog());
    Assert(!compiled.IsSuccess && compiled.Plan is null && compiled.Diagnostics.Any(d=>d.Code=="CFG_PROFILE"),"Unsupported profile must reject");
    return Task.CompletedTask;
});
var report=new {observedAtUtc=DateTimeOffset.UtcNow,framework=RuntimeInformation.FrameworkDescription,os=RuntimeInformation.OSDescription,scope="Experimental generated-registry/Core/Composition integration with in-process module recorders only; no real transport/provider/tenant/identity/E2E/HA/production qualification",passed,failed,results};
Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
await using(var stream=new FileStream(outputPath,FileMode.CreateNew,FileAccess.Write,FileShare.None)) await JsonSerializer.SerializeAsync(stream,report,new JsonSerializerOptions {WriteIndented=true});
Console.WriteLine($"Portable generated consumer: {passed}/{passed+failed}");
return failed==0?0:1;

public sealed record AddNumbers(int Left,int Right);
public sealed record Sum(int Value);
[Operation("calculator.add")]
public sealed class AddNumbersHandler(Action disposed):IOperationHandler<AddNumbers,Sum>,IDisposable
{
    public ValueTask<OperationResult<Sum>> HandleAsync(AddNumbers request,OperationContext context,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Math.Abs((long)request.Left)>1000 || Math.Abs((long)request.Right)>1000
            ? OperationResult<Sum>.Failure(new("input.out_of_range","Inputs must be between -1000 and 1000."))
            : OperationResult<Sum>.Success(new(request.Left+request.Right)));
    }
    public void Dispose()=>disposed();
}
sealed class BusinessFactory:IOperationHandlerFactory
{
    public int Created,Disposed;
    public THandler Create<THandler>() where THandler:class
    {
        if(typeof(THandler)!=typeof(AddNumbersHandler)) throw new InvalidOperationException("Unknown generated factory type");
        Created++; return (THandler)(object)new AddNumbersHandler(()=>Disposed++);
    }
}
sealed class ModuleCounters
{
    public int Factories,Constructors,Connections,Endpoints,Background,Disposed;
    public bool IsZero=>Factories==0 && Constructors==0 && Connections==0 && Endpoints==0 && Background==0 && Disposed==0;
}
sealed class RecorderModule:IAsyncDisposable
{
    private readonly ModuleCounters counters;
    public RecorderModule(ModuleCounters counters) { this.counters=counters; counters.Constructors++; counters.Connections++; counters.Endpoints++; counters.Background++; }
    public ValueTask DisposeAsync() { counters.Disposed++; return ValueTask.CompletedTask; }
}
