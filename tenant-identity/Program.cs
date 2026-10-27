using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text.Json;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;

var output=Path.GetFullPath(args.Single(a=>a.StartsWith("--output=",StringComparison.Ordinal))[9..]);
if(File.Exists(output)) throw new IOException("Use a new output file.");
var checks=new List<object>();var passed=0;var failed=0;
void Assert(bool ok,string reason) {if(!ok) throw new InvalidOperationException(reason);}
async Task Check(string name,Func<Task> action)
{
    try {await action();checks.Add(new {name,passed=true});passed++;}
    catch(Exception error) {checks.Add(new {name,passed=false,error=error.ToString()});failed++;}
}
OperationContext Correlation(bool spoof=false)=>new("fixture-call",spoof?new Dictionary<string,string>{{"tenant","tenant-b"},{"role","admin"},{"permission","*"},{"issuer","urn:attacker"},{"subject","bob"}}:null);
void Denied(OperationResult<DocumentView> result)=>Assert(!result.IsSuccess && result.Error.Code=="access.denied" && result.Error.Message=="Access denied.","Denial leaked or changed");

await Check("same resource ID belongs independently to A and B",async()=>
{
    var store=new FixtureStore();var alice=new Edge(store,"alice");var bob=new Edge(store,"bob");
    var a=await alice.Call(new("tenant-a","shared"),Correlation());var b=await bob.Call(new("tenant-b","shared"),Correlation());
    Assert(a.IsSuccess && a.Value.Text=="A fixture content" && b.IsSuccess && b.Value.Text=="B fixture content","Tenant-scoped keys aliased");
    Assert(store.Factories==2 && store.Reads==2 && store.Disposals==2,"Owned business lifecycle differs");
});
await Check("both cross-tenant directions deny before business factory/read",async()=>
{
    var store=new FixtureStore();var alice=new Edge(store,"alice");var bob=new Edge(store,"bob");
    Denied(await alice.Call(new("tenant-b","shared"),Correlation()));Denied(await bob.Call(new("tenant-a","shared"),Correlation()));
    Assert(store.Factories==0 && store.Constructors==0 && store.Reads==0 && store.Writes==0,"Unauthorized business work");
    Assert(alice.Gateways.Created==1 && bob.Gateways.Created==1,"Generated stateless entry gateway not exercised");
});
await Check("metadata admin/tenant/identity strings grant no authority",async()=>
{
    var store=new FixtureStore();var alice=new Edge(store,"alice");
    Denied(await alice.Call(new("tenant-b","shared"),Correlation(true)));
    var allowed=await alice.Call(new("tenant-a","shared"),Correlation(true));
    Assert(allowed.IsSuccess && allowed.Value.Tenant=="tenant-a" && store.Factories==1 && store.Reads==1,"Metadata changed scope");
});
await Check("misbound authoritative resource owner is rejected",async()=>
{
    var store=new FixtureStore {WrongOwner=true};var alice=new Edge(store,"alice");Denied(await alice.Call(new("tenant-a","shared"),Correlation()));
    Assert(store.Factories==0 && store.Reads==0,"Wrong owner reached handler");
});
await Check("missing policy denies even with valid identity and membership",async()=>
{
    var store=new FixtureStore();var alice=new Edge(store,"alice",usePolicy:false);Denied(await alice.Call(new("tenant-a","shared"),Correlation()));
    Assert(store.Factories==0 && store.Reads==0,"Missing policy permitted work");
});
await Check("membership revocation is resolved on the next call",async()=>
{
    var store=new FixtureStore();var alice=new Edge(store,"alice");Assert((await alice.Call(new("tenant-a","shared"),Correlation())).IsSuccess,"Initial allow failed");
    alice.Authority.Revoked=true;Denied(await alice.Call(new("tenant-a","shared"),Correlation()));
    Assert(alice.Authority.IdentityCalls==2 && alice.Authority.MembershipCalls==2 && store.Factories==1 && store.Reads==1,"Stale grant reused");
});
await Check("anonymous identity cannot be replaced by metadata",async()=>
{
    var store=new FixtureStore();var alice=new Edge(store,"alice");alice.Authority.Anonymous=true;Denied(await alice.Call(new("tenant-a","shared"),Correlation(true)));
    Assert(alice.Authority.MembershipCalls==0 && store.Factories==0 && store.Reads==0,"Anonymous spoof granted scope");
});
await Check("retained checked context is inactive after operation cleanup",async()=>
{
    var store=new FixtureStore();var alice=new Edge(store,"alice");Assert((await alice.Call(new("tenant-a","shared"),Correlation())).IsSuccess,"Allow failed");
    var captured=store.Seen.Single();
    try {captured.DemandAccess(new("tenant-a"),"document","shared","documents.read");throw new InvalidOperationException("Scope replay accepted");}
    catch(TenantAccessDeniedException) { }
    Assert(store.Disposals==1,"Handler not cleaned up");
});
await Check("parallel A/B operations share business logic without ambient tenant",async()=>
{
    var store=new FixtureStore();var alice=new Edge(store,"alice");var bob=new Edge(store,"bob");
    var operations=Enumerable.Range(0,20).Select(i=>Task.Run(async()=>
    {
        var tenant=i%2==0?"tenant-a":"tenant-b";var edge=i%2==0?alice:bob;
        var result=await edge.Call(new(tenant,"shared"),Correlation());
        Assert(result.IsSuccess && result.Value.Tenant==tenant,"Parallel scope crossed");
    }));
    await Task.WhenAll(operations);Assert(store.Factories==20 && store.Reads==20 && store.Disposals==20 && store.Seen.Distinct().Count()==20,"Scope or handler reused");
});
await Check("deep snapshot survives caller mutation during authority await",async()=>
{
    var store=new FixtureStore();var alice=new Edge(store,"alice");alice.Authority.Block=true;
    var mutable=new ReadDocument("tenant-a","shared");var pending=alice.Call(mutable,Correlation());await alice.Authority.Entered.Task;
    mutable.Tenant="tenant-b";mutable.DocumentId="changed";alice.Authority.Release.TrySetResult();
    var result=await pending;Assert(result.IsSuccess && result.Value.Tenant=="tenant-a" && result.Value.Id=="shared" && store.Reads==1,"Mutable input retargeted checked scope");
});
var report=new {observedAtUtc=DateTimeOffset.UtcNow,framework=RuntimeInformation.FrameworkDescription,os=RuntimeInformation.OSDescription,scope="In-process generated Core gateway, fixture identity/membership/resource policy and tenant-aware data port only; not actual authn/IdP/provider/job/cache/retrieval/transport proof",passed,failed,checks};
Directory.CreateDirectory(Path.GetDirectoryName(output)!);
await using(var stream=new FileStream(output,FileMode.CreateNew,FileAccess.Write,FileShare.None)) await JsonSerializer.SerializeAsync(stream,report,new JsonSerializerOptions {WriteIndented=true});
Console.WriteLine($"Tenant identity consumer: {passed}/{passed+failed}");return failed==0?0:1;

public sealed class ReadDocument(string tenant,string documentId) {public string Tenant {get;set;}=tenant;public string DocumentId {get;set;}=documentId;}
public sealed record DocumentView(string Tenant,string Id,string Text);
[Operation("documents.read")]
public sealed class ReadGateway(TenantOperationDispatcher dispatcher,GatewayCounters counters):IOperationHandler<ReadDocument,DocumentView>,IDisposable
{
    public ValueTask<OperationResult<DocumentView>> HandleAsync(ReadDocument request,OperationContext context,CancellationToken ct)=>dispatcher.DispatchAsync<ReadDocument,DocumentView>("documents.read",request,context,ct);
    public void Dispose()=>Interlocked.Increment(ref counters.Disposed);
}
public sealed class GatewayCounters {public int Created,Disposed;}
sealed class GatewayFactory(TenantOperationDispatcher dispatcher,GatewayCounters counters):IOperationHandlerFactory
{
    public THandler Create<THandler>() where THandler:class {if(typeof(THandler)!=typeof(ReadGateway)) throw new InvalidOperationException();Interlocked.Increment(ref counters.Created);return (THandler)(object)new ReadGateway(dispatcher,counters);}
}
sealed class Edge
{
    private readonly OperationDispatcher core;
    internal readonly FixtureAuthority Authority;
    internal readonly GatewayCounters Gateways=new();
    internal Edge(FixtureStore store,string subject,bool usePolicy=true)
    {
        Authority=new(subject);
        var registry=new TenantOperationRegistryBuilder().Register<ReadDocument,DocumentView>("documents.read","documents.read","document",r=>new(r.Tenant,r.DocumentId),r=>new(new TenantId(r.Tenant),r.DocumentId),()=>{Interlocked.Increment(ref store.Factories);return new DocumentReader(store);}).Build();
        var dispatcher=new TenantOperationDispatcher(registry,new TenantSecurityServices(Authority,new IdentityTrustPolicy([FixtureAuthority.Issuer],["fixture"]),Authority,store,TimeSpan.FromSeconds(30),usePolicy?new ExactPolicy():null,new FixedClock()));
        var builder=new OperationRegistryBuilder();Cehpalon.Engine.Generated.OperationRegistrations.RegisterAll(builder,new GatewayFactory(dispatcher,Gateways));core=new(builder.Build());
    }
    internal ValueTask<OperationResult<DocumentView>> Call(ReadDocument request,OperationContext context)=>core.DispatchAsync<ReadDocument,DocumentView>("documents.read",request,context);
}
sealed class ExactPolicy:ITenantAccessPolicy
{
    public ValueTask<bool> IsAllowedAsync(TenantAccessRequest request,CancellationToken ct) {ct.ThrowIfCancellationRequested();return ValueTask.FromResult(request.OperationId=="documents.read" && request.Action=="documents.read");}
}
sealed class FixedClock:TimeProvider {public override DateTimeOffset GetUtcNow()=>FixtureAuthority.Now;}
sealed class FixtureAuthority(string subject):IIdentitySource,ITenantMembershipSource
{
    internal const string Issuer="urn:cehpalon:identity-fixture";
    internal static readonly DateTimeOffset Now=new(2026,10,27,0,0,0,TimeSpan.Zero);
    internal bool Revoked,Anonymous,Block;
    internal int IdentityCalls,MembershipCalls;
    internal readonly TaskCompletionSource Entered=new(TaskCreationOptions.RunContinuationsAsynchronously),Release=new(TaskCreationOptions.RunContinuationsAsynchronously);
    public async ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();Interlocked.Increment(ref IdentityCalls);if(Block) {Entered.TrySetResult();await Release.Task.WaitAsync(ct);}
        return Anonymous?null:new(new(Issuer,subject),"fixture",Now.AddMinutes(-1),Now.AddHours(1));
    }
    public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot identity,TenantId tenant,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();Interlocked.Increment(ref MembershipCalls);
        var member=identity.Principal.Issuer==Issuer && ((subject=="alice" && tenant.Value=="tenant-a") || (subject=="bob" && tenant.Value=="tenant-b"));
        return ValueTask.FromResult<TenantMembershipSnapshot?>(member?new(identity.Principal,tenant,!Revoked,Now.AddMinutes(-1),Now.AddHours(1),"membership-v1"):null);
    }
}
sealed class FixtureStore:IResourceScopeSource
{
    internal int Factories,Constructors,Reads,Disposals;
    internal int Writes=0;
    internal bool WrongOwner;
    internal readonly ConcurrentBag<TenantOperationContext> Seen=new();
    private readonly IReadOnlyDictionary<(string Tenant,string Id),string> documents=new Dictionary<(string,string),string>{{("tenant-a","shared"),"A fixture content"},{("tenant-b","shared"),"B fixture content"}};
    public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId tenant,string kind,string id,CancellationToken ct)
    {ct.ThrowIfCancellationRequested();return ValueTask.FromResult<ResourceScopeSnapshot?>(kind=="document" && documents.ContainsKey((tenant.Value,id))?new(WrongOwner?new TenantId("tenant-b"):tenant,kind,id,"document-v1"):null);}
    internal DocumentView Read(ReadDocument request,TenantOperationContext context)
    {
        context.DemandAccess(new(request.Tenant),"document",request.DocumentId,"documents.read");
        if(context.Resource.Version!="document-v1") throw new TenantAccessDeniedException();
        Interlocked.Increment(ref Reads);Seen.Add(context);return new(context.Tenant.Value,context.Resource.ResourceId,documents[(context.Tenant.Value,context.Resource.ResourceId)]);
    }
}
sealed class DocumentReader:ITenantOperationHandler<ReadDocument,DocumentView>,IDisposable
{
    private readonly FixtureStore store;
    internal DocumentReader(FixtureStore store) {this.store=store;Interlocked.Increment(ref store.Constructors);}
    public ValueTask<OperationResult<DocumentView>> HandleAsync(ReadDocument request,TenantOperationContext context,CancellationToken ct) {ct.ThrowIfCancellationRequested();return ValueTask.FromResult(OperationResult<DocumentView>.Success(store.Read(request,context)));}
    public void Dispose()=>Interlocked.Increment(ref store.Disposals);
}
