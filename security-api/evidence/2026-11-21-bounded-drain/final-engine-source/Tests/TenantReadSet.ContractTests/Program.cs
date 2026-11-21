using System.Text.Json;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;

var output=Path.GetFullPath(args.Single(a=>a.StartsWith("--output=",StringComparison.Ordinal))[9..]);
if(File.Exists(output))throw new IOException("Keep previous results; choose a fresh path.");
var checks=new List<object>();var passed=0;var failed=0;
void Assert(bool value){if(!value)throw new InvalidOperationException("Contract assertion failed.");}
async Task Check(string name,Func<Task> test)
{
    try{await test();passed++;checks.Add(new{name,passed=true});}
    catch(Exception error){failed++;checks.Add(new{name,passed=false,error=error.ToString()});}
}
async Task<T> Throws<T>(Func<Task> test) where T:Exception
{try{await test();}catch(T error){return error;}throw new InvalidOperationException("Expected "+typeof(T).Name);}

await Check("selection reuses identity and checks each destination; no global tenant state",async()=>
{
    var f=new Fixture();var dispatcher=f.Selection();
    var a=await dispatcher.DispatchAsync<TenantSelectionRequest,TenantSelectionResult>("tenant.select",new(new("A")),new("tab-a"));
    var b=await dispatcher.DispatchAsync<TenantSelectionRequest,TenantSelectionResult>("tenant.select",new(new("B")),new("tab-b"));
    Assert(a.Value.Tenant.Value=="A"&&b.Value.Tenant.Value=="B"&&f.IdentityCalls==2&&f.MemberCalls==2&&f.Queries==0);
    Assert(f.SelectionActions.All(x=>x=="select")&&f.SelectionKinds.All(x=>x=="tenant")&&f.SelectionResources.SequenceEqual(new[]{"A","B"}));
});
await Check("selection destination membership and policy denial leave other requests intact",async()=>
{
    var f=new Fixture{DeniedTenant="B"};var d=f.Selection();
    Assert(!(await d.DispatchAsync<TenantSelectionRequest,TenantSelectionResult>("tenant.select",new(new("B")),new("select"))).IsSuccess);
    Assert((await d.DispatchAsync<TenantSelectionRequest,TenantSelectionResult>("tenant.select",new(new("A")),new("select"))).IsSuccess);
    f.DeniedTenant=null;f.PolicyDenied=true;Assert(!(await d.DispatchAsync<TenantSelectionRequest,TenantSelectionResult>("tenant.select",new(new("B")),new("select"))).IsSuccess);
});
await Check("parallel selected tenant requests keep independent checked contexts",async()=>
{
    var f=new Fixture{ParallelBarrier=new()};var one=f.Single("A");var two=f.Single("B");
    var a=one.AsTask();var b=two.AsTask();await f.ParallelEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
    Assert(f.Contexts.Count==2&&f.Contexts[0].Tenant.Value!=f.Contexts[1].Tenant.Value);f.ParallelBarrier.SetResult();
    Assert((await a).Value=="A"&&(await b).Value=="B"&&f.Disposals==2);
    foreach(var c in f.Contexts)await Throws<TenantAccessDeniedException>(()=>Task.Run(()=>c.DemandAccess(c.Tenant,"document","shared","read")));
});
await Check("ordinary selection grants no multi-tenant permission",async()=>
{
    var f=new Fixture{MissingGrant=true};Assert((await f.Selection().DispatchAsync<TenantSelectionRequest,TenantSelectionResult>("tenant.select",new(new("A")),new("select"))).IsSuccess);
    Assert(!(await f.Batch()).IsSuccess&&f.Factories==0&&f.GrantCalls==1);
});
await Check("all means exact explicit grant tenants and each child resolves fresh authority",async()=>
{
    var f=new Fixture();var result=await f.Batch();Assert(result.IsSuccess);
    Assert(result.Value.Results.Select(x=>x.Tenant.Value).SequenceEqual(new[]{"A","B"}));
    Assert(result.Value.Results.Select(x=>x.Value).SequenceEqual(new[]{"A","B"})&&f.IdentityCalls==3&&f.MemberCalls==2&&f.ResourceCalls==2&&f.Factories==2&&f.Disposals==2);
});
await Check("caller subset is exact, contained and cannot add or alias tenants",async()=>
{
    var f=new Fixture();var result=await f.Batch([new("B")]);Assert(result.IsSuccess&&result.Value.Results.Count==1&&result.Value.Results[0].Tenant.Value=="B");
    var before=f.Factories;Assert(!(await f.Batch([new("A"),new("C")])).IsSuccess&&f.Factories==before);
    Assert(!(await f.Batch([new("a")])).IsSuccess&&f.Factories==before);
});
foreach(var invalid in new[]{"principal","operation","kind","resource","future","expired","missing"})
await Check("grant binding denies "+invalid+" before query factories",async()=>
{
    var f=new Fixture{GrantMutation=invalid};Assert(!(await f.Batch()).IsSuccess&&f.Factories==0);
});
await Check("empty, duplicate, null and over-limit subsets deny without grant lookup",async()=>
{
    var f=new Fixture();Assert(!(await f.Batch([])).IsSuccess);Assert(!(await f.Batch([new("A"),new("A")])).IsSuccess);
    Assert(!(await f.Batch([null!])).IsSuccess);Assert(!(await f.Batch(Enumerable.Range(0,65).Select(i=>new TenantId("T"+i)))).IsSuccess);
    Assert(f.GrantCalls==0&&f.Factories==0);
});
await Check("grant representation bounds reject empty/duplicates/over-limit and wildcard",async()=>
{
    var f=new Fixture();await Throws<ArgumentException>(()=>Task.Run(()=>f.Grant([])));
    await Throws<ArgumentException>(()=>Task.Run(()=>f.Grant([new("A"),new("A")])));
    await Throws<ArgumentException>(()=>Task.Run(()=>f.Grant(Enumerable.Range(0,65).Select(i=>new TenantId("T"+i)))));
    await Throws<ArgumentException>(()=>Task.Run(()=>new TenantId("*")));
});
await Check("query, subset and grant defensively freeze before authority awaits",async()=>
{
    var f=new Fixture();var query=new Query("shared");var subset=new List<TenantId>{new("A")};var granted=new List<TenantId>{new("A"),new("B")};
    var snapshot=f.Grant(granted);granted.Clear();f.GrantOverride=snapshot;
    f.GrantHook=()=>{query.Id="changed";subset.Clear();subset.Add(new("C"));};
    var result=await f.Batch(subset,query);Assert(result.IsSuccess&&result.Value.Results.Count==1&&result.Value.Results[0].Tenant.Value=="A"&&f.ResourceIds.Single()=="shared");
});
await Check("different child identity principal or scheme never combines user data",async()=>
{
    foreach(var mutation in new[]{"principal","issuer","scheme","anonymous"})
    {
        var f=new Fixture{ChangeIdentityAt=3,IdentityMutation=mutation};var result=await f.Batch();
        Assert(!result.IsSuccess&&result.Error.Code=="access.denied"&&f.Queries==1&&f.Disposals==1);
        await Throws<InvalidOperationException>(()=>Task.Run(()=>result.Value));
    }
});
await Check("late tenant revocation withholds partial response while preserving earlier reads",async()=>
{
    var f=new Fixture();f.AfterRead=tenant=>{if(tenant=="A")f.DeniedTenant="B";};
    var result=await f.Batch();Assert(!result.IsSuccess&&result.Error.Code=="access.denied"&&f.Queries==1&&f.Disposals==1);
});
await Check("late per-tenant business rejection is generic and has no partial value",async()=>
{
    var f=new Fixture{RejectedTenant="B"};var result=await f.Batch();Assert(!result.IsSuccess&&result.Error.Code=="tenant.read_set_failed"&&f.Disposals==2);
    Assert(!result.Error.Message.Contains("secret"));
});
await Check("late provider or handler fault preserves exception and joins cleanup",async()=>
{
    var cause=new IOException("private handler detail");var f=new Fixture{FailedTenant="B",HandlerFailure=cause};
    var result=await Throws<IOException>(async()=>await f.Batch());Assert(ReferenceEquals(result,cause)&&f.Disposals==2);
    f=new Fixture{ProviderFailure=cause};var e=await Throws<IOException>(async()=>await f.Batch());Assert(ReferenceEquals(e,cause)&&f.Factories==0);
});
await Check("cancellation after an earlier read returns no partial result and cleans ownership",async()=>
{
    using var cts=new CancellationTokenSource();var f=new Fixture();f.AfterRead=_=>cts.Cancel();
    await Throws<OperationCanceledException>(async()=>await f.Batch(token:cts.Token));Assert(f.Disposals==1);
});
await Check("grant expiry during child execution bounds checked contexts and withholds rows",async()=>
{
    var f=new Fixture();f.BeforeRead=_=>f.Clock.Advance(TimeSpan.FromMinutes(2));
    Assert(!(await f.Batch()).IsSuccess&&f.Queries==0&&f.Disposals==1);
});
await Check("grant expiry after child completion is checked before releasing results",async()=>
{
    var f=new Fixture();f.AfterRead=_=>f.Clock.Advance(TimeSpan.FromMinutes(2));
    Assert(!(await f.Batch()).IsSuccess&&f.Queries==1&&f.Disposals==1);
});
await Check("monotonic lifetime cap still denies after UTC moves back within validity",async()=>
{
    var f=new Fixture();f.AfterRead=_=>{f.Clock.Elapsed+=TimeSpan.FromMinutes(2);f.Clock.Now=f.Clock.Now.AddSeconds(1);};
    Assert(!(await f.Batch()).IsSuccess&&f.Disposals==1);
});
await Check("UTC rollback during grant resolution denies before query factories",async()=>
{
    var f=new Fixture();f.GrantHook=()=>f.Clock.Now=f.Clock.Now.AddSeconds(-1);
    Assert(!(await f.Batch()).IsSuccess&&f.Factories==0);
});
await Check("missing audit services perform no sink calls",async()=>
{
    var f=new Fixture();Assert((await f.Batch()).IsSuccess&&f.Audit.Count==0&&f.AuditCalls==0);
});
await Check("required root audit precedes children and every child links root id",async()=>
{
    var f=new Fixture{UseAudit=true};f.AuditHook=e=>{if(e.ResourceKind=="tenant-read-set"&&e.Stage==TenantAuditStage.Authorization)Assert(f.Factories==0);};
    Assert((await f.Batch()).IsSuccess&&f.Audit.Count==6);
    var roots=f.Audit.Where(e=>e.ResourceKind=="tenant-read-set").ToArray();Assert(roots.Length==2&&roots[0].InvocationId==roots[1].InvocationId&&roots.All(e=>e.AuthorizedTenant is null&&e.ParentInvocationId is null));
    Assert(f.Audit.Where(e=>e.ResourceKind=="document").All(e=>e.ParentInvocationId==roots[0].InvocationId&&e.AuthorizedTenant is not null));
    Assert(f.Audit[^1].Outcome==TenantAuditOutcome.Succeeded&&f.Disposals==2);
});
await Check("grant denial is a control-plane event excluded from tenant history",async()=>
{
    var f=new Fixture{UseAudit=true,MissingGrant=true};Assert(!(await f.Batch()).IsSuccess&&f.Audit.Count==1&&f.Audit[0].AuthorizedTenant is null&&f.Audit[0].Outcome==TenantAuditOutcome.Denied);
});
await Check("root authorization persistence failure prevents every business query",async()=>
{
    var f=new Fixture{UseAudit=true,FailAuditAt=1};var e=await Throws<TenantAuditWriteException>(async()=>await f.Batch());
    Assert(!e.OperationMayHaveExecuted&&f.Factories==0&&f.AuditCalls==1);
});
await Check("child audit failure cannot publish a partial result",async()=>
{
    var f=new Fixture{UseAudit=true,FailAuditAt=4};await Throws<TenantAuditWriteException>(async()=>await f.Batch());
    Assert(f.Queries==1&&f.Disposals==1&&f.Audit[^1].ResourceKind=="tenant-read-set"&&f.Audit[^1].Outcome==TenantAuditOutcome.Faulted);
});
await Check("root terminal audit failure after reads reports possible effects",async()=>
{
    var f=new Fixture{UseAudit=true,FailAuditAt=6};var e=await Throws<TenantAuditWriteException>(async()=>await f.Batch());Assert(e.OperationMayHaveExecuted&&f.Disposals==2);
});
await Check("simultaneous operation and terminal persistence faults preserve both causes",async()=>
{
    var cause=new IOException("private business detail");var f=new Fixture{UseAudit=true,FailedTenant="B",HandlerFailure=cause,FailAuditAt=6};
    var e=await Throws<AggregateException>(async()=>await f.Batch());Assert(e.InnerExceptions.Count==2&&ReferenceEquals(e.InnerExceptions[0],cause)&&e.InnerExceptions[1] is TenantAuditWriteException);
});
await Check("final root write cannot release rows after grant expiry",async()=>
{
    var f=new Fixture{UseAudit=true};f.AuditHook=e=>{if(e.ResourceKind=="tenant-read-set"&&e.Stage==TenantAuditStage.Terminal)f.Clock.Advance(TimeSpan.FromMinutes(2));};
    Assert(!(await f.Batch()).IsSuccess&&f.Disposals==2&&f.Audit[^1].Outcome==TenantAuditOutcome.Succeeded);
});
await Check("caller cancellation during final root write is rechecked before release",async()=>
{
    using var cts=new CancellationTokenSource();var f=new Fixture{UseAudit=true};f.AuditHook=e=>{if(e.ResourceKind=="tenant-read-set"&&e.Stage==TenantAuditStage.Terminal)cts.Cancel();};
    await Throws<OperationCanceledException>(async()=>await f.Batch(token:cts.Token));Assert(f.Disposals==2&&f.Audit[^1].Outcome==TenantAuditOutcome.Succeeded);
});
await Check("cleanup denial is infrastructure failure rather than ordinary policy denial",async()=>
{
    var f=new Fixture{CleanupDenial=true,UseAudit=true};var e=await Throws<InvalidOperationException>(async()=>await f.Batch());
    Assert(e.InnerException is TenantAccessDeniedException&&f.Disposals==1&&f.Audit[^1].Outcome==TenantAuditOutcome.Faulted);
});
await Check("shared tenant concurrency budget still governs children and cleanup",async()=>
{
    var f=new Fixture();var budget=new TenantOperationConcurrencyBudget(1,1);await budget.DrainAsync();
    var result=await f.Batch(budget:budget);Assert(!result.IsSuccess&&f.Factories==0&&budget.GetSnapshot().Total.IsAdmissionClosed);
});
await Check("audit parent identifiers reject empty and self references",async()=>
{
    var id=Guid.NewGuid();await Throws<ArgumentException>(()=>Task.Run(()=>new TenantAuditEvent(id,TenantAuditStage.Terminal,TenantAuditOutcome.Denied,DateTimeOffset.UtcNow,"document.read_all","read","tenant-read-set",parentInvocationId:Guid.Empty)));
    await Throws<ArgumentException>(()=>Task.Run(()=>new TenantAuditEvent(id,TenantAuditStage.Terminal,TenantAuditOutcome.Denied,DateTimeOffset.UtcNow,"document.read_all","read","tenant-read-set",parentInvocationId:id)));
});

Directory.CreateDirectory(Path.GetDirectoryName(output)!);
await using(var stream=new FileStream(output,FileMode.CreateNew))await JsonSerializer.SerializeAsync(stream,new{passed,failed,checks,scope="Bounded portable contracts; no real IdP/provider/atomic multi-tenant snapshot or benchmark qualification"});
Console.WriteLine(JsonSerializer.Serialize(new{passed,failed,output}));return failed==0?0:1;

sealed class Clock:TimeProvider
{
    public DateTimeOffset Now=new(2026,11,20,12,0,0,TimeSpan.Zero);public TimeSpan Elapsed;
    public override DateTimeOffset GetUtcNow()=>Now;public override long TimestampFrequency=>TimeSpan.TicksPerSecond;
    public override long GetTimestamp()=>Elapsed.Ticks;
    public void Advance(TimeSpan time){Now+=time;Elapsed+=time;}
}
sealed class Query(string id){public string Id=id;}
sealed class Fixture:IIdentitySource,ITenantMembershipSource,IResourceScopeSource,ITenantAccessPolicy,ITenantReadSetSource,ITenantAuditSink
{
    internal static readonly PrincipalId Principal=new("urn:fixture","alice");public readonly Clock Clock=new();
    public int IdentityCalls,MemberCalls,ResourceCalls,GrantCalls,Factories,Queries,Disposals,AuditCalls,FailAuditAt,ChangeIdentityAt;
    public string? DeniedTenant,RejectedTenant,FailedTenant;public string GrantMutation="",IdentityMutation="";
    public bool MissingGrant,PolicyDenied,UseAudit,CleanupDenial;public Exception? ProviderFailure,HandlerFailure;public TenantReadSetSnapshot? GrantOverride;
    public Action? GrantHook;public Action<string>? BeforeRead,AfterRead;public Action<TenantAuditEvent>? AuditHook;
    public List<string> ResourceIds=[],SelectionActions=[],SelectionKinds=[],SelectionResources=[];public readonly List<TenantOperationContext> Contexts=[];
    public List<TenantAuditEvent> Audit=[];public TaskCompletionSource? ParallelBarrier;public readonly TaskCompletionSource ParallelEntered=new(TaskCreationOptions.RunContinuationsAsynchronously);
    public TenantSecurityServices Services()=>new(this,new(["urn:fixture"],["fixture"]),this,this,TimeSpan.FromSeconds(30),this,Clock,UseAudit?new(this):null);
    public TenantOperationDispatcher Selection()=>new(new TenantOperationRegistryBuilder().RegisterTenantSelection().Build(),Services());
    public ValueTask<OperationResult<string>> Single(string tenant)
    {
        var registry=new TenantOperationRegistryBuilder().Register<Query,string>("document.read","read","document",q=>new(q.Id),_=>new(new(tenant),"shared"),()=>{Interlocked.Increment(ref Factories);return new Handler(this);}).Build();
        return new TenantOperationDispatcher(registry,Services()).DispatchAsync<Query,string>("document.read",new("shared"),new("parallel"));
    }
    public ValueTask<OperationResult<TenantReadSetResult<string>>> Batch(IEnumerable<TenantId>? tenants=null,Query? query=null,CancellationToken token=default,TenantOperationConcurrencyBudget? budget=null)
    {
        var op=new TenantReadSetOperation<Query,string>("document.read_all","document",q=>new(q.Id),q=>q.Id,()=>{Factories++;return new Handler(this);});
        return new TenantReadSetDispatcher(Services(),this,budget).DispatchAsync(op,query??new("shared"),new("batch"),tenants,token);
    }
    public TenantReadSetSnapshot Grant(IEnumerable<TenantId> tenants)=>new(Principal,"document.read_all","document","shared",tenants,Clock.Now.AddMinutes(-1),Clock.Now.AddMinutes(1),"g1");
    public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken token)
    {
        IdentityCalls++;token.ThrowIfCancellationRequested();var change=ChangeIdentityAt!=0&&IdentityCalls>=ChangeIdentityAt;
        if(change&&IdentityMutation=="anonymous")return ValueTask.FromResult<IdentitySnapshot?>(null);
        var p=change&&IdentityMutation=="principal"?new PrincipalId("urn:fixture","bob"):change&&IdentityMutation=="issuer"?new PrincipalId("urn:other","alice"):Principal;
        return ValueTask.FromResult<IdentitySnapshot?>(new(p,change&&IdentityMutation=="scheme"?"other":"fixture",Clock.Now.AddHours(-1),Clock.Now.AddHours(1)));
    }
    public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot identity,TenantId tenant,CancellationToken token)
    {MemberCalls++;token.ThrowIfCancellationRequested();return ValueTask.FromResult<TenantMembershipSnapshot?>(tenant.Value==DeniedTenant?null:new(identity.Principal,tenant,true,Clock.Now.AddMinutes(-1),Clock.Now.AddMinutes(5),"m1"));}
    public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId tenant,string kind,string id,CancellationToken token)
    {ResourceCalls++;ResourceIds.Add(id);token.ThrowIfCancellationRequested();return ValueTask.FromResult<ResourceScopeSnapshot?>(new(tenant,kind,id,"r1"));}
    public ValueTask<bool> IsAllowedAsync(TenantAccessRequest request,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();if(request.OperationId=="tenant.select"){SelectionActions.Add(request.Action);SelectionKinds.Add(request.Resource.Kind);SelectionResources.Add(request.Resource.ResourceId);}
        return ValueTask.FromResult(!PolicyDenied);
    }
    public async ValueTask<TenantReadSetSnapshot?> ResolveAsync(TenantReadSetRequest request,CancellationToken token)
    {
        GrantCalls++;await Task.Yield();token.ThrowIfCancellationRequested();GrantHook?.Invoke();if(ProviderFailure is not null)throw ProviderFailure;
        if(MissingGrant||GrantMutation=="missing")return null;if(GrantOverride is not null)return GrantOverride;
        return new(GrantMutation=="principal"?new("urn:fixture","bob"):Principal,GrantMutation=="operation"?"other.read":request.OperationId,
            GrantMutation=="kind"?"other":request.ResourceKind,GrantMutation=="resource"?"other":request.ResourceId,[new("A"),new("B")],
            Clock.Now.AddMinutes(GrantMutation=="future"?1:-1),Clock.Now.AddMinutes(GrantMutation=="expired"?-0.5:GrantMutation=="future"?2:1),"g1");
    }
    public ValueTask AppendAsync(TenantAuditEvent entry,CancellationToken token)
    {AuditCalls++;token.ThrowIfCancellationRequested();AuditHook?.Invoke(entry);if(AuditCalls==FailAuditAt)throw new IOException("private audit failure");Audit.Add(entry);return ValueTask.CompletedTask;}
    private sealed class Handler(Fixture f):ITenantOperationHandler<Query,string>,IAsyncDisposable
    {
        public async ValueTask<OperationResult<string>> HandleAsync(Query query,TenantOperationContext context,CancellationToken token)
        {
            lock(f.Contexts){f.Contexts.Add(context);if(f.Contexts.Count==2)f.ParallelEntered.TrySetResult();}
            if(f.ParallelBarrier is not null)await f.ParallelBarrier.Task.WaitAsync(token);
            f.BeforeRead?.Invoke(context.Tenant.Value);token.ThrowIfCancellationRequested();context.DemandAccess(context.Tenant,"document",query.Id,"read");
            if(f.FailedTenant==context.Tenant.Value)throw f.HandlerFailure??new IOException("private handler detail");
            Interlocked.Increment(ref f.Queries);f.AfterRead?.Invoke(context.Tenant.Value);
            return f.RejectedTenant==context.Tenant.Value?OperationResult<string>.Failure(new("business.private","secret")):OperationResult<string>.Success(context.Tenant.Value);
        }
        public ValueTask DisposeAsync(){Interlocked.Increment(ref f.Disposals);if(f.CleanupDenial)throw new TenantAccessDeniedException();return ValueTask.CompletedTask;}
    }
}
