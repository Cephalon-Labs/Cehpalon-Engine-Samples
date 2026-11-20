using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;

var checks=new List<object>(); var failed=0;
void Assert(bool condition,string message="Assertion failed") { if(!condition) throw new InvalidOperationException(message); }
async Task Check(string name,Func<Task> body) { try { await body(); checks.Add(new{name,passed=true}); } catch(Exception error) { failed++; checks.Add(new{name,passed=false,error=error.ToString()}); } }
Task Sync(Action body) { body(); return Task.CompletedTask; }
async Task Throws<T>(Func<Task> body) where T:Exception { try { await body(); } catch(T) { return; } throw new Exception("Expected "+typeof(T).Name); }
await Check("tenant-ids-ordinal-and-canonical-bounds",()=>Sync(()=>
{
    Assert(new TenantId("A").Equals(new TenantId("A"))); Assert(!new TenantId("A").Equals(new TenantId("a"))); Assert(new TenantId("0-a_b.c").Value=="0-a_b.c");
    foreach(var invalid in new[]{""," A","a ","a/b","a:b","a\n","é","_a",new string('a',129)})
    { try { _=new TenantId(invalid); throw new Exception("Accepted invalidID"); } catch(ArgumentException) { } }
    _=new TenantId(new string('a',128));
}));
await Check("resource-values-reject-controls-and-malformed-unicode",()=>Sync(()=>
{
    foreach(var invalid in new[]{""," ","id\n","\uD800","\uDC00",new string('x',513)})
    { try { _=new TenantTarget(Fixture.A,invalid); throw new Exception("Accepted invalidvalue"); } catch(ArgumentException) { } }
    _=new TenantTarget(Fixture.A,"document.😀");
}));
await Check("snapshot-constructors-and-validity-bounds",()=>Sync(()=>
{
    try { _=new TenantMembershipSnapshot(Fixture.Principal,Fixture.A,true,Fixture.Now,Fixture.Now,"v1"); throw new Exception("emptytime"); } catch(ArgumentException) { }
    try { _=new ResourceScopeSnapshot(Fixture.A,"UPPER","doc","v1"); throw new Exception("badkind"); } catch(ArgumentException) { }
    try { _=new ResourceScopeSnapshot(Fixture.A,"document","doc","\uD800"); throw new Exception("badversion"); } catch(ArgumentException) { }
    var member=new TenantMembershipSnapshot(Fixture.Principal,Fixture.A,true,Fixture.Now.ToOffset(TimeSpan.FromHours(7)),Fixture.Now.AddHours(1).ToOffset(TimeSpan.FromHours(7)),"v"); Assert(member.NotBeforeUtc.Offset==TimeSpan.Zero && member.ExpiresAtUtc.Offset==TimeSpan.Zero);
}));
await Check("registry-and-services-preflight-no-callbacks",async()=>
{
    var f=new Fixture(); var calls=0;
    var builder=new TenantOperationRegistryBuilder().Register<Request,int>("document.read","document.read","document",x=>{calls++;return x.Copy();},x=>new(new(x.Tenant),x.Id),()=>new Handler(f));
    var registry=builder.Build(); Assert(calls==0 && f.Created==0); builder.Register<Request,int>("document.other","document.read","document",x=>x.Copy(),x=>new(new(x.Tenant),x.Id),()=>new Handler(f)); Assert(registry.OperationIds.SequenceEqual(new[]{"document.read"}));
    await Throws<ArgumentException>(()=>Sync(()=>builder.Register<Request,int>("document.read","document.read","document",x=>x.Copy(),x=>new(new(x.Tenant),x.Id),()=>new Handler(f))));
    await Throws<ArgumentOutOfRangeException>(()=>Sync(()=>_=new TenantSecurityServices(f,f.Trust,f,f,TimeSpan.Zero,f,f.Clock)));
});
await Check("normal-same-tenant-allows-and-cleans-up",async()=>
{ var f=new Fixture();var result=await f.Call();Assert(result.IsSuccess && result.Value==10 && f.Created==1 && f.Reads==1 && f.Disposed==1 && f.IdentityCalls==1 && f.MembershipCalls==1 && f.ResourceCalls==1 && f.PolicyCalls==1); });
foreach(var tenant in new[]{"A","B"})
    await Check("same-resource-id-in-distinct-authorized-tenant-"+tenant,async()=>
    {var f=new Fixture{MemberB=true};var r=await f.Call(new(tenant,"shared"));Assert(r.IsSuccess && r.Value==(tenant=="A"?10:20) && f.LastLookupTenant==tenant);});
foreach(var metadata in new[]{new Dictionary<string,string>{{"tenant","B"}},new Dictionary<string,string>{{"role","admin"},{"action","*"},{"principal","root"}},new Dictionary<string,string>{{"authorization","minted"},{"tenant_scope","B"}}})
    await Check("caller-metadata-does-not-grant-membership-"+metadata.Keys.First(),async()=>
    {var f=new Fixture();var r=await f.Call(new("B","shared"),new("spoof",metadata));Assert(!r.IsSuccess && r.Error.Code=="access.denied" && f.Created==0 && f.ResourceCalls==0);});
await Check("same-subject-different-issuer-does-not-bind-membership",async()=>
{var f=new Fixture{MembershipOverride=new(new("urn:other","alice"),Fixture.A,true,Fixture.Now.AddMinutes(-1),Fixture.Now.AddHours(1),"m")};AssertDenied(await f.Call(),f);});
await Check("same-issuer-different-subject-does-not-bind-membership",async()=>
{var f=new Fixture{MembershipOverride=new(new(Fixture.Issuer,"bob"),Fixture.A,true,Fixture.Now.AddMinutes(-1),Fixture.Now.AddHours(1),"m")};AssertDenied(await f.Call(),f);});
await Check("cross-tenant-membership-snapshot-rejected",async()=>
{var f=new Fixture{MembershipOverride=new(Fixture.Principal,Fixture.B,true,Fixture.Now.AddMinutes(-1),Fixture.Now.AddHours(1),"m")};AssertDenied(await f.Call(),f);});
await Check("cross-tenant-resource-snapshot-rejected",async()=>
{var f=new Fixture{ResourceOverride=new(Fixture.B,"document","shared","r")};AssertDenied(await f.Call(),f);});
await Check("mismatched-resource-id-rejected",async()=>
{var f=new Fixture{ResourceOverride=new(Fixture.A,"document","other","r")};AssertDenied(await f.Call(),f);});
await Check("mismatched-resource-kind-rejected",async()=>
{var f=new Fixture{ResourceOverride=new(Fixture.A,"cache","shared","r")};AssertDenied(await f.Call(),f);});
foreach(var mode in new[]{"anonymous","unknown-issuer","wrong-scheme","expired-identity","future-identity","inactive-membership","expired-membership","future-membership","missing-member","missing-resource","policy-denial","default-policy"})
    await Check("deny-before-business-"+mode,async()=>
    {
        var f=new Fixture();
        switch(mode)
        {
            case "anonymous":f.Anonymous=true;break;
            case "unknown-issuer":f.IdentityOverride=new(new("urn:unknown","alice"),"fixture",Fixture.Now.AddMinutes(-1),Fixture.Now.AddHours(1));break;
            case "wrong-scheme":f.IdentityOverride=new(Fixture.Principal,"other",Fixture.Now.AddMinutes(-1),Fixture.Now.AddHours(1));break;
            case "expired-identity":f.IdentityOverride=new(Fixture.Principal,"fixture",Fixture.Now.AddHours(-1),Fixture.Now);break;
            case "future-identity":f.IdentityOverride=new(Fixture.Principal,"fixture",Fixture.Now.AddTicks(1),Fixture.Now.AddHours(1));break;
            case "inactive-membership":f.Active=false;break;
            case "expired-membership":f.MemberExpires=Fixture.Now;break;
            case "future-membership":f.MemberStarts=Fixture.Now.AddTicks(1);break;
            case "missing-member":f.MissingMember=true;break;
            case "missing-resource":f.MissingResource=true;break;
            case "policy-denial":f.Allow=false;break;
            case "default-policy":f.DefaultPolicy=true;break;
        }
        AssertDenied(await f.Call(),f);
    });
await Check("denial-errors-do-not-reveal-resource-existence",async()=>
{var a=new Fixture{MissingResource=true};var b=new Fixture{ResourceOverride=new(Fixture.B,"document","shared","r")};var x=await a.Call();var y=await b.Call();Assert(x.Error.Code==y.Error.Code && x.Error.Message==y.Error.Message && x.Error.Message=="Access denied.");});
await Check("membership-revoked-next-call-refreshes-authorities",async()=>
{var f=new Fixture();var dispatcher=f.Build();Assert((await dispatcher.DispatchAsync<Request,int>("document.read",new("A","shared"),new("first"))).IsSuccess);f.Active=false;AssertDenied(await dispatcher.DispatchAsync<Request,int>("document.read",new("A","shared"),new("second")),f,1,1);Assert(f.IdentityCalls==2 && f.MembershipCalls==2 && f.Reads==1);});
await Check("identity-removed-next-call-refreshes-authorities",async()=>
{var f=new Fixture();var dispatcher=f.Build();Assert((await dispatcher.DispatchAsync<Request,int>("document.read",new("A","shared"),new("first"))).IsSuccess);f.Anonymous=true;AssertDenied(await dispatcher.DispatchAsync<Request,int>("document.read",new("A","shared"),new("second")),f,1,1);Assert(f.IdentityCalls==2 && f.MembershipCalls==1);});
foreach(var at in new[]{"identity","membership","resource","policy","factory","handler"})
    await Check("cancellation-at-"+at,async()=>
    {
        using var source=new CancellationTokenSource();var f=new Fixture();f.Hooks[at]=()=>source.Cancel();
        await Throws<OperationCanceledException>(async()=>{await f.Call(token:source.Token);});
        Assert(f.Reads==0 && f.Disposed==f.Created);if(at is not ("factory" or "handler"))Assert(f.Created==0);
    });
await Check("pre-cancelled-call-performs-zero-authority-and-business-work",async()=>
{var f=new Fixture();using var source=new CancellationTokenSource();source.Cancel();await Throws<OperationCanceledException>(async()=>{await f.Call(token:source.Token);});Assert(f.IdentityCalls==0 && f.Created==0);});
foreach(var at in new[]{"identity","membership","resource","policy"})
    await Check("unexpected-source-fault-at-"+at,async()=>
    {var f=new Fixture();f.Hooks[at]=()=>throw new IOException("fixture failure");await Throws<IOException>(async()=>{await f.Call();});Assert(f.Created==0 && f.Reads==0);});
foreach(var at in new[]{"membership","resource","policy","factory"})
    await Check("expiry-during-"+at+"-denies-before-business",async()=>
    {var f=new Fixture();f.Hooks[at]=()=>f.Clock.Advance(TimeSpan.FromHours(2));AssertDenied(await f.Call(),f,at=="factory"?1:0);Assert(f.Reads==0 && f.Disposed==f.Created);});
await Check("lease-expiry-mid-handler-fails-demand-and-cleans-up",async()=>
{var f=new Fixture();f.Hooks["handler"]=()=>f.Clock.Advance(TimeSpan.FromSeconds(31));AssertDenied(await f.Call(),f,1);Assert(f.Disposed==1 && f.Reads==0);});
await Check("clock-rollback-mid-handler-fails-lease-demand",async()=>
{var f=new Fixture();f.Hooks["handler"]=()=>f.Clock.Advance(TimeSpan.FromMinutes(-2));AssertDenied(await f.Call(),f,1);Assert(f.Disposed==1);});
await Check("monotonic-cap-rejects-small-utc-rollback-extension",async()=>
{var f=new Fixture();f.Hooks["handler"]=()=>{f.Clock.Advance(TimeSpan.FromSeconds(1));f.Clock.AdvanceElapsed(TimeSpan.FromSeconds(31));};AssertDenied(await f.Call(),f,1);Assert(f.Disposed==1);});
await Check("observed-utc-expiry-permanently-revokes-lease",async()=>
{var f=new Fixture();f.Hooks["handler"]=()=>{f.Clock.Advance(TimeSpan.FromSeconds(31));try{f.Captured!.DemandAccess(Fixture.A,"document","shared","document.read");throw new Exception("Expectedexpiry");}catch(TenantAccessDeniedException){}f.Clock.Advance(TimeSpan.FromSeconds(-30));};AssertDenied(await f.Call(),f,1);});
await Check("negative-monotonic-elapsed-is-invalid",async()=>
{var f=new Fixture();f.Hooks["handler"]=()=>f.Clock.AdvanceElapsed(TimeSpan.FromTicks(-1));AssertDenied(await f.Call(),f,1);});
await Check("observed-monotonic-expiry-does-not-resurrect",async()=>
{var f=new Fixture();f.Hooks["handler"]=()=>{f.Clock.AdvanceElapsed(TimeSpan.FromSeconds(31));try{f.Captured!.DemandAccess(Fixture.A,"document","shared","document.read");throw new Exception("Expectedexpiry");}catch(TenantAccessDeniedException){}f.Clock.AdvanceElapsed(TimeSpan.FromSeconds(-30));};AssertDenied(await f.Call(),f,1);});
await Check("expiry-after-resource-does-not-call-policy",async()=>
{var f=new Fixture();f.Hooks["resource"]=()=>f.Clock.Advance(TimeSpan.FromHours(2));AssertDenied(await f.Call(),f);Assert(f.PolicyCalls==0);});
await Check("captured-context-rejected-after-success",async()=>
{var f=new Fixture();Assert((await f.Call()).IsSuccess);await Throws<TenantAccessDeniedException>(()=>Sync(()=>f.Captured!.DemandAccess(Fixture.A,"document","shared","document.read")));});
await Check("captured-context-rejected-after-failure",async()=>
{var f=new Fixture{HandlerFailure=true};await Throws<IOException>(async()=>{await f.Call();});await Throws<TenantAccessDeniedException>(()=>Sync(()=>f.Captured!.DemandAccess(Fixture.A,"document","shared","document.read")));Assert(f.Disposed==1);});
foreach(var mismatch in new[]{"tenant","kind","resource","action"})
    await Check("checked-scope-rejects-confused-deputy-"+mismatch,async()=>
    {var f=new Fixture();f.ScopeMismatch=mismatch;AssertDenied(await f.Call(),f,1);Assert(f.Reads==0 && f.Disposed==1);});
await Check("retained-context-cannot-be-replayed-during-new-invocation",async()=>
{
    var f=new Fixture();Assert((await f.Call()).IsSuccess);var old=f.Captured!;
    f.Hooks["handler"]=()=>{try{old.DemandAccess(Fixture.A,"document","shared","document.read");throw new Exception("Replayed");}catch(TenantAccessDeniedException){}};
    Assert((await f.Call()).IsSuccess && !ReferenceEquals(old,f.Captured));
});
await Check("mutable-request-is-deep-frozen-before-await",async()=>
{
    var f=new Fixture{MemberB=true};var request=new Request("A","shared");
    f.Hooks["identity"]=()=>{request.Tenant="B";request.Id="different";request.Nested[0]="B";};
    var result=await f.Call(request);Assert(result.IsSuccess && result.Value==10 && f.LastHandledTenant=="A" && f.LastHandledNested=="A");
});
await Check("parallel-tenant-invocations-have-independent-contexts",async()=>
{
    var f=new Fixture{MemberB=true};var dispatcher=f.Build();
    var results=await Task.WhenAll(Enumerable.Range(0,40).Select(async i=>await dispatcher.DispatchAsync<Request,int>("document.read",new(i%2==0?"A":"B","shared"),new("parallel"))));
    Assert(results.Where((_,i)=>i%2==0).All(x=>x.IsSuccess&&x.Value==10)&&results.Where((_,i)=>i%2!=0).All(x=>x.IsSuccess&&x.Value==20)&&f.Created==40&&f.Disposed==40);
});
await Check("shared-budget-keeps-unauthorized-denial-and-skips-authorized-factory-at-capacity", async () =>
{
    var budget = new OperationConcurrencyBudget(1);
    var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var holder = new OperationDispatcher(new OperationRegistryBuilder()
        .Register<int, int>("capacity.hold", () => new HoldingOperation(gate.Task)).Build());
    var pending = budget.DispatchAsync<int, int>(holder, "capacity.hold", 1, new("held")).AsTask();
    try
    {
        var f = new Fixture();
        var protectedDispatcher = f.Build(budget);
        AssertDenied(await protectedDispatcher.DispatchAsync<Request, int>("document.read", new("B", "shared"), new("blocked")), f);
        var result = await protectedDispatcher.DispatchAsync<Request, int>("document.read", new("A", "shared"), new("full"));
        Assert(result.Error.Code == OperationConcurrencyBudget.CapacityExceededCode);
        Assert(f.Created == 0 && f.IdentityCalls == 2 && f.MembershipCalls == 2 && f.PolicyCalls == 1);
        gate.SetResult();
        Assert((await pending).IsSuccess);
        Assert((await protectedDispatcher.DispatchAsync<Request, int>("document.read", new("A", "shared"), new("available"))).Value == 10);
        Assert(f.Created == 1 && f.Disposed == 1 && f.IdentityCalls == 3 && f.MembershipCalls == 3 && f.PolicyCalls == 2);
    }
    finally { gate.TrySetResult(); }
});
await Check("budget-does-not-queue-and-keeps-permits-during-cleanup", BudgetChecks.ConcurrentCleanup);
await Check("budget-releases-permits-after-factory-fault-and-cancellation", BudgetChecks.FailureRecovery);
await Check("tenant-budget-is-shared-while-tenant-cleanup-retains-capacity", BudgetChecks.TenantLimits);
await Check("tenant-budget-recovers-from-factory-cancellation-and-cleanup-fault", BudgetChecks.TenantFailureRecovery);
await Check("core-budget-drain-closes-spare-capacity-and-waits-through-cleanup", BudgetChecks.DrainCore);
await Check("tenant-budget-drain-preserves-fresh-authorization-and-independent-waits", BudgetChecks.DrainTenants);
await Check("budget-snapshot-stays-bounded-during-concurrent-admission-and-drain", BudgetChecks.SnapshotRace);
await Check("opt-in-budget-metrics-observe-owned-lifecycle-and-dispose-cleanly", BudgetChecks.MetricsLifecycle);
await Check("business-failure-result-is-preserved-and-owned-handler-disposed",async()=>
{var f=new Fixture{BusinessFailure=true};var result=await f.Call();Assert(!result.IsSuccess&&result.Error.Code=="business.invalid"&&f.Disposed==1);});
await Check("unexpected-handler-and-cleanup-faults-both-preserved",async()=>
{
    var f=new Fixture{HandlerFailure=true,CleanupFailure=true};
    try{await f.Call();throw new Exception("Expectedaggregate");}catch(AggregateException error){Assert(error.InnerExceptions.Count==2 && error.InnerExceptions[0] is IOException && error.InnerExceptions[1] is InvalidDataException);}
});
await Check("denied-scope-plus-cleanup-fault-is-not-silently-converted",async()=>
{var f=new Fixture{ScopeMismatch="tenant",CleanupFailure=true};try{await f.Call();throw new Exception("Expectedaggregate");}catch(AggregateException error){Assert(error.InnerExceptions[0] is TenantAccessDeniedException && error.InnerExceptions[1] is InvalidDataException);}});
await Check("cleanup-only-denial-is-an-unexpected-cleanup-fault",async()=>
{var f=new Fixture{CleanupDenial=true};try{await f.Call();throw new Exception("Expectedcleanupfault");}catch(InvalidOperationException error){Assert(error.InnerException is TenantAccessDeniedException&&f.Reads==1&&f.Disposed==1);}});
await Check("null-handler-factory-fails-without-business-work",async()=>
{var f=new Fixture{NullHandler=true};await Throws<InvalidOperationException>(async()=>{await f.Call();});Assert(f.Reads==0&&f.Disposed==0);});
await Check("unknown-operation-and-contract-mismatch-do-not-query-authority",async()=>
{var f=new Fixture();var d=f.Build();Assert(!(await d.DispatchAsync<Request,int>("missing.op",new("A","shared"),new("missing"))).IsSuccess);Assert(!(await d.DispatchAsync<string,int>("document.read","wrong",new("wrong"))).IsSuccess);Assert(f.IdentityCalls==0&&f.Created==0);});
await Check("checked-context-has-no-public-mint-or-core-registry-surface",()=>Sync(()=>
{Assert(typeof(TenantOperationContext).GetConstructors().Length==0&&typeof(TenantAccessRequest).GetConstructors().Length==0);Assert(!typeof(TenantOperationDispatcher).GetMembers(BindingFlags.Public|BindingFlags.Instance).Any(m=>m is PropertyInfo p&&(p.PropertyType==typeof(OperationRegistry)||p.PropertyType==typeof(OperationDispatcher))));}));
await Check("tenancy-assembly-dependencies-are-core-identity-and-bcl-only",()=>Sync(()=>
{var names=typeof(TenantOperationDispatcher).Assembly.GetReferencedAssemblies().Select(x=>x.Name!).ToArray();Assert(names.All(x=>x.StartsWith("System.",StringComparison.Ordinal)||x is "Cehpalon.Engine.Core" or "Cehpalon.Engine.Identity.Contracts"));}));

var report=new{observedAtUtc=DateTimeOffset.UtcNow,framework=RuntimeInformation.FrameworkDescription,os=RuntimeInformation.OSDescription,scope="Portable in-process tenant/identity policy and Core bridge component contracts. No real JWT/OIDC, provider/store RLS, network transports, jobs/cache/retrieval, distributed revocation, supported-Windows/hostedCI/benchmark/production qualification.",passed=checks.Count-failed,failed,checks};
var json=JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true});
var output=args.SingleOrDefault(x=>x.StartsWith("--output=",StringComparison.Ordinal));if(output is not null){var path=Path.GetFullPath(output[9..]);Directory.CreateDirectory(Path.GetDirectoryName(path)!);await File.WriteAllTextAsync(path,json+"\n");}
Console.WriteLine(json);return failed==0?0:1;

void AssertDenied(OperationResult<int> result,Fixture fixture,int created=0,int reads=0)=>Assert(!result.IsSuccess&&result.Error.Code=="access.denied"&&result.Error.Message=="Access denied."&&fixture.Created==created&&fixture.Reads==reads);
sealed class Request(string tenant,string id)
{
    public string Tenant=tenant,Id=id; public string[] Nested=[tenant];
    public Request Copy()=>new(Tenant,Id){Nested=(string[])Nested.Clone()};
}
sealed class Clock:TimeProvider
{
    private long ticks=Fixture.Now.UtcTicks;
    private long elapsed;
    public override DateTimeOffset GetUtcNow()=>new(Interlocked.Read(ref ticks),TimeSpan.Zero);
    public override long GetTimestamp()=>Interlocked.Read(ref elapsed);
    public override long TimestampFrequency=>TimeSpan.TicksPerSecond;
    public void Advance(TimeSpan amount)=>Interlocked.Add(ref ticks,amount.Ticks);
    public void AdvanceElapsed(TimeSpan amount)=>Interlocked.Add(ref elapsed,amount.Ticks);
}
sealed class Fixture:IIdentitySource,ITenantMembershipSource,IResourceScopeSource,ITenantAccessPolicy
{
    public const string Issuer="urn:fixture"; public static readonly PrincipalId Principal=new(Issuer,"alice");
    public static readonly TenantId A=new("A"),B=new("B");public static readonly DateTimeOffset Now=new(2026,10,27,0,0,0,TimeSpan.Zero);
    public readonly Clock Clock=new(); public readonly IdentityTrustPolicy Trust=new([Issuer],["fixture"]);
    public int Created,Disposed,Reads,IdentityCalls,MembershipCalls,ResourceCalls,PolicyCalls;
    public bool Anonymous,MemberB,MissingMember,MissingResource,DefaultPolicy,HandlerFailure,CleanupFailure,CleanupDenial,BusinessFailure,NullHandler;
    public bool Active=true,Allow=true;public DateTimeOffset MemberStarts=Now.AddMinutes(-1),MemberExpires=Now.AddHours(1);
    public IdentitySnapshot? IdentityOverride; public TenantMembershipSnapshot? MembershipOverride;public ResourceScopeSnapshot? ResourceOverride;
    public string? ScopeMismatch,LastLookupTenant,LastHandledTenant,LastHandledNested;public TenantOperationContext? Captured;
    public readonly Dictionary<string,Action> Hooks=new(StringComparer.Ordinal);
    public void Hook(string at) { if(Hooks.TryGetValue(at,out var action)) action(); }
    public TaskCompletionSource? CleanupEntered, CleanupRelease;
    public TenantOperationDispatcher Build(OperationConcurrencyBudget? budget = null, TenantOperationConcurrencyBudget? tenantBudget = null)
    {
        var registry = new TenantOperationRegistryBuilder().Register<Request,int>("document.read","document.read","document",x=>x.Copy(),x=>new(new(x.Tenant),x.Id),()=>
        {Interlocked.Increment(ref Created);Hook("factory");return NullHandler?null!:new Handler(this);}).Build();
        var security = new TenantSecurityServices(this,Trust,this,this,TimeSpan.FromSeconds(30),DefaultPolicy?null:this,Clock);
        if (tenantBudget is not null)
            return TenantOperationDispatcher.WithTenantConcurrencyBudget(registry, security, tenantBudget);
        return budget is null ? new(registry, security) : new(registry, security, budget);
    }
    public ValueTask<OperationResult<int>> Call(Request? request=null,OperationContext? context=null,CancellationToken token=default)=>Build().DispatchAsync<Request,int>("document.read",request??new("A","shared"),context??new("fixture"),token);
    public async ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken token)
    {Interlocked.Increment(ref IdentityCalls);Hook("identity");await Task.Yield();return Anonymous?null:IdentityOverride??new(Principal,"fixture",Now.AddMinutes(-1),Now.AddHours(1));}
    public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot identity,TenantId tenant,CancellationToken token)
    {Interlocked.Increment(ref MembershipCalls);Hook("membership");return ValueTask.FromResult(MissingMember||tenant.Equals(B)&&!MemberB?null:MembershipOverride??new(Principal,tenant,Active,MemberStarts,MemberExpires,"m1"));}
    public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId tenant,string kind,string id,CancellationToken token)
    {Interlocked.Increment(ref ResourceCalls);LastLookupTenant=tenant.Value;Hook("resource");return ValueTask.FromResult(MissingResource?null:ResourceOverride??new(tenant,kind,id,"r1"));}
    public ValueTask<bool> IsAllowedAsync(TenantAccessRequest request,CancellationToken token)
    {Interlocked.Increment(ref PolicyCalls);Hook("policy");return ValueTask.FromResult(Allow&&request.Action=="document.read");}
}
sealed class Handler(Fixture fixture):ITenantOperationHandler<Request,int>,IAsyncDisposable,IDisposable
{
    public ValueTask<OperationResult<int>> HandleAsync(Request request,TenantOperationContext context,CancellationToken token)
    {
        fixture.Captured=context;fixture.Hook("handler");token.ThrowIfCancellationRequested();
        context.DemandAccess(fixture.ScopeMismatch=="tenant"?Fixture.B:context.Tenant,fixture.ScopeMismatch=="kind"?"cache":"document",fixture.ScopeMismatch=="resource"?"other":request.Id,fixture.ScopeMismatch=="action"?"document.write":"document.read");
        if(fixture.HandlerFailure)throw new IOException("handler failed");
        fixture.LastHandledTenant=request.Tenant;fixture.LastHandledNested=request.Nested[0];Interlocked.Increment(ref fixture.Reads);
        return ValueTask.FromResult(fixture.BusinessFailure?OperationResult<int>.Failure(new("business.invalid","Business rejected.")):OperationResult<int>.Success(context.Tenant.Equals(Fixture.A)?10:20));
    }
    public async ValueTask DisposeAsync()
    {
        fixture.CleanupEntered?.TrySetResult();
        if (fixture.CleanupRelease is not null) await fixture.CleanupRelease.Task;
        Interlocked.Increment(ref fixture.Disposed);
        if (fixture.CleanupDenial) throw new TenantAccessDeniedException();
        if (fixture.CleanupFailure) throw new InvalidDataException("cleanup failed");
    }
    public void Dispose()=>throw new Exception("Async disposal must be preferred");
}
