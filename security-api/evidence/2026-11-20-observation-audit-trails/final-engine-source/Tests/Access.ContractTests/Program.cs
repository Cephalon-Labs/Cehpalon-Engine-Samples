using System.Security.Claims;
using System.Text.Json;
using Cehpalon.Engine.Authorization;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Identity.AspNetCore;
using Cehpalon.Engine.Tenancy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

var output=Path.GetFullPath(args.Single(a=>a.StartsWith("--output=",StringComparison.Ordinal))[9..]);
if(File.Exists(output)) throw new IOException("Retain previous output.");
var checks=new List<object>(); var passed=0; var failed=0;
void Require(bool value) { if(!value) throw new InvalidOperationException("Contract assertion failed."); }
async Task Check(string name,Func<Task> test)
{
    try { await test(); passed++; checks.Add(new{name,passed=true}); }
    catch(Exception error) { failed++; checks.Add(new{name,passed=false,error=error.ToString()}); }
}
async Task<T> Throws<T>(Func<Task> action) where T:Exception
{
    try { await action(); } catch(T error) { return error; }
    throw new InvalidOperationException("Expected "+typeof(T).Name);
}
AccessRule Rbac()=>new("doc.read","read","document",["reader"]);
AccessRule Abac()=>new("doc.read","read","document",allAttributes:[
    AttributePredicate.Match(AttributeScope.Subject,"department",AttributeScope.Resource,"department"),
    AttributePredicate.EqualTo(AttributeScope.Environment,"network","private")]);

await Check("RBAC accepts any exact role and resolves fresh on each invocation",async()=>
{
    var f=new Fixture(Rbac()); Require((await f.Call()).IsSuccess); f.Roles=["other"];
    Require(!(await f.Call()).IsSuccess && f.Created==1 && f.FactsCalls==2);
});
await Check("ABAC matches subject/resource and trusted environment",async()=>
{
    var f=new Fixture(Abac()); Require((await f.Call()).IsSuccess);
    f.Department="sales"; Require(!(await f.Call()).IsSuccess && f.Created==1);
});
await Check("combined RBAC AND ABAC never grants from one side alone",async()=>
{
    var f=new Fixture(new("doc.read","read","document",["reader"],
        [AttributePredicate.EqualTo(AttributeScope.Subject,"department","finance")]));
    Require((await f.Call()).IsSuccess); f.Roles=[]; Require(!(await f.Call()).IsSuccess);
    f.Roles=["reader"]; f.Department="wrong"; Require(!(await f.Call()).IsSuccess && f.Created==1);
});
foreach(var mutation in new[]{"principal","tenant","membership-version","kind","id","resource-version","expired","future","missing","role-case","attribute-case","missing-attribute"})
await Check("bound facts reject "+mutation+" before handler",async()=>
{
    var f=new Fixture(mutation is "attribute-case" or "missing-attribute"?Abac():Rbac()){Mutation=mutation};
    var result=await f.Call(); Require(!result.IsSuccess && result.Error.Code=="access.denied" && f.Created==0);
});
await Check("membership and resource owner mismatches prevent even facts lookup",async()=>
{
    var f=new Fixture(Rbac()){WrongMember=true}; Require(!(await f.Call()).IsSuccess && f.FactsCalls==0);
    f.WrongMember=false; f.WrongResource=true; Require(!(await f.Call()).IsSuccess && f.FactsCalls==0 && f.Created==0);
});
await Check("unregistered policy rule denies without facts lookup",async()=>
{
    var f=new Fixture(new("other.read","read","document",["reader"]));
    Require(!(await f.Call()).IsSuccess && f.FactsCalls==0 && f.Created==0);
});
await Check("rules and attributes snapshot mutable configuration",async()=>
{
    var roles=new List<string>{"reader"}; var predicates=new List<AttributePredicate>{AttributePredicate.EqualTo(AttributeScope.Subject,"department","finance")};
    var rule=new AccessRule("doc.read","read","document",roles,predicates); roles.Clear(); predicates.Clear();
    var f=new Fixture(rule){Roles=[]}; Require(!(await f.Call()).IsSuccess);
    var input=new Dictionary<string,string>{{"department","finance"}}; var attrs=new AccessAttributes(input); input["department"]="sales";
    Require(attrs.Values["department"]=="finance");
});
await Check("invalid unconstrained/oversized/duplicate configuration rejects",async()=>
{
    await Throws<ArgumentException>(()=>Task.Run(()=>new AccessRule("doc.read","read","document")));
    await Throws<ArgumentException>(()=>Task.Run(()=>new AccessAttributes(Enumerable.Repeat(new KeyValuePair<string,string>("x","y"),65))));
    await Throws<ArgumentException>(()=>Task.Run(()=>new AccessAttributes([new("x","bad\nline")])));
    await Throws<ArgumentException>(()=>Task.Run(()=>new AccessAttributes([new("x","\ud800")])));
    await Throws<ArgumentException>(()=>Task.Run(()=>new AccessRule("doc.read","read","document",["reader","reader"])));
});
await Check("facts provider cancellation and faults do not grant or create handler",async()=>
{
    var f=new Fixture(Rbac()){FactsFailure=new IOException("private-provider-detail")};
    await Throws<IOException>(async()=>await f.Call()); Require(f.Created==0);
    f.FactsFailure=null; using var cts=new CancellationTokenSource(); f.FactsHook=()=>cts.Cancel();
    await Throws<OperationCanceledException>(async()=>await f.Call(cts.Token)); Require(f.Created==0);
});
await Check("facts expiry during required audit prevents business creation",async()=>
{
    var f=new Fixture(Rbac()){Audit=true}; f.WriteHook=e=>{if(e.Stage==TenantAuditStage.Authorization)f.Clock.Now=f.Clock.Now.AddMinutes(2);};
    Require(!(await f.Call()).IsSuccess && f.Created==0 && f.Entries.Count==2 && f.Entries[1].Outcome==TenantAuditOutcome.Denied);
});
await Check("facts expiry bounds checked handler lease",async()=>
{
    var f=new Fixture(Rbac()); f.HandlerHook=()=>f.Clock.Now=f.Clock.Now.AddMinutes(2);
    Require(!(await f.Call()).IsSuccess && f.Created==1 && f.Disposed==1);
});
await Check("clock rollback during required audit cannot revive policy authority",async()=>
{
    var f=new Fixture(Rbac()){Audit=true};f.WriteHook=e=>{if(e.Stage==TenantAuditStage.Authorization)f.Clock.Now=f.Clock.Now.AddSeconds(-1);};
    Require(!(await f.Call()).IsSuccess&&f.Created==0&&f.Entries[^1].Outcome==TenantAuditOutcome.Denied);
});
await Check("audit is absent by default and makes zero sink calls",async()=>
{
    var f=new Fixture(Rbac()); Require((await f.Call()).IsSuccess && f.Entries.Count==0 && f.WriteCalls==0);
});
await Check("required authorization record precedes business and terminal follows cleanup",async()=>
{
    var f=new Fixture(Rbac()){Audit=true};
    f.WriteHook=e=>Require(e.Stage==TenantAuditStage.Authorization?f.Created==0:f.Disposed==1);
    Require((await f.Call()).IsSuccess && f.Entries.Count==2);
    Require(f.Entries[0].Outcome==TenantAuditOutcome.Authorized && f.Entries[1].Outcome==TenantAuditOutcome.Succeeded);
    Require(f.Entries[0].InvocationId==f.Entries[1].InvocationId && f.Entries.All(e=>e.AuthorizedTenant!.Value=="A"));
});
await Check("anonymous and policy denials never stamp authorized tenant history",async()=>
{
    var f=new Fixture(Rbac()){Audit=true,Anonymous=true}; Require(!(await f.Call()).IsSuccess);
    f.Anonymous=false;f.Roles=[];Require(!(await f.Call()).IsSuccess);
    Require(f.Created==0 && f.Entries.Count==2 && f.Entries.All(e=>e.Outcome==TenantAuditOutcome.Denied && e.AuthorizedTenant is null && e.Principal is null));
});
await Check("pre-execution sink failure prevents work and is not semantic denial",async()=>
{
    var f=new Fixture(Rbac()){Audit=true,FailWrite=1};
    var e=await Throws<TenantAuditWriteException>(async()=>await f.Call());
    Require(!e.OperationMayHaveExecuted && f.Created==0 && f.WriteCalls==1);
});
await Check("terminal sink failure reports possible effects after cleanup",async()=>
{
    var f=new Fixture(Rbac()){Audit=true,FailWrite=2};
    var e=await Throws<TenantAuditWriteException>(async()=>await f.Call());
    Require(e.OperationMayHaveExecuted && f.Created==1 && f.Disposed==1);
});
await Check("business rejection and semantic handler denial get terminal outcomes",async()=>
{
    var f=new Fixture(Rbac()){Audit=true,BusinessRejected=true};Require(!(await f.Call()).IsSuccess);
    Require(f.Entries[^1].Outcome==TenantAuditOutcome.Rejected);
    f.BusinessRejected=false;f.HandlerFailure=new TenantAccessDeniedException();Require(!(await f.Call()).IsSuccess);
    Require(f.Entries[^1].Outcome==TenantAuditOutcome.Denied && f.Disposed==2);
});
await Check("operation and audit failure preserve both causes",async()=>
{
    var cause=new IOException("private handler detail");var f=new Fixture(Rbac()){Audit=true,HandlerFailure=cause,FailWrite=2};
    var e=await Throws<AggregateException>(async()=>await f.Call());
    Require(e.InnerExceptions.Count==2 && ReferenceEquals(e.InnerExceptions[0],cause) && e.InnerExceptions[1] is TenantAuditWriteException && f.Disposed==1);
});
await Check("handler cancellation records terminal with independent write token",async()=>
{
    using var cts=new CancellationTokenSource();var f=new Fixture(Rbac()){Audit=true};f.HandlerHook=()=>cts.Cancel();
    await Throws<OperationCanceledException>(async()=>await f.Call(cts.Token));
    Require(f.Entries[^1].Outcome==TenantAuditOutcome.Cancelled && f.Disposed==1 && !f.WriteTokensCancelled);
});
await Check("audit sink timeout is awaited and fails before work",async()=>
{
    var f=new Fixture(Rbac()){Audit=true,StallSink=true};
    var e=await Throws<TenantAuditWriteException>(async()=>await f.Call());
    Require(e.InnerException is OperationCanceledException && f.Created==0 && f.SinkExited);
});
await Check("history requires checked scope and tenant-filtered bounded page",async()=>
{
    var f=new Fixture(new("doc.read","read","audit-history",["reader"])){Kind="audit-history",ResourceId="tenant",UseHistory=true};
    f.HistoryEntries=[new(Guid.NewGuid(),TenantAuditStage.Terminal,TenantAuditOutcome.Succeeded,f.Clock.Now,"doc.read","read","document",Fixture.Principal,new("A"),"shared")];
    Require((await f.Call()).Value==1 && f.HistoryTenant=="A");
    f.HistoryEntries=[new(Guid.NewGuid(),TenantAuditStage.Terminal,TenantAuditOutcome.Succeeded,f.Clock.Now,"doc.read","read","document",Fixture.Principal,new("B"),"shared")];
    await Throws<InvalidOperationException>(async()=>await f.Call());
});
await Check("history rejects unverified records and expired lease after await",async()=>
{
    var f=new Fixture(new("doc.read","read","audit-history",["reader"])){Kind="audit-history",ResourceId="tenant",UseHistory=true};
    f.HistoryEntries=[new(Guid.NewGuid(),TenantAuditStage.Terminal,TenantAuditOutcome.Denied,f.Clock.Now,"doc.read","read","document")];
    await Throws<InvalidOperationException>(async()=>await f.Call());
    f.HistoryEntries=[];f.HistoryHook=()=>f.Clock.Now=f.Clock.Now.AddMinutes(2);Require(!(await f.Call()).IsSuccess);
});
await Check("history rejects ordinary scope without calling provider",async()=>
{
    var f=new Fixture(Rbac()){UseHistory=true}; Require(!(await f.Call()).IsSuccess && f.HistoryCalls==0);
});
await Check("audit serialization excludes payloads, raw claims and exception messages",async()=>
{
    var f=new Fixture(Rbac()){Audit=true,HandlerFailure=new IOException("SECRET_EXCEPTION_PAYLOAD")};
    await Throws<IOException>(async()=>await f.Call()); var text=JsonSerializer.Serialize(f.Entries);
    Require(!text.Contains("SECRET_EXCEPTION_PAYLOAD") && !text.Contains("Bearer") && !text.Contains("department"));
});
await Check("cleanup infrastructure denial remains a fault in terminal audit",async()=>
{
    var f=new Fixture(Rbac()){Audit=true,CleanupFailure=true};
    var e=await Throws<InvalidOperationException>(async()=>await f.Call());
    Require(e.InnerException is TenantAccessDeniedException&&f.Entries[^1].Outcome==TenantAuditOutcome.Faulted&&f.Disposed==1);
});
await Check("history oversized page and revoked retained context reject",async()=>
{
    var f=new Fixture(new("doc.read","read","audit-history",["reader"])){Kind="audit-history",ResourceId="tenant",UseHistory=true,HistoryLimit=1};
    var e=new TenantAuditEvent(Guid.NewGuid(),TenantAuditStage.Terminal,TenantAuditOutcome.Succeeded,f.Clock.Now,"doc.read","read","document",Fixture.Principal,new("A"),"shared");
    f.HistoryEntries=[e,e];await Throws<InvalidOperationException>(async()=>await f.Call());
    f.HistoryEntries=[];Require((await f.Call()).IsSuccess);
    var before=f.HistoryCalls;await Throws<TenantAccessDeniedException>(async()=>await new TenantAuditHistoryReader(f).ReadAsync(f.Captured!));Require(f.HistoryCalls==before);
});

await Check("ASP.NET source calls exact configured scheme and accepts one valid ticket",async()=>
{
    var auth=new TicketService();var context=new DefaultHttpContext();
    using var provider=new ServiceCollection().AddSingleton<IAuthenticationService>(auth).BuildServiceProvider();context.RequestServices=provider;
    var adapter=new AspNetCoreJwtIdentitySource(new HttpContextAccessor{HttpContext=context},"fixture",new Clock());
    var snapshot=await adapter.ResolveAsync(default);Require(snapshot is not null && snapshot.Principal.Equals(Fixture.Principal) && auth.Scheme=="fixture");
});
foreach(var mutation in new[]{"anonymous","failure","wrong-scheme","flag-only","multi-identity","duplicate-sub","duplicate-issuer","missing-nbf","expired","future","bad-date","huge-date","bad-sub","too-many-claims"})
await Check("ASP.NET authentication mapping rejects "+mutation,async()=>
{
    var auth=new TicketService{Mutation=mutation};var context=new DefaultHttpContext();
    context.User=new(new ClaimsIdentity([new("sub","spoofed")],"untrusted-flag"));
    using var provider=new ServiceCollection().AddSingleton<IAuthenticationService>(auth).BuildServiceProvider();context.RequestServices=provider;
    var adapter=new AspNetCoreJwtIdentitySource(new HttpContextAccessor{HttpContext=context},"fixture",new Clock());
    Require(await adapter.ResolveAsync(default) is null && auth.Scheme=="fixture");
});
await Check("ASP.NET absent request and cancellation never authenticate",async()=>
{
    var adapter=new AspNetCoreJwtIdentitySource(new HttpContextAccessor(),"fixture");Require(await adapter.ResolveAsync(default) is null);
    using var cts=new CancellationTokenSource();cts.Cancel();await Throws<OperationCanceledException>(async()=>await adapter.ResolveAsync(cts.Token));
});
await Check("ASP.NET infrastructure failure and post-auth caller cancellation preserve semantics",async()=>
{
    var auth=new TicketService{Failure=new IOException("private authentication detail")};var context=new DefaultHttpContext();
    using var provider=new ServiceCollection().AddSingleton<IAuthenticationService>(auth).BuildServiceProvider();context.RequestServices=provider;
    var adapter=new AspNetCoreJwtIdentitySource(new HttpContextAccessor{HttpContext=context},"fixture",new Clock());
    await Throws<IOException>(async()=>await adapter.ResolveAsync(default));auth.Failure=null;
    using var cts=new CancellationTokenSource();auth.Hook=()=>cts.Cancel();await Throws<OperationCanceledException>(async()=>await adapter.ResolveAsync(cts.Token));
    auth.Hook=null;context.RequestAborted=cts.Token;await Throws<OperationCanceledException>(async()=>await adapter.ResolveAsync(default));
});
Directory.CreateDirectory(Path.GetDirectoryName(output)!);
await using(var stream=new FileStream(output,FileMode.CreateNew))await JsonSerializer.SerializeAsync(stream,new{passed,failed,checks});
Console.WriteLine(JsonSerializer.Serialize(new{passed,failed,output}));return failed==0?0:1;

sealed class Clock:TimeProvider
{
    public DateTimeOffset Now=new(2026,11,20,12,0,0,TimeSpan.Zero);
    public override DateTimeOffset GetUtcNow()=>Now;
}
sealed record Request(string Tenant,string Id);
sealed class Fixture(AccessRule rule):IIdentitySource,ITenantMembershipSource,IResourceScopeSource,IAuthorizationFactsSource,ITenantAuditSink,ITenantAuditHistorySource
{
    public static readonly PrincipalId Principal=new("urn:fixture","alice");
    public readonly Clock Clock=new(); public string[] Roles=["reader"];
    public string Department="finance",Mutation="",Kind="document",ResourceId="shared";
    public bool Audit,Anonymous,WrongMember,WrongResource,BusinessRejected,StallSink,SinkExited,UseHistory,WriteTokensCancelled,CleanupFailure;
    public int HistoryLimit=50;public TenantOperationContext? Captured;
    public int Created,Disposed,FactsCalls,WriteCalls,FailWrite,HistoryCalls; public string? HistoryTenant;
    public Exception? FactsFailure,HandlerFailure;public Action? FactsHook,HandlerHook,HistoryHook;
    public Action<TenantAuditEvent>? WriteHook;
    public List<TenantAuditEvent> Entries=[];public TenantAuditEvent[] HistoryEntries=[];
    public ValueTask<OperationResult<int>> Call(CancellationToken token=default)
    {
        var registry=new TenantOperationRegistryBuilder().Register<Request,int>("doc.read","read",Kind,r=>r with{},r=>new(new(r.Tenant),r.Id),()=>{Created++;return new Handler(this);}).Build();
        var policy=new RoleAttributeAccessPolicy([rule],this,Clock);
        var services=new TenantSecurityServices(this,new(["urn:fixture"],["fixture"]),this,this,TimeSpan.FromMinutes(5),policy,Clock,Audit?new(this,StallSink?TimeSpan.FromMilliseconds(20):null):null);
        return new TenantOperationDispatcher(registry,services).DispatchAsync<Request,int>("doc.read",new("A",ResourceId),new("test"),token);
    }
    public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken token)=>ValueTask.FromResult<IdentitySnapshot?>(Anonymous?null:new(Principal,"fixture",Clock.Now.AddHours(-1),Clock.Now.AddHours(1)));
    public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot identity,TenantId tenant,CancellationToken token)
        =>ValueTask.FromResult<TenantMembershipSnapshot?>(new(WrongMember?new("urn:fixture","other"):Principal,tenant,true,Clock.Now.AddHours(-1),Clock.Now.AddHours(1),"m1"));
    public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId tenant,string kind,string id,CancellationToken token)
        =>ValueTask.FromResult<ResourceScopeSnapshot?>(new(WrongResource?new("B"):tenant,kind,id,"r1"));
    public ValueTask<AuthorizationFacts?> ResolveAsync(TenantAccessRequest request,CancellationToken token)
    {
        FactsCalls++;FactsHook?.Invoke();if(FactsFailure is not null)throw FactsFailure;
        if(Mutation=="missing")return ValueTask.FromResult<AuthorizationFacts?>(null);
        var facts=new AuthorizationFacts(Mutation=="principal"?new("urn:fixture","other"):Principal,new(Mutation=="tenant"?"B":"A"),
            Mutation=="membership-version"?"m2":"m1",Mutation=="kind"?"other":Kind,Mutation=="id"?"other":ResourceId,Mutation=="resource-version"?"r2":"r1",
            Clock.Now.AddMinutes(Mutation=="future"?1:-1),Clock.Now.AddMinutes(Mutation=="expired"?-0.5:Mutation=="future"?2:1),Mutation=="role-case"?["Reader"]:Roles,
            new([new("department",Mutation=="attribute-case"?"Finance":Department)]),new([new("department","finance")]),
            new(Mutation=="missing-attribute"?[]:[new("network","private")]));return ValueTask.FromResult<AuthorizationFacts?>(facts);
    }
    public async ValueTask AppendAsync(TenantAuditEvent entry,CancellationToken token)
    {
        WriteCalls++;WriteTokensCancelled|=token.IsCancellationRequested;WriteHook?.Invoke(entry);
        if(StallSink){try{await Task.Delay(Timeout.InfiniteTimeSpan,token);}finally{SinkExited=true;}}
        if(WriteCalls==FailWrite)throw new IOException("private sink details");Entries.Add(entry);
    }
    public async ValueTask<TenantAuditHistoryPage> ReadAsync(TenantId tenant,int limit,string? cursor,CancellationToken token)
    {HistoryCalls++;HistoryTenant=tenant.Value;await Task.Yield();HistoryHook?.Invoke();return new(HistoryEntries);}
    private sealed class Handler(Fixture f):ITenantOperationHandler<Request,int>,IDisposable
    {
        public async ValueTask<OperationResult<int>> HandleAsync(Request request,TenantOperationContext context,CancellationToken token)
        {
            f.Captured=context;
            f.HandlerHook?.Invoke();token.ThrowIfCancellationRequested();context.DemandAccess(context.Tenant,f.Kind,request.Id,"read");
            if(f.HandlerFailure is not null)throw f.HandlerFailure;
            if(f.UseHistory)return OperationResult<int>.Success((await new TenantAuditHistoryReader(f).ReadAsync(context,f.HistoryLimit,cancellationToken:token)).Entries.Count);
            return f.BusinessRejected?OperationResult<int>.Failure(new("business.rejected","Rejected.")):OperationResult<int>.Success(1);
        }
        public void Dispose(){f.Disposed++;if(f.CleanupFailure)throw new TenantAccessDeniedException();}
    }
}
sealed class TicketService:IAuthenticationService
{
    public string Mutation="";public string? Scheme;public Exception? Failure;public Action? Hook;
    public Task<AuthenticateResult> AuthenticateAsync(HttpContext context,string? scheme)
    {
        Scheme=scheme;Hook?.Invoke();if(Failure is not null)return Task.FromException<AuthenticateResult>(Failure);
        if(Mutation=="anonymous")return Task.FromResult(AuthenticateResult.NoResult());
        if(Mutation=="failure")return Task.FromResult(AuthenticateResult.Fail("rejected"));
        var clock=new Clock();var claims=new List<Claim>{new("iss","urn:fixture"),new("sub",Mutation=="bad-sub"?"bad\nsubject":"alice"),
            new("nbf",clock.Now.AddMinutes(Mutation=="future"?1:-1).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new("exp",clock.Now.AddMinutes(Mutation=="expired"?-0.5:1).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture))};
        if(Mutation=="duplicate-sub")claims.Add(new("sub","mallory"));if(Mutation=="duplicate-issuer")claims.Add(new("iss","other"));
        if(Mutation=="missing-nbf")claims.RemoveAll(c=>c.Type=="nbf");
        if(Mutation is "bad-date" or "huge-date"){claims.RemoveAll(c=>c.Type=="exp");claims.Add(new("exp",Mutation=="bad-date"?"1.5":"9223372036854775807"));}
        if(Mutation=="too-many-claims")claims.AddRange(Enumerable.Range(0,257).Select(i=>new Claim("unused",i.ToString(System.Globalization.CultureInfo.InvariantCulture))));
        var principal=new ClaimsPrincipal(new ClaimsIdentity(claims,Mutation=="flag-only"?null:"jwt"));
        if(Mutation=="multi-identity")principal.AddIdentity(new ClaimsIdentity([new("sub","other")],"jwt"));
        return Task.FromResult(AuthenticateResult.Success(new(principal,Mutation=="wrong-scheme"?"other":scheme!)));
    }
    public Task ChallengeAsync(HttpContext context,string? scheme,AuthenticationProperties? properties)=>throw new NotSupportedException();
    public Task ForbidAsync(HttpContext context,string? scheme,AuthenticationProperties? properties)=>throw new NotSupportedException();
    public Task SignInAsync(HttpContext context,string? scheme,ClaimsPrincipal principal,AuthenticationProperties? properties)=>throw new NotSupportedException();
    public Task SignOutAsync(HttpContext context,string? scheme,AuthenticationProperties? properties)=>throw new NotSupportedException();
}
