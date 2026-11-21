using System.Security.Claims;
using System.Text.Json;
using Cehpalon.Engine.Composition;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Identity.AspNetCore;
using Cehpalon.Engine.Tenancy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

var output=Path.GetFullPath(args.Single(a=>a.StartsWith("--output=",StringComparison.Ordinal))[9..]);
if(File.Exists(output))throw new IOException("Keep prior results; use a fresh output.");
var checks=new List<object>();var passed=0;var failed=0;
void Require(bool value){if(!value)throw new InvalidOperationException("Session contract assertion failed.");}
async Task Check(string name,Func<Task> test)
{try{await test();passed++;checks.Add(new{name,passed=true});}catch(Exception error){failed++;checks.Add(new{name,passed=false,error=error.GetType().Name});}}
async Task Throws<T>(Func<Task> body)where T:Exception
{try{await body();}catch(T){return;}throw new InvalidOperationException("Expected exception type "+typeof(T).Name);}

await Check("legacy four-argument identity constructor preserves null session and binary signature",()=>
{
 var f=new Fixture();var i=new IdentitySnapshot(f.Identity.Principal,"Bearer",f.Clock.Now.AddMinutes(-1),f.Clock.Now.AddHours(1));
 Require(i.SessionId is null&&typeof(IdentitySnapshot).GetConstructor([typeof(PrincipalId),typeof(string),typeof(DateTimeOffset),typeof(DateTimeOffset)]) is not null);return Task.CompletedTask;
});
await Check("legacy undecorated identity source performs no session-status lookup",async()=>
{var f=new Fixture();Require(await ((IIdentitySource)f).ResolveAsync(default) is not null&&f.StatusCalls==0);});
await Check("active exact principal scheme and session observation preserves binding and bounds validity",async()=>
{var f=new Fixture();var i=await f.Source().ResolveAsync(default);Require(i is not null&&i.SessionId=="session-a"&&i.Principal.Equals(f.Identity.Principal)&&i.NotBeforeUtc==f.Clock.Now&&i.ExpiresAtUtc==f.Clock.Now.AddSeconds(30));});
foreach(var shape in new[]{(Name:"empty",Value:""),(Name:"blank",Value:" "),(Name:"control",Value:"x\n"),(Name:"malformed-utf16",Value:"\ud800"),(Name:"overlimit",Value:new string('s',257))})
await Check("session identifier representation rejects invalid shape "+shape.Name,async()=>
{var f=new Fixture();await Throws<ArgumentException>(()=>Task.Run(()=>new IdentitySnapshot(f.Identity.Principal,"Bearer",f.Clock.Now,f.Clock.Now.AddMinutes(1),shape.Value)));await Throws<ArgumentException>(()=>Task.Run(()=>new SessionStatusSnapshot(f.Identity.Principal,"Bearer",shape.Value,true,f.Clock.Now,f.Clock.Now.AddMinutes(1))));});
await Check("maximum session identifier accepted with exact ordinal identity and UTC normalization",async()=>
{var f=new Fixture();f.Identity=new(f.Identity.Principal,"Bearer",f.Clock.Now.ToOffset(TimeSpan.FromHours(7)).AddMinutes(-1),f.Clock.Now.AddHours(1),new string('s',256));var i=await f.Source().ResolveAsync(default);Require(i?.SessionId?.Length==256&&i.NotBeforeUtc.Offset==TimeSpan.Zero);});
await Check("invalid status intervals and observation limits reject at construction",async()=>
{var f=new Fixture();await Throws<ArgumentException>(()=>Task.Run(()=>new SessionStatusSnapshot(f.Identity.Principal,"Bearer","s",true,f.Clock.Now,f.Clock.Now)));foreach(var cap in new[]{TimeSpan.Zero,TimeSpan.FromTicks(-1),TimeSpan.FromMinutes(5).Add(TimeSpan.FromTicks(1))})await Throws<ArgumentOutOfRangeException>(()=>Task.Run(()=>f.Source(cap)));});
foreach(var mutation in new[]{"missing","inactive","principal","issuer","scheme","scheme-case","session","session-case","future","expired"})
await Check("status binding or validity denies "+mutation,async()=>
{var f=new Fixture{Mutation=mutation};Require(await f.Source().ResolveAsync(default) is null&&f.StatusCalls==1);});
foreach(var mutation in new[]{"anonymous","sessionless","expired","future"})
await Check("unusable authenticated identity skips session authority "+mutation,async()=>
{var f=new Fixture{IdentityMutation=mutation};Require(await f.Source().ResolveAsync(default) is null&&f.StatusCalls==0);});
await Check("revocation is rechecked with no successful-result cache",async()=>
{var f=new Fixture();var s=f.Source();Require(await s.ResolveAsync(default) is not null);f.Mutation="inactive";Require(await s.ResolveAsync(default) is null&&f.StatusCalls==2);});
await Check("new login uses a distinct session while revoked original remains denied",async()=>
{var f=new Fixture();f.Revoked.Add("session-a");Require(await f.Source().ResolveAsync(default) is null);f.Identity=new(f.Identity.Principal,"Bearer",f.Identity.NotBeforeUtc,f.Identity.ExpiresAtUtc,"session-b");Require(await f.Source().ResolveAsync(default) is not null);f.Identity=new(f.Identity.Principal,"Bearer",f.Identity.NotBeforeUtc,f.Identity.ExpiresAtUtc,"session-a");Require(await f.Source().ResolveAsync(default) is null);});
await Check("status expiry and identity expiry cap the returned observation",async()=>
{var f=new Fixture{StatusLifetime=TimeSpan.FromSeconds(4)};Require((await f.Source().ResolveAsync(default))!.ExpiresAtUtc==f.Clock.Now.AddSeconds(4));f.StatusLifetime=TimeSpan.FromHours(1);f.Identity=new(f.Identity.Principal,"Bearer",f.Clock.Now.AddSeconds(-1),f.Clock.Now.AddSeconds(2),"session-a");Require((await f.Source().ResolveAsync(default))!.ExpiresAtUtc==f.Clock.Now.AddSeconds(2));});
await Check("frozen UTC consumes monotonic time spent in both inner and session awaits",async()=>
{var f=new Fixture();f.IdentityHook=()=>{f.Clock.Timestamp+=TimeSpan.FromSeconds(10).Ticks;};f.StatusHook=()=>{f.Clock.Timestamp+=TimeSpan.FromSeconds(10).Ticks;};var i=await f.Source().ResolveAsync(default);Require(i?.ExpiresAtUtc==f.Clock.Now.AddSeconds(10));});
await Check("normally advancing source delay does not restart full observation lifetime",async()=>
{var f=new Fixture();var before=f.Clock.Now;f.StatusHook=()=>f.Clock.Advance(TimeSpan.FromSeconds(20));var i=await f.Source().ResolveAsync(default);Require(i?.ExpiresAtUtc==before.AddSeconds(30)&&i.ExpiresAtUtc-f.Clock.Now==TimeSpan.FromSeconds(10));});
await Check("inner observation consuming entire cap skips session lookup",async()=>
{var f=new Fixture();f.IdentityHook=()=>f.Clock.Advance(TimeSpan.FromSeconds(30));Require(await f.Source().ResolveAsync(default) is null&&f.StatusCalls==0);});
await Check("session observation consuming entire cap denies without fallback",async()=>
{var f=new Fixture();f.StatusHook=()=>f.Clock.Advance(TimeSpan.FromSeconds(30));Require(await f.Source().ResolveAsync(default) is null);});
foreach(var mutation in new[]{"utc-backward","monotonic-backward","partial-utc-backward","partial-monotonic-backward","utc-cap-overrun"})
await Check("clock discontinuity denies "+mutation,async()=>
{var f=new Fixture();if(mutation.StartsWith("partial",StringComparison.Ordinal))f.IdentityHook=()=>f.Clock.Advance(TimeSpan.FromSeconds(10));f.StatusHook=()=>{switch(mutation){case "utc-backward":f.Clock.Now-=TimeSpan.FromSeconds(1);break;case "monotonic-backward":f.Clock.Timestamp--;break;case "partial-utc-backward":f.Clock.Now-=TimeSpan.FromSeconds(5);break;case "partial-monotonic-backward":f.Clock.Timestamp-=TimeSpan.FromSeconds(5).Ticks;break;default:f.Clock.Now+=TimeSpan.FromMinutes(1);break;}};Require(await f.Source().ResolveAsync(default) is null);});
await Check("date arithmetic caps safely near maximum UTC",async()=>
{var f=new Fixture();f.Clock.Now=DateTimeOffset.MaxValue.AddSeconds(-2);f.Identity=new(f.Identity.Principal,"Bearer",f.Clock.Now.AddSeconds(-1),DateTimeOffset.MaxValue,"session-a");f.StatusLifetime=TimeSpan.FromSeconds(2);Require((await f.Source().ResolveAsync(default))?.ExpiresAtUtc==DateTimeOffset.MaxValue);});
await Check("cancellation before identity invokes no source",async()=>
{var f=new Fixture();using var cts=new CancellationTokenSource();cts.Cancel();await Throws<OperationCanceledException>(async()=>await f.Source().ResolveAsync(cts.Token));Require(f.IdentityCalls==0&&f.StatusCalls==0);});
await Check("cancellation after identity prevents session query",async()=>
{var f=new Fixture();using var cts=new CancellationTokenSource();f.IdentityHook=cts.Cancel;await Throws<OperationCanceledException>(async()=>await f.Source().ResolveAsync(cts.Token));Require(f.StatusCalls==0);});
await Check("cancellation after session await propagates despite an active result",async()=>
{var f=new Fixture();using var cts=new CancellationTokenSource();f.StatusHook=cts.Cancel;await Throws<OperationCanceledException>(async()=>await f.Source().ResolveAsync(cts.Token));});
await Check("session provider and clock faults propagate with no stale active fallback",async()=>
{var f=new Fixture();var s=f.Source();Require(await s.ResolveAsync(default) is not null);f.StatusHook=()=>throw new IOException("Controlled fixture fault.");await Throws<IOException>(async()=>await s.ResolveAsync(default));f.StatusHook=null;f.Clock.Fail=true;await Throws<InvalidOperationException>(async()=>await s.ResolveAsync(default));f.Clock.Fail=false;f.Mutation="inactive";Require(await s.ResolveAsync(default) is null);});

await Check("held asynchronous session lookup observes revocation before returning identity",async()=>
{var f=new Fixture();var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var resume=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var port=new DelegateSessions(async(identity,token)=>{entered.SetResult();await resume.Task.WaitAsync(token);return await ((IIdentitySessionStatusSource)f).ResolveAsync(identity,token);});var source=new SessionValidatingIdentitySource(f,port,TimeSpan.FromSeconds(30),f.Clock);var pending=source.ResolveAsync(default).AsTask();await entered.Task;Require(!pending.IsCompleted);f.Mutation="inactive";resume.SetResult();Require(await pending is null);});
await Check("held provider cancellation is propagated after an ignored cancellation token",async()=>
{var f=new Fixture();using var cts=new CancellationTokenSource();var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var resume=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var sawToken=false;var port=new DelegateSessions(async(identity,token)=>{entered.SetResult();await resume.Task;sawToken=token==cts.Token&&token.IsCancellationRequested;return new SessionStatusSnapshot(identity.Principal,identity.AuthenticationScheme,identity.SessionId!,true,f.Clock.Now.AddMinutes(-1),f.Clock.Now.AddMinutes(1));});var pending=new SessionValidatingIdentitySource(f,port,TimeSpan.FromSeconds(30),f.Clock).ResolveAsync(cts.Token).AsTask();await entered.Task;cts.Cancel();resume.SetResult();await Throws<OperationCanceledException>(async()=>await pending);Require(sawToken);});
await Check("returned lower validity bound begins at completion of delayed observation",async()=>
{var f=new Fixture();f.StatusHook=()=>f.Clock.Advance(TimeSpan.FromSeconds(5));var i=await f.Source().ResolveAsync(default);Require(i?.NotBeforeUtc==f.Clock.Now);f.Clock.Now-=TimeSpan.FromSeconds(2);Require(!new IdentityTrustPolicy(["issuer"],["Bearer"]).IsAccepted(i,f.Clock.Now));});

await Check("legacy JWT mapper ignores session claim unless explicit mapping selected",async()=>
{using var a=new AuthFixture();a.Claims.Add(new("sid","one"));a.Claims.Add(new("sid","two"));a.Refresh();var i=await new AspNetCoreJwtIdentitySource(a.Accessor,"Bearer",a.Clock).ResolveAsync(default);Require(i is not null&&i.SessionId is null);});
await Check("explicit JWT mapping carries unique authenticated session claim",async()=>
{using var a=new AuthFixture();a.Claims.Add(new("sid","session-a"));a.Refresh();var i=await new AspNetCoreJwtIdentitySource(a.Accessor,"Bearer",a.Clock,"sid").ResolveAsync(default);Require(i?.SessionId=="session-a");});
foreach(var mutation in new[]{"missing","duplicate","control","oversized","case"})
await Check("explicit JWT mapping denies invalid session claim "+mutation,async()=>
{using var a=new AuthFixture();if(mutation!="missing")a.Claims.Add(new(mutation=="case"?"SID":"sid",mutation=="control"?"x\n":mutation=="oversized"?new string('s',257):"session-a"));if(mutation=="duplicate")a.Claims.Add(new("sid","session-b"));a.Refresh();Require(await new AspNetCoreJwtIdentitySource(a.Accessor,"Bearer",a.Clock,"sid").ResolveAsync(default) is null);});
await Check("same cached authenticated ticket still performs fresh session observations",async()=>
{using var a=new AuthFixture();a.Claims.Add(new("sid","session-a"));a.Refresh();var f=new Fixture();var source=new SessionValidatingIdentitySource(new AspNetCoreJwtIdentitySource(a.Accessor,"Bearer",a.Clock,"sid"),f,TimeSpan.FromSeconds(30),a.Clock);Require(await source.ResolveAsync(default) is not null);f.Mutation="inactive";Require(await source.ResolveAsync(default) is null&&f.StatusCalls==2&&a.Authentication.Calls==2);});
await Check("cookie custom mapper binds session from the same established ticket",async()=>
{using var a=new AuthFixture();a.Claims.Clear();a.Claims.Add(new(ClaimTypes.NameIdentifier,"alice"));a.Claims.Add(new("session-key","cookie-session"));a.Refresh("Cookies");var mapper=new SessionBoundTicketIdentityMapper(new TicketPropertyIdentityMapper("issuer"),"session-key");var i=await new AspNetCoreIdentitySource(a.Accessor,"Cookies",mapper,a.Clock).ResolveAsync(default);Require(i?.SessionId=="cookie-session"&&i.Principal.Issuer=="issuer");});
await Check("generic session mapper denies duplicate session claims and failed host tickets",async()=>
{using var a=new AuthFixture();a.Claims.Clear();a.Claims.Add(new(ClaimTypes.NameIdentifier,"alice"));a.Claims.Add(new("sid","one"));a.Claims.Add(new("sid","two"));a.Refresh("Cookies");var source=new AspNetCoreIdentitySource(a.Accessor,"Cookies",new SessionBoundTicketIdentityMapper(new TicketPropertyIdentityMapper("issuer")),a.Clock);Require(await source.ResolveAsync(default) is null);a.Authentication.Fail=true;Require(await source.ResolveAsync(default) is null);});
await Check("generic mapper preserves matching inner session and denies conflicting inner session",()=>
{using var a=new AuthFixture();a.Claims.Clear();a.Claims.Add(new(ClaimTypes.NameIdentifier,"alice"));a.Claims.Add(new("sid","cookie-session"));a.Refresh("Cookies");var mapper=new TicketPropertyIdentityMapper("issuer");var same=new SessionBoundTicketIdentityMapper(new ExistingSessionMapper(mapper,"cookie-session"));var other=new SessionBoundTicketIdentityMapper(new ExistingSessionMapper(mapper,"other-session"));Require(same.Map(a.Authentication.Ticket!,"Cookies",a.Clock.Now)?.SessionId=="cookie-session"&&other.Map(a.Authentication.Ticket!,"Cookies",a.Clock.Now) is null);return Task.CompletedTask;});
await Check("session claim mapping cannot turn a caller-set User flag into authentication",async()=>
{using var a=new AuthFixture();a.Claims.Add(new("sid","session-a"));a.Refresh();a.Authentication.Fail=true;a.Context.User=a.Authentication.Ticket!.Principal;Require(await new AspNetCoreJwtIdentitySource(a.Accessor,"Bearer",a.Clock,"sid").ResolveAsync(default) is null);});

await Check("tenant switch repeats session status and denies revoked session before business factories",async()=>
{var f=new TenantFixture();Require((await f.Switch("A")).IsSuccess);f.Revoked=true;var before=f.Factories;Require(!(await f.Switch("B")).IsSuccess&&f.Factories==before&&f.StatusCalls==2);});
await Check("same session remains independently tenant authorized across parallel selections",async()=>
{var f=new TenantFixture();var result=await Task.WhenAll(Task.Run(async()=>await f.Switch("A")),Task.Run(async()=>await f.Switch("B")));Require(result.All(r=>r.IsSuccess)&&result.Select(r=>r.Value.Tenant.Value).Order().SequenceEqual(new[]{"A","B"}));});
await Check("readset preserves original session id in each clamped child identity",async()=>
{var f=new TenantFixture();var r=await f.Batch();Require(r.IsSuccess&&r.Value.Results.Count==2&&f.ObservedSessions.SequenceEqual(new[]{"session-a","session-a"})&&f.StatusCalls==3);});
await Check("revocation between aggregate children withholds response and preserves prior read effects",async()=>
{var f=new TenantFixture{AfterFirst=()=>{}};f.AfterFirst=()=>f.Revoked=true;var r=await f.Batch();Require(!r.IsSuccess&&f.Factories==1&&f.Disposals==1);await Throws<InvalidOperationException>(()=>Task.Run(()=>r.Value));});
foreach(var change in new[]{"another-session","null-to-session","session-to-null"})
await Check("aggregate pins ordinal session identity including null "+change,async()=>
{var f=new TenantFixture{Decorate=false};if(change=="null-to-session")f.Sid=null;f.AfterFirst=()=>f.Sid=change=="session-to-null"?null:"session-b";var r=await f.Batch();Require(!r.IsSuccess&&f.Factories==1&&f.Disposals==1);});
await Check("session denial retains required audit lineage without stamping an authorized tenant",async()=>
{var f=new TenantFixture{Revoked=true};var r=await f.Switch("B");Require(!r.IsSuccess&&f.Factories==0&&f.Events.Count==1&&f.Events[0].Outcome==TenantAuditOutcome.Denied&&f.Events[0].AuthorizedTenant is null);});
await Check("withdrawal after observation is outside atomic business admission guarantee",async()=>
{var f=new TenantFixture();f.PolicyHook=()=>f.Revoked=true;Require((await f.Switch("A")).IsSuccess);Require(!(await f.Switch("A")).IsSuccess&&f.StatusCalls==2);});
await Check("disabled composition never calls session status provider factory",async()=>
{var calls=0;var compiled=CompositionCompiler.Compile("""{"Cehpalon":{"SchemaVersion":1,"Architecture":"Modular","Topology":"SingleProcess","Pattern":"RequestReply","Modules":{"session":{"Enabled":false}}}}""",[new("session",ModuleRole.Support)]);await using var lease=await PlanActivator.ActivateAsync(compiled.Plan!,[new("session",token=>{calls++;var f=new Fixture();_=f.Source();return ValueTask.FromResult<IAsyncDisposable>(new Empty());})]);Require(calls==0);});

Directory.CreateDirectory(Path.GetDirectoryName(output)!);await using(var file=new FileStream(output,FileMode.CreateNew))await JsonSerializer.SerializeAsync(file,new{passed,failed,checks});Console.WriteLine(JsonSerializer.Serialize(new{passed,failed,output}));return failed==0?0:1;

sealed class Clock:TimeProvider
{public DateTimeOffset Now=new(2026,11,20,0,0,0,TimeSpan.Zero);public long Timestamp;public bool Fail;public override long TimestampFrequency=>TimeSpan.TicksPerSecond;public override DateTimeOffset GetUtcNow()=>Fail?throw new InvalidOperationException("Controlled clock fault."):Now;public override long GetTimestamp()=>Timestamp;public void Advance(TimeSpan span){Now+=span;Timestamp+=span.Ticks;}}
sealed class Fixture:IIdentitySource,IIdentitySessionStatusSource
{
 public Clock Clock{get;}=new();public IdentitySnapshot Identity;public int IdentityCalls,StatusCalls;public string? Mutation,IdentityMutation;public Action? IdentityHook,StatusHook;public TimeSpan StatusLifetime=TimeSpan.FromHours(1);public HashSet<string> Revoked{get;}=new(StringComparer.Ordinal);
 public Fixture()=>Identity=new(new("issuer","alice"),"Bearer",Clock.Now.AddMinutes(-1),Clock.Now.AddHours(1),"session-a");
 public SessionValidatingIdentitySource Source(TimeSpan? cap=null)=>new(this,this,cap??TimeSpan.FromSeconds(30),Clock);
 public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken token)
 {token.ThrowIfCancellationRequested();IdentityCalls++;IdentityHook?.Invoke();return ValueTask.FromResult<IdentitySnapshot?>(IdentityMutation switch{"anonymous"=>null,"sessionless"=>new(Identity.Principal,Identity.AuthenticationScheme,Identity.NotBeforeUtc,Identity.ExpiresAtUtc),"expired"=>new(Identity.Principal,Identity.AuthenticationScheme,Clock.Now.AddMinutes(-2),Clock.Now,"session-a"),"future"=>new(Identity.Principal,Identity.AuthenticationScheme,Clock.Now.AddMinutes(1),Clock.Now.AddMinutes(2),"session-a"),_=>Identity});}
 public ValueTask<SessionStatusSnapshot?> ResolveAsync(IdentitySnapshot identity,CancellationToken token)
 {token.ThrowIfCancellationRequested();StatusCalls++;StatusHook?.Invoke();if(Mutation=="missing")return ValueTask.FromResult<SessionStatusSnapshot?>(null);var expires=StatusLifetime.Ticks>DateTimeOffset.MaxValue.UtcTicks-Clock.Now.UtcTicks?DateTimeOffset.MaxValue:Clock.Now+StatusLifetime;return ValueTask.FromResult<SessionStatusSnapshot?>(new(new(Mutation=="issuer"?"other":identity.Principal.Issuer,Mutation=="principal"?"bob":identity.Principal.Subject),Mutation=="scheme"?"Other":Mutation=="scheme-case"?"bearer":identity.AuthenticationScheme,Mutation=="session"?"other-session":Mutation=="session-case"?"Session-A":identity.SessionId!,Mutation!="inactive"&&!Revoked.Contains(identity.SessionId!),Mutation=="future"?Clock.Now.AddMinutes(1):Clock.Now.AddMinutes(-1),Mutation=="expired"?Clock.Now:expires));}
}
sealed class FixedContext(HttpContext context):IHttpContextAccessor{public HttpContext? HttpContext{get;set;}=context;}
sealed class AuthFixture:IDisposable
{
 public Clock Clock{get;}=new();public List<Claim> Claims{get;}=[];public Authentication Authentication{get;}=new();public DefaultHttpContext Context{get;}=new();public FixedContext Accessor{get;}private readonly ServiceProvider services;
 public AuthFixture(){Claims.AddRange([new("iss","issuer"),new("sub","alice"),new("nbf",Clock.Now.AddMinutes(-1).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)),new("exp",Clock.Now.AddHours(1).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture))]);services=new ServiceCollection().AddSingleton<IAuthenticationService>(Authentication).BuildServiceProvider();Context.RequestServices=services;Accessor=new(Context);Refresh();}
 public void Refresh(string scheme="Bearer")=>Authentication.Ticket=new(new ClaimsPrincipal(new ClaimsIdentity(Claims,scheme)),new AuthenticationProperties{IssuedUtc=Clock.Now.AddMinutes(-1),ExpiresUtc=Clock.Now.AddHours(1)},scheme);
 public void Dispose()=>services.Dispose();
}
sealed class Authentication:IAuthenticationService
{
 public AuthenticationTicket? Ticket;public bool Fail;public int Calls;
 public Task<AuthenticateResult> AuthenticateAsync(HttpContext context,string? scheme){Calls++;return Task.FromResult(Fail?AuthenticateResult.NoResult():AuthenticateResult.Success(Ticket!));}
 public Task ChallengeAsync(HttpContext context,string? scheme,AuthenticationProperties? properties)=>throw new NotSupportedException();public Task ForbidAsync(HttpContext context,string? scheme,AuthenticationProperties? properties)=>throw new NotSupportedException();public Task SignInAsync(HttpContext context,string? scheme,ClaimsPrincipal principal,AuthenticationProperties? properties)=>throw new NotSupportedException();public Task SignOutAsync(HttpContext context,string? scheme,AuthenticationProperties? properties)=>throw new NotSupportedException();
}
sealed class TenantFixture:IIdentitySource,IIdentitySessionStatusSource,ITenantMembershipSource,IResourceScopeSource,ITenantAccessPolicy,ITenantReadSetSource,ITenantAuditSink
{
 public Clock Clock{get;}=new();public string? Sid="session-a";public bool Revoked,Decorate=true;public int StatusCalls,Factories,Disposals;public Action? AfterFirst,PolicyHook;public List<string?> ObservedSessions{get;}=[];public List<TenantAuditEvent> Events{get;}=[];
 public TenantSecurityServices Services()=>new(Decorate?new SessionValidatingIdentitySource(this,this,TimeSpan.FromSeconds(30),Clock):this,new(["issuer"],["Bearer"]),this,this,TimeSpan.FromSeconds(30),this,Clock,new(this));
 public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken token){token.ThrowIfCancellationRequested();return ValueTask.FromResult<IdentitySnapshot?>(new(new("issuer","alice"),"Bearer",Clock.Now.AddMinutes(-1),Clock.Now.AddMinutes(5),Sid));}
 public ValueTask<SessionStatusSnapshot?> ResolveAsync(IdentitySnapshot identity,CancellationToken token){token.ThrowIfCancellationRequested();Interlocked.Increment(ref StatusCalls);return ValueTask.FromResult<SessionStatusSnapshot?>(new(identity.Principal,identity.AuthenticationScheme,identity.SessionId!,!Revoked,Clock.Now.AddMinutes(-1),Clock.Now.AddMinutes(1)));}
 public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot identity,TenantId tenant,CancellationToken token)=>ValueTask.FromResult<TenantMembershipSnapshot?>(new(identity.Principal,tenant,true,Clock.Now.AddMinutes(-1),Clock.Now.AddMinutes(1),"m1"));
 public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId tenant,string kind,string id,CancellationToken token)=>ValueTask.FromResult<ResourceScopeSnapshot?>(new(tenant,kind,id,"r1"));
 public ValueTask<bool> IsAllowedAsync(TenantAccessRequest request,CancellationToken token){PolicyHook?.Invoke();return ValueTask.FromResult(true);}
 public ValueTask<TenantReadSetSnapshot?> ResolveAsync(TenantReadSetRequest request,CancellationToken token)=>ValueTask.FromResult<TenantReadSetSnapshot?>(new(request.Identity.Principal,request.OperationId,request.ResourceKind,request.ResourceId,[new("A"),new("B")],Clock.Now.AddMinutes(-1),Clock.Now.AddMinutes(1),"g1"));
 public ValueTask AppendAsync(TenantAuditEvent entry,CancellationToken token){lock(Events)Events.Add(entry);return ValueTask.CompletedTask;}
 public ValueTask<OperationResult<TenantSelectionResult>> Switch(string tenant)=>new TenantOperationDispatcher(new TenantOperationRegistryBuilder().RegisterTenantSelection().Build(),Services()).DispatchAsync<TenantSelectionRequest,TenantSelectionResult>("tenant.select",new(new(tenant)),new("switch"));
 public ValueTask<OperationResult<TenantReadSetResult<string>>> Batch(){var op=new TenantReadSetOperation<string,string>("document.read_all","document",x=>x,x=>x,()=>{Interlocked.Increment(ref Factories);return new Handler(this);});return new TenantReadSetDispatcher(Services(),this).DispatchAsync(op,"shared",new("batch"));}
 private sealed class Handler(TenantFixture f):ITenantOperationHandler<string,string>,IAsyncDisposable
 {public ValueTask<OperationResult<string>> HandleAsync(string request,TenantOperationContext context,CancellationToken token){context.DemandAccess(context.Tenant,"document",request,"read");f.ObservedSessions.Add(context.Identity.SessionId);if(f.Factories==1)f.AfterFirst?.Invoke();return ValueTask.FromResult(OperationResult<string>.Success(context.Tenant.Value));}public ValueTask DisposeAsync(){Interlocked.Increment(ref f.Disposals);return ValueTask.CompletedTask;}}
}
sealed class Empty:IAsyncDisposable{public ValueTask DisposeAsync()=>ValueTask.CompletedTask;}

sealed class DelegateSessions(Func<IdentitySnapshot,CancellationToken,ValueTask<SessionStatusSnapshot?>> resolve):IIdentitySessionStatusSource
{public ValueTask<SessionStatusSnapshot?> ResolveAsync(IdentitySnapshot identity,CancellationToken token)=>resolve(identity,token);}
sealed class ExistingSessionMapper(IAuthenticatedTicketIdentityMapper inner,string sessionId):IAuthenticatedTicketIdentityMapper
{public IdentitySnapshot? Map(AuthenticationTicket ticket,string scheme,DateTimeOffset now){var i=inner.Map(ticket,scheme,now);return i is null?null:new(i.Principal,i.AuthenticationScheme,i.NotBeforeUtc,i.ExpiresAtUtc,sessionId);}}
