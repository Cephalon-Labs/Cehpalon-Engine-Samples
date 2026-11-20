using System.Security.Claims;
using System.Text.Json;
using Cehpalon.Engine.Composition;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Identity.AspNetCore;
using Cehpalon.Engine.Tenancy;
using Microsoft.AspNetCore.Authentication;

var output=Path.GetFullPath(args.Single(a=>a.StartsWith("--output=",StringComparison.Ordinal))[9..]);
if(File.Exists(output))throw new IOException("Retain earlier results.");
var checks=new List<object>();var passed=0;var failed=0;
void Require(bool value){if(!value)throw new InvalidOperationException("Observation contract assertion failed.");}
async Task Check(string name,Func<Task> body){try{await body();passed++;checks.Add(new{name,passed=true});}catch(Exception e){failed++;checks.Add(new{name,passed=false,error=e.GetType().Name});}}
async Task Throws<T>(Func<Task> body)where T:Exception{try{await body();}catch(T){return;}throw new InvalidOperationException("Expected "+typeof(T).Name);}
IdentityTrustPolicy Trust()=>new(["issuer"],["Bearer"]);

await Check("legacy identity constructors and exact public property shape remain unchanged",()=>
{var p=new PrincipalId("issuer","alice");var i=new IdentitySnapshot(p,"Bearer",DateTimeOffset.UnixEpoch,DateTimeOffset.MaxValue);Require(i.SessionId is null&&i.SatisfiesObservationConstraints());Require(typeof(IdentitySnapshot).GetConstructor([typeof(PrincipalId),typeof(string),typeof(DateTimeOffset),typeof(DateTimeOffset)]) is not null);Require(typeof(IdentitySnapshot).GetProperties().Select(p=>p.Name).Order().SequenceEqual(new[]{"Principal","AuthenticationScheme","NotBeforeUtc","ExpiresAtUtc","SessionId"}.Order()));return Task.CompletedTask;});
await Check("observation helper is not ordinary UTC or issuer authentication",()=>
{var i=new IdentitySnapshot(new("untrusted","alice"),"Other",DateTimeOffset.UnixEpoch,DateTimeOffset.UnixEpoch.AddSeconds(1));Require(i.SatisfiesObservationConstraints()&&!Trust().IsAccepted(i,DateTimeOffset.UtcNow));return Task.CompletedTask;});
await Check("plain UTC narrowing and intersection preserve binding without clocks",()=>
{var i=new IdentitySnapshot(new("issuer","alice"),"Bearer",DateTimeOffset.UnixEpoch,DateTimeOffset.MaxValue,"sid");var c=i.WithValidity(DateTimeOffset.UnixEpoch.AddHours(1),DateTimeOffset.MaxValue.AddHours(-1));Require(c.SatisfiesObservationConstraints()&&c.Principal.Equals(i.Principal)&&c.SessionId==i.SessionId&&c.IntersectValidity(i)?.ExpiresAtUtc==c.ExpiresAtUtc);return Task.CompletedTask;});
foreach(var kind in new[]{"expand-before","expand-after","empty","reverse"})
await Check("UTC narrowing rejects "+kind,async()=>
{var f=new Fixture();var i=await f.Observe();var before=kind=="expand-before"?i.NotBeforeUtc.AddTicks(-1):i.NotBeforeUtc;var after=kind=="expand-after"?i.ExpiresAtUtc.AddTicks(1):kind=="empty"?before:kind=="reverse"?before.AddTicks(-1):i.ExpiresAtUtc;await Throws<ArgumentException>(()=>Task.Run(()=>i.WithValidity(before,after)));});
foreach(var kind in new[]{"issuer","subject","scheme","scheme-case","session","session-case","session-null","disjoint"})
await Check("intersection denies incompatible binding or interval "+kind,async()=>
{var f=new Fixture();var i=await f.Observe();var other=new IdentitySnapshot(new(kind=="issuer"?"other":"issuer",kind=="subject"?"bob":"alice"),kind=="scheme"?"Other":kind=="scheme-case"?"bearer":"Bearer",kind=="disjoint"?i.ExpiresAtUtc:i.NotBeforeUtc,kind=="disjoint"?i.ExpiresAtUtc.AddSeconds(1):i.ExpiresAtUtc,kind=="session"?"other":kind=="session-case"?"Session-a":kind=="session-null"?null:"session-a");Require(i.IntersectValidity(other) is null);});
await Check("validity copies share a latched original observation and cannot reset it",async()=>
{var f=new Fixture();var i=await f.Observe();var c=i.WithValidity(i.NotBeforeUtc,i.ExpiresAtUtc);var joined=c.IntersectValidity(i)!;f.Clock.Mono(3);Require(!Trust().IsAccepted(i,f.Clock.Now)&&!c.SatisfiesObservationConstraints()&&!joined.SatisfiesObservationConstraints());f.Clock.Timestamp=0;Require(!i.SatisfiesObservationConstraints()&&!c.SatisfiesObservationConstraints());});
await Check("original cap expires under stalled UTC after source returned",async()=>
{var f=new Fixture();var i=await f.Observe();f.Clock.Mono(1);Require(Trust().IsAccepted(i,f.Clock.Now));f.Clock.Mono(1);Require(!Trust().IsAccepted(i,f.Clock.Now));});
foreach(var kind in new[]{"status","identity"})
await Check("original shorter "+kind+" UTC validity clips native ceiling under stalled UTC",async()=>
{var f=new Fixture{Cap=TimeSpan.FromSeconds(30)};if(kind=="status")f.StatusLifetime=TimeSpan.FromSeconds(3);else f.IdentityLifetime=TimeSpan.FromSeconds(3);var i=await f.Observe();f.Clock.Mono(3);Require(!i.SatisfiesObservationConstraints());});
await Check("lookup latency plus shorter returned validity clips from original timestamp",async()=>
{var f=new Fixture{Cap=TimeSpan.FromSeconds(30),StatusLifetime=TimeSpan.FromSeconds(3)};f.StatusHook=()=>f.Clock.Mono(7);var i=await f.Observe();f.Clock.Mono(2);Require(i.SatisfiesObservationConstraints());f.Clock.Mono(1);Require(!i.SatisfiesObservationConstraints());});
foreach(var kind in new[]{"utc","timestamp","frequency"})
await Check("partial "+kind+" rollback or frequency drift latches across copies",async()=>
{var f=new Fixture{Cap=TimeSpan.FromSeconds(30)};var i=await f.Observe();f.Clock.Advance(5);Require(i.SatisfiesObservationConstraints());if(kind=="utc")f.Clock.Now-=TimeSpan.FromSeconds(1);else if(kind=="timestamp")f.Clock.Timestamp-=TimeSpan.FromSeconds(1).Ticks;else f.Clock.Frequency*=2;Require(!i.SatisfiesObservationConstraints());f.Clock.Advance(1);f.Clock.Frequency=TimeSpan.TicksPerSecond;Require(!i.WithValidity(i.NotBeforeUtc,i.ExpiresAtUtc).SatisfiesObservationConstraints());});
await Check("first clock fault propagates and permanently invalidates shared observation",async()=>
{var f=new Fixture();var i=await f.Observe();var clone=i.WithValidity(i.NotBeforeUtc,i.ExpiresAtUtc);f.Clock.FailNext=true;await Throws<IOException>(()=>Task.Run(()=>i.SatisfiesObservationConstraints()));Require(!clone.SatisfiesObservationConstraints()&&!i.SatisfiesObservationConstraints());});
await Check("parallel checks serialize original clock reads without interleaved state",async()=>
{var f=new Fixture{Cap=TimeSpan.FromMinutes(1)};var i=await f.Observe();f.Clock.ProbePairs=true;var results=await Task.WhenAll(Enumerable.Range(0,32).Select(_=>Task.Run(()=>Enumerable.Range(0,8).All(_=>Trust().IsAccepted(i,f.Clock.Now)))));f.Clock.ProbePairs=false;Require(results.All(v=>v)&&!f.Clock.PairOverlap&&f.Clock.ActivePairs==0);});
await Check("intersection deduplicates original guard references instead of growing chains",async()=>
{var f=new Fixture();var i=await f.Observe();var result=i;for(var n=0;n<100;n++)result=result.IntersectValidity(i)!;Require(result is not null&&result.SatisfiesObservationConstraints());f.Clock.Mono(2);Require(!result!.SatisfiesObservationConstraints());});
await Check("sixteen distinct observations accepted and seventeenth rejected without truncation",async()=>
{var f=new Fixture{Cap=TimeSpan.FromMinutes(1)};var observations=new List<IdentitySnapshot>();for(var n=0;n<17;n++)observations.Add(await f.Observe());var joined=observations[0];for(var n=1;n<16;n++)joined=joined.IntersectValidity(observations[n])!;Require(joined.SatisfiesObservationConstraints()&&joined.IntersectValidity(observations[16]) is null);});
await Check("nested session decorators retain older inner observation on later checks",async()=>
{var inner=new Fixture();var original=await inner.Observe();var outer=new Fixture{Cap=TimeSpan.FromSeconds(30)};var wrapped=new SessionValidatingIdentitySource(new FixedIdentity(original),outer,outer.Cap,outer.Clock);var i=await wrapped.ResolveAsync(default);Require(i is not null);inner.Clock.Mono(2);Require(!i!.SatisfiesObservationConstraints());});
await Check("nested session decorator rechecks inherited guard after its status await",async()=>
{var inner=new Fixture();var original=await inner.Observe();var outer=new Fixture{Cap=TimeSpan.FromSeconds(30)};outer.StatusHook=()=>inner.Clock.Mono(2);Require(await new SessionValidatingIdentitySource(new FixedIdentity(original),outer,outer.Cap,outer.Clock).ResolveAsync(default) is null);});
await Check("nested session decorator denies already exhausted inherited observation before status call",async()=>
{var inner=new Fixture();var original=await inner.Observe();inner.Clock.Mono(2);var outer=new Fixture();Require(await new SessionValidatingIdentitySource(new FixedIdentity(original),outer,outer.Cap,outer.Clock).ResolveAsync(default) is null&&outer.StatusCalls==0);});
await Check("nested decorator bound rejects seventeenth fresh observation",async()=>
{var f=new Fixture{Cap=TimeSpan.FromMinutes(1)};IIdentitySource source=f;for(var n=0;n<17;n++)source=new SessionValidatingIdentitySource(source,f,f.Cap,f.Clock);Require(await source.ResolveAsync(default) is null);});
await Check("matching generic ticket mapper retains original observation instead of reconstructing DTO",async()=>
{var f=new Fixture();var i=await f.Observe();var ticket=new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity([new Claim("sid","session-a")],"Cookies")),"Cookies");var mapper=new SessionBoundTicketIdentityMapper(new Mapper(i));var mapped=mapper.Map(ticket,"Bearer",f.Clock.Now);Require(ReferenceEquals(i,mapped));f.Clock.Mono(2);Require(!mapped!.SatisfiesObservationConstraints());});
foreach(var phase in new[]{"membership","resource","policy","audit"})
await Check("original observation expires during "+phase+" before business factory",async()=>
{var f=new Fixture();f.At(phase,()=>f.Clock.Mono(3));var r=await f.Dispatch();Require(!r.IsSuccess&&r.Error.Code=="access.denied"&&f.Factories==0&&f.Disposals==0);var authorizations=f.Events.Count(e=>e.Stage==TenantAuditStage.Authorization);Require(authorizations==(phase=="audit"?1:0)&&f.Events.Last().Outcome==TenantAuditOutcome.Denied);});
await Check("expiration during handler construction cleans up without invoking business",async()=>
{var f=new Fixture();f.FactoryHook=()=>f.Clock.Mono(3);var r=await f.Dispatch();Require(!r.IsSuccess&&f.Factories==1&&f.Executions==0&&f.Disposals==1);});
foreach(var phase in new[]{"handler","cleanup"})
await Check("success after "+phase+" expiry is withheld after owned cleanup with effects retained",async()=>
{var f=new Fixture();f.At(phase,()=>f.Clock.Mono(3));var r=await f.Dispatch();Require(!r.IsSuccess&&r.Error.Code=="access.denied"&&f.Executions==1&&f.Disposals==1&&f.Events.Last().Outcome==TenantAuditOutcome.Denied);});
await Check("checked context demand retains original clock origin through handler await",async()=>
{var f=new Fixture{DemandAfterHook=true};f.HandlerHook=()=>f.Clock.Mono(3);var r=await f.Dispatch();Require(!r.IsSuccess&&f.Executions==1&&f.Disposals==1);});
await Check("business failure is preserved rather than replaced by expired observation",async()=>
{var f=new Fixture{BusinessFailure=true};f.HandlerHook=()=>f.Clock.Mono(3);var r=await f.Dispatch();Require(!r.IsSuccess&&r.Error.Code=="business.rejected"&&f.Disposals==1&&f.Events.Last().Outcome==TenantAuditOutcome.Rejected);});
await Check("cleanup fault remains a fault when original observation has expired",async()=>
{var f=new Fixture();f.DisposeHook=()=>{f.Clock.Mono(3);throw new IOException("Controlled cleanup failure.");};await Throws<IOException>(async()=>await f.Dispatch());Require(f.Disposals==1&&f.Events.Last().Outcome==TenantAuditOutcome.Faulted);});
await Check("execution and cleanup failures retain both errors despite observation expiry",async()=>
{var f=new Fixture();f.HandlerHook=()=>throw new InvalidOperationException("Controlled execution failure.");f.DisposeHook=()=>{f.Clock.Mono(3);throw new IOException("Controlled cleanup failure.");};try{await f.Dispatch();throw new Exception("Expected aggregate");}catch(AggregateException e){Require(e.InnerExceptions.Count==2&&e.InnerExceptions[0] is InvalidOperationException&&e.InnerExceptions[1] is IOException);}Require(f.Disposals==1);});
await Check("post-cleanup observation clock fault propagates with required audit fault outcome",async()=>
{var f=new Fixture();f.DisposeHook=()=>f.Clock.FailNext=true;await Throws<IOException>(async()=>await f.Dispatch());Require(f.Disposals==1&&f.Events.Last().Outcome==TenantAuditOutcome.Faulted);});
await Check("cancellation remains cancellation with cleanup ownership preserved",async()=>
{var f=new Fixture();using var cancel=new CancellationTokenSource();f.HandlerHook=()=>{f.Clock.Mono(3);cancel.Cancel();cancel.Token.ThrowIfCancellationRequested();};await Throws<OperationCanceledException>(async()=>await f.Dispatch(cancel.Token));Require(f.Disposals==1&&f.Events.Last().Outcome==TenantAuditOutcome.Cancelled);});
foreach(var capacity in new[]{"shared","tenant"})
await Check("success observation check includes owned cleanup under "+capacity+" budget",async()=>
{var f=new Fixture();f.DisposeHook=()=>f.Clock.Mono(3);var r=await f.Dispatch(capacity:capacity);Require(!r.IsSuccess&&f.Disposals==1&&f.LastBudgetActive==0);});
foreach(var phase in new[]{"grant","batch-audit"})
await Check("parent read-set observation expires during "+phase+" before child activation",async()=>
{var f=new Fixture();f.At(phase,()=>f.Clock.Mono(3));var r=await f.Batch();Require(!r.IsSuccess&&f.Factories==0&&f.Events.Last().Outcome==TenantAuditOutcome.Denied);});
await Check("older parent observation is not reset by fresh child identity",async()=>
{var f=new Fixture();f.GrantHook=()=>f.Clock.Mono(1);f.MembershipHook=()=>f.Clock.Mono(1.5);var r=await f.Batch();Require(!r.IsSuccess&&f.Factories==0&&f.StatusCalls>=2);});
await Check("child context preserves both parent and fresh observations",async()=>
{var f=new Fixture{DemandAfterHook=true};f.GrantHook=()=>f.Clock.Mono(1);f.HandlerHook=()=>f.Clock.Mono(1.5);var r=await f.Batch();Require(!r.IsSuccess&&f.Executions==1&&f.Disposals==1);});
await Check("fresh child observation can expire before still-live parent",async()=>
{var f=new Fixture{Cap=TimeSpan.FromSeconds(10),ChildStatusLifetime=TimeSpan.FromSeconds(1)};f.HandlerHook=()=>f.Clock.Mono(2);var r=await f.Batch();Require(!r.IsSuccess&&f.Executions==1&&f.Disposals==1);});
await Check("expiry after first child prevents later factories and withholds partial result",async()=>
{var f=new Fixture();f.AfterFirst=()=>f.Clock.Mono(3);var r=await f.Batch();Require(!r.IsSuccess&&f.Factories==1&&f.Disposals==1);await Throws<InvalidOperationException>(()=>Task.Run(()=>r.Value));});
await Check("expiry during terminal read-set audit still withholds successful rows",async()=>
{var f=new Fixture();f.BatchTerminalHook=()=>f.Clock.Mono(3);var r=await f.Batch();Require(!r.IsSuccess&&f.Factories==2&&f.Disposals==2);});
await Check("unconstrained legacy success retains existing semantics without observation checks",async()=>
{var f=new Fixture{Decorate=false};f.HandlerHook=()=>f.Clock.Mono(90);var r=await f.Dispatch();Require(r.IsSuccess&&f.Disposals==1);});
await Check("required audit contains no raw session identifier or added observation state",async()=>
{var f=new Fixture();f.PolicyHook=()=>f.Clock.Mono(3);await f.Dispatch();var text=JsonSerializer.Serialize(f.Events);Require(!text.Contains("session-a",StringComparison.Ordinal)&&!text.Contains("Observation",StringComparison.Ordinal)&&f.Events.All(e=>e.AuthorizedTenant is null));});
await Check("disabled composition creates no observation or session provider work",async()=>
{var calls=0;var plan=CompositionCompiler.Compile("""{"Cehpalon":{"SchemaVersion":1,"Architecture":"Modular","Topology":"SingleProcess","Pattern":"RequestReply","Modules":{"session":{"Enabled":false}}}}""",[new("session",ModuleRole.Support)]);await using var lease=await PlanActivator.ActivateAsync(plan.Plan!,[new("session",_=>{calls++;return ValueTask.FromResult<IAsyncDisposable>(new Empty());})]);Require(calls==0);});
await Check("portable observation implementation references only BCL",()=>
{var names=typeof(IdentitySnapshot).Assembly.GetReferencedAssemblies().Select(a=>a.Name!);Require(names.All(n=>n.StartsWith("System.",StringComparison.Ordinal)||n=="netstandard"));return Task.CompletedTask;});
Directory.CreateDirectory(Path.GetDirectoryName(output)!);await using(var file=new FileStream(output,FileMode.CreateNew))await JsonSerializer.SerializeAsync(file,new{passed,failed,checks});Console.WriteLine(JsonSerializer.Serialize(new{passed,failed,output}));return failed==0?0:1;

sealed class Clock:TimeProvider
{
 public DateTimeOffset Now=new(2026,11,20,0,0,0,TimeSpan.Zero);public long Timestamp,Frequency=TimeSpan.TicksPerSecond;public bool FailNext,ProbePairs,PairOverlap;public int ActivePairs;
 public override long TimestampFrequency=>Frequency;
 public override DateTimeOffset GetUtcNow(){if(FailNext){FailNext=false;throw new IOException("Controlled clock failure.");}if(ProbePairs){if(Interlocked.Increment(ref ActivePairs)!=1)PairOverlap=true;Thread.SpinWait(3000);}return Now;}
 public override long GetTimestamp(){var value=Timestamp;if(ProbePairs)Interlocked.Decrement(ref ActivePairs);return value;}
 public void Mono(double seconds)=>Timestamp+=TimeSpan.FromSeconds(seconds).Ticks;
 public void Advance(double seconds){Now+=TimeSpan.FromSeconds(seconds);Mono(seconds);}
}
sealed class Fixture:IIdentitySource,IIdentitySessionStatusSource,ITenantMembershipSource,IResourceScopeSource,ITenantAccessPolicy,ITenantReadSetSource,ITenantAuditSink
{
 public Clock Clock{get;}=new();public TimeSpan Cap=TimeSpan.FromSeconds(2),IdentityLifetime=TimeSpan.FromMinutes(5),StatusLifetime=TimeSpan.FromMinutes(5);public TimeSpan? ChildStatusLifetime;public bool Decorate=true,BusinessFailure,DemandAfterHook;public int StatusCalls,Factories,Executions,Disposals,LastBudgetActive;
 public Action? StatusHook,MembershipHook,ResourceHook,PolicyHook,AuthorizationHook,GrantHook,HandlerHook,DisposeHook,FactoryHook,AfterFirst,BatchAuthorizationHook,BatchTerminalHook;
 public List<TenantAuditEvent> Events{get;}=[];
 public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken token){token.ThrowIfCancellationRequested();return ValueTask.FromResult<IdentitySnapshot?>(new(new("issuer","alice"),"Bearer",Clock.Now.AddMinutes(-1),Clock.Now+IdentityLifetime,"session-a"));}
 public ValueTask<SessionStatusSnapshot?> ResolveAsync(IdentitySnapshot i,CancellationToken token){token.ThrowIfCancellationRequested();StatusCalls++;StatusHook?.Invoke();var lifetime=StatusCalls>1&&ChildStatusLifetime.HasValue?ChildStatusLifetime.Value:StatusLifetime;return ValueTask.FromResult<SessionStatusSnapshot?>(new(i.Principal,i.AuthenticationScheme,i.SessionId!,true,Clock.Now.AddMinutes(-1),Clock.Now+lifetime));}
 public async Task<IdentitySnapshot> Observe()=>await new SessionValidatingIdentitySource(this,this,Cap,Clock).ResolveAsync(default)??throw new InvalidOperationException("Expected identity.");
 public TenantSecurityServices Services()=>new(Decorate?new SessionValidatingIdentitySource(this,this,Cap,Clock):this,new(["issuer"],["Bearer"]),this,this,TimeSpan.FromSeconds(30),this,Clock,new(this));
 public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot i,TenantId t,CancellationToken token){MembershipHook?.Invoke();return ValueTask.FromResult<TenantMembershipSnapshot?>(new(i.Principal,t,true,Clock.Now.AddMinutes(-1),Clock.Now.AddMinutes(5),"m1"));}
 public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId t,string kind,string id,CancellationToken token){ResourceHook?.Invoke();return ValueTask.FromResult<ResourceScopeSnapshot?>(new(t,kind,id,"r1"));}
 public ValueTask<bool> IsAllowedAsync(TenantAccessRequest r,CancellationToken token){PolicyHook?.Invoke();return ValueTask.FromResult(true);}
 public ValueTask<TenantReadSetSnapshot?> ResolveAsync(TenantReadSetRequest r,CancellationToken token){GrantHook?.Invoke();return ValueTask.FromResult<TenantReadSetSnapshot?>(new(r.Identity.Principal,r.OperationId,r.ResourceKind,r.ResourceId,[new("A"),new("B")],Clock.Now.AddMinutes(-1),Clock.Now.AddMinutes(5),"g1"));}
 public ValueTask AppendAsync(TenantAuditEvent e,CancellationToken token){Events.Add(e);if(e.OperationId=="document.read_all"&&e.AuthorizedTenant is null){if(e.Stage==TenantAuditStage.Authorization)BatchAuthorizationHook?.Invoke();else BatchTerminalHook?.Invoke();}else if(e.Stage==TenantAuditStage.Authorization)AuthorizationHook?.Invoke();return ValueTask.CompletedTask;}
 public void At(string phase,Action action){switch(phase){case "membership":MembershipHook=action;break;case "resource":ResourceHook=action;break;case "policy":PolicyHook=action;break;case "audit":AuthorizationHook=action;break;case "handler":HandlerHook=action;break;case "cleanup":DisposeHook=action;break;case "grant":GrantHook=action;break;case "batch-audit":BatchAuthorizationHook=action;break;default:throw new ArgumentException("Phase");}}
 public async ValueTask<OperationResult<string>> Dispatch(CancellationToken token=default,string? capacity=null)
 {
  var registry=new TenantOperationRegistryBuilder().Register<string,string>("document.read","read","document",x=>x,x=>new(new("A"),x),NewHandler).Build();
  var shared=capacity=="shared"?new OperationConcurrencyBudget(1):null;var tenant=capacity=="tenant"?new TenantOperationConcurrencyBudget(1,1):null;
  var dispatcher=tenant is null?shared is null?new TenantOperationDispatcher(registry,Services()):new TenantOperationDispatcher(registry,Services(),shared):TenantOperationDispatcher.WithTenantConcurrencyBudget(registry,Services(),tenant);
  var result=await dispatcher.DispatchAsync<string,string>("document.read","shared",new("observation"),token);LastBudgetActive=shared?.GetSnapshot().ActiveOperations??tenant?.GetSnapshot().Total.ActiveOperations??0;return result;
 }
 public ValueTask<OperationResult<TenantReadSetResult<string>>> Batch(){var operation=new TenantReadSetOperation<string,string>("document.read_all","document",x=>x,x=>x,NewHandler);return new TenantReadSetDispatcher(Services(),this).DispatchAsync(operation,"shared",new("observation-batch"));}
 private ITenantOperationHandler<string,string> NewHandler(){Factories++;FactoryHook?.Invoke();return new Handler(this);}
 private sealed class Handler(Fixture f):ITenantOperationHandler<string,string>,IAsyncDisposable
 {public ValueTask<OperationResult<string>> HandleAsync(string r,TenantOperationContext c,CancellationToken token){f.Executions++;f.HandlerHook?.Invoke();if(f.DemandAfterHook)c.DemandAccess(c.Tenant,"document",r,"read");return ValueTask.FromResult(f.BusinessFailure?OperationResult<string>.Failure(new("business.rejected","Rejected.")):OperationResult<string>.Success(c.Tenant.Value));}public ValueTask DisposeAsync(){f.Disposals++;f.DisposeHook?.Invoke();if(f.Factories==1)f.AfterFirst?.Invoke();return ValueTask.CompletedTask;}}
}
sealed class FixedIdentity(IdentitySnapshot identity):IIdentitySource{public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken token)=>ValueTask.FromResult<IdentitySnapshot?>(identity);}
sealed class Mapper(IdentitySnapshot identity):IAuthenticatedTicketIdentityMapper{public IdentitySnapshot? Map(AuthenticationTicket ticket,string scheme,DateTimeOffset now)=>identity;}
sealed class Empty:IAsyncDisposable{public ValueTask DisposeAsync()=>ValueTask.CompletedTask;}
