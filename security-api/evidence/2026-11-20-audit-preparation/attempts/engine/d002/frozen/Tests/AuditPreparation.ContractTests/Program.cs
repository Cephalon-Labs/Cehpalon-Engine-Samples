using System.Text.Json;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;

var output=Path.GetFullPath(args.Single(a=>a.StartsWith("--output=",StringComparison.Ordinal))[9..]);
if(File.Exists(output))throw new IOException("Retain previous output.");
var checks=new List<object>();var passed=0;var failed=0;
void Require(bool condition){if(!condition)throw new InvalidOperationException("Contract assertion failed.");}
void Throws<T>(Action action)where T:Exception{try{action();throw new InvalidOperationException("Expected exception.");}catch(T){}}
async Task Check(string name,Func<Task> body){try{await body();checks.Add(new{name,passed=true});passed++;}catch(Exception error){checks.Add(new{name,passed=false,error=error.GetType().FullName});failed++;}}
TenantChangeAuditPolicy Policy(TenantChangeAuditMode mode=TenantChangeAuditMode.ChangedFields,string operation="document.update",string action="write",string kind="document",bool emptyFields=false)
 =>new(mode,[new TenantChangeAuditRule(operation,action,kind,emptyFields?[]:[new TenantChangeFieldRule("title"),new TenantChangeFieldRule("secret",true)])]);
TenantChangeStates States()=>new(new([KeyValuePair.Create("title",TenantChangeValue.Text("old")),KeyValuePair.Create("secret",TenantChangeValue.Text("private-before"))]),new([KeyValuePair.Create("title",TenantChangeValue.Text("new")),KeyValuePair.Create("secret",TenantChangeValue.Text("private-after"))]));
TenantChangeReceipt Receipt(TenantOperationContext c,string? mutation=null)=>new(Guid.NewGuid(),mutation=="principal"?new("issuer","other"):c.Identity.Principal,mutation=="scheme"?"Other":c.Identity.AuthenticationScheme,mutation=="tenant"?new("B"):c.Tenant,mutation=="operation"?"other.read":c.OperationId,mutation=="action"?"read":c.Action,mutation=="kind"?"other":c.Resource.Kind,mutation=="entity"?"other":c.Resource.ResourceId,mutation=="acl"?"other":c.Resource.Version,TenantChangeKind.Update,"entity-v1","entity-v2");
async Task<TenantChangeAuditWriteException> FailedWrite(Func<Task> body){try{await body();throw new InvalidOperationException("Expected checked completion failure.");}catch(TenantChangeAuditWriteException error){Require(error.MayHaveCommitted);return error;}}
TenantChangeAuditRecorder Validated(Fixture f,Store s,TenantChangeAuditPolicy? policy=null)=>TenantChangeAuditRecorder.ActivateValidated(policy??Policy(),f.Registry,["document.update"],()=>s,timeProvider:f.Clock)!;

await Check("descriptions come from actual sorted immutable registrations without callbacks",()=>
{var f=new Fixture();var rows=f.Registry.DescribeOperations();Require(rows.Select(x=>x.OperationId).SequenceEqual(new[]{"document.update","other.read"})&&rows[0].Action=="write"&&rows[0].ResourceKind=="document");Require(f.Factories==0&&f.Freezes==0&&f.Selectors==0);Throws<NotSupportedException>(()=>((IList<TenantOperationDescription>)rows)[0]=rows[1]);Require(f.Registry.DescribeOperations()[0].Action=="write"&&typeof(TenantOperationDescription).GetConstructors().Length==0);return Task.CompletedTask;});
await Check("registry snapshot descriptions ignore later builder additions",()=>
{var f=new Fixture();f.Builder.Register<string,bool>("later.write","write","document",x=>x,x=>new(new("A"),x),()=>throw new InvalidOperationException());Require(f.Registry.DescribeOperations().Count==2&&f.Builder.Build().DescribeOperations().Count==3&&f.Factories==0);return Task.CompletedTask;});
await Check("validated activation loads one selected sink after catalog validation",()=>
{var f=new Fixture();var calls=0;var constructors=Store.Constructors;var recorder=TenantChangeAuditRecorder.ActivateValidated(Policy(),f.Registry,["document.update"],()=>{calls++;return new Store();});Require(recorder is not null&&calls==1&&Store.Constructors==constructors+1&&f.Factories==0&&f.Freezes==0&&f.Selectors==0);return Task.CompletedTask;});
await Check("disabled validated activation skips null catalog poison enumeration sink and timeout",()=>
{var calls=0;var p=new TenantChangeAuditPolicy(TenantChangeAuditMode.Disabled);Require(TenantChangeAuditRecorder.ActivateValidated(p,null,Poison(),()=>{calls++;throw new InvalidOperationException();},TimeSpan.FromSeconds(-1))is null&&calls==0);Require(TenantChangeAuditRecorder.ActivateValidated(p,null,null)is null);return Task.CompletedTask;});
foreach(var mutation in new[]{"missing-rule","unknown-rule","wrong-action","wrong-kind","required-unknown","required-duplicate","required-invalid","required-null","catalog-null","timeout","sink-null"})
await Check("invalid declared catalog or requirement fails before sink factory "+mutation,()=>
{var f=new Fixture();var calls=0;var p=mutation switch{"missing-rule"=>new TenantChangeAuditPolicy(),"unknown-rule"=>Policy(operation:"absent.write"),"wrong-action"=>Policy(action:"create"),"wrong-kind"=>Policy(kind:"other"),_=>Policy()};IEnumerable<string>? required=mutation switch{"required-unknown"=>["absent.write"],"required-duplicate"=>["document.update","document.update"],"required-invalid"=>["invalid id"],"required-null"=>null,_=>["document.update"]};Throws<ArgumentException>(()=>TenantChangeAuditRecorder.ActivateValidated(p,mutation=="catalog-null"?null:f.Registry,required,mutation=="sink-null"?null:()=>{calls++;return new Store();},mutation=="timeout"?TimeSpan.Zero:null));Require(calls==0&&f.Factories==0);return Task.CompletedTask;});
await Check("every configured rule is validated even when not declared required",()=>
{var f=new Fixture();var calls=0;var p=new TenantChangeAuditPolicy(TenantChangeAuditMode.MetadataOnly,[new("document.update","write","document"),new("other.read","write","document")]);Throws<ArgumentException>(()=>TenantChangeAuditRecorder.ActivateValidated(p,f.Registry,["document.update"],()=>{calls++;return new Store();}));Require(calls==0);return Task.CompletedTask;});
await Check("required enumeration is bounded before duplicate checks or provider loading",()=>
{var f=new Fixture();var visited=0;IEnumerable<string> Infinite(){while(true){visited++;yield return "document.update";}}Throws<ArgumentException>(()=>TenantChangeAuditRecorder.ActivateValidated(Policy(),f.Registry,Infinite(),()=>throw new InvalidOperationException()));Require(visited==129);return Task.CompletedTask;});
await Check("all128 explicit audited operations can be validated without activation",()=>
{var b=new TenantOperationRegistryBuilder();var rules=new List<TenantChangeAuditRule>();var names=new List<string>();for(var i=0;i<128;i++){var id="op."+i;names.Add(id);rules.Add(new(id,"write","document"));b.Register<string,bool>(id,"write","document",x=>x,x=>new(new("A"),x),()=>throw new InvalidOperationException());}var count=0;Require(TenantChangeAuditRecorder.ActivateValidated(new(TenantChangeAuditMode.MetadataOnly,rules),b.Build(),names,()=>{count++;return new Store();})is not null&&count==1);return Task.CompletedTask;});
await Check("required identifiers do not infer write or CRUD semantics",()=>
{var f=new Fixture();var store=new Store();Require(TenantChangeAuditRecorder.ActivateValidated(Policy(TenantChangeAuditMode.MetadataOnly,operation:"other.read",action:"read"),f.Registry,["other.read"],()=>store)is not null);return Task.CompletedTask;});
await Check("missing rules fail at validated startup before source fixture mutation",()=>
{var f=new Fixture();var sinks=0;Throws<ArgumentException>(()=>TenantChangeAuditRecorder.ActivateValidated(new(),f.Registry,["document.update"],()=>{sinks++;return new Store();}));Require(sinks==0&&f.Mutations==0&&f.Factories==0);return Task.CompletedTask;});
await Check("prepare checks a missing runtime rule before application mutation",async()=>
{var f=new Fixture();var s=new Store();var r=TenantChangeAuditRecorder.Activate(new(),()=>s)!;await f.Run(c=>{Throws<TenantAccessDeniedException>(()=>r.Prepare(c));Require(f.Mutations==0&&s.AppendCalls==0);return Task.CompletedTask;});});
await Check("prepare pre-cancellation remains ordinary cancellation with no effects",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);using var cancel=new CancellationTokenSource();cancel.Cancel();await f.Run(c=>{Throws<OperationCanceledException>(()=>r.Prepare(c,cancel.Token));Require(f.Mutations==0&&s.AppendCalls==0);return Task.CompletedTask;});});
await Check("prepare expired context remains ordinary denial before effects",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);await f.Run(c=>{f.Clock.Advance(TimeSpan.FromMinutes(2));Throws<TenantAccessDeniedException>(()=>r.Prepare(c));Require(f.Mutations==0&&s.AppendCalls==0);return Task.CompletedTask;});});
await Check("retained context cannot create a preparation after dispatch lease disposal",async()=>
{var f=new Fixture();var r=Validated(f,new());TenantOperationContext? held=null;await f.Run(c=>{held=c;return Task.CompletedTask;});Throws<TenantAccessDeniedException>(()=>r.Prepare(held!));});
foreach(var clone in new[]{false,true})
await Check("validated recorder rejects foreign registry instance "+(clone?"same-builder snapshot":"independent matching catalog"),async()=>
{var a=new Fixture();var s=new Store();var r=Validated(a,s);var b=clone?a:new Fixture();var registry=clone?a.Builder.Build():b.Registry;await b.Run(c=>{Throws<TenantAccessDeniedException>(()=>r.Prepare(c));Require(b.Mutations==0&&s.AppendCalls==0);return Task.CompletedTask;},registry);});
await Check("validated direct legacy-shaped RecordAsync also enforces exact registry origin",async()=>
{var a=new Fixture();var b=new Fixture();var s=new Store();var r=Validated(a,s);await b.Run(async c=>{b.Mutations++;var error=await FailedWrite(()=>r.RecordAsync(c,Receipt(c),States).AsTask());Require(error.InnerException is TenantAccessDeniedException&&s.AppendCalls==0&&b.Mutations==1);});});
await Check("legacy unvalidated activation and RecordAsync retain independent-registry behavior",async()=>
{var a=new Fixture();var b=new Fixture();var s=new Store();var r=TenantChangeAuditRecorder.Activate(Policy(TenantChangeAuditMode.MetadataOnly),()=>s)!;await a.Run(c=>r.RecordAsync(c,Receipt(c)).AsTask());await b.Run(c=>r.RecordAsync(c,Receipt(c)).AsTask());Require(s.AppendCalls==2);});
foreach(var mode in new[]{TenantChangeAuditMode.MetadataOnly,TenantChangeAuditMode.ChangedFields,TenantChangeAuditMode.BeforeAfterSnapshots})
await Check("prepared completion retains selected field mode "+mode,async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s,Policy(mode));var images=0;await f.Run(async c=>{var p=r.Prepare(c);Require(s.AppendCalls==0&&images==0);f.Mutations++;await p.CompleteAsync(Receipt(c),()=>{images++;return States();});});Require(f.Mutations==1&&s.AppendCalls==1&&images==(mode==TenantChangeAuditMode.MetadataOnly?0:1));Require(!JsonSerializer.Serialize(s.Rows).Contains("private-",StringComparison.Ordinal));});
await Check("prepared empty allowlist never calls a state factory",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s,Policy(emptyFields:true));await f.Run(c=>r.Prepare(c).CompleteAsync(Receipt(c),()=>throw new InvalidOperationException()).AsTask());Require(s.AppendCalls==1&&s.Rows[0].Fields.Count==0);});
await Check("preparation is opaque and only captures its original checked context",async()=>
{Require(typeof(TenantChangeAuditPreparation).IsSealed&&typeof(TenantChangeAuditPreparation).GetConstructors().Length==0);var f=new Fixture();var s=new Store();var r=Validated(f,s);TenantChangeAuditPreparation? prepared=null;TenantChangeReceipt? receipt=null;await f.Run(c=>{prepared=r.Prepare(c);receipt=Receipt(c);return Task.CompletedTask;});var e=await FailedWrite(()=>prepared!.CompleteAsync(receipt!,States).AsTask());Require(e.InnerException is TenantAccessDeniedException&&s.AppendCalls==0);});
foreach(var mutation in new[]{"principal","scheme","tenant","operation","action","kind","entity","acl"})
await Check("failed first completion consumes preparation before receipt binding "+mutation,async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);var images=0;await f.Run(async c=>{var p=r.Prepare(c);var e=await FailedWrite(()=>p.CompleteAsync(Receipt(c,mutation),()=>{images++;return States();}).AsTask());Require(e.InnerException is TenantAccessDeniedException);await FailedWrite(()=>p.CompleteAsync(Receipt(c),()=>{images++;return States();}).AsTask());});Require(images==0&&s.AppendCalls==0);});
await Check("null receipt still consumes preparation and reports possible effects",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);await f.Run(async c=>{var p=r.Prepare(c);var e=await FailedWrite(()=>p.CompleteAsync(null!).AsTask());Require(e.InnerException is ArgumentNullException);await FailedWrite(()=>p.CompleteAsync(Receipt(c),States).AsTask());});Require(s.AppendCalls==0);});
await Check("completion pre-cancellation consumes once and preserves possible effects",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);using var cancel=new CancellationTokenSource();await f.Run(async c=>{var p=r.Prepare(c);f.Mutations++;cancel.Cancel();var e=await FailedWrite(()=>p.CompleteAsync(Receipt(c),States,cancel.Token).AsTask());Require(e.InnerException is OperationCanceledException);await FailedWrite(()=>p.CompleteAsync(Receipt(c),States).AsTask());});Require(f.Mutations==1&&s.AppendCalls==0);});
await Check("completion after observation expiry cannot append despite actual prior mutation",async()=>
{var f=new Fixture{Observed=true};var s=new Store();var r=Validated(f,s);var result=await f.Run(async c=>{var p=r.Prepare(c);f.Mutations++;f.Clock.Mono(3);var e=await FailedWrite(()=>p.CompleteAsync(Receipt(c),States).AsTask());Require(e.InnerException is TenantAccessDeniedException);});Require(!result.IsSuccess&&f.Mutations==1&&s.AppendCalls==0);});
await Check("state factory failure consumes once without touching sink",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);var images=0;await f.Run(async c=>{var p=r.Prepare(c);var e=await FailedWrite(()=>p.CompleteAsync(Receipt(c),()=>{images++;throw new IOException("Controlled projection failure.");}).AsTask());Require(e.InnerException is IOException);await FailedWrite(()=>p.CompleteAsync(Receipt(c),States).AsTask());});Require(images==1&&s.AppendCalls==0);});
await Check("sink failure after actual mutation consumes attempt and does not retry",async()=>
{var f=new Fixture();var s=new Store{Fail=true};var r=Validated(f,s);await f.Run(async c=>{var p=r.Prepare(c);f.Mutations++;var e=await FailedWrite(()=>p.CompleteAsync(Receipt(c),States).AsTask());Require(e.InnerException is IOException);s.Fail=false;await FailedWrite(()=>p.CompleteAsync(Receipt(c),States).AsTask());});Require(f.Mutations==1&&s.AppendCalls==1&&s.Rows.Count==0);});
await Check("successful completion replay cannot repeat payload or append",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);var images=0;await f.Run(async c=>{var p=r.Prepare(c);var receipt=Receipt(c);await p.CompleteAsync(receipt,()=>{images++;return States();});var e=await FailedWrite(()=>p.CompleteAsync(receipt,()=>{images++;return States();}).AsTask());Require(e.InnerException is InvalidOperationException);});Require(images==1&&s.AppendCalls==1);});
foreach(var failSink in new[]{false,true})
await Check("independently scheduled concurrent completion has one facade attempt "+(failSink?"failed winner":"successful winner"),async()=>
{var f=new Fixture();var s=new Store{Fail=failSink};var r=Validated(f,s);var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var release=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var start=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var images=0;var success=0;var rejected=0;s.Gate=async token=>{entered.TrySetResult();await release.Task.WaitAsync(token);};await f.Run(async c=>{var p=r.Prepare(c);var receipt=Receipt(c);f.Mutations++;var work=Enumerable.Range(0,16).Select(_=>Task.Run(async()=>{await start.Task;try{await p.CompleteAsync(receipt,()=>{Interlocked.Increment(ref images);return States();});Interlocked.Increment(ref success);}catch(TenantChangeAuditWriteException e){Require(e.MayHaveCommitted);Interlocked.Increment(ref rejected);}})).ToArray();start.TrySetResult();try{await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));}finally{release.TrySetResult();}await Task.WhenAll(work);});Require(s.AppendCalls==1&&images==1&&success==(failSink?0:1)&&rejected==(failSink?16:15)&&f.Mutations==1);});
await Check("distinct preparations do not promise backend receipt exactly-once",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);await f.Run(async c=>{var receipt=Receipt(c);await r.Prepare(c).CompleteAsync(receipt,States);var e=await FailedWrite(()=>r.Prepare(c).CompleteAsync(receipt,States).AsTask());Require(e.InnerException is InvalidOperationException);});Require(s.AppendCalls==2&&s.Rows.Count==1);});
await Check("no automatic abort or provider readiness work happens during preparation",async()=>
{var f=new Fixture();var s=new Store{Fail=true};var r=Validated(f,s);await f.Run(c=>{Require(r.Prepare(c)is not null&&s.AppendCalls==0&&f.Mutations==0);return Task.CompletedTask;});Require(s.AppendCalls==0);});

Directory.CreateDirectory(Path.GetDirectoryName(output)!);await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{passed,failed,checks,scope="Local catalog/pre-effect preparation and single facade attempt contracts; no database transaction, backend exactly-once, durable provider or production qualification."},new JsonSerializerOptions{WriteIndented=true}));
Console.WriteLine($"Audit preparation contracts: {passed}/{passed+failed}");return failed==0?0:1;
static IEnumerable<string> Poison(){yield return ThrowPoison();}
static string ThrowPoison()=>throw new InvalidOperationException("Must not enumerate disabled requirements.");

sealed class Clock:TimeProvider
{public DateTimeOffset Now=DateTimeOffset.Parse("2026-11-20T00:00:00Z");public long Timestamp;public override long TimestampFrequency=>TimeSpan.TicksPerSecond;public override DateTimeOffset GetUtcNow()=>Now;public override long GetTimestamp()=>Timestamp;public void Advance(TimeSpan t){Now+=t;Timestamp+=t.Ticks;}public void Mono(int seconds)=>Timestamp+=TimeSpan.FromSeconds(seconds).Ticks;}
sealed class Fixture:IIdentitySource,IIdentitySessionStatusSource,ITenantMembershipSource,IResourceScopeSource,ITenantAccessPolicy
{
 public Clock Clock{get;}=new();public int Mutations,Factories,Freezes,Selectors;public bool Observed;
 public TenantOperationRegistryBuilder Builder{get;}=new();public TenantOperationRegistry Registry{get;}
 private Func<TenantOperationContext,Task> body=_=>Task.CompletedTask;
 public Fixture(){foreach(var op in new[]{("document.update","write"),("other.read","read")})Builder.Register<string,bool>(op.Item1,op.Item2,"document",x=>{Freezes++;return x;},x=>{Selectors++;var parts=x.Split(':',2);return new(new(parts[0]),parts[1]);},()=>{Factories++;return new Handler(this);});Registry=Builder.Build();}
 public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken token)=>ValueTask.FromResult<IdentitySnapshot?>(new(new("issuer","alice"),"Bearer",Clock.Now.AddMinutes(-1),Clock.Now.AddMinutes(5),"session-a"));
 public ValueTask<SessionStatusSnapshot?> ResolveAsync(IdentitySnapshot i,CancellationToken token)=>ValueTask.FromResult<SessionStatusSnapshot?>(new(i.Principal,i.AuthenticationScheme,i.SessionId!,true,Clock.Now.AddMinutes(-1),Clock.Now.AddMinutes(5)));
 public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot i,TenantId t,CancellationToken token)=>ValueTask.FromResult<TenantMembershipSnapshot?>(new(i.Principal,t,true,Clock.Now.AddMinutes(-1),Clock.Now.AddMinutes(5),"m1"));
 public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId t,string kind,string id,CancellationToken token)=>ValueTask.FromResult<ResourceScopeSnapshot?>(new(t,kind,id,"acl1"));
 public ValueTask<bool> IsAllowedAsync(TenantAccessRequest request,CancellationToken token)=>ValueTask.FromResult(true);
 public async Task<OperationResult<bool>> Run(Func<TenantOperationContext,Task> callback,TenantOperationRegistry? registry=null){body=callback;IIdentitySource identity=Observed?new SessionValidatingIdentitySource(this,this,TimeSpan.FromSeconds(2),Clock):this;var services=new TenantSecurityServices(identity,new(["issuer"],["Bearer"]),this,this,TimeSpan.FromMinutes(1),this,Clock);return await new TenantOperationDispatcher(registry??Registry,services).DispatchAsync<string,bool>("document.update","A:entity-1",new("fixture"));}
 private sealed class Handler(Fixture fixture):ITenantOperationHandler<string,bool>{public async ValueTask<OperationResult<bool>> HandleAsync(string request,TenantOperationContext context,CancellationToken token){await fixture.body(context);return OperationResult<bool>.Success(true);}}
}
sealed class Store:ITenantChangeAuditSink
{
 public static int Constructors;public Store(){Interlocked.Increment(ref Constructors);}public List<TenantChangeAuditRecord> Rows{get;}=[];public int AppendCalls;public bool Fail;public Func<CancellationToken,Task>? Gate;
 public async ValueTask AppendAsync(TenantChangeAuditRecord record,CancellationToken token){Interlocked.Increment(ref AppendCalls);if(Gate is not null)await Gate(token);if(Fail)throw new IOException("Controlled fixture sink failure.");lock(Rows){if(Rows.Any(x=>x.Receipt.ReceiptId==record.Receipt.ReceiptId))throw new InvalidOperationException("Duplicate fixture receipt.");Rows.Add(record);}}
}
