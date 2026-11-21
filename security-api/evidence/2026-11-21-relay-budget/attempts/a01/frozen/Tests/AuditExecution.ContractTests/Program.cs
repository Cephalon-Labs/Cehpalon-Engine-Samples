using System.Text.Json;
using System.Threading.Tasks.Sources;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;

var output=Path.GetFullPath(args.Single(a=>a.StartsWith("--output=",StringComparison.Ordinal))[9..]);
if(File.Exists(output))throw new IOException("Retain previous output.");
var checks=new List<object>();var passed=0;var failed=0;
void Require(bool condition){if(!condition)throw new InvalidOperationException("Contract assertion failed.");}
async Task Check(string name,Func<Task> body){try{await body();checks.Add(new{name,passed=true});passed++;}catch(Exception error){checks.Add(new{name,passed=false,error=error.GetType().FullName});failed++;}}
async Task<T> Throws<T>(Func<Task> body)where T:Exception{try{await body();throw new InvalidOperationException("Expected exception.");}catch(T error){return error;}}
async Task<TenantChangeAuditWriteException> Failed(Func<Task> body){var e=await Throws<TenantChangeAuditWriteException>(body);Require(e.MayHaveCommitted);return e;}
TenantChangeAuditPolicy Policy(TenantChangeAuditMode mode=TenantChangeAuditMode.ChangedFields,bool empty=false)
 =>new(mode,[new TenantChangeAuditRule("document.update","write","document",empty?[]:[new("title"),new("secret",true)])]);
TenantChangeStates States()=>new(new([KeyValuePair.Create("title",TenantChangeValue.Text("old")),KeyValuePair.Create("secret",TenantChangeValue.Text("private-before"))]),new([KeyValuePair.Create("title",TenantChangeValue.Text("new")),KeyValuePair.Create("secret",TenantChangeValue.Text("private-after"))]));
TenantChangeReceipt Receipt(TenantOperationContext c,string? mutation=null)=>new(Guid.NewGuid(),mutation=="principal"?new("issuer","other"):c.Identity.Principal,mutation=="scheme"?"Other":c.Identity.AuthenticationScheme,mutation=="tenant"?new("B"):c.Tenant,mutation=="operation"?"other.read":c.OperationId,mutation=="action"?"read":c.Action,mutation=="kind"?"other":c.Resource.Kind,mutation=="entity"?"other":c.Resource.ResourceId,mutation=="acl"?"other":c.Resource.Version,TenantChangeKind.Update,"entity-v1","entity-v2");
TenantChangeAuditRecorder Validated(Fixture f,Store s,TenantChangeAuditPolicy? policy=null,TimeSpan? timeout=null)=>TenantChangeAuditRecorder.ActivateValidated(policy??Policy(),f.Registry,["document.update"],()=>s,timeout,f.Clock)!;

await Check("null callback is an ordinary argument failure before mutation",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);await f.Run(async c=>{await Throws<ArgumentNullException>(()=>r.ExecuteAsync<int>(c,null!).AsTask());});Require(f.Mutations==0&&s.AppendCalls==0);});
await Check("null context is an ordinary argument failure without invoking callback",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);await Throws<ArgumentNullException>(()=>r.ExecuteAsync<int>(null!,_=>{f.Mutations++;throw new IOException();}).AsTask());Require(f.Mutations==0&&s.AppendCalls==0);});
await Check("pre-cancelled caller remains ordinary cancellation without invocation",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);using var ct=new CancellationTokenSource();ct.Cancel();await f.Run(async c=>{await Throws<OperationCanceledException>(()=>r.ExecuteAsync<int>(c,_=>{f.Mutations++;throw new IOException();},ct.Token).AsTask());});Require(f.Mutations==0&&s.AppendCalls==0);});
await Check("missing rule denies before callback without possible-commit wrapper",async()=>
{var f=new Fixture();var s=new Store();var r=TenantChangeAuditRecorder.Activate(new(),()=>s)!;await f.Run(async c=>{await Throws<TenantAccessDeniedException>(()=>r.ExecuteAsync<int>(c,_=>{f.Mutations++;throw new IOException();}).AsTask());});Require(f.Mutations==0&&s.AppendCalls==0);});
foreach(var clone in new[]{false,true})
await Check("foreign registry preflight prevents callback "+(clone?"same-builder snapshot":"independent matching catalog"),async()=>
{var a=new Fixture();var b=clone?a:new Fixture();var s=new Store();var r=Validated(a,s);await b.Run(async c=>{await Throws<TenantAccessDeniedException>(()=>r.ExecuteAsync<int>(c,_=>{b.Mutations++;throw new IOException();}).AsTask());},clone?a.Builder.Build():b.Registry);Require(b.Mutations==0&&s.AppendCalls==0);});
await Check("expired checked scope denies before callback",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);await f.Run(async c=>{f.Clock.Advance(TimeSpan.FromMinutes(2));await Throws<TenantAccessDeniedException>(()=>r.ExecuteAsync<int>(c,_=>{f.Mutations++;throw new IOException();}).AsTask());});Require(f.Mutations==0&&s.AppendCalls==0);});
await Check("retained disposed context denies before callback",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);TenantOperationContext? held=null;await f.Run(c=>{held=c;return Task.CompletedTask;});await Throws<TenantAccessDeniedException>(()=>r.ExecuteAsync<int>(held!,_=>{f.Mutations++;throw new IOException();}).AsTask());Require(f.Mutations==0&&s.AppendCalls==0);});
await Check("typed result is returned only after exactly one mutation and append",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);var images=0;var expected=new Result("value",17);await f.Run(async c=>{var actual=await r.ExecuteAsync(c,token=>{Require(token==CancellationToken.None&&s.AppendCalls==0);f.Mutations++;return ValueTask.FromResult(new TenantChangeAuditMutation<Result>(Receipt(c),expected,()=>{images++;return States();}));});Require(ReferenceEquals(actual,expected)&&s.Rows.Count==1);});Require(f.Mutations==1&&images==1&&s.AppendCalls==1);});
await Check("abandoned manual preparation can leave an actual mutation without a trail",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);await f.Run(c=>{_ = r.Prepare(c);f.Mutations++;return Task.CompletedTask;});Require(f.Mutations==1&&s.AppendCalls==0&&s.Rows.Count==0);});
await Check("nullable business result remains a successful typed result",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);await f.Run(async c=>{var value=await r.ExecuteAsync(c,_=>ValueTask.FromResult(new TenantChangeAuditMutation<string?>(Receipt(c),null,States)));Require(value is null&&s.Rows.Count==1);});});
await Check("mutation result envelope has no public writable receipt result or states callback",()=>
{var type=typeof(TenantChangeAuditMutation<int>);Require(type.IsSealed&&type.GetProperties().Select(p=>p.Name).Order().SequenceEqual(new[]{"Receipt","Result"})&&type.GetProperties().All(p=>!p.CanWrite));return Task.CompletedTask;});
foreach(var asynchronous in new[]{false,true})
await Check("callback failure after actual effects preserves no fabricated receipt "+(asynchronous?"async":"synchronous"),async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);var original=new IOException("Controlled mutation failure.");await f.Run(async c=>{ValueTask<TenantChangeAuditMutation<int>> Mutation(CancellationToken token){f.Mutations++;if(!asynchronous)throw original;return Async();}async ValueTask<TenantChangeAuditMutation<int>> Async(){await Task.Yield();throw original;}var e=await Failed(()=>r.ExecuteAsync(c,Mutation).AsTask());Require(ReferenceEquals(e.InnerException,original));});Require(f.Mutations==1&&s.AppendCalls==0);});
foreach(var cancelToken in new[]{false,true})
await Check("callback cancellation after invocation reports possible effects "+(cancelToken?"caller signalled":"independent OCE"),async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);using var ct=new CancellationTokenSource();await f.Run(async c=>{var e=await Failed(()=>r.ExecuteAsync<int>(c,token=>{f.Mutations++;if(cancelToken)ct.Cancel();throw new OperationCanceledException(token);},ct.Token).AsTask());Require(e.InnerException is OperationCanceledException);});Require(f.Mutations==1&&s.AppendCalls==0);});
await Check("null returned envelope reports uncertainty without payload or append",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);await f.Run(async c=>{var e=await Failed(()=>r.ExecuteAsync<int>(c,_=>{f.Mutations++;return ValueTask.FromResult<TenantChangeAuditMutation<int>>(null!);}).AsTask());Require(e.InnerException is ArgumentException);});Require(f.Mutations==1&&s.AppendCalls==0);});
await Check("null receipt constructor failure inside callback reports possible committed effects",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);await f.Run(async c=>{var e=await Failed(()=>r.ExecuteAsync<int>(c,_=>{f.Mutations++;return ValueTask.FromResult(new TenantChangeAuditMutation<int>(null!,1,States));}).AsTask());Require(e.InnerException is ArgumentNullException);});Require(f.Mutations==1&&s.AppendCalls==0);});
foreach(var binding in new[]{"principal","scheme","tenant","operation","action","kind","entity","acl"})
await Check("post-mutation receipt binding rejects without values or append "+binding,async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);var images=0;await f.Run(async c=>{var e=await Failed(()=>r.ExecuteAsync(c,_=>{f.Mutations++;return ValueTask.FromResult(new TenantChangeAuditMutation<int>(Receipt(c,binding),1,()=>{images++;return States();}));}).AsTask());Require(e.InnerException is TenantAccessDeniedException);});Require(f.Mutations==1&&images==0&&s.AppendCalls==0);});
foreach(var mode in new[]{TenantChangeAuditMode.MetadataOnly,TenantChangeAuditMode.ChangedFields,TenantChangeAuditMode.BeforeAfterSnapshots})
await Check("mode and field redaction remain selected by recorder "+mode,async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s,Policy(mode));var images=0;await f.Run(async c=>{await r.ExecuteAsync(c,_=>ValueTask.FromResult(new TenantChangeAuditMutation<int>(Receipt(c),2,()=>{images++;return States();})));});Require(images==(mode==TenantChangeAuditMode.MetadataOnly?0:1)&&s.AppendCalls==1&&s.Rows[0].Mode==mode&&!JsonSerializer.Serialize(s.Rows).Contains("private-",StringComparison.Ordinal));});
await Check("empty allowlist skips poisoned lazy states callback",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s,Policy(empty:true));await f.Run(async c=>{Require(await r.ExecuteAsync(c,_=>ValueTask.FromResult(new TenantChangeAuditMutation<int>(Receipt(c),9,()=>throw new IOException())))==9);});Require(s.AppendCalls==1&&s.Rows[0].Fields.Count==0);});
await Check("metadata mode needs no states factory",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s,Policy(TenantChangeAuditMode.MetadataOnly));await f.Run(async c=>{Require(await r.ExecuteAsync(c,_=>ValueTask.FromResult(new TenantChangeAuditMutation<int>(Receipt(c),3)))==3);});Require(s.Rows.Count==1&&s.Rows[0].Fields.Count==0);});
await Check("required missing states reports possible effects before append",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);await f.Run(async c=>{var e=await Failed(()=>r.ExecuteAsync(c,_=>{f.Mutations++;return ValueTask.FromResult(new TenantChangeAuditMutation<int>(Receipt(c),3));}).AsTask());Require(e.InnerException is ArgumentException);});Require(f.Mutations==1&&s.AppendCalls==0);});
await Check("throwing states projection preserves original failure and no automatic retry",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);var images=0;var original=new IOException("Controlled states failure.");await f.Run(async c=>{var e=await Failed(()=>r.ExecuteAsync(c,_=>{f.Mutations++;return ValueTask.FromResult(new TenantChangeAuditMutation<int>(Receipt(c),3,()=>{images++;throw original;}));}).AsTask());Require(ReferenceEquals(e.InnerException,original));});Require(f.Mutations==1&&images==1&&s.AppendCalls==0);});
await Check("sink failure remains a single uncertainty wrapper with no mutation or append retry",async()=>
{var f=new Fixture();var s=new Store{Fail=true};var r=Validated(f,s);await f.Run(async c=>{var e=await Failed(()=>r.ExecuteAsync(c,_=>{f.Mutations++;return ValueTask.FromResult(new TenantChangeAuditMutation<int>(Receipt(c),3,States));}).AsTask());Require(e.InnerException is IOException);});Require(f.Mutations==1&&s.AppendCalls==1&&s.Rows.Count==0);});
await Check("existing possible-commit exception thrown by callback is not double wrapped",async()=>
{var f=new Fixture();var s=new Store{Fail=true};var r=Validated(f,s);await f.Run(async c=>{var original=await Failed(()=>r.RecordAsync(c,Receipt(c),States).AsTask());var e=await Failed(()=>r.ExecuteAsync<int>(c,_=>throw original).AsTask());Require(ReferenceEquals(e,original));});Require(s.AppendCalls==1);});
await Check("caller token is forwarded to mutation exactly",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);using var ct=new CancellationTokenSource();await f.Run(async c=>{await r.ExecuteAsync(c,token=>{Require(token==ct.Token);return ValueTask.FromResult(new TenantChangeAuditMutation<int>(Receipt(c),1,States));},ct.Token);});Require(s.AppendCalls==1);});
await Check("caller cancellation after returned receipt still appends before reporting uncertainty",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);using var ct=new CancellationTokenSource();await f.Run(async c=>{var e=await Failed(()=>r.ExecuteAsync(c,_=>{f.Mutations++;ct.Cancel();return ValueTask.FromResult(new TenantChangeAuditMutation<int>(Receipt(c),1,States));},ct.Token).AsTask());Require(e.InnerException is OperationCanceledException);});Require(f.Mutations==1&&s.AppendCalls==1&&s.Rows.Count==1);});
await Check("pending caller cancellation does not mask failed persistence",async()=>
{var f=new Fixture();var s=new Store{Fail=true};var r=Validated(f,s);using var ct=new CancellationTokenSource();await f.Run(async c=>{var e=await Failed(()=>r.ExecuteAsync(c,_=>{ct.Cancel();return ValueTask.FromResult(new TenantChangeAuditMutation<int>(Receipt(c),1,States));},ct.Token).AsTask());Require(e.InnerException is IOException);});Require(s.AppendCalls==1);});
await Check("held append prevents result and caller cancellation leaves private write token live",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);using var ct=new CancellationTokenSource();var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var release=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);s.Gate=async token=>{entered.TrySetResult();await release.Task.WaitAsync(token);Require(!token.IsCancellationRequested&&token!=ct.Token);};await f.Run(async c=>{var work=r.ExecuteAsync(c,_=>{f.Mutations++;return ValueTask.FromResult(new TenantChangeAuditMutation<int>(Receipt(c),1,States));},ct.Token).AsTask();try{await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));Require(!work.IsCompleted&&s.Rows.Count==0);ct.Cancel();Require(!work.IsCompleted);}finally{release.TrySetResult();}var e=await Failed(()=>work);Require(e.InnerException is OperationCanceledException);});Require(f.Mutations==1&&s.Rows.Count==1&&s.AppendCalls==1);});
await Check("successful held append must complete before helper releases result",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var release=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);s.Gate=async token=>{entered.TrySetResult();await release.Task.WaitAsync(token);};await f.Run(async c=>{var work=r.ExecuteAsync(c,_=>ValueTask.FromResult(new TenantChangeAuditMutation<int>(Receipt(c),41,States))).AsTask();try{await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));Require(!work.IsCompleted&&s.Rows.Count==0);}finally{release.TrySetResult();}Require(await work==41&&s.Rows.Count==1);});});
await Check("private write deadline still bounds cooperative sink after mutation",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s,timeout:TimeSpan.FromMilliseconds(100));s.Gate=token=>Task.Delay(Timeout.InfiniteTimeSpan,token);await f.Run(async c=>{var e=await Failed(()=>r.ExecuteAsync(c,_=>{f.Mutations++;return ValueTask.FromResult(new TenantChangeAuditMutation<int>(Receipt(c),1,States));}).AsTask());Require(e.InnerException is OperationCanceledException);});Require(f.Mutations==1&&s.AppendCalls==1&&s.Rows.Count==0);});
await Check("callback invalidating checked lease cannot append after actual effects",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);await f.Run(async c=>{var e=await Failed(()=>r.ExecuteAsync(c,_=>{f.Mutations++;f.Clock.Advance(TimeSpan.FromMinutes(2));return ValueTask.FromResult(new TenantChangeAuditMutation<int>(Receipt(c),1,States));}).AsTask());Require(e.InnerException is TenantAccessDeniedException);});Require(f.Mutations==1&&s.AppendCalls==0);});
await Check("native observation expiry still prevents post-callback append",async()=>
{var f=new Fixture{Observed=true};var s=new Store();var r=Validated(f,s);var result=await f.Run(async c=>{var e=await Failed(()=>r.ExecuteAsync(c,_=>{f.Mutations++;f.Clock.Mono(3);return ValueTask.FromResult(new TenantChangeAuditMutation<int>(Receipt(c),1,States));}).AsTask());Require(e.InnerException is TenantAccessDeniedException);});Require(!result.IsSuccess&&f.Mutations==1&&s.AppendCalls==0);});
await Check("context expiry during append withholds result despite persisted trail",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);s.Gate=_=>{f.Clock.Advance(TimeSpan.FromMinutes(2));return Task.CompletedTask;};await f.Run(async c=>{var e=await Failed(()=>r.ExecuteAsync(c,_=>{f.Mutations++;return ValueTask.FromResult(new TenantChangeAuditMutation<int>(Receipt(c),1,States));}).AsTask());Require(e.InnerException is TenantAccessDeniedException);});Require(f.Mutations==1&&s.AppendCalls==1&&s.Rows.Count==1);});
await Check("single-consumption ValueTask source is consumed once",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);await f.Run(async c=>{var source=new OnceSource<TenantChangeAuditMutation<int>>(new(Receipt(c),7,States));Require(await r.ExecuteAsync(c,_=>source.Task)==7&&source.Gets==1);});Require(s.AppendCalls==1);});
await Check("independently scheduled executions do not share or suppress distinct mutations",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);var start=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);await f.Run(async c=>{var work=Enumerable.Range(0,16).Select(index=>Task.Run(async()=>{await start.Task;return await r.ExecuteAsync<int>(c,async _=>{Interlocked.Increment(ref f.Mutations);await Task.Yield();return new(Receipt(c),index,States);});})).ToArray();start.TrySetResult();var results=await Task.WhenAll(work);Require(results.Order().SequenceEqual(Enumerable.Range(0,16)));});Require(f.Mutations==16&&s.AppendCalls==16&&s.Rows.Count==16);});
await Check("separate new calls are not an idempotent mutation retry protocol",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);await f.Run(async c=>{var receipt=Receipt(c);await r.ExecuteAsync(c,_=>{f.Mutations++;return ValueTask.FromResult(new TenantChangeAuditMutation<int>(receipt,1,States));});var e=await Failed(()=>r.ExecuteAsync(c,_=>{f.Mutations++;return ValueTask.FromResult(new TenantChangeAuditMutation<int>(receipt,2,States));}).AsTask());Require(e.InnerException is InvalidOperationException);});Require(f.Mutations==2&&s.AppendCalls==2&&s.Rows.Count==1);});
await Check("direct preparation caller cancellation behavior remains unchanged",async()=>
{var f=new Fixture();var s=new Store();var r=Validated(f,s);using var ct=new CancellationTokenSource();await f.Run(async c=>{var p=r.Prepare(c);ct.Cancel();var e=await Failed(()=>p.CompleteAsync(Receipt(c),States,ct.Token).AsTask());Require(e.InnerException is OperationCanceledException);});Require(s.AppendCalls==0);});

Directory.CreateDirectory(Path.GetDirectoryName(output)!);await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{passed,failed,checks,scope="Local checked audit execution contracts; no atomic mutation/trail transaction, inferred receipt, backend exactly-once, durable provider or production qualification."},new JsonSerializerOptions{WriteIndented=true}));
Console.WriteLine($"Audit execution contracts: {passed}/{passed+failed}");return failed==0?0:1;

sealed record Result(string Name,int Number);
sealed class OnceSource<T>:IValueTaskSource<T>
{
 private ManualResetValueTaskSourceCore<T> core;
 public int Gets;
 public OnceSource(T value){core.RunContinuationsAsynchronously=true;core.SetResult(value);}
 public ValueTask<T> Task=>new(this,core.Version);
 public T GetResult(short token){if(Interlocked.Increment(ref Gets)!=1)throw new InvalidOperationException("ValueTask consumed more than once.");return core.GetResult(token);}
 public ValueTaskSourceStatus GetStatus(short token)=>core.GetStatus(token);
 public void OnCompleted(Action<object?> continuation,object? state,short token,ValueTaskSourceOnCompletedFlags flags)=>core.OnCompleted(continuation,state,token,flags);
}
sealed class Clock:TimeProvider
{public DateTimeOffset Now=DateTimeOffset.Parse("2026-11-21T00:00:00Z");public long Timestamp;public override long TimestampFrequency=>TimeSpan.TicksPerSecond;public override DateTimeOffset GetUtcNow()=>Now;public override long GetTimestamp()=>Timestamp;public void Advance(TimeSpan t){Now+=t;Timestamp+=t.Ticks;}public void Mono(int seconds)=>Timestamp+=TimeSpan.FromSeconds(seconds).Ticks;}
sealed class Fixture:IIdentitySource,IIdentitySessionStatusSource,ITenantMembershipSource,IResourceScopeSource,ITenantAccessPolicy
{
 public Clock Clock{get;}=new();public int Mutations;public bool Observed;
 public TenantOperationRegistryBuilder Builder{get;}=new();public TenantOperationRegistry Registry{get;}
 private Func<TenantOperationContext,Task> body=_=>Task.CompletedTask;
 public Fixture(){foreach(var op in new[]{("document.update","write"),("other.read","read")})Builder.Register<string,bool>(op.Item1,op.Item2,"document",x=>x,x=>{var parts=x.Split(':',2);return new(new(parts[0]),parts[1]);},()=>new Handler(this));Registry=Builder.Build();}
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
 public List<TenantChangeAuditRecord> Rows{get;}=[];public int AppendCalls;public bool Fail;public Func<CancellationToken,Task>? Gate;
 public async ValueTask AppendAsync(TenantChangeAuditRecord record,CancellationToken token){Interlocked.Increment(ref AppendCalls);if(Gate is not null)await Gate(token);if(Fail)throw new IOException("Controlled fixture sink failure.");lock(Rows){if(Rows.Any(x=>x.Receipt.ReceiptId==record.Receipt.ReceiptId))throw new InvalidOperationException("Duplicate fixture receipt.");Rows.Add(record);}}
}
