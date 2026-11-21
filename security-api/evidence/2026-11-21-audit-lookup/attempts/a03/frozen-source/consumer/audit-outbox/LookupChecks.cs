extern alias securityapi;
using System.Collections.Concurrent;
using System.Net.Http.Json;
using Cehpalon.Engine.Tenancy;
using Npgsql;
using securityapi::SecurityApi;
using Host=securityapi::SecurityApi.Host;

namespace AuditOutbox;

public static class LookupChecks
{
    private static void Require(bool value){if(!value)throw new InvalidOperationException("Exact lookup consumer assertion failed.");}
    private static TaskCompletionSource Signal()=>new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static async Task<Exception> Failure(Func<Task> action){try{await action();}catch(Exception error){return error;}throw new InvalidOperationException("Expected lookup failure.");}
    private static async Task Join(Task task){try{await task;}catch(Exception){}}
    private static TenantChangeAuditPolicy Policy(TenantChangeAuditMode mode=TenantChangeAuditMode.ChangedFields)=>OutboxIntegration.Policy(mode);
    private static TenantChangeReceipt Receipt(TenantChangeReceipt r,Guid? id=null,TenantId? tenant=null)=>new(id??r.ReceiptId,r.Principal,r.AuthenticationScheme,tenant??r.Tenant,r.OperationId,r.Action,r.ResourceKind,r.ResourceId,r.AuthorizationResourceVersion,r.Kind,r.BeforeEntityVersion,r.AfterEntityVersion,r.ReportedAtUtc);
    private static TenantChangeAuditRecord Copy(TenantChangeAuditRecord r,TenantChangeReceipt receipt,IEnumerable<TenantChangeField>? fields=null,TenantChangeAuditMode? mode=null,TenantChangeAuditMode? captured=null)=>new(receipt,r.RecordedAtUtc,mode??r.Mode,fields??r.Fields,captured??r.CapturedMode);
    private static async Task<TenantChangeAuditRecord?> Read(LookupHost host,Guid id,string tenant="A")
    {var result=await host.Run(id,tenant);Require(result.IsSuccess&&result.Value.Tenant==tenant);return result.Value.Record;}
    public static async Task Run(Func<string,Func<Task>,Task> outer,Func<Task<PostgresStore>> createStore,Func<PostgresStore,Task> mutate,string connection,Action<object> observe)
    {
        var stores=new List<PostgresStore>();async Task<PostgresStore> Store(){var store=await createStore();stores.Add(store);return store;}
        async Task Check(string name,Func<Task> action)=>await outer(name,async()=>{stores.Clear();await action();Require(stores.All(s=>s.StatusReads==0&&s.HistoryReads==0));});
        async Task<TenantChangeAuditRecord> Publish(PostgresStore store)
        {await mutate(store);var record=PayloadCodec.Decode((await store.Payloads()).Last());Require((await new RelayHost(TenantChangeAuditOutboxRelay.Activate(true,()=>store,()=>store)).Run()).IsSuccess);return record;}
        PostgresLookupSource Source(PostgresStore store)=>new(connection,store.Schema);
        async Task<TenantChangeAuditRecord> Snapshot(PostgresStore store)
        {
            var original=await Publish(store);var record=Copy(original,Receipt(original.Receipt,Guid.NewGuid()),original.Fields.Concat([new TenantChangeField("same",TenantChangeValue.Text("stable"),TenantChangeValue.Text("stable"),false),new("unknown",TenantChangeValue.Text("unlisted-before"),TenantChangeValue.Text("unlisted-after"))]),TenantChangeAuditMode.BeforeAfterSnapshots,TenantChangeAuditMode.BeforeAfterSnapshots);await store.AppendOnceAsync(record,default);return record;
        }
        await Check("lookup Disabled skips poisoned source and host factory work",()=>
        {
            var factories=0;var policy=new TenantChangeAuditPolicy(TenantChangeAuditMode.Disabled);Require(LookupHost.Activate(policy,()=>{factories++;throw new InvalidOperationException();}) is null&&TenantChangeAuditLookupReader.Activate(policy) is null&&factories==0);observe(new{phase="disabled",source_factories=0,host_activated=false});return Task.CompletedTask;
        });
        await Check("lookup adapter rejects unowned schema and direct Disabled reader rejects activation",()=>
        {
            var bad=false;try{_ =new PostgresLookupSource(connection,"public; SELECT secret");}catch(ArgumentException){bad=true;}Require(bad);var source=new PostgresLookupSource(connection,"ao_"+Guid.NewGuid().ToString("N"));var disabled=false;try{_ =new TenantChangeAuditLookupReader(source,new(TenantChangeAuditMode.Disabled));}catch(ArgumentException){disabled=true;}Require(disabled&&source.QueryAttempts==0&&source.Connections==0);return Task.CompletedTask;
        });
        await Check("selected lookup factory construction is distinct from authorization denied query zero",async()=>
        {
            var store=await Store();var source=Source(store);var factories=0;var host=LookupHost.Activate(Policy(),()=>{factories++;return source;})!;host.Authority.AllowLookup=false;Require(!(await host.Run(Guid.NewGuid())).IsSuccess&&factories==1&&source.QueryAttempts==0&&source.Connections==0&&host.HandlerFactories==0);observe(new{phase="denied",selected_source_factories=1,lookup_queries=0,connections=0});
        });
        await Check("new typed lookup registration stays lazy before selected dispatch",()=>
        {
            var source=new PostgresLookupSource(connection,"ao_"+Guid.NewGuid().ToString("N"));var host=new LookupHost(new(source,Policy()));Require(host.GatewayFactories==0&&host.HandlerFactories==0&&source.QueryAttempts==0&&source.Connections==0);return Task.CompletedTask;
        });
        await Check("lookup null context empty receipt and pre-caller cancellation reject before query",async()=>
        {
            var store=await Store();var source=Source(store);var reader=new TenantChangeAuditLookupReader(source,Policy());var host=new LookupHost(reader);Require(await Failure(()=>reader.FindAsync(null!,Guid.NewGuid()).AsTask()) is ArgumentNullException);Require(await Failure(()=>host.Run(Guid.Empty).AsTask()) is ArgumentException);using var caller=new CancellationTokenSource();caller.Cancel();Require(await Failure(()=>host.Run(Guid.NewGuid(),token:caller.Token).AsTask()) is OperationCanceledException cancelled&&cancelled.CancellationToken==caller.Token&&source.QueryAttempts==0);
        });
        await Check("committed pending receipt is absent until actual relay publishes exact final payload",async()=>
        {
            var store=await Store();await mutate(store);var record=PayloadCodec.Decode((await store.Payloads()).Single());var source=Source(store);var host=new LookupHost(new(source,Policy()));Require(await Read(host,record.Receipt.ReceiptId) is null&&(await store.Counts())==(1,0,0));Require((await new RelayHost(TenantChangeAuditOutboxRelay.Activate(true,()=>store,()=>store)).Run()).IsSuccess);var found=await Read(host,record.Receipt.ReceiptId);Require(found is not null&&PayloadCodec.Encode(found)==PayloadCodec.Encode(record)&&source.QueryAttempts==2&&(await store.Counts())==(1,1,1));observe(new{phase="pending_to_published",pending_lookup_null=true,post_relay_exact_lookup=true,absence_is_not_commit_or_health_proof=true});
        });
        await Check("missing exact receipt returns provider absence without mutating stored rows",async()=>
        {
            var store=await Store();await Publish(store);var before=(await store.Payloads("audit_sink")).Single();var row=await store.Row();var source=Source(store);Require(await Read(new(new(source,Policy())),Guid.NewGuid()) is null&&source.QueryAttempts==1&&(await store.Payloads("audit_sink")).Single()==before&&(await store.Row())==row&&(await store.Counts())==(1,1,1));
        });
        await Check("actual sink tenant keys isolate the same receipt Guid in A and B",async()=>
        {
            var store=await Store();var a=await Publish(store);var b=Copy(a,Receipt(a.Receipt,tenant:new("B")),[new("title",TenantChangeValue.Text("B-before"),TenantChangeValue.Text("B-after"))]);await store.AppendOnceAsync(b,default);var source=Source(store);var host=new LookupHost(new(source,Policy()));Require(!(await host.Run(a.Receipt.ReceiptId,"B")).IsSuccess&&source.QueryAttempts==0);host.Authority.AllowB=true;var av=await Read(host,a.Receipt.ReceiptId);var bv=await Read(host,a.Receipt.ReceiptId,"B");Require(av is not null&&bv is not null&&av.Receipt.Tenant.Value=="A"&&bv.Receipt.Tenant.Value=="B"&&av.Receipt.ReceiptId==bv.Receipt.ReceiptId&&av.Fields.Single(f=>f.Name=="title").After.TextValue!=bv.Fields.Single().After.TextValue&&(await store.Counts("B")).Sink==1);observe(new{phase="same_receipt",controlled_sink_rows=true,same_guid=true,tenant_partitioned=true,independent_B_grant=true});
        });
        await Check("MetadataOnly lookup creates fresh metadata and preserves captured mode",async()=>
        {
            var store=await Store();var raw=await Publish(store);var source=new Wrapper(Source(store));var found=await Read(new(new(source,Policy(TenantChangeAuditMode.MetadataOnly))),raw.Receipt.ReceiptId);Require(found is not null&&found.Mode==TenantChangeAuditMode.MetadataOnly&&found.CapturedMode==raw.CapturedMode&&found.Fields.Count==0&&!ReferenceEquals(found,source.LastRecord)&&source.LastRecord!.Fields.Count==raw.Fields.Count);
        });
        await Check("ChangedFields lookup drops unknown unchanged fields and redacts both values",async()=>
        {
            var store=await Store();var raw=await Snapshot(store);var policy=new TenantChangeAuditPolicy(TenantChangeAuditMode.ChangedFields,[new("entity.update","update","entity",[new("title",true),new("same")])]);var found=await Read(new(new(Source(store),policy)),raw.Receipt.ReceiptId);Require(found is not null&&found.Mode==TenantChangeAuditMode.ChangedFields&&found.CapturedMode==TenantChangeAuditMode.BeforeAfterSnapshots&&found.Fields.Count==1&&found.Fields[0].Name=="title"&&found.Fields[0].Before.Kind==TenantChangeValueKind.Redacted&&found.Fields[0].After.Kind==TenantChangeValueKind.Redacted);
        });
        await Check("BeforeAfterSnapshots lookup preserves captured unchanged fields under current rules",async()=>
        {
            var store=await Store();var raw=await Snapshot(store);var policy=new TenantChangeAuditPolicy(TenantChangeAuditMode.BeforeAfterSnapshots,[new("entity.update","update","entity",[new("title"),new("same"),new("secret",true)])]);var found=await Read(new(new(Source(store),policy)),raw.Receipt.ReceiptId);Require(found is not null&&found.Mode==TenantChangeAuditMode.BeforeAfterSnapshots&&found.CapturedMode==TenantChangeAuditMode.BeforeAfterSnapshots&&found.Fields.Count==3&&!found.Fields.Single(f=>f.Name=="same").WasChanged&&found.Fields.All(f=>f.Name!="unknown"));
        });
        await Check("richer lookup policy cannot restore redacted or omitted capture values",async()=>
        {
            var store=await Store();var raw=await Publish(store);var policy=new TenantChangeAuditPolicy(TenantChangeAuditMode.BeforeAfterSnapshots,[new("entity.update","update","entity",[new("title"),new("amount"),new("secret")])]);var source=Source(store);var host=new LookupHost(new(source,policy));var found=await Read(host,raw.Receipt.ReceiptId);Require(found is not null&&found.Mode==TenantChangeAuditMode.ChangedFields&&found.CapturedMode==TenantChangeAuditMode.ChangedFields&&found.Fields.Single(f=>f.Name=="secret").Before.Kind==TenantChangeValueKind.Redacted&&found.Fields.Single(f=>f.Name=="secret").After.Kind==TenantChangeValueKind.Redacted);var omitted=Copy(raw,Receipt(raw.Receipt,Guid.NewGuid()),[],TenantChangeAuditMode.MetadataOnly);await store.AppendOnceAsync(omitted,default);var empty=await Read(host,omitted.Receipt.ReceiptId);Require(empty is not null&&empty.Mode==TenantChangeAuditMode.MetadataOnly&&empty.Fields.Count==0&&empty.CapturedMode==raw.CapturedMode);
        });
        await Check("lookup wrong returned tenant is a source integrity fault even under metadata policy",async()=>
        {
            var store=await Store();var raw=await Publish(store);var requested=Guid.NewGuid();var encoded=Copy(raw,Receipt(raw.Receipt,requested,new("B")));await new SqlProbe(connection,store.Schema).SeedPayloadRow(requested,encoded);var actual=Source(store);var host=new LookupHost(new(actual,Policy(TenantChangeAuditMode.MetadataOnly)));Require(await Failure(()=>host.Run(requested).AsTask()) is InvalidOperationException&&actual.QueryAttempts==1&&host.ReaderResults==0);observe(new{phase="stored_identity_mismatch",kind="tenant",actual_sql_row_key_tenant="A",encoded_tenant="B",fault_before_reader_return=true});
            var source=new Wrapper(actual);source.After=(record,_,_,_)=>Task.FromResult<TenantChangeAuditRecord?>(Copy(record!,Receipt(record!.Receipt,tenant:new("B"))));var wrapped=new LookupHost(new(source,Policy(TenantChangeAuditMode.MetadataOnly)));Require(await Failure(()=>wrapped.Run(raw.Receipt.ReceiptId).AsTask()) is InvalidOperationException&&source.Calls==1&&wrapped.ReaderResults==0);
        });
        await Check("lookup wrong returned receipt is a source integrity fault before projection",async()=>
        {
            var store=await Store();var raw=await Publish(store);var requested=Guid.NewGuid();var encoded=Copy(raw,Receipt(raw.Receipt,Guid.NewGuid()));await new SqlProbe(connection,store.Schema).SeedPayloadRow(requested,encoded);var actual=Source(store);var host=new LookupHost(new(actual,Policy(TenantChangeAuditMode.MetadataOnly)));Require(await Failure(()=>host.Run(requested).AsTask()) is InvalidOperationException&&actual.QueryAttempts==1&&host.ReaderResults==0);observe(new{phase="stored_identity_mismatch",kind="receipt",actual_sql_key_matches_request=true,encoded_receipt_differs=true,fault_before_reader_return=true});
            var source=new Wrapper(actual);source.After=(record,_,_,_)=>Task.FromResult<TenantChangeAuditRecord?>(Copy(record!,Receipt(record!.Receipt,Guid.NewGuid())));var wrapped=new LookupHost(new(source,Policy(TenantChangeAuditMode.MetadataOnly)));Require(await Failure(()=>wrapped.Run(raw.Receipt.ReceiptId).AsTask()) is InvalidOperationException&&source.Calls==1&&wrapped.ReaderResults==0);
        });
        await Check("live operation-metadata history relay and inspect scopes do not grant field lookup",async()=>
        {
            var store=await Store();var source=Source(store);var reader=new TenantChangeAuditLookupReader(source,Policy());
            foreach(var scope in new[]{("read","audit-history"),("relay","audit-outbox"),("inspect","audit-outbox")}){var host=new LookupHost(reader,scope.Item1,scope.Item2);Require(await Failure(()=>host.Run(Guid.NewGuid()).AsTask()) is TenantAccessDeniedException&&host.HandlerFactories==1&&source.QueryAttempts==0);}
            var exact=new LookupHost(reader);exact.Authority.GrantedOperation="outbox.relay";Require(!(await exact.Run(Guid.NewGuid())).IsSuccess&&exact.HandlerFactories==0&&source.QueryAttempts==0);
        });
        await Check("lookup forwards original caller token and retains exact provider failure objects",async()=>
        {
            var store=await Store();var raw=await Publish(store);var source=new Wrapper(Source(store));var host=new LookupHost(new(source,Policy()));using var caller=new CancellationTokenSource();Require((await host.Run(raw.Receipt.ReceiptId,token:caller.Token)).IsSuccess&&source.Tokens.Single()==caller.Token);
            using var other=new CancellationTokenSource();other.Cancel();foreach(var original in new Exception[]{new IOException("Controlled lookup wrapper failure."),new OperationCanceledException(other.Token)}){source.Override=(_,_,_)=>throw original;Require(ReferenceEquals(await Failure(()=>host.Run(raw.Receipt.ReceiptId,token:caller.Token).AsTask()),original));}
        });
        await Check("caller cancellation after actual record query withholds reader result before outer dispatch",async()=>
        {
            var store=await Store();var raw=await Publish(store);var actual=Source(store);var source=new Wrapper(actual);using var caller=new CancellationTokenSource();source.After=(record,_,_,_)=>{caller.Cancel();return Task.FromResult(record);};var host=new LookupHost(new(source,Policy()));Require(await Failure(()=>host.Run(raw.Receipt.ReceiptId,token:caller.Token).AsTask()) is OperationCanceledException cancelled&&cancelled.CancellationToken==caller.Token&&actual.QueryAttempts==1&&host.ReaderResults==0&&(await store.Counts())==(1,1,1));
        });
        await Check("caller cancellation after actual null query also withholds reader result",async()=>
        {
            var store=await Store();var actual=Source(store);var source=new Wrapper(actual);using var caller=new CancellationTokenSource();source.After=(record,_,_,_)=>{Require(record is null);caller.Cancel();return Task.FromResult(record);};var host=new LookupHost(new(source,Policy()));Require(await Failure(()=>host.Run(Guid.NewGuid(),token:caller.Token).AsTask()) is OperationCanceledException cancelled&&cancelled.CancellationToken==caller.Token&&actual.QueryAttempts==1&&host.ReaderResults==0);
        });
        await Check("record and null lookup preserve expired live-scope latch after fixture clock restore",async()=>
        {
            foreach(var present in new[]{true,false})
            {
                var store=await Store();var raw=await Publish(store);var actual=Source(store);var source=new Wrapper(actual);var clock=new FixtureClock();var host=new LookupHost(new(source,Policy()),clock:clock);var latched=false;source.After=(record,_,_,_)=>{Require((record is not null)==present);clock.Advance(TimeSpan.FromMinutes(1));try{host.RetainedContext!.DemandAccess(new("A"),"audit-trail","tenant","read");}catch(TenantAccessDeniedException){latched=true;}clock.Advance(TimeSpan.FromMinutes(-1));return Task.FromResult(record);};Require(await Failure(()=>host.Run(present?raw.Receipt.ReceiptId:Guid.NewGuid()).AsTask()) is TenantAccessDeniedException&&latched&&host.ReaderResults==0&&actual.QueryAttempts==1);observe(new{phase="scope_latch",provider_return=present?"record":"null",clock_restored=true,reader_results=0});
            }
        });
        await Check("uncooperative record and null source wrappers are held then unblocked and joined after caller cancellation",async()=>
        {
            foreach(var present in new[]{true,false})
            {
                var store=await Store();var raw=await Publish(store);var actual=Source(store);var source=new Wrapper(actual);var pause=new Pause();source.After=async(record,_,_,token)=>{Require((record is not null)==present);await pause.Wait(token);return record;};var host=new LookupHost(new(source,Policy()));using var caller=new CancellationTokenSource();var pending=host.Run(present?raw.Receipt.ReceiptId:Guid.NewGuid(),token:caller.Token).AsTask();
                try{await pause.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));caller.Cancel();await pause.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(10));Require(!pending.IsCompleted&&host.ReaderResults==0);pause.Release();Require(await Failure(()=>pending).WaitAsync(TimeSpan.FromSeconds(10)) is OperationCanceledException&&host.ReaderResults==0);}
                finally{caller.Cancel();pause.Release();await Join(pending);await source.JoinOwned();}
                Require(source.Owned.All(t=>t.IsCompleted)&&(await store.Counts())==(1,1,1));observe(new{phase="held_source",provider_return=present?"record":"null",caller_cancelled_while_held=true,task_not_abandoned=true,all_source_tasks_joined=true});
            }
        });
        await Check("actual tagged PostgreSQL lookup Lock wait receives cancellation and quiesces before reuse",async()=>
        {
            var store=await Store();var raw=await Publish(store);var original=(await store.Payloads("audit_sink")).Single();var actual=Source(store);var host=new LookupHost(new(actual,Policy()));using var caller=new CancellationTokenSource();var probe=new SqlProbe(connection,store.Schema);var blocker=await probe.HoldSink();var pending=host.Run(raw.Receipt.ReceiptId,token:caller.Token).AsTask();var pid=0;
            try{pid=await probe.Observe(actual,pending,caller.Token);caller.Cancel();Require(await Failure(()=>pending).WaitAsync(TimeSpan.FromSeconds(10)) is OperationCanceledException&&host.ReaderResults==0&&await probe.Quiescent(actual,pid));}
            finally{caller.Cancel();await blocker.DisposeAsync();await Join(pending);}
            var found=await Read(host,raw.Receipt.ReceiptId);Require(found is not null&&actual.QueryAttempts==2&&await probe.Quiescent(actual,pid)&&(await store.Payloads("audit_sink")).Single()==original&&(await store.Counts())==(1,1,1));observe(new{phase="actual_sql_cancel",sql_tag="owned-audit-receipt-lookup",backend_pid=pid,lock_observed_before_caller_cancel=true,command_completed_before_blocker_release=true,backend_quiescent=true,source_reused=true,rows_unchanged=true});
        });
        await Check("independently scheduled same-ID tenant lookups preserve partition and data",async()=>
        {
            var store=await Store();var a=await Publish(store);var b=Copy(a,Receipt(a.Receipt,tenant:new("B")),[new("title",TenantChangeValue.Text("B-before"),TenantChangeValue.Text("B-concurrent"))]);await store.AppendOnceAsync(b,default);var source=Source(store);var reader=new TenantChangeAuditLookupReader(source,Policy());var hostA=new LookupHost(reader);var hostB=new LookupHost(reader);hostB.Authority.AllowB=true;var start=Signal();var workers=Enumerable.Range(0,8).Select(i=>Task.Run(async()=>{await start.Task;var value=await Read(i%2==0?hostA:hostB,a.Receipt.ReceiptId,i%2==0?"A":"B");Require(value is not null&&value.Receipt.Tenant.Value==(i%2==0?"A":"B"));return value;})).ToArray();start.TrySetResult();var values=await Task.WhenAll(workers);Require(source.QueryAttempts==8&&hostA.Authority.IdentityLookups==4&&hostB.Authority.IdentityLookups==4&&values.Count(x=>x!.Receipt.Tenant.Value=="A")==4&&values.Count(x=>x!.Receipt.Tenant.Value=="B")==4&&(await store.Counts())==(1,1,1)&&(await store.Counts("B")).Sink==1);observe(new{phase="concurrent_reads",independently_scheduled_workers=8,tenant_A=4,tenant_B=4,rows_unchanged=true});
        });
        await Check("configured immutable lookup policy changes only through newly selected reader",async()=>
        {
            var store=await Store();var raw=await Publish(store);var source=Source(store);var policy=Policy();var reader=new TenantChangeAuditLookupReader(source,policy);var existing=new LookupHost(reader);Require((await Read(existing,raw.Receipt.ReceiptId))!.Fields.Count==raw.Fields.Count);policy=Policy(TenantChangeAuditMode.MetadataOnly);Require((await Read(existing,raw.Receipt.ReceiptId))!.Fields.Count==raw.Fields.Count);var fresh=await Read(new(new(source,policy)),raw.Receipt.ReceiptId);Require(fresh is not null&&fresh.Fields.Count==0&&fresh.CapturedMode==raw.CapturedMode);
        });
        await Check("disposed lookup context and live writer context cannot query field history",async()=>
        {
            var store=await Store();var raw=await Publish(store);var source=Source(store);var reader=new TenantChangeAuditLookupReader(source,Policy());var host=new LookupHost(reader);await Read(host,raw.Receipt.ReceiptId);Require(await Failure(()=>reader.FindAsync(host.RetainedContext!,raw.Receipt.ReceiptId).AsTask()) is TenantAccessDeniedException&&source.QueryAttempts==1);var denied=false;await MutateWriter(store,async context=>{try{await reader.FindAsync(context,raw.Receipt.ReceiptId);}catch(TenantAccessDeniedException){denied=true;}});Require(denied&&source.QueryAttempts==1&&(await store.Counts())==(2,1,1));
        });
    }
    private static async Task MutateWriter(PostgresStore store,Func<TenantOperationContext,Task> after)
    {
        var integration=new OutboxIntegration(store,OutboxIntegration.Policy(TenantChangeAuditMode.ChangedFields)){AfterMutation=after};using var tls=new TlsFixture();using var jwt=new JwtFixture();await using var host=new Host();await host.Start(tls,jwt,trailProfile:new(TenantChangeAuditMode.ChangedFields),trailIntegration:integration);using var client=tls.Client(host.Address);using var request=new HttpRequestMessage(HttpMethod.Post,"/entity/update"){Content=JsonContent.Create(new EntityMutationRequest("A","shared","lookup-writer",6,"private-lookup"))};request.Headers.Authorization=new("Bearer",jwt.Token());using var response=await client.SendAsync(request);Require(response.IsSuccessStatusCode);
    }
    private sealed class Wrapper(ITenantChangeAuditLookupSource inner):ITenantChangeAuditLookupSource
    {
        public int Calls;public TenantChangeAuditRecord? LastRecord;public ConcurrentQueue<CancellationToken> Tokens{get;}=new();public ConcurrentBag<Task> Owned{get;}=new();
        public Func<TenantId,Guid,CancellationToken,ValueTask<TenantChangeAuditRecord?>>? Override;
        public Func<TenantChangeAuditRecord?,TenantId,Guid,CancellationToken,Task<TenantChangeAuditRecord?>>? After;
        public ValueTask<TenantChangeAuditRecord?> FindAsync(TenantId tenant,Guid receipt,CancellationToken token)
        {Interlocked.Increment(ref Calls);Tokens.Enqueue(token);var task=Execute(tenant,receipt,token);Owned.Add(task);return new(task);}
        private async Task<TenantChangeAuditRecord?> Execute(TenantId tenant,Guid receipt,CancellationToken token)
        {var record=Override is null?await inner.FindAsync(tenant,receipt,token):await Override(tenant,receipt,token);LastRecord=record;return After is null?record:await After(record,tenant,receipt,token);}
        public async Task JoinOwned()=>await Task.WhenAll(Owned.Select(Join));
    }
    private sealed class Pause
    {
        public TaskCompletionSource Entered{get;}=Signal();public TaskCompletionSource Cancelled{get;}=Signal();private readonly TaskCompletionSource exit=Signal();
        public async Task Wait(CancellationToken token){using var registration=token.Register(()=>Cancelled.TrySetResult());Entered.TrySetResult();await exit.Task;}
        public void Release()=>exit.TrySetResult();
    }
    private sealed class FixtureClock:TimeProvider
    {
        private readonly DateTimeOffset origin=DateTimeOffset.UtcNow;private long ticks;public override long TimestampFrequency=>TimeSpan.TicksPerSecond;public override DateTimeOffset GetUtcNow()=>origin.AddTicks(ticks);public override long GetTimestamp()=>ticks;public void Advance(TimeSpan duration)=>ticks+=duration.Ticks;
    }
    private sealed class SqlLock(NpgsqlConnection connection,NpgsqlTransaction transaction):IAsyncDisposable
    {
        private int disposed;public async ValueTask DisposeAsync(){if(Interlocked.Exchange(ref disposed,1)!=0)return;try{await transaction.RollbackAsync();}finally{await transaction.DisposeAsync();await connection.DisposeAsync();}}
    }
    private sealed class SqlProbe(string connection,string schema)
    {
        private async Task<NpgsqlConnection> Open(){var c=new NpgsqlConnection(connection);try{await c.OpenAsync();return c;}catch{await c.DisposeAsync();throw;}}
        // Explicit faulty stored-row fixture only: the SQL key and encoded receipt deliberately disagree.
        public async Task SeedPayloadRow(Guid requested,TenantChangeAuditRecord encoded)
        {await using var c=await Open();await using var cmd=new NpgsqlCommand($"INSERT INTO {schema}.audit_sink(tenant,receipt,payload) VALUES($1,$2,$3)",c);cmd.Parameters.AddWithValue("A");cmd.Parameters.AddWithValue(requested);cmd.Parameters.AddWithValue(PayloadCodec.Encode(encoded));await cmd.ExecuteNonQueryAsync();}
        public async Task<SqlLock> HoldSink(){var c=await Open();var tx=await c.BeginTransactionAsync();try{await using var cmd=new NpgsqlCommand($"LOCK TABLE {schema}.audit_sink IN ACCESS EXCLUSIVE MODE",c,tx);await cmd.ExecuteNonQueryAsync();return new(c,tx);}catch{await tx.DisposeAsync();await c.DisposeAsync();throw;}}
        public async Task<int> Observe(PostgresLookupSource source,Task pending,CancellationToken caller)
        {
            await using var c=await Open();for(var i=0;i<100;i++)
            {
                await using var cmd=new NpgsqlCommand("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND application_name=$2 AND wait_event_type='Lock' AND query LIKE $3 AND query LIKE $4)",c);cmd.Parameters.AddWithValue(source.LastBackendPid);cmd.Parameters.AddWithValue(source.ApplicationName);cmd.Parameters.AddWithValue("%owned-audit-receipt-lookup%");cmd.Parameters.AddWithValue("%"+schema+".audit_sink%");if((bool)(await cmd.ExecuteScalarAsync())!){Require(!pending.IsCompleted&&!caller.IsCancellationRequested);return source.LastBackendPid;}Require(!pending.IsCompleted);await Task.Delay(20);
            }
            throw new InvalidOperationException("Actual tagged lookup Lock wait was not observed before cancellation.");
        }
        public async Task<bool> Quiescent(PostgresLookupSource source,int pid){Require(pid>0);await using var c=await Open();await using var cmd=new NpgsqlCommand("SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND application_name=$2 AND (state='active' OR wait_event_type='Lock'))",c);cmd.Parameters.AddWithValue(pid);cmd.Parameters.AddWithValue(source.ApplicationName);return(bool)(await cmd.ExecuteScalarAsync())!;}
    }
}
