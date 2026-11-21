extern alias securityapi;
using System.Text.Json;
using Cehpalon.Engine.Composition;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;
using Npgsql;
using securityapi::SecurityApi;
using Host=securityapi::SecurityApi.Host;

namespace AuditOutbox;

public static class IndexedStorageChecks
{
    private static void Require(bool value){if(!value)throw new InvalidOperationException("Indexed storage consumer assertion failed.");}
    private static TaskCompletionSource Signal()=>new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static async Task<Exception> Failure(Func<Task> action){try{await action();}catch(Exception error){return error;}throw new InvalidOperationException("Expected indexed profile failure.");}
    private static async Task Join(Task task){try{await task;}catch(Exception){}}
    private static Guid Key(int n)=>Guid.Parse("00000000-0000-0000-0000-"+n.ToString("x12"));
    private static TenantChangeAuditRecord Record(Guid id,string tenant="A",string kind="entity",string resource="shared",string title="indexed",DateTimeOffset? at=null)=>new(new(id,new PrincipalId("owned-indexed-fixture","reported-writer"),"fixture-service",new(tenant),"entity.update","update",kind,resource,"fixture-v1",TenantChangeKind.Update,"0","1"),at??DateTimeOffset.UnixEpoch.AddDays(20000),TenantChangeAuditMode.ChangedFields,[new("title",TenantChangeValue.Text("before"),TenantChangeValue.Text(title)),new("secret",TenantChangeValue.Text("sensitive-before"),TenantChangeValue.Text("sensitive-after"))]);
    private static TenantChangeAuditPolicy Policy(TenantChangeAuditMode mode=TenantChangeAuditMode.ChangedFields)=>new(mode,[new("entity.update","update","entity",[new("title"),new("secret",true)])]);
    private static TenantChangeAuditResourceQuery Q(int limit=50,TenantChangeAuditResourceCursor? cursor=null,string kind="entity",string resource="shared")=>new(kind,resource,limit,cursor);
    public static async Task Run(Func<string,Func<Task>,Task> outer,Func<Task<PostgresStore>> createStore,Func<PostgresStore,Task> mutate,string connection,string connectionFile,Action<object> observe)
    {
        var stores=new List<PostgresStore>();var actualCredentialReads=0;
        async ValueTask<string> Credentials(CancellationToken token){Interlocked.Increment(ref actualCredentialReads);return(await File.ReadAllTextAsync(connectionFile,token)).Trim();}
        async Task<PostgresStore> Store(){var store=await createStore();stores.Add(store);return store;}
        async Task Check(string name,Func<Task> action)=>await outer(name,async()=>{stores.Clear();actualCredentialReads=0;await action();Require(stores.All(s=>s.StatusReads==0&&s.HistoryReads==0));});
        Task<IndexedProfileActivation> Activate(PostgresStore store,IndexedProfileCounters counters,IndexedProfileOpenMode mode=IndexedProfileOpenMode.CreateNew,CancellationToken token=default)=>IndexedProfileComposition.ActivateAsync(IndexedProfileComposition.Configuration(true),store.Schema,mode,Credentials,counters,token);
        await Check("indexed Support module compilation is pure and yields immutable selected plan",()=>
        {
            var counters=new IndexedProfileCounters();var compiled=IndexedProfileComposition.Compile(IndexedProfileComposition.Configuration(true));Require(compiled.IsSuccess&&compiled.Plan!.ActivationOrder.SequenceEqual(new[]{IndexedProfileComposition.ModuleId})&&compiled.Plan.Modules.Single().Role==ModuleRole.Support&&counters.FactoryCalls==0&&actualCredentialReads==0);return Task.CompletedTask;
        });
        await Check("disabled indexed module skips credential factory constructor and SQL",async()=>
        {
            var counters=new IndexedProfileCounters();await using var selected=await IndexedProfileComposition.ActivateAsync(IndexedProfileComposition.Configuration(false),"unused-invalid-schema",(IndexedProfileOpenMode)99,_=>throw new InvalidOperationException(),counters);Require(selected.Storage is null&&selected.Plan.ActivationOrder.Count==0&&counters.FactoryCalls==0&&counters.CredentialCalls==0&&counters.Constructors==0&&actualCredentialReads==0);
        });
        await Check("invalid indexed configuration and selected invalid arguments reject before factories",async()=>
        {
            var counters=new IndexedProfileCounters();foreach(var config in new[]{"{}",IndexedProfileComposition.Configuration(true).Replace("RequestReply","Other",StringComparison.Ordinal)})Require(await Failure(()=>IndexedProfileComposition.ActivateAsync(config,"bad",IndexedProfileOpenMode.CreateNew,Credentials,counters)) is ArgumentException);
            Require(await Failure(()=>IndexedProfileComposition.ActivateAsync(IndexedProfileComposition.Configuration(true),"bad",IndexedProfileOpenMode.CreateNew,Credentials,counters)) is ArgumentException);Require(await Failure(()=>IndexedProfileComposition.ActivateAsync(IndexedProfileComposition.Configuration(true),"ao_"+Guid.NewGuid().ToString("N"),(IndexedProfileOpenMode)99,Credentials,counters)) is ArgumentOutOfRangeException&&counters.FactoryCalls==0&&actualCredentialReads==0);
        });
        await Check("pre-cancelled indexed activation performs no factory credential or SQL",async()=>
        {
            var counters=new IndexedProfileCounters();using var caller=new CancellationTokenSource();caller.Cancel();Require(await Failure(()=>IndexedProfileComposition.ActivateAsync(IndexedProfileComposition.Configuration(true),"ao_"+Guid.NewGuid().ToString("N"),IndexedProfileOpenMode.CreateNew,Credentials,counters,caller.Token)) is OperationCanceledException&&counters.FactoryCalls==0&&counters.Constructors==0&&actualCredentialReads==0);
        });
        await Check("actual Composition CreateNew ordering owns ready indexed module through ActivationLease",async()=>
        {
            var store=await Store();var counters=new IndexedProfileCounters();await using var selected=await Activate(store,counters);var storage=selected.Storage!;Require(storage.IsReady&&counters.Events.SequenceEqual(new[]{"plan.validated","factory","credential","constructor","create","ready"})&&counters.FactoryCalls==1&&actualCredentialReads==1&&storage.InitializationAttempts==1&&storage.DdlCommands>0);var inventory=await storage.ReadInventoryAsync();observe(new{phase="actual_composition",events=counters.Events.ToArray(),support_module=IndexedProfileComposition.ModuleId,inventory=JsonSerializer.SerializeToElement(inventory)});await selected.DisposeAsync();Require(storage.IsDisposed&&storage.DataSourceDisposals==1);
        });
        await Check("indexed client constructor is I/O-free and requires explicit initialization",async()=>
        {
            var store=await Store();await using var storage=new PostgresIndexedAuditStorage(connection,store.Schema);Require(!storage.IsReady&&!storage.IsDisposed&&storage.Connections==0&&storage.InitializationAttempts==0&&storage.DdlCommands==0&&storage.QueryAttempts==0);Require(await Failure(()=>storage.FindAsync(new("A"),Key(1),default).AsTask()) is InvalidOperationException&&storage.Connections==0);
        });
        await Check("repeat CreateNew faults without overwrite and partial candidate is disposed",async()=>
        {
            var store=await Store();var firstCounters=new IndexedProfileCounters();await using var first=await Activate(store,firstCounters);await first.Storage!.AppendOnceAsync(Record(Key(1)),default);var failed=new IndexedProfileCounters();await Failure(()=>Activate(store,failed));Require(failed.FactoryFailures==1&&failed.LastConstructed is not null&&failed.LastConstructed.IsDisposed&&failed.LastConstructed.DataSourceDisposals==1&&failed.Events.Last()=="partial.disposed"&&await first.Storage.FindAsync(new("A"),Key(1),default) is not null);observe(new{phase="partial_factory_failure",owned_candidate_disposed=true,existing_visible_record_retained=true,no_committed_DDL_rollback_claim=true});
        });
        await Check("credential factory failure constructs no indexed client",async()=>
        {
            var store=await Store();var counters=new IndexedProfileCounters();var original=new IOException("Controlled credential factory failure.");Require(ReferenceEquals(await Failure(()=>IndexedProfileComposition.ActivateAsync(IndexedProfileComposition.Configuration(true),store.Schema,IndexedProfileOpenMode.CreateNew,_=>throw original,counters)),original)&&counters.FactoryFailures==1&&counters.Constructors==0&&counters.LastConstructed is null&&actualCredentialReads==0);
        });
        await Check("explicit OpenExisting reopens verified storage read-only without creating schema",async()=>
        {
            var store=await Store();await using var initial=await Activate(store,new());await initial.Storage!.AppendOnceAsync(Record(Key(1)),default);await initial.DisposeAsync();var counters=new IndexedProfileCounters();await using var reopened=await Activate(store,counters,IndexedProfileOpenMode.OpenExisting);Require(reopened.Storage!.IsReady&&reopened.Storage.DdlCommands==0&&reopened.Storage.InventoryChecks>0&&await reopened.Storage.FindAsync(new("A"),Key(1),default) is not null);observe(new{phase="open_existing",DDL_commands=0,explicit_inventory_verified=true,visible_record_retained=true});
        });
        await Check("OpenExisting missing profile fails closed and never auto-creates",async()=>
        {
            var store=await Store();var counters=new IndexedProfileCounters();await Failure(()=>Activate(store,counters,IndexedProfileOpenMode.OpenExisting));Require(counters.LastConstructed!.IsDisposed&&counters.LastConstructed.DdlCommands==0&&!await new SqlFixture(connection,store.Schema).Exists());
        });
        await Check("OpenExisting rejects version columns nullability and collation corruption then explicit restore",async()=>
        {
            foreach(var corruption in new[]{"version","extra","nullable","collation","not-valid","default","domain","generated","rls","rule","trigger","inheritance"})
            {
                var store=await Store();await using var created=await Activate(store,new());var fixture=new SqlFixture(connection,store.Schema);await fixture.CorruptShape(corruption);var counters=new IndexedProfileCounters();await Failure(()=>Activate(store,counters,IndexedProfileOpenMode.OpenExisting));Require(counters.LastConstructed!.IsDisposed&&counters.LastConstructed.DdlCommands==0);
                // Dropped attributes are deliberately outside the closed profile: retain destructive fixtures.
                if(corruption=="extra")
                {
                    await fixture.RestoreShape("extra");var dropped=new IndexedProfileCounters();await Failure(()=>Activate(store,dropped,IndexedProfileOpenMode.OpenExisting));Require(dropped.LastConstructed!.IsDisposed&&dropped.LastConstructed.DdlCommands==0);continue;
                }
                if(corruption=="generated")continue;
                await fixture.RestoreShape(corruption);await using var valid=await Activate(store,new(),IndexedProfileOpenMode.OpenExisting);Require(valid.Storage!.IsReady);
            }
            observe(new{phase="closed_catalog_negatives",independent_schemas=true,version_columns_collations_defaults_domain_generated=true,not_valid_payload_not_null_rejected=true,RLS_rules_triggers_inheritance_rejected=true,dropped_attribute_after_fixture_drop_rejected=true,only_reversible_fixtures_restored=true,automatic_repair=false});
        });
        await Check("OpenExisting rejects missing or different resource index without repairing it",async()=>
        {
            var store=await Store();await using var created=await Activate(store,new());var fixture=new SqlFixture(connection,store.Schema);await fixture.DropResourceIndex();var missing=new IndexedProfileCounters();await Failure(()=>Activate(store,missing,IndexedProfileOpenMode.OpenExisting));Require(missing.LastConstructed!.DdlCommands==0&&!await fixture.HasResourceIndex());await fixture.WrongResourceIndex();var wrong=new IndexedProfileCounters();await Failure(()=>Activate(store,wrong,IndexedProfileOpenMode.OpenExisting));Require(wrong.LastConstructed!.DdlCommands==0);await fixture.DropResourceIndex();await fixture.RestoreResourceIndex();await using var valid=await Activate(store,new(),IndexedProfileOpenMode.OpenExisting);Require(valid.Storage!.IsReady);
        });
        await Check("ActivationLease disposal rejects new work and waits for caller-owned active SQL",async()=>
        {
            var store=await Store();await using var selected=await Activate(store,new());var storage=selected.Storage!;await storage.AppendOnceAsync(Record(Key(1)),default);var fixture=new SqlFixture(connection,store.Schema);var blocker=await fixture.HoldTable();using var caller=new CancellationTokenSource();var pending=storage.FindAsync(new("A"),Key(1),caller.Token).AsTask();Task? disposing=null;
            try{await fixture.Observe(storage,pending,caller.Token);disposing=selected.DisposeAsync().AsTask();for(var i=0;i<100&&!storage.IsDisposed;i++)await Task.Delay(10);Require(storage.IsDisposed&&!disposing.IsCompleted);var before=storage.Connections;Require(await Failure(()=>storage.FindAsync(new("A"),Key(1),default).AsTask()) is ObjectDisposedException&&storage.Connections==before);caller.Cancel();Require(await Failure(()=>pending).WaitAsync(TimeSpan.FromSeconds(10)) is OperationCanceledException);}
            finally{caller.Cancel();await blocker.DisposeAsync();await Join(pending);if(disposing is not null)await disposing.WaitAsync(TimeSpan.FromSeconds(10));else await selected.DisposeAsync();}
            Require(storage.ActiveOperations==0&&storage.DataSourceDisposals==1);observe(new{phase="dispose_inflight",new_work_rejected=true,active_caller_task_joined=true,owned_data_source_disposals=1,no_global_pool_clear=true});
        });
        await Check("exact indexed replay keeps one visible immutable record",async()=>
        {
            var store=await Store();await using var selected=await Activate(store,new());var storage=selected.Storage!;var record=Record(Key(1));await storage.AppendOnceAsync(record,default);await storage.AppendOnceAsync(record,default);Require(await new SqlFixture(connection,store.Schema).Count()==1&&PayloadCodec.Encode((await storage.FindAsync(new("A"),Key(1),default))!)==PayloadCodec.Encode(record));observe(new{phase="exact_replay",visible_rows=1,no_physical_MVCC_update_absence_claim=true});
        });
        await Check("indexed payload or resource metadata conflict never overwrites winner",async()=>
        {
            var store=await Store();await using var selected=await Activate(store,new());var storage=selected.Storage!;var original=Record(Key(1));await storage.AppendOnceAsync(original,default);foreach(var conflict in new[]{Record(Key(1),title:"different"),Record(Key(1),resource:"other"),Record(Key(1),kind:"other")})Require(await Failure(()=>storage.AppendOnceAsync(conflict,default).AsTask()) is InvalidOperationException);Require(PayloadCodec.Encode((await storage.FindAsync(new("A"),Key(1),default))!)==PayloadCodec.Encode(original)&&await new SqlFixture(connection,store.Schema).Count()==1);
        });
        await Check("eight independently scheduled identical indexed appends deduplicate visibly",async()=>
        {
            var store=await Store();await using var selected=await Activate(store,new());var storage=selected.Storage!;var record=Record(Key(1));var start=Signal();var tasks=Enumerable.Range(0,8).Select(_=>Task.Run(async()=>{await start.Task;await storage.AppendOnceAsync(record,default);})).ToArray();start.TrySetResult();await Task.WhenAll(tasks);Require(await new SqlFixture(connection,store.Schema).Count()==1);observe(new{phase="concurrent_same_append",scheduled_workers=8,all_succeeded=true,visible_rows=1});
        });
        await Check("independently scheduled conflicting indexed appends have one winner and one fault",async()=>
        {
            var store=await Store();await using var selected=await Activate(store,new());var storage=selected.Storage!;var left=Record(Key(1),title:"left");var right=Record(Key(1),title:"right");var start=Signal();var tasks=new[]{left,right}.Select(r=>Task.Run(async()=>{await start.Task;try{await storage.AppendOnceAsync(r,default);return true;}catch(InvalidOperationException){return false;}})).ToArray();start.TrySetResult();var results=await Task.WhenAll(tasks);var actual=await storage.FindAsync(new("A"),Key(1),default);Require(results.Count(x=>x)==1&&actual is not null&&PayloadCodec.Encode(actual)==PayloadCodec.Encode(results[0]?left:right)&&await new SqlFixture(connection,store.Schema).Count()==1);observe(new{phase="concurrent_conflict",scheduled_workers=2,winners=1,conflicts=1,no_overwrite=true});
        });
        await Check("indexed tenant resource and cursor keys remain independently bound",async()=>
        {
            var store=await Store();await using var selected=await Activate(store,new());var storage=selected.Storage!;await storage.AppendOnceAsync(Record(Key(1)),default);await storage.AppendOnceAsync(Record(Key(1),"B"),default);await storage.AppendOnceAsync(Record(Key(2),resource:"other"),default);await storage.AppendOnceAsync(Record(Key(3)),default);var page=await storage.ReadAsync(new("A"),Q(1),default);Require(page.Entries.Single().Receipt.Tenant.Value=="A"&&page.NextCursor!.AfterReceiptId==Key(1));Require((await storage.ReadAsync(new("A"),Q(5,page.NextCursor),default)).Entries.Single().Receipt.ReceiptId==Key(3)&&(await storage.ReadAsync(new("B"),Q(),default)).Entries.Single().Receipt.ReceiptId==Key(1));
        });
        await Check("maximum tenant kind and CJK resource key plus NUL field roundtrip through index",async()=>
        {
            var store=await Store();await using var selected=await Activate(store,new());var storage=selected.Storage!;var tenant=new string('t',128);var kind=new string('k',128);var resource=new string('\u754c',512);var record=Record(Key(1),tenant,kind,resource,"a\0b");await storage.AppendOnceAsync(record,default);var found=await storage.FindAsync(new(tenant),Key(1),default);var page=await storage.ReadAsync(new(tenant),new(kind,resource),default);Require(found is not null&&PayloadCodec.Encode(found)==PayloadCodec.Encode(record)&&page.Entries.Single().Fields.Single(f=>f.Name=="title").After.TextValue=="a\0b");observe(new{phase="max_keys",tenant_UTF16=128,kind_ASCII=128,resource_CJK_UTF16=512,NUL_payload_roundtrip=true});
        });
        await Check("touched metadata poison faults while selective query does not attest unrelated rows",async()=>
        {
            var store=await Store();await using var selected=await Activate(store,new());var storage=selected.Storage!;await storage.AppendOnceAsync(Record(Key(1)),default);var fixture=new SqlFixture(connection,store.Schema);await fixture.SetResource(Key(1),"hidden");Require((await storage.ReadAsync(new("A"),Q(),default)).Entries.Count==0);Require(await Failure(()=>storage.FindAsync(new("A"),Key(1),default).AsTask()) is InvalidOperationException&&await Failure(()=>storage.ReadAsync(new("A"),Q(resource:"hidden"),default).AsTask()) is InvalidOperationException);await fixture.SetResource(Key(1),"shared");Require(await storage.FindAsync(new("A"),Key(1),default) is not null);observe(new{phase="metadata_poison",selective_query_can_hide_corrupted_metadata=true,touched_lookup_query_fail_closed=true,no_continuous_integrity_claim=true});
        });
        await Check("indexed lookahead validates metadata and decoded identity before limiting page",async()=>
        {
            var store=await Store();await using var selected=await Activate(store,new());var storage=selected.Storage!;await storage.AppendOnceAsync(Record(Key(1)),default);await storage.AppendOnceAsync(Record(Key(2)),default);await new SqlFixture(connection,store.Schema).SetPayload(Key(2),Record(Key(2),"B"));Require(await Failure(()=>storage.ReadAsync(new("A"),Q(1),default).AsTask()) is InvalidOperationException);
        });
        await Check("actual old outbox publishes to Composition-selected new sink through generated relay",async()=>
        {
            var store=await Store();await mutate(store);var receipt=PayloadCodec.Decode((await store.Payloads()).Single());await using var selected=await Activate(store,new());var storage=selected.Storage!;var lookup=new LookupHost(new(storage,Policy()));Require((await lookup.Run(receipt.Receipt.ReceiptId)).IsSuccess&&(await storage.FindAsync(new("A"),receipt.Receipt.ReceiptId,default)) is null);var relay=new RelayHost(TenantChangeAuditOutboxRelay.Activate(true,()=>store,()=>storage));Require((await relay.Run()).IsSuccess&&(await store.Counts())==(1,1,0));var result=await lookup.Run(receipt.Receipt.ReceiptId);Require(result.IsSuccess&&result.Value.Record is not null&&result.Value.Record.Receipt.ReceiptId==receipt.Receipt.ReceiptId);observe(new{phase="old_outbox_new_sink",old_sink_rows=0,new_sink_rows=1,provider_acknowledged=true,actual_Composition_selected=true});
        });
        await Check("acknowledgement loss replays indexed sink idempotently only under fresh authority",async()=>
        {
            var store=await Store();await mutate(store);await using var selected=await Activate(store,new());var storage=selected.Storage!;var relay=TenantChangeAuditOutboxRelay.Activate(true,()=>store,()=>storage)!;store.Fault=ProviderFault.Ack;Require(await Failure(()=>new RelayHost(relay).Run().AsTask()) is TenantChangeAuditOutboxRelayException failure&&failure.MayHaveDelivered&&failure.AcknowledgedCount==0&&(await store.Counts())==(1,0,0)&&await new SqlFixture(connection,store.Schema).Count()==1);store.Fault=ProviderFault.None;var fresh=new RelayHost(relay);fresh.Authority.AllowRelay=false;var claims=store.Claims;Require(!(await fresh.Run()).IsSuccess&&store.Claims==claims);fresh.Authority.AllowRelay=true;Require((await fresh.Run()).IsSuccess&&fresh.Authority.IdentityLookups==2&&(await store.Counts())==(1,1,0)&&await new SqlFixture(connection,store.Schema).Count()==1);
        });
        await Check("old source lease fencing still rejects stale acknowledgement with indexed sink",async()=>
        {
            var store=await Store();await mutate(store);await using var selected=await Activate(store,new());var first=await store.ClaimAsync(new("A"),1,TimeSpan.FromSeconds(30),default)??throw new InvalidOperationException();await store.ReleaseAsync(first,default);var second=await store.ClaimAsync(new("A"),1,TimeSpan.FromSeconds(30),default)??throw new InvalidOperationException();await selected.Storage!.AppendOnceAsync(second.Records.Single(),default);Require(!await store.AcknowledgeAsync(first,first.Records.Single().Receipt.ReceiptId,default));await store.ReleaseAsync(first,default);Require(await store.ClaimAsync(new("A"),1,TimeSpan.FromSeconds(30),default) is null&&await store.AcknowledgeAsync(second,second.Records.Single().Receipt.ReceiptId,default));await store.ReleaseAsync(second,default);
        });
        await Check("selecting new history never backfills already acknowledged legacy receipts",async()=>
        {
            var store=await Store();await mutate(store);var legacy=PayloadCodec.Decode((await store.Payloads()).Single());Require((await new RelayHost(TenantChangeAuditOutboxRelay.Activate(true,()=>store,()=>store)).Run()).IsSuccess);await using var selected=await Activate(store,new());Require(await selected.Storage!.FindAsync(new("A"),legacy.Receipt.ReceiptId,default) is null);await mutate(store);Require((await new RelayHost(TenantChangeAuditOutboxRelay.Activate(true,()=>store,()=>selected.Storage)).Run()).IsSuccess&&(await store.Counts())==(2,2,1)&&await new SqlFixture(connection,store.Schema).Count()==1);observe(new{phase="history_divergence",old_history=1,new_history=1,already_acknowledged_not_imported=true,delivered_flag_not_destination_attestation=true});
        });
        await Check("existing generated lookup and history gateways enforce current policy and fresh scope",async()=>
        {
            var store=await Store();await using var selected=await Activate(store,new());var storage=selected.Storage!;await storage.AppendOnceAsync(Record(Key(1)),default);var lookup=new LookupHost(new(storage,Policy()));var history=new ResourceHistoryHost(new(storage,Policy()));var found=await lookup.Run(Key(1));var page=await history.Run(Q());Require(found.IsSuccess&&page.IsSuccess&&found.Value.Record!.Fields.Single(f=>f.Name=="secret").After.Kind==TenantChangeValueKind.Redacted&&page.Value.Page.Entries.Count==1);var metadata=await new ResourceHistoryHost(new(storage,Policy(TenantChangeAuditMode.MetadataOnly))).Run(Q());Require(metadata.IsSuccess&&metadata.Value.Page.Entries.Single().Fields.Count==0);var before=storage.QueryAttempts;lookup.Authority.AllowLookup=false;history.Authority.GrantedOperation="trail.lookup";Require(!(await lookup.Run(Key(1))).IsSuccess&&!(await history.Run(Q())).IsSuccess&&storage.QueryAttempts==before);lookup.Authority.AllowLookup=true;history.Authority.GrantedOperation="trail.resource-history";Require((await lookup.Run(Key(1))).IsSuccess&&(await history.Run(Q())).IsSuccess&&lookup.Authority.IdentityLookups==3&&history.Authority.IdentityLookups==3);observe(new{phase="indexed_existing_gateways",projected_redaction=true,metadata_only=true,denied_query_zero=true,fresh_grants=true});
        });
        await Check("disabled reader selection never activates optional indexed storage",()=>
        {
            var factory=0;Require(LookupHost.Activate(new(TenantChangeAuditMode.Disabled),()=>{factory++;throw new InvalidOperationException();}) is null&&ResourceHistoryHost.Activate(new(TenantChangeAuditMode.Disabled),()=>{factory++;throw new InvalidOperationException();}) is null&&factory==0&&actualCredentialReads==0);return Task.CompletedTask;
        });
        await Check("indexed provider preserves caller cancellation and reader cursor binding",async()=>
        {
            var store=await Store();await using var selected=await Activate(store,new());var storage=selected.Storage!;using var caller=new CancellationTokenSource();caller.Cancel();var before=storage.Connections;var failure=await Failure(()=>storage.FindAsync(new("A"),Key(1),caller.Token).AsTask());Require(failure is OperationCanceledException canceled&&canceled.CancellationToken==caller.Token&&storage.Connections==before);var host=new ResourceHistoryHost(new(storage,Policy()));var attempts=storage.QueryAttempts;Require(await Failure(()=>host.Run(Q(cursor:new(new("B"),"entity","shared",Key(1)))).AsTask()) is ArgumentException&&storage.QueryAttempts==attempts);var read=new TenantChangeAuditResourceHistoryReader(storage,Policy());Require((await host.Run(Q())).IsSuccess);attempts=storage.QueryAttempts;Require(await Failure(()=>read.ReadAsync(host.RetainedContext!,Q()).AsTask()) is TenantAccessDeniedException&&storage.QueryAttempts==attempts);
        });
        await Check("actual tagged indexed SQL lock cancels then becomes quiescent and reusable",async()=>
        {
            var store=await Store();await using var selected=await Activate(store,new());var storage=selected.Storage!;await storage.AppendOnceAsync(Record(Key(1)),default);var fixture=new SqlFixture(connection,store.Schema);var blocker=await fixture.HoldTable();using var caller=new CancellationTokenSource();var pending=storage.ReadAsync(new("A"),Q(),caller.Token).AsTask();object? observed=null;var pid=0;
            try{observed=await fixture.Observe(storage,pending,caller.Token);pid=storage.LastBackendPid;caller.Cancel();Require(await Failure(()=>pending).WaitAsync(TimeSpan.FromSeconds(10)) is OperationCanceledException);}
            finally{caller.Cancel();await blocker.DisposeAsync();await Join(pending);}
            await fixture.Quiescent(storage,pid);Require(storage.ActiveOperations==0&&(await storage.ReadAsync(new("A"),Q(),default)).Entries.Count==1);observe(new{phase="actual_indexed_sql_cancellation",backend=observed,backend_task_quiescent=true,manual_reuse=true,wrapper_pause=false});
        });
        await Check("eight scheduled existing query gateways keep same receipt tenants isolated",async()=>
        {
            var store=await Store();await using var selected=await Activate(store,new());var storage=selected.Storage!;await storage.AppendOnceAsync(Record(Key(1)),default);await storage.AppendOnceAsync(Record(Key(1),"B"),default);var start=Signal();var tasks=Enumerable.Range(0,8).Select(i=>Task.Run(async()=>{var tenant=i%2==0?"A":"B";var host=new ResourceHistoryHost(new(storage,Policy()));host.Authority.AllowB=true;await start.Task;var result=await host.Run(Q(),tenant);Require(result.IsSuccess&&result.Value.Page.Entries.Single().Receipt.Tenant.Value==tenant);})).ToArray();start.TrySetResult();await Task.WhenAll(tasks);observe(new{phase="indexed_scheduled_query_gateways",workers=8,tenant_isolation=true,existing_generated_gateway=true});
        });
        await Check("declared 4096-row default-planner corpus retains exact plans without coercion",async()=>
        {
            var store=await Store();await using var selected=await Activate(store,new());var storage=selected.Storage!;for(var t=0;t<2;t++)for(var n=1;n<=2048;n++)await storage.AppendOnceAsync(Record(Key(n),t==0?"A":"B","document","item-"+((n-1)/16).ToString("000"),at:DateTimeOffset.UnixEpoch.AddSeconds(n)),default);var fixture=new SqlFixture(connection,store.Schema);await fixture.Analyze();Require(await fixture.Count()==4096);var firstQuery=Q(8,kind:"document",resource:"item-064");var first=await storage.ReadAsync(new("A"),firstQuery,default);var firstCandidates=storage.LastCandidateRows;var firstDecoded=storage.LastDecodedRows;Require(first.Entries.Select(r=>r.Receipt.ReceiptId).SequenceEqual(Enumerable.Range(1025,8).Select(Key))&&first.NextCursor!.AfterReceiptId==Key(1032));var secondQuery=Q(8,first.NextCursor,"document","item-064");var second=await storage.ReadAsync(new("A"),secondQuery,default);var secondCandidates=storage.LastCandidateRows;var secondDecoded=storage.LastDecodedRows;Require(second.Entries.Select(r=>r.Receipt.ReceiptId).SequenceEqual(Enumerable.Range(1033,8).Select(Key))&&second.NextCursor is null&&firstCandidates==9&&firstDecoded==9&&secondCandidates==8&&secondDecoded==8);var inventory=await storage.ReadInventoryAsync();var settings=await fixture.Settings();var firstPlan=JsonDocument.Parse(await storage.ExplainResourceQueryAsync(new("A"),firstQuery)).RootElement.Clone();var secondPlan=JsonDocument.Parse(await storage.ExplainResourceQueryAsync(new("A"),secondQuery)).RootElement.Clone();observe(new{phase="default_planner_4096",rows=4096,tenants=2,rows_per_tenant=2048,resources_per_tenant=128,rows_per_resource=16,selected_tenant="A",selected_kind="document",selected_resource="item-064",limit=8,first_keys=first.Entries.Select(r=>r.Receipt.ReceiptId).ToArray(),second_keys=second.Entries.Select(r=>r.Receipt.ReceiptId).ToArray(),firstCandidates,firstDecoded,secondCandidates,secondDecoded,sql=storage.ResourceSelectSql,inventory,settings,firstPlan,secondPlan,planner_coerced=false,timed_benchmark=false,total_IO_cost_claim=false});
        });
        await Check("exact replay rejects divergent physical metadata without repairing storage",async()=>
        {
            var store=await Store();await using var selected=await Activate(store,new());var storage=selected.Storage!;var record=Record(Key(1));await storage.AppendOnceAsync(record,default);var fixture=new SqlFixture(connection,store.Schema);await fixture.SetResource(Key(1),"Shared");Require(await Failure(()=>storage.AppendOnceAsync(record,default).AsTask()) is InvalidOperationException&&await fixture.Resource(Key(1))=="Shared"&&await fixture.Count()==1);await fixture.SetResource(Key(1),"shared");await storage.AppendOnceAsync(record,default);Require(await fixture.Count()==1);
        });
    }
    private sealed class SqlFixture(string connection,string schema)
    {
        private string Table=>schema+"."+PostgresIndexedAuditStorage.StorageTable;
        private async Task<NpgsqlConnection> Open(){var c=new NpgsqlConnection(connection);try{await c.OpenAsync();return c;}catch{await c.DisposeAsync();throw;}}
        private async Task<object?> Scalar(string sql,params object[] args){await using var c=await Open();await using var cmd=new NpgsqlCommand(sql,c);foreach(var arg in args)cmd.Parameters.AddWithValue(arg);return await cmd.ExecuteScalarAsync();}
        public async Task Execute(string sql){await using var c=await Open();await using var cmd=new NpgsqlCommand(sql,c);await cmd.ExecuteNonQueryAsync();}
        public async Task<bool> Exists()=>(bool)(await Scalar("SELECT to_regclass($1) IS NOT NULL",Table))!;
        public async Task<long> Count()=>(long)(await Scalar("SELECT count(*) FROM "+Table))!;
        public async Task<bool> HasResourceIndex()=>(bool)(await Scalar("SELECT to_regclass($1) IS NOT NULL",schema+"."+PostgresIndexedAuditStorage.ResourceIndex))!;
        public Task DropResourceIndex()=>Execute("DROP INDEX "+schema+"."+PostgresIndexedAuditStorage.ResourceIndex);
        public Task WrongResourceIndex()=>Execute("CREATE INDEX "+PostgresIndexedAuditStorage.ResourceIndex+" ON "+Table+"(tenant,resource_kind,receipt,resource_id)");
        public Task RestoreResourceIndex()=>Execute("CREATE INDEX "+PostgresIndexedAuditStorage.ResourceIndex+" ON "+Table+"(tenant,resource_kind,resource_id,receipt)");
        public async Task SetResource(Guid key,string value)=>_ = await Scalar("UPDATE "+Table+" SET resource_id=$1 WHERE tenant='A' AND receipt=$2 RETURNING receipt",value,key);
        public async Task<string> Resource(Guid key)=>(string)(await Scalar("SELECT resource_id FROM "+Table+" WHERE tenant='A' AND receipt=$1",key))!;
        public async Task SetPayload(Guid key,TenantChangeAuditRecord record)=>_ = await Scalar("UPDATE "+Table+" SET payload=$1 WHERE tenant='A' AND receipt=$2 RETURNING receipt",PayloadCodec.Encode(record),key);
        public Task Analyze()=>Execute("ANALYZE "+Table);
        public async Task<JsonElement> Settings()=>JsonDocument.Parse((string)(await Scalar("SELECT json_object_agg(name,setting)::text FROM pg_settings WHERE name IN ('enable_seqscan','enable_indexscan','enable_bitmapscan','enable_indexonlyscan','random_page_cost','seq_page_cost','plan_cache_mode')"))!).RootElement.Clone();
        public Task CorruptShape(string kind)=>Execute(kind switch
        {
            "version"=>"COMMENT ON TABLE "+Table+" IS 'unsupported-fixture-version'",
            "extra"=>"ALTER TABLE "+Table+" ADD COLUMN unexpected text",
            "nullable"=>"ALTER TABLE "+Table+" ALTER COLUMN resource_id DROP NOT NULL",
            "collation"=>"ALTER TABLE "+Table+" ALTER COLUMN resource_id TYPE text COLLATE \"POSIX\"",
            "not-valid"=>"ALTER TABLE "+Table+" ALTER COLUMN payload DROP NOT NULL; ALTER TABLE "+Table+" ADD CONSTRAINT fixture_payload_nn NOT NULL payload NOT VALID",
            "default"=>"ALTER TABLE "+Table+" ALTER COLUMN payload SET DEFAULT '{}'",
            "domain"=>"CREATE DOMAIN "+schema+".fixture_text AS text COLLATE \"C\"; ALTER TABLE "+Table+" ALTER COLUMN resource_id TYPE "+schema+".fixture_text",
            "generated"=>"ALTER TABLE "+Table+" DROP COLUMN payload; ALTER TABLE "+Table+" ADD COLUMN payload text COLLATE \"C\" GENERATED ALWAYS AS ('{}'::text) STORED NOT NULL",
            "inheritance"=>"CREATE TABLE "+schema+".fixture_child () INHERITS ("+Table+")",
            "rls"=>"ALTER TABLE "+Table+" ENABLE ROW LEVEL SECURITY",
            "rule"=>"CREATE RULE fixture_no_delete AS ON DELETE TO "+Table+" DO INSTEAD NOTHING",
            "trigger"=>"CREATE FUNCTION "+schema+".fixture_trigger() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'; CREATE TRIGGER fixture_trigger BEFORE INSERT ON "+Table+" FOR EACH ROW EXECUTE FUNCTION "+schema+".fixture_trigger()",
            _=>throw new ArgumentException("Unknown owned fixture corruption.")
        });
        public Task RestoreShape(string kind)=>Execute(kind switch
        {
            "version"=>"COMMENT ON TABLE "+Table+" IS '"+PostgresIndexedAuditStorage.VersionMarker+"'",
            "extra"=>"ALTER TABLE "+Table+" DROP COLUMN unexpected",
            "nullable"=>"ALTER TABLE "+Table+" ALTER COLUMN resource_id SET NOT NULL",
            "collation"=>"ALTER TABLE "+Table+" ALTER COLUMN resource_id TYPE text COLLATE \"C\"",
            "not-valid"=>"ALTER TABLE "+Table+" VALIDATE CONSTRAINT fixture_payload_nn",
            "default"=>"ALTER TABLE "+Table+" ALTER COLUMN payload DROP DEFAULT",
            "domain"=>"ALTER TABLE "+Table+" ALTER COLUMN resource_id TYPE text COLLATE \"C\"; DROP DOMAIN "+schema+".fixture_text",
            "generated"=>"ALTER TABLE "+Table+" DROP COLUMN payload; ALTER TABLE "+Table+" ADD COLUMN payload text COLLATE \"C\" NOT NULL",
            "inheritance"=>"DROP TABLE "+schema+".fixture_child",
            "rls"=>"ALTER TABLE "+Table+" DISABLE ROW LEVEL SECURITY",
            "rule"=>"DROP RULE fixture_no_delete ON "+Table,
            "trigger"=>"DROP TRIGGER fixture_trigger ON "+Table+"; DROP FUNCTION "+schema+".fixture_trigger()",
            _=>throw new ArgumentException("Unknown owned fixture corruption.")
        });
        public async Task<SqlBlocker> HoldTable(){var c=await Open();var tx=await c.BeginTransactionAsync();try{await using var cmd=new NpgsqlCommand("LOCK TABLE "+Table+" IN ACCESS EXCLUSIVE MODE",c,tx);await cmd.ExecuteNonQueryAsync();return new(c,tx);}catch{await tx.DisposeAsync();await c.DisposeAsync();throw;}}
        public async Task<object> Observe(PostgresIndexedAuditStorage storage,Task pending,CancellationToken caller)
        {
            for(var i=0;i<200;i++)
            {
                Require(!pending.IsCompleted&&!caller.IsCancellationRequested);var pid=storage.LastBackendPid;
                var found=(bool)(await Scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND application_name=$2 AND state='active' AND wait_event_type='Lock' AND query LIKE $3 AND (query LIKE $4 OR query LIKE $5))",pid,storage.ApplicationName,"%"+Table+"%","%"+PostgresIndexedAuditStorage.LookupTag+"%","%"+PostgresIndexedAuditStorage.ResourceTag+"%"))!;
                if(found){Require(!pending.IsCompleted&&!caller.IsCancellationRequested);return new{pid,application_name=storage.ApplicationName,qualified_table=Table,wait_event_type="Lock",exact_owned_tag=true,observed_before_cancellation=true};}await Task.Delay(20);
            }
            throw new InvalidOperationException("Exact tagged indexed SQL backend did not enter Lock wait before caller cancellation.");
        }
        public async Task Quiescent(PostgresIndexedAuditStorage storage,int pid)
        {
            for(var i=0;i<100;i++){if((bool)(await Scalar("SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND application_name=$2 AND (state='active' OR wait_event_type='Lock'))",pid,storage.ApplicationName))!)return;await Task.Delay(20);}throw new InvalidOperationException("Owned indexed SQL backend did not quiesce.");
        }
    }
    private sealed class SqlBlocker(NpgsqlConnection connection,NpgsqlTransaction transaction):IAsyncDisposable
    {
        private bool disposed;public async ValueTask DisposeAsync(){if(disposed)return;disposed=true;try{await transaction.RollbackAsync();}finally{await transaction.DisposeAsync();await connection.DisposeAsync();}}
    }
}
