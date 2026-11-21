extern alias securityapi;
using System.Collections.Concurrent;
using System.Net.Http.Json;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;
using Npgsql;
using securityapi::SecurityApi;
using Host=securityapi::SecurityApi.Host;

namespace AuditOutbox;

public static class ResourceHistoryChecks
{
    private static void Require(bool value){if(!value)throw new InvalidOperationException("Resource history consumer assertion failed.");}
    private static TaskCompletionSource Signal()=>new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static async Task<Exception> Failure(Func<Task> action){try{await action();}catch(Exception error){return error;}throw new InvalidOperationException("Expected resource history fault.");}
    private static async Task Join(Task task){try{await task;}catch(Exception){}}
    private static Guid Key(int value)=>Guid.Parse("00000000-0000-0000-0000-"+value.ToString("x12"));
    private static TenantChangeAuditResourceQuery Q(int limit=50,TenantChangeAuditResourceCursor? after=null,string kind="entity",string id="shared")=>new(kind,id,limit,after);
    private static TenantChangeAuditResourceCursor C(Guid after,string tenant="A",string kind="entity",string id="shared")=>new(new(tenant),kind,id,after);
    private static TenantChangeAuditPolicy Policy(TenantChangeAuditMode mode=TenantChangeAuditMode.BeforeAfterSnapshots)=>new(mode,[new("entity.update","update","entity",[new("title"),new("secret",true),new("same")]),new("entity.update","update","other",[new("title"),new("secret",true),new("same")])]);
    private static TenantChangeAuditRecord Record(Guid key,string tenant="A",string kind="entity",string id="shared",string title="fixture",TenantChangeAuditMode mode=TenantChangeAuditMode.BeforeAfterSnapshots,DateTimeOffset? time=null)
    {
        var receipt=new TenantChangeReceipt(key,new PrincipalId("owned-history-fixture","reported-writer"),"fixture-service",new(tenant),"entity.update","update",kind,id,"fixture-v1",TenantChangeKind.Update,"0","1");var fields=new List<TenantChangeField>();
        if(mode!=TenantChangeAuditMode.MetadataOnly){fields.Add(new("title",TenantChangeValue.Text("before:"+title),TenantChangeValue.Text(title)));fields.Add(new("secret",TenantChangeValue.Text("fixture-sensitive-before"),TenantChangeValue.Text("fixture-sensitive-after")));fields.Add(new("unknown",TenantChangeValue.Text("unknown-before"),TenantChangeValue.Text("unknown-after")));if(mode==TenantChangeAuditMode.BeforeAfterSnapshots)fields.Add(new("same",TenantChangeValue.Text("stable"),TenantChangeValue.Text("stable"),false));}
        return new(receipt,time??DateTimeOffset.UtcNow,mode,fields);
    }
    private static async Task<TenantChangeAuditResourcePage> Read(ResourceHistoryHost host,TenantChangeAuditResourceQuery query,string tenant="A")
    {var result=await host.Run(query,tenant);Require(result.IsSuccess&&result.Value.Tenant==tenant);return result.Value.Page;}
    private static Guid[] Keys(TenantChangeAuditResourcePage page)=>page.Entries.Select(r=>r.Receipt.ReceiptId).ToArray();
    public static async Task Run(Func<string,Func<Task>,Task> outer,Func<Task<PostgresStore>> createStore,Func<PostgresStore,Task> mutate,string connection,Action<object> observe)
    {
        var stores=new List<PostgresStore>();async Task<PostgresStore> Store(){var s=await createStore();stores.Add(s);return s;}
        async Task Check(string name,Func<Task> action)=>await outer(name,async()=>{stores.Clear();await action();Require(stores.All(s=>s.StatusReads==0&&s.HistoryReads==0));});
        PostgresResourceHistorySource Source(PostgresStore store)=>new(connection,store.Schema);
        async Task Seed(PostgresStore store,IEnumerable<Guid> keys,string tenant="A",string kind="entity",string id="shared"){foreach(var key in keys)await store.AppendOnceAsync(Record(key,tenant,kind,id),default);}
        await Check("resource history Disabled policy skips source and host factories",()=>
        {var factories=0;Require(ResourceHistoryHost.Activate(new(TenantChangeAuditMode.Disabled),()=>{factories++;throw new InvalidOperationException();}) is null&&TenantChangeAuditResourceHistoryReader.Activate(new(TenantChangeAuditMode.Disabled)) is null&&factories==0);observe(new{phase="disabled",factories=0,host_activated=false});return Task.CompletedTask;});
        await Check("resource history rejects unowned schema and direct Disabled reader",()=>
        {
            var bad=false;try{_ =new PostgresResourceHistorySource(connection,"public;delete");}catch(ArgumentException){bad=true;}var source=new PostgresResourceHistorySource(connection,"ao_"+Guid.NewGuid().ToString("N"));var disabled=false;try{_ =new TenantChangeAuditResourceHistoryReader(source,new(TenantChangeAuditMode.Disabled));}catch(ArgumentException){disabled=true;}Require(bad&&disabled&&source.QueryAttempts==0&&source.Connections==0);return Task.CompletedTask;
        });
        await Check("selected resource source factory differs from denied query zero",async()=>
        {var store=await Store();var source=Source(store);var factories=0;var host=ResourceHistoryHost.Activate(Policy(),()=>{factories++;return source;})!;host.Authority.AllowHistory=false;var denied=await host.Run(Q());Require(!denied.IsSuccess&&denied.Error.Code=="access.denied"&&factories==1&&host.HandlerFactories==0&&source.QueryAttempts==0);observe(new{phase="denied",source_factories=1,queries=0});});
        await Check("fifth typed resource history registration stays lazy",()=>
        {var source=new PostgresResourceHistorySource(connection,"ao_"+Guid.NewGuid().ToString("N"));var host=new ResourceHistoryHost(new(source,Policy()));Require(host.GatewayFactories==0&&host.HandlerFactories==0&&source.QueryAttempts==0&&source.Connections==0);return Task.CompletedTask;});
        await Check("resource query cursor bounds and null context reject before source",async()=>
        {
            foreach(var factory in new Action[]{()=>{_ =Q(0);},()=>{_ =Q(201);},()=>{_ =Q(kind:"Entity");},()=>{_ =Q(id:new string('x',513));},()=>{_ =C(Guid.Empty);}}){var bad=false;try{factory();}catch(ArgumentException){bad=true;}Require(bad);}
            var store=await Store();var source=Source(store);var reader=new TenantChangeAuditResourceHistoryReader(source,Policy());var host=new ResourceHistoryHost(reader);Require(await Failure(()=>reader.ReadAsync(null!,Q()).AsTask()) is ArgumentNullException&&await Failure(()=>host.Run(null!).AsTask()) is ArgumentNullException&&source.QueryAttempts==0);
        });
        await Check("cursor tenant and exact filter binding reject before provider query",async()=>
        {
            var store=await Store();var source=Source(store);var host=new ResourceHistoryHost(new(source,Policy()));foreach(var cursor in new[]{C(Key(1),"B"),C(Key(1),kind:"other"),C(Key(1),id:"other")})Require(await Failure(()=>host.Run(Q(after:cursor)).AsTask()) is ArgumentException&&source.QueryAttempts==0);var bad=await host.Run(Q(),"B");Require(!bad.IsSuccess&&bad.Error.Code=="access.denied"&&source.QueryAttempts==0);
        });
        await Check("pending resource history becomes visible only after actual relay publication",async()=>
        {
            var store=await Store();await mutate(store);var raw=PayloadCodec.Decode((await store.Payloads()).Single());var source=Source(store);var host=new ResourceHistoryHost(new(source,Policy()));Require((await Read(host,Q())).Entries.Count==0&&(await store.Counts())==(1,0,0));Require((await new RelayHost(TenantChangeAuditOutboxRelay.Activate(true,()=>store,()=>store)).Run()).IsSuccess);var page=await Read(host,Q());Require(page.Entries.Count==1&&page.Entries[0].Receipt.ReceiptId==raw.Receipt.ReceiptId&&(await store.Counts())==(1,1,1));observe(new{phase="pending_to_relay",pending_empty=true,post_relay_visible=true,empty_not_noncommit_proof=true});
        });
        await Check("exact resource kind and id select independent same-id resources",async()=>
        {
            var store=await Store();await Seed(store,[Key(1)]);await Seed(store,[Key(2)],id:"other");await Seed(store,[Key(3)],kind:"other");var host=new ResourceHistoryHost(new(Source(store),Policy()));Require(Keys(await Read(host,Q())).SequenceEqual(new[]{Key(1)})&&Keys(await Read(host,Q(id:"other"))).SequenceEqual(new[]{Key(2)})&&Keys(await Read(host,Q(kind:"other"))).SequenceEqual(new[]{Key(3)}));
        });
        await Check("tenants share resource identifiers and receipt keys without sharing history",async()=>
        {
            var store=await Store();await Seed(store,[Key(1)]);await Seed(store,[Key(1)],"B");var source=Source(store);var host=new ResourceHistoryHost(new(source,Policy()));var denied=await host.Run(Q(),"B");Require(!denied.IsSuccess&&denied.Error.Code=="access.denied"&&source.QueryAttempts==0);host.Authority.AllowB=true;var a=await Read(host,Q());var b=await Read(host,Q(),"B");Require(a.Entries.Single().Receipt.Tenant.Value=="A"&&b.Entries.Single().Receipt.Tenant.Value=="B"&&Keys(a).SequenceEqual(Keys(b)));observe(new{phase="tenant_partition",same_resource_id=true,same_receipt_guid=true,separate_fresh_B_grant=true});
        });
        await Check("exact Ordinal Unicode resource filters preserve legacy TEXT NUL payloads",async()=>
        {
            var store=await Store();var ids=new[]{"Shared","shared","\u00e9","e\u0301","resource' OR true--"};for(var i=0;i<ids.Length;i++)await Seed(store,[Key(i+1)],id:ids[i]);var host=new ResourceHistoryHost(new(Source(store),Policy()));for(var i=0;i<ids.Length;i++)Require(Keys(await Read(host,Q(id:ids[i]))).SequenceEqual(new[]{Key(i+1)}));Require((await Read(host,Q(id:"SHARED"))).Entries.Count==0);observe(new{phase="exact_ordinal_filter",case_variants_distinct=true,unicode_normalizations_distinct=true,quote_is_literal_metadata=true});
            TenantChangeAuditRecord Nul(Guid key,string resource)=>new(Record(key,id:resource).Receipt,DateTimeOffset.UtcNow,TenantChangeAuditMode.ChangedFields,[new("title",TenantChangeValue.Text("before"),TenantChangeValue.Text("a\0b"))]);var unrelated=Nul(Key(6),"unrelated-nul");var matching=Nul(Key(7),"matching-nul");await store.AppendOnceAsync(unrelated,default);await store.AppendOnceAsync(matching,default);var nulPage=await Read(host,Q(id:"matching-nul"));Require(nulPage.Entries.Single().Fields.Single(f=>f.Name=="title").After.TextValue=="a\0b");var oldLookup=await new LookupHost(new(new PostgresLookupSource(connection,store.Schema),Policy())).Run(Key(7));Require(oldLookup.IsSuccess&&oldLookup.Value.Record!.Fields.Single(f=>f.Name=="title").After.TextValue=="a\0b"&&PayloadCodec.Encode(PayloadCodec.Decode(PayloadCodec.Encode(matching)))==PayloadCodec.Encode(matching));observe(new{phase="legacy_TEXT_wire",old_AppendOnce_and_lookup_preserved=true,matching_field_NUL_roundtrip=true,earlier_unrelated_NUL_row_safely_filtered=true});
        });
        await Check("actual PostgreSQL UUID order agrees with adversarial canonical Guid-N not recorded time",async()=>
        {
            var store=await Store();var texts=new[]{"ffffffff-ffff-ffff-ffff-ffffffffffff","80000000-0000-0000-0000-000000000000","7fffffff-ffff-ffff-ffff-ffffffffffff","00010000-0000-0000-0000-000000000000","0000ffff-0000-0000-0000-000000000000","00000100-0000-0000-0000-000000000000","000000ff-0000-0000-0000-000000000000","00000001-0000-0000-0000-000000000000","00000000-0001-0000-0000-000000000000","00000000-0000-0001-0000-000000000000","00000000-0000-0000-0001-000000000000","00000000-0000-0000-0000-000000010000","00000000-0000-0000-0000-00000000ffff","00000000-0000-0000-0000-000000000001"};var expected=texts.Select(Guid.Parse).OrderBy(g=>g.ToString("N"),StringComparer.Ordinal).ToArray();var recordedBase=DateTimeOffset.UtcNow.AddDays(-1);for(var i=0;i<expected.Length;i++)await store.AppendOnceAsync(Record(expected[i],time:recordedBase.AddMinutes(-i)),default);var host=new ResourceHistoryHost(new(Source(store),Policy()));foreach(var size in new[]{1,2,3,7,200}){var all=new List<Guid>();TenantChangeAuditResourceCursor? cursor=null;do{var page=await Read(host,Q(size,cursor));all.AddRange(Keys(page));cursor=page.NextCursor;}while(cursor is not null);Require(all.SequenceEqual(expected));}var whole=await Read(host,Q(200));Require(whole.Entries.Zip(whole.Entries.Skip(1)).All(p=>p.First.RecordedAtUtc>p.Second.RecordedAtUtc));observe(new{phase="uuid_order",adversarial_keys=expected.Length,page_sizes=new[]{1,2,3,7,200},canonical_guid_n_matches_native_uuid=true,recorded_time_intentionally_reverse=true});
        });
        await Check("page size can change while continuation retains exact value order",async()=>
        {
            var store=await Store();await Seed(store,Enumerable.Range(1,6).Select(Key));var host=new ResourceHistoryHost(new(Source(store),Policy()));var first=await Read(host,Q(1));var second=await Read(host,Q(3,first.NextCursor));var third=await Read(host,Q(2,second.NextCursor));Require(Keys(first).Concat(Keys(second)).Concat(Keys(third)).SequenceEqual(Enumerable.Range(1,6).Select(Key))&&third.NextCursor is null);
        });
        await Check("empty exact resource page returns no continuation and no data mutation",async()=>
        {var store=await Store();await Seed(store,[Key(1)]);var page=await Read(new(new(Source(store),Policy())),Q(id:"absent"));Require(page.Entries.Count==0&&page.NextCursor is null&&(await store.Counts()).Sink==1);});
        await Check("full final page and after-last empty page do not manufacture next cursor",async()=>
        {var store=await Store();await Seed(store,[Key(1),Key(2)]);var host=new ResourceHistoryHost(new(Source(store),Policy()));var full=await Read(host,Q(2));var end=await Read(host,Q(2,C(Key(2))));Require(full.Entries.Count==2&&full.NextCursor is null&&end.Entries.Count==0&&end.NextCursor is null);});
        await Check("reader accepts legal positive underfilled wrapper continuation",async()=>
        {
            var store=await Store();await Seed(store,[Key(1),Key(2)]);var source=new Wrapper(Source(store));source.Override=async(tenant,query,token)=>{var page=await source.Inner.ReadAsync(tenant,query,token);return new(page.Entries.Take(1),new(tenant,query.ResourceKind,query.ResourceId,page.Entries[0].Receipt.ReceiptId));};var host=new ResourceHistoryHost(new(source,Policy()));var first=await Read(host,Q(3));Require(first.Entries.Count==1&&first.NextCursor is not null);source.Override=null;Require(Keys(await Read(host,Q(3,first.NextCursor))).SequenceEqual(new[]{Key(2)}));observe(new{phase="underfilled_wrapper",entries=1,requested=3,valid_continuation=true,not_provider_profile_lookahead_claim=true});
        });
        await Check("caller-constructed bookmark position is selection metadata not authenticity",async()=>
        {var store=await Store();await Seed(store,[Key(10),Key(30),Key(50)]);var host=new ResourceHistoryHost(new(Source(store),Policy()));var cursor=C(Key(20));Require(Keys(await Read(host,Q(50,cursor))).SequenceEqual(new[]{Key(30),Key(50)}));observe(new{phase="constructed_cursor",bookmark_row_need_not_exist=true,no_authenticity_claim=true});});
        await Check("inserted keys before and after bookmark demonstrate value continuation without snapshot",async()=>
        {
            var store=await Store();await Seed(store,[Key(10),Key(30),Key(50)]);var host=new ResourceHistoryHost(new(Source(store),Policy()));var first=await Read(host,Q(1));Require(first.NextCursor is not null);await Seed(store,[Key(5),Key(20)]);var resumed=await Read(host,Q(50,first.NextCursor));Require(Keys(resumed).SequenceEqual(new[]{Key(20),Key(30),Key(50)})&&!Keys(resumed).Contains(Key(5)));observe(new{phase="insert_after_page",before_bookmark_insert_missed=true,later_key_insert_visible=true,no_snapshot_claim=true});
        });
        await Check("deleting bookmark and another row resumes by position value not row existence",async()=>
        {
            var store=await Store();await Seed(store,[Key(10),Key(20),Key(30),Key(40)]);var host=new ResourceHistoryHost(new(Source(store),Policy()));var first=await Read(host,Q(2));Require(first.NextCursor?.AfterReceiptId==Key(20));var fixture=new SqlFixture(connection,store.Schema);await fixture.Delete(Key(20));await fixture.Delete(Key(30));var rest=await Read(host,Q(50,first.NextCursor));Require(Keys(rest).SequenceEqual(new[]{Key(40)})&&rest.NextCursor is null);observe(new{phase="delete_after_page",bookmark_deleted=true,other_later_row_deleted=true,resumed_by_value=true,no_snapshot_claim=true});
        });
        await Check("physical tenant versus encoded payload poison faults before page projection",async()=>
        {
            var store=await Store();await new SqlFixture(connection,store.Schema).SeedRow(Key(10),Record(Key(10),tenant:"B"));var source=Source(store);var host=new ResourceHistoryHost(new(source,Policy(TenantChangeAuditMode.MetadataOnly)));Require(await Failure(()=>host.Run(Q()).AsTask()) is InvalidOperationException&&source.QueryAttempts==1&&host.ReaderResults==0);observe(new{phase="physical_poison",kind="tenant",sql_tenant_A_payload_B=true,reader_results=0});
        });
        await Check("physical receipt versus encoded receipt poison faults before page projection",async()=>
        {
            var store=await Store();await new SqlFixture(connection,store.Schema).SeedRow(Key(10),Record(Key(20)));var source=Source(store);var host=new ResourceHistoryHost(new(source,Policy(TenantChangeAuditMode.MetadataOnly)));Require(await Failure(()=>host.Run(Q()).AsTask()) is InvalidOperationException&&source.QueryAttempts==1&&host.ReaderResults==0);observe(new{phase="physical_poison",kind="receipt",physical_and_payload_id_differ=true,reader_results=0});
        });
        await Check("lookahead poison and malformed unrelated scanned TEXT fail closed",async()=>
        {
            var store=await Store();await Seed(store,[Key(10)]);await new SqlFixture(connection,store.Schema).SeedRow(Key(20),Record(Key(20),tenant:"B"));var host=new ResourceHistoryHost(new(Source(store),Policy()));Require(await Failure(()=>host.Run(Q(1)).AsTask()) is InvalidOperationException&&host.ReaderResults==0);
            var malformed=await Store();await new SqlFixture(connection,malformed.Schema).SeedRaw(Key(1),"{broken");await Seed(malformed,[Key(10)]);var other=new ResourceHistoryHost(new(Source(malformed),Policy()));Require(await Failure(()=>other.Run(Q()).AsTask()) is System.Text.Json.JsonException&&other.ReaderResults==0);observe(new{phase="scanned_poison",matching_lookahead_validated=true,malformed_unrelated_candidate_not_silently_skipped=true});
        });
        await Check("provider wrapper null oversized duplicate backwards nonadvancing and foreign rows reject",async()=>
        {
            var store=await Store();var source=new Wrapper(Source(store));var host=new ResourceHistoryHost(new(source,Policy()));var cases=new (TenantChangeAuditResourceQuery Query,TenantChangeAuditResourcePage? Page)[]{(Q(),null),(Q(1),new([Record(Key(1)),Record(Key(2))])),(Q(),new([Record(Key(1)),Record(Key(1))])),(Q(),new([Record(Key(2)),Record(Key(1))])),(Q(after:C(Key(1))),new([Record(Key(1))])),(Q(),new([Record(Key(1),tenant:"B")])),(Q(),new([Record(Key(1),kind:"other")])),(Q(),new([Record(Key(1),id:"other")]))};
            foreach(var test in cases){source.Override=(_,_,_)=>ValueTask.FromResult(test.Page!);Require(await Failure(()=>host.Run(test.Query).AsTask()) is InvalidOperationException&&host.ReaderResults==0);}Require(source.Calls==cases.Length);
        });
        await Check("provider wrapper continuation requires nonempty exact filter and last-row position",async()=>
        {
            var store=await Store();var source=new Wrapper(Source(store));var host=new ResourceHistoryHost(new(source,Policy()));var pages=new[]{new TenantChangeAuditResourcePage([],C(Key(1))),new([Record(Key(1))],C(Key(2))),new([Record(Key(1))],C(Key(1),"B")),new([Record(Key(1))],C(Key(1),kind:"other")),new([Record(Key(1))],C(Key(1),id:"other"))};foreach(var page in pages){source.Override=(_,_,_)=>ValueTask.FromResult(page);Require(await Failure(()=>host.Run(Q()).AsTask()) is InvalidOperationException&&host.ReaderResults==0);}
        });
        await Check("all captured and enabled read modes project without unknown fields or invented values",async()=>
        {
            var store=await Store();var source=Source(store);foreach(var captured in new[]{TenantChangeAuditMode.MetadataOnly,TenantChangeAuditMode.ChangedFields,TenantChangeAuditMode.BeforeAfterSnapshots})
            {
                var id="capture-"+captured;var raw=Record(Key((int)captured),id:id,mode:captured);await store.AppendOnceAsync(raw,default);
                foreach(var read in new[]{TenantChangeAuditMode.MetadataOnly,TenantChangeAuditMode.ChangedFields,TenantChangeAuditMode.BeforeAfterSnapshots})
                {
                    var page=await Read(new(new(source,Policy(read))),Q(id:id));var result=page.Entries.Single();Require(result.CapturedMode==captured&&result.Fields.All(f=>f.Name!="unknown"));if(read==TenantChangeAuditMode.MetadataOnly||captured==TenantChangeAuditMode.MetadataOnly)Require(result.Fields.Count==0&&result.Mode==TenantChangeAuditMode.MetadataOnly);else{Require(result.Fields.Single(f=>f.Name=="secret").Before.Kind==TenantChangeValueKind.Redacted&&result.Fields.Single(f=>f.Name=="secret").After.Kind==TenantChangeValueKind.Redacted);Require(result.Fields.Any(f=>f.Name=="same")== (read==TenantChangeAuditMode.BeforeAfterSnapshots&&captured==TenantChangeAuditMode.BeforeAfterSnapshots));}
                }
            }
        });
        await Check("resource reader captures immutable policy until a new reader is configured",async()=>
        {
            var store=await Store();await Seed(store,[Key(1)]);var source=Source(store);var policy=Policy();var existing=new ResourceHistoryHost(new(source,policy));Require((await Read(existing,Q())).Entries.Single().Fields.Count==3);policy=Policy(TenantChangeAuditMode.MetadataOnly);Require((await Read(existing,Q())).Entries.Single().Fields.Count==3&&(await Read(new(new(source,policy)),Q())).Entries.Single().Fields.Count==0);
        });
        await Check("resource source receives original caller token and preserves exact provider fault refs",async()=>
        {
            var store=await Store();await Seed(store,[Key(1)]);var source=new Wrapper(Source(store));var host=new ResourceHistoryHost(new(source,Policy()));using var caller=new CancellationTokenSource();Require((await host.Run(Q(),token:caller.Token)).IsSuccess&&source.Tokens.Single()==caller.Token);using var other=new CancellationTokenSource();other.Cancel();foreach(var fault in new Exception[]{new IOException("Controlled resource source wrapper fault."),new OperationCanceledException(other.Token)}){source.Override=(_,_,_)=>throw fault;Require(ReferenceEquals(await Failure(()=>host.Run(Q(),token:caller.Token).AsTask()),fault));}
        });
        await Check("record and empty resource pages are withheld for caller cancellation after I/O",async()=>
        {
            foreach(var present in new[]{true,false}){var store=await Store();await Seed(store,[Key(1)]);var source=new Wrapper(Source(store));using var caller=new CancellationTokenSource();source.After=(page,_,_,_)=>{Require((page.Entries.Count>0)==present);caller.Cancel();return Task.FromResult(page);};var host=new ResourceHistoryHost(new(source,Policy()));Require(await Failure(()=>host.Run(Q(id:present?"shared":"missing"),token:caller.Token).AsTask()) is OperationCanceledException cancelled&&cancelled.CancellationToken==caller.Token&&host.ReaderResults==0);observe(new{phase="late_caller",page=present?"record":"empty",reader_results=0,original_caller_token=true});}
        });
        await Check("record and empty resource pages retain expired-scope latch after clock restore",async()=>
        {
            foreach(var present in new[]{true,false}){var store=await Store();await Seed(store,[Key(1)]);var actual=Source(store);var source=new Wrapper(actual);var clock=new FixtureClock();var host=new ResourceHistoryHost(new(source,Policy()),clock:clock);var latched=false;source.After=(page,_,_,_)=>{Require((page.Entries.Count>0)==present);clock.Advance(TimeSpan.FromMinutes(1));try{host.RetainedContext!.DemandAccess(new("A"),"audit-trail","tenant","read");}catch(TenantAccessDeniedException){latched=true;}clock.Advance(TimeSpan.FromMinutes(-1));return Task.FromResult(page);};var denied=await host.Run(Q(id:present?"shared":"missing"));Require(!denied.IsSuccess&&denied.Error.Code=="access.denied"&&latched&&host.ReaderResults==0&&actual.QueryAttempts==1);observe(new{phase="scope_latch",page=present?"record":"empty",rejection=denied.Error.Code,invalidity_latched=true,clock_restored=true,reader_results=0});}
        });
        await Check("held record and empty resource source work is unblocked and joined after cancellation",async()=>
        {
            foreach(var present in new[]{true,false})
            {
                var store=await Store();await Seed(store,[Key(1)]);var source=new Wrapper(Source(store));var pause=new Pause();source.After=async(page,_,_,token)=>{Require((page.Entries.Count>0)==present);await pause.Wait(token);return page;};var host=new ResourceHistoryHost(new(source,Policy()));using var caller=new CancellationTokenSource();var pending=host.Run(Q(id:present?"shared":"missing"),token:caller.Token).AsTask();
                try{await pause.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));caller.Cancel();await pause.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(10));Require(!pending.IsCompleted&&host.ReaderResults==0);pause.Release();Require(await Failure(()=>pending).WaitAsync(TimeSpan.FromSeconds(10)) is OperationCanceledException&&host.ReaderResults==0);}
                finally{caller.Cancel();pause.Release();await Join(pending);await source.JoinOwned();}
                Require(source.Owned.All(t=>t.IsCompleted));observe(new{phase="held_source",page=present?"record":"empty",not_abandoned=true,all_owned_tasks_joined=true});
            }
        });
        await Check("actual resource SQL Lock cancellation quiesces before blocker release and reuses source",async()=>
        {
            var store=await Store();await Seed(store,[Key(1)]);var original=(await store.Payloads("audit_sink")).Single();var source=Source(store);var host=new ResourceHistoryHost(new(source,Policy()));var fixture=new SqlFixture(connection,store.Schema);using var caller=new CancellationTokenSource();var blocker=await fixture.HoldSink();var pending=host.Run(Q(),token:caller.Token).AsTask();var pid=0;
            try{pid=await fixture.Observe(source,pending,caller.Token);caller.Cancel();Require(await Failure(()=>pending).WaitAsync(TimeSpan.FromSeconds(10)) is OperationCanceledException&&host.ReaderResults==0&&await fixture.Quiescent(source,pid));}
            finally{caller.Cancel();await blocker.DisposeAsync();await Join(pending);}
            Require(Keys(await Read(host,Q())).SequenceEqual(new[]{Key(1)})&&source.QueryAttempts==2&&await fixture.Quiescent(source,pid)&&(await store.Payloads("audit_sink")).Single()==original);observe(new{phase="actual_sql_cancel",backend_pid=pid,lock_observed_before_cancel=true,command_done_before_unlock=true,quiescent=true,reuse=true,rows_unchanged=true});
        });
        await Check("eight independently scheduled resource reads preserve tenant partition and rows",async()=>
        {
            var store=await Store();await Seed(store,[Key(1),Key(2)]);await Seed(store,[Key(1),Key(2)],"B");var source=Source(store);var reader=new TenantChangeAuditResourceHistoryReader(source,Policy());var a=new ResourceHistoryHost(reader);var b=new ResourceHistoryHost(reader);b.Authority.AllowB=true;var start=Signal();var workers=Enumerable.Range(0,8).Select(i=>Task.Run(async()=>{await start.Task;var page=await Read(i%2==0?a:b,Q(),i%2==0?"A":"B");Require(page.Entries.Count==2&&page.Entries.All(r=>r.Receipt.Tenant.Value==(i%2==0?"A":"B")));})).ToArray();start.TrySetResult();await Task.WhenAll(workers);Require(source.QueryAttempts==8&&a.Authority.IdentityLookups==4&&b.Authority.IdentityLookups==4&&(await store.Counts()).Sink==2&&(await store.Counts("B")).Sink==2);observe(new{phase="concurrent_reads",scheduled_workers=8,tenant_A=4,tenant_B=4,rows_unchanged=true});
        });
        await Check("wrong scopes grants disposed contexts and live writers cannot query resource history",async()=>
        {
            var store=await Store();await Seed(store,[Key(1)]);var source=Source(store);var reader=new TenantChangeAuditResourceHistoryReader(source,Policy());foreach(var scope in new[]{("read","audit-history"),("relay","audit-outbox"),("inspect","audit-outbox")}){var wrong=new ResourceHistoryHost(reader,scope.Item1,scope.Item2);var denied=await wrong.Run(Q());Require(!denied.IsSuccess&&denied.Error.Code=="access.denied"&&wrong.HandlerFactories==1&&wrong.ReaderResults==0&&source.QueryAttempts==0);}
            var host=new ResourceHistoryHost(reader);host.Authority.GrantedOperation="trail.lookup";var badGrant=await host.Run(Q());Require(!badGrant.IsSuccess&&badGrant.Error.Code=="access.denied"&&host.HandlerFactories==0&&source.QueryAttempts==0);host.Authority.GrantedOperation="trail.resource-history";await Read(host,Q());Require(await Failure(()=>reader.ReadAsync(host.RetainedContext!,Q()).AsTask()) is TenantAccessDeniedException&&source.QueryAttempts==1);host.Authority.AllowHistory=false;var revoked=await host.Run(Q());Require(!revoked.IsSuccess&&revoked.Error.Code=="access.denied"&&source.QueryAttempts==1);
            var deniedWriter=false;var integration=new OutboxIntegration(store,OutboxIntegration.Policy(TenantChangeAuditMode.ChangedFields)){AfterMutation=async context=>{try{await reader.ReadAsync(context,Q());}catch(TenantAccessDeniedException){deniedWriter=true;}}};using var tls=new TlsFixture();using var jwt=new JwtFixture();await using var writer=new Host();await writer.Start(tls,jwt,trailProfile:new(TenantChangeAuditMode.ChangedFields),trailIntegration:integration);using var client=tls.Client(writer.Address);using var request=new HttpRequestMessage(HttpMethod.Post,"/entity/update"){Content=JsonContent.Create(new EntityMutationRequest("A","shared","resource-history-writer",8,"private-resource-history"))};request.Headers.Authorization=new("Bearer",jwt.Token());using var response=await client.SendAsync(request);Require(response.IsSuccessStatusCode&&deniedWriter&&source.QueryAttempts==1);
        });
    }
    private sealed class Wrapper(ITenantChangeAuditResourceHistorySource inner):ITenantChangeAuditResourceHistorySource
    {
        public ITenantChangeAuditResourceHistorySource Inner{get;}=inner;public int Calls;public ConcurrentQueue<CancellationToken> Tokens{get;}=new();public ConcurrentBag<Task> Owned{get;}=new();
        public Func<TenantId,TenantChangeAuditResourceQuery,CancellationToken,ValueTask<TenantChangeAuditResourcePage>>? Override;
        public Func<TenantChangeAuditResourcePage,TenantId,TenantChangeAuditResourceQuery,CancellationToken,Task<TenantChangeAuditResourcePage>>? After;
        public ValueTask<TenantChangeAuditResourcePage> ReadAsync(TenantId tenant,TenantChangeAuditResourceQuery query,CancellationToken token){Interlocked.Increment(ref Calls);Tokens.Enqueue(token);var task=Execute(tenant,query,token);Owned.Add(task);return new(task);}
        private async Task<TenantChangeAuditResourcePage> Execute(TenantId tenant,TenantChangeAuditResourceQuery query,CancellationToken token){var page=Override is null?await Inner.ReadAsync(tenant,query,token):await Override(tenant,query,token);return After is null?page:await After(page,tenant,query,token);}
        public async Task JoinOwned()=>await Task.WhenAll(Owned.Select(Join));
    }
    private sealed class Pause
    {
        public TaskCompletionSource Entered{get;}=Signal();public TaskCompletionSource Cancelled{get;}=Signal();private readonly TaskCompletionSource exit=Signal();public async Task Wait(CancellationToken token){using var registration=token.Register(()=>Cancelled.TrySetResult());Entered.TrySetResult();await exit.Task;}public void Release()=>exit.TrySetResult();
    }
    private sealed class FixtureClock:TimeProvider
    {private readonly DateTimeOffset origin=DateTimeOffset.UtcNow;private long ticks;public override long TimestampFrequency=>TimeSpan.TicksPerSecond;public override DateTimeOffset GetUtcNow()=>origin.AddTicks(ticks);public override long GetTimestamp()=>ticks;public void Advance(TimeSpan span)=>ticks+=span.Ticks;}
    private sealed class SqlLock(NpgsqlConnection connection,NpgsqlTransaction transaction):IAsyncDisposable
    {private int disposed;public async ValueTask DisposeAsync(){if(Interlocked.Exchange(ref disposed,1)!=0)return;try{await transaction.RollbackAsync();}finally{await transaction.DisposeAsync();await connection.DisposeAsync();}}}
    private sealed class SqlFixture(string connection,string schema)
    {
        private async Task<NpgsqlConnection> Open(){var c=new NpgsqlConnection(connection);try{await c.OpenAsync();return c;}catch{await c.DisposeAsync();throw;}}
        // These mutate only declared owned fixture rows, never the read-only provider or old Store SQL.
        public Task SeedRow(Guid physical,TenantChangeAuditRecord encoded)=>SeedRaw(physical,PayloadCodec.Encode(encoded));
        public async Task SeedRaw(Guid physical,string encoded){await using var c=await Open();await using var cmd=new NpgsqlCommand($"INSERT INTO {schema}.audit_sink(tenant,receipt,payload) VALUES($1,$2,$3)",c);cmd.Parameters.AddWithValue("A");cmd.Parameters.AddWithValue(physical);cmd.Parameters.AddWithValue(encoded);await cmd.ExecuteNonQueryAsync();}
        public async Task Delete(Guid receipt){await using var c=await Open();await using var cmd=new NpgsqlCommand($"DELETE FROM {schema}.audit_sink WHERE tenant=$1 AND receipt=$2",c);cmd.Parameters.AddWithValue("A");cmd.Parameters.AddWithValue(receipt);await cmd.ExecuteNonQueryAsync();}
        public async Task<SqlLock> HoldSink(){var c=await Open();var tx=await c.BeginTransactionAsync();try{await using var cmd=new NpgsqlCommand($"LOCK TABLE {schema}.audit_sink IN ACCESS EXCLUSIVE MODE",c,tx);await cmd.ExecuteNonQueryAsync();return new(c,tx);}catch{await tx.DisposeAsync();await c.DisposeAsync();throw;}}
        public async Task<int> Observe(PostgresResourceHistorySource source,Task pending,CancellationToken caller)
        {
            await using var c=await Open();for(var i=0;i<100;i++){await using var cmd=new NpgsqlCommand("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND application_name=$2 AND wait_event_type='Lock' AND query LIKE $3 AND query LIKE $4)",c);cmd.Parameters.AddWithValue(source.LastBackendPid);cmd.Parameters.AddWithValue(source.ApplicationName);cmd.Parameters.AddWithValue("%owned-resource-history-query%");cmd.Parameters.AddWithValue("%"+schema+".audit_sink%");if((bool)(await cmd.ExecuteScalarAsync())!){Require(!pending.IsCompleted&&!caller.IsCancellationRequested);return source.LastBackendPid;}Require(!pending.IsCompleted);await Task.Delay(20);}throw new InvalidOperationException("Owned resource SQL Lock wait not observed.");
        }
        public async Task<bool> Quiescent(PostgresResourceHistorySource source,int pid){Require(pid>0);await using var c=await Open();await using var cmd=new NpgsqlCommand("SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND application_name=$2 AND (state='active' OR wait_event_type='Lock'))",c);cmd.Parameters.AddWithValue(pid);cmd.Parameters.AddWithValue(source.ApplicationName);return(bool)(await cmd.ExecuteScalarAsync())!;}
    }
}
