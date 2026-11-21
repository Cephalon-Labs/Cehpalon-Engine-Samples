extern alias securityapi;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Cehpalon.Engine.Authorization;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Identity.JwtBearer;
using Cehpalon.Engine.Tenancy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using securityapi::SecurityApi;

namespace AuditOutbox;

public static partial class ResourceTransportChecks
{
    private static readonly TimeSpan Watchdog=TimeSpan.FromSeconds(30),Budget=TimeSpan.FromSeconds(6);
    private const string Selection="tenant entries { receiptId tenant resourceKind resourceId recordedAtUtc mode capturedMode } nextCursor { tenant resourceKind resourceId afterReceiptId }";
    private const string ProjectionSelection="tenant entries { receiptId resourceKind mode capturedMode fields { name wasChanged before { kind text } after { kind text number boolean } } } nextCursor { tenant resourceKind resourceId afterReceiptId }";
    private static void Require(bool value){if(!value)throw new InvalidOperationException("Resource transport conformance assertion failed.");}
    private static TaskCompletionSource Signal()=>new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static async Task<Exception> Failure(Func<Task> action){try{await action();}catch(Exception error){return error;}throw new InvalidOperationException("Expected controlled resource transport failure.");}
    private static async Task Join(Task task){try{await task;}catch(Exception){}}
    private static async Task Wait(Func<bool> predicate){for(var i=0;i<1000;i++){if(predicate())return;await Task.Delay(20);}throw new InvalidOperationException("Owned resource transport signal was not observed.");}
    private static Guid Key(int n)=>Guid.Parse("00000000-0000-0000-0000-"+n.ToString("x12"));
    private static AuditReceiptTransportOptions Options(bool graph,TimeSpan? timeout=null,bool receipt=false,bool resource=true)=>new(!graph,graph,true,timeout){ReceiptLookupEnabled=receipt,ResourceHistoryEnabled=resource};
    private static AuditResourceHistoryRequest Q(int limit=50,AuditResourceHistoryCursor? cursor=null,string tenant="A",string kind="entity",string id="shared")=>new(tenant,kind,id,limit,cursor);
    private static TenantChangeAuditPolicy Policy(TenantChangeAuditMode mode=TenantChangeAuditMode.ChangedFields)=>new(mode,[new("entity.update","update","entity",[new("title"),new("secret",true),new("same")])]);
    private static TenantChangeAuditRecord Record(Guid key,string tenant="A",string kind="entity",string id="shared",string title="value",DateTimeOffset? time=null)=>new(new(key,new PrincipalId("owned-resource-wire-record","record-writer"),"fixture-service",new(tenant),"entity.update","update",kind,id,"fixture-v1",TenantChangeKind.Update,"0","1"),time??DateTimeOffset.UnixEpoch.AddDays(20000),TenantChangeAuditMode.BeforeAfterSnapshots,[new("title",TenantChangeValue.Text("before"),TenantChangeValue.Text(title)),new("secret",TenantChangeValue.Text("SECRET-BEFORE"),TenantChangeValue.Text("SECRET-AFTER")),new("same",TenantChangeValue.Text("stable"),TenantChangeValue.Text("stable"),false),new("unknown",TenantChangeValue.Text("HIDDEN-UNKNOWN"),TenantChangeValue.Text("HIDDEN-UNKNOWN"),false)]);
    private sealed class Authority:ITenantMembershipSource,IResourceScopeSource,IAuthorizationFactsSource
    {
        public volatile bool MembershipRevoked,ResourceRevoked,PolicyRevoked;public int MembershipCalls,ResourceCalls,PolicyCalls;
        public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot identity,TenantId tenant,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();Interlocked.Increment(ref MembershipCalls);var subject=identity.Principal.Subject;var allowed=!MembershipRevoked&&((subject is "resource-both" or "both-reader")&&(tenant.Value is "A" or "B")||subject=="resource-b"&&tenant.Value=="B"||(subject is "resource-a" or "receipt-only" or "no-role" or "wrong-attribute" or "history-only" or "entity-only")&&tenant.Value=="A");var now=DateTimeOffset.UtcNow;return ValueTask.FromResult<TenantMembershipSnapshot?>(allowed?new(identity.Principal,tenant,true,now.AddMinutes(-1),now.AddMinutes(1),"resource-wire-membership"):null);
        }
        public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId tenant,string kind,string id,CancellationToken token)
        {token.ThrowIfCancellationRequested();Interlocked.Increment(ref ResourceCalls);return ValueTask.FromResult<ResourceScopeSnapshot?>(ResourceRevoked?null:new(tenant,kind,id,"resource-wire-scope"));}
        public ValueTask<AuthorizationFacts?> ResolveAsync(TenantAccessRequest request,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();Interlocked.Increment(ref PolicyCalls);var subject=request.Identity.Principal.Subject;string[] roles=PolicyRevoked||subject=="no-role"?[]:subject=="receipt-only"?["receipt-reader"]:subject=="history-only"?["history-reader"]:subject=="entity-only"?["entity-reader"]:subject=="both-reader"?["receipt-reader","resource-reader"]:["resource-reader"];var now=DateTimeOffset.UtcNow;return ValueTask.FromResult<AuthorizationFacts?>(new(request.Identity.Principal,request.Tenant,request.Membership.Version,request.Resource.Kind,request.Resource.ResourceId,request.Resource.Version,now.AddMinutes(-1),now.AddMinutes(1),roles,new([new("department",subject=="wrong-attribute"?"sales":"audit")]),new([new("department","audit")])));
        }
    }
    private sealed record Reply(HttpStatusCode Status,string Body,JsonElement Root)
    {
        public bool Success(bool graph)=>Status==HttpStatusCode.OK&&Root.ValueKind==JsonValueKind.Object&&(!graph||!Root.TryGetProperty("errors",out _));
        public JsonElement Value(bool graph)=>graph?Root.GetProperty("data").GetProperty("trailResourceHistory"):Root;
        public bool Error(bool graph,string code)=>Root.ValueKind==JsonValueKind.Object&&(graph?Root.TryGetProperty("errors",out var errors)&&errors.EnumerateArray().Any(e=>e.GetProperty("extensions").GetProperty("code").GetString()==code):Root.TryGetProperty("code",out var c)&&c.GetString()==code);
    }
    private static Guid[] Keys(Reply reply,bool graph)=>reply.Value(graph).GetProperty("entries").EnumerateArray().Select(r=>Guid.Parse(r.GetProperty("receiptId").GetString()??throw new InvalidOperationException("Missing wire receipt key."))).ToArray();
    private static AuditResourceHistoryCursor? Cursor(Reply reply,bool graph)
    {var value=reply.Value(graph).GetProperty("nextCursor");return value.ValueKind==JsonValueKind.Null?null:new(value.GetProperty("tenant").GetString()??throw new InvalidOperationException(),value.GetProperty("resourceKind").GetString()??throw new InvalidOperationException(),value.GetProperty("resourceId").GetString()??throw new InvalidOperationException(),Guid.Parse(value.GetProperty("afterReceiptId").GetString()??throw new InvalidOperationException()));}
    private static string Input(AuditResourceHistoryRequest request,bool includeLimit=true)
    {
        var text="{tenant:"+JsonSerializer.Serialize(request.Tenant)+",resourceKind:"+JsonSerializer.Serialize(request.ResourceKind)+",resourceId:"+JsonSerializer.Serialize(request.ResourceId)+(includeLimit?",limit:"+request.Limit.ToString(CultureInfo.InvariantCulture):"");if(request.Continuation is{ } cursor)text+=",continuation:{tenant:"+JsonSerializer.Serialize(cursor.Tenant)+",resourceKind:"+JsonSerializer.Serialize(cursor.ResourceKind)+",resourceId:"+JsonSerializer.Serialize(cursor.ResourceId)+",afterReceiptId:"+JsonSerializer.Serialize(cursor.AfterReceiptId.ToString("D"))+"}";return text+"}";
    }
    private sealed class Fixture(PostgresStore store,string connection,string connectionFile,TlsFixture tls,JwtFixture jwt)
    {
        private PostgresIndexedAuditStorage? source;
        public PostgresIndexedAuditStorage Source=>source??throw new InvalidOperationException("Fixture source has not been delivered by activation.");
        public PostgresStore Store=>store;public readonly Authority Authority=new();public readonly AuditReceiptTransportProbe Probe=new();public int CredentialReads,SecurityCallbacks,ConfigureCallbacks;
        public async ValueTask<PostgresIndexedAuditStorage> SourceFactory(CancellationToken token){Require(Probe.Events.Contains("plan.validated")&&Probe.Events.Contains("security.validated"));Interlocked.Increment(ref CredentialReads);var value=(await File.ReadAllTextAsync(connectionFile,token)).Trim();var client=new PostgresIndexedAuditStorage(value,store.Schema);source=client;return client;}
        public AuditReceiptTransportSecurity Security(TenantChangeAuditPolicy? policy=null)
        {
            Require(Probe.Events.Contains("plan.validated"));Interlocked.Increment(ref SecurityCallbacks);var predicates=new[]{AttributePredicate.Match(AttributeScope.Subject,"department",AttributeScope.Resource,"department")};return new("Bearer",new([JwtFixture.Issuer],["Bearer"]),Authority,Authority,new RoleAttributeAccessPolicy([new("trail.lookup","read","audit-trail",["receipt-reader"],predicates),new("trail.resource-history","read","audit-trail",["resource-reader"],predicates)],Authority),policy??Policy(),TimeSpan.FromSeconds(30));
        }
        public void Configure(WebApplicationBuilder builder)
        {
            Interlocked.Increment(ref ConfigureCallbacks);builder.WebHost.ConfigureKestrel(k=>k.Listen(IPAddress.Loopback,0,l=>{l.Protocols=HttpProtocols.Http1;l.UseHttps(tls.Server);}));var settings=new JwtProfileSettings{Scheme="Bearer",Issuer=JwtFixture.Issuer,Audience=JwtFixture.Audience,Algorithm="RS256",KeySource=JwtKeySource.PublicJwks};builder.Configuration.AddJsonStream(new MemoryStream(JsonSerializer.SerializeToUtf8Bytes(new{Authentication=settings})));var profile=JwtAuthenticationProfile.FromConfiguration(builder.Configuration.GetSection("Authentication"));builder.Services.AddAuthentication("Bearer").AddCehpalonJwtBearer(profile,publicJwks:()=>jwt.PublicJwks());
        }
        public Task<AuditReceiptTransportHost> Start(AuditReceiptTransportOptions options,TenantChangeAuditPolicy? policy=null)=>AuditReceiptTransportHost.ActivateAsync(options,SourceFactory,()=>Security(policy),Configure,Probe).AsTask();
        public HttpClient Client(AuditReceiptTransportHost host){var client=tls.Client(host.Address);client.Timeout=Watchdog;return client;}
        public string Token(string subject="resource-a")=>jwt.Token(subject);
        public SqlProbe Sql()=>new(connection,store.Schema,()=>Source);
        public async Task Append(IEnumerable<TenantChangeAuditRecord> records){await using var writer=new PostgresIndexedAuditStorage(connection,store.Schema);await writer.OpenExistingAsync();foreach(var record in records)await writer.AppendOnceAsync(record,default);}
        public async Task<Reply> Send(HttpClient client,bool graph,AuditResourceHistoryRequest? request=null,string? token=null,string? raw=null,string selection=Selection,CancellationToken cancellationToken=default)
        {
            request??=Q();using var message=new HttpRequestMessage(HttpMethod.Post,graph?"/graphql":"/audit/resources/history");if(token is not null)message.Headers.Authorization=new("Bearer",token);message.Content=raw is not null?new StringContent(raw,Encoding.UTF8,"application/json"):graph?JsonContent.Create(new{query="query { trailResourceHistory(input:"+Input(request)+") {"+selection+"} }"}):JsonContent.Create(request);return await SendMessage(client,message,cancellationToken);
        }
        public async Task<Reply> Receipt(HttpClient client,bool graph,string? token=null,CancellationToken cancellationToken=default)
        {using var message=new HttpRequestMessage(HttpMethod.Post,graph?"/graphql":"/audit/receipts/lookup");if(token is not null)message.Headers.Authorization=new("Bearer",token);message.Content=graph?JsonContent.Create(new{query="query { trailReceipt(input:{tenant:\"A\",receiptId:\""+Key(1)+"\"}) {tenant record{receiptId tenant}} }"}):JsonContent.Create(new AuditReceiptLookupRequest("A",Key(1)));return await SendMessage(client,message,cancellationToken);}
        public async Task<Reply> Siblings(HttpClient client,string token,bool mixed=false)
        {var query="query { a:trailResourceHistory(input:"+Input(Q())+") {"+Selection+"} b:"+(mixed?"trailReceipt(input:{tenant:\"A\",receiptId:\""+Key(1)+"\"}) {tenant record{receiptId tenant}}":"trailResourceHistory(input:"+Input(Q(tenant:"B"))+") {"+Selection+"}")+" }";return await Send(client,true,token:token,raw:JsonSerializer.Serialize(new{query}));}
        private static async Task<Reply> SendMessage(HttpClient client,HttpRequestMessage request,CancellationToken token)
        {using var response=await client.SendAsync(request,token);var body=await response.Content.ReadAsStringAsync(token);JsonElement root=default;try{root=JsonDocument.Parse(body).RootElement.Clone();}catch(JsonException){}return new(response.StatusCode,body,root);}
    }
    public static async Task Run(Func<string,Func<Task>,Task> check,Func<Task<PostgresStore>> createStore,Func<PostgresStore,Task> mutate,string connection,string connectionFile,Action<object> observe)
    {
        using var tls=new TlsFixture();using var jwt=new JwtFixture();using var wrongJwt=new JwtFixture();
        async Task<Fixture> Create(bool seed=true)
        {var store=await createStore();await using(var provision=await IndexedProfileComposition.ActivateAsync(IndexedProfileComposition.Configuration(true),store.Schema,IndexedProfileOpenMode.CreateNew,_=>ValueTask.FromResult(connection),new())){if(seed){var writer=provision.Storage??throw new InvalidOperationException("Fixture provisioning did not deliver storage.");await writer.AppendOnceAsync(Record(Key(1)),default);await writer.AppendOnceAsync(Record(Key(1),"B"),default);}}return new(store,connection,connectionFile,tls,jwt);}
        await check("legacy four-position options ABI defaults to unchanged receipt-only wire behavior",async()=>
        {
            var options=new AuditReceiptTransportOptions(true,false,true,null);var(http,graph,security,timeout)=options;Require(http&&!graph&&security&&timeout is null&&options.ReceiptLookupEnabled&&!options.ResourceHistoryEnabled);var f=await Create();await using var host=await f.Start(options);using var client=f.Client(host);Require((await f.Receipt(client,false,f.Token("receipt-only"))).Success(false));var absent=await f.Send(client,false,token:f.Token());Require(absent.Status==HttpStatusCode.NotFound&&f.Source.LookupQueries==1&&f.Source.ResourceQueries==0&&f.Probe.SourceLookupCalls==1&&f.Probe.ReaderResults==1&&f.Probe.ResourceGatewayFactories==0&&f.Probe.ResourceHandlerFactories==0&&f.Probe.SourceResourceHistoryCalls==0&&f.Probe.ResourceReaderResults==0);observe(new{phase="resource_options_compatibility",four_ctor_and_deconstruct_positions_preserved=true,default_receipt_only=true,old_lookup_counters_unchanged=true,resource_work=0});
        });
        await check("both read selectors or both transports off skip all owned callbacks and unused invalid budget",async()=>
        {
            foreach(var options in new[]{new AuditReceiptTransportOptions(true,true,false,TimeSpan.FromTicks(-1)){ReceiptLookupEnabled=false,ResourceHistoryEnabled=false},new AuditReceiptTransportOptions(false,false,false,TimeSpan.FromTicks(-1)){ReceiptLookupEnabled=false,ResourceHistoryEnabled=true}})
            {
                var callbacks=0;var probe=new AuditReceiptTransportProbe();await using var host=await AuditReceiptTransportHost.ActivateAsync(options,_=>{callbacks++;throw new InvalidOperationException();},()=>{callbacks++;throw new InvalidOperationException();},_=>{callbacks++;throw new InvalidOperationException();},probe);Require(callbacks==0&&host.Plan.ActivationOrder.Count==0&&host.App is null&&host.Source is null&&probe.SourceFactories==0&&probe.SecurityFactories==0&&probe.HostFactories==0&&probe.AuthenticationServices==0&&probe.GraphQLServices==0&&probe.HttpEndpoints==0&&probe.GraphQLEndpoints==0);
            }
            observe(new{phase="resource_disabled",both_reads_off_or_both_transports_off=true,owned_factories_services_endpoints=0,unused_invalid_budget_ignored=true});
        });
        await check("invalid security and resource-only combined or single-transport selections retain one source",async()=>
        {
            foreach(var options in new[]{new AuditReceiptTransportOptions(true,false,false){ReceiptLookupEnabled=false,ResourceHistoryEnabled=true},Options(false,TimeSpan.Zero),Options(true,TimeSpan.FromTicks(TimeSpan.TicksPerMinute+1))})
            {var callbacks=0;Require(await Failure(()=>AuditReceiptTransportHost.ActivateAsync(options,_=>{callbacks++;throw new InvalidOperationException();},()=>{callbacks++;throw new InvalidOperationException();},_=>{callbacks++;throw new InvalidOperationException();}).AsTask()) is ArgumentException&&callbacks==0);}
            foreach(var graph in new[]{false,true})
            {
                var f=await Create();await using var host=await f.Start(Options(graph));using var client=f.Client(host);Require(!(await f.Receipt(client,graph,f.Token("receipt-only"))).Success(graph)&&f.Source.LookupQueries==0&&f.Source.ResourceQueries==0);var disabled=await f.Send(client,!graph,token:f.Token());Require(disabled.Status==HttpStatusCode.NotFound);Require((await f.Send(client,graph,token:f.Token())).Success(graph)&&f.Source.ResourceQueries==1&&f.Source.LookupQueries==0&&f.Probe.GatewayFactories==0&&f.Probe.HandlerFactories==0&&f.Probe.ReaderResults==0&&f.Probe.SourceResourceHistoryCalls==1&&f.Probe.ResourceReaderResults==1&&f.Probe.SourceFactories==1&&f.Probe.SourceOpenAttempts==1&&f.CredentialReads==1&&f.Source.DdlCommands==0&&((f.Probe.GraphQLServices>0)==graph));
            }
            var combined=await Create();await using(var host=await combined.Start(new(true,true){ResourceHistoryEnabled=true})){using var client=combined.Client(host);var reply=await combined.Siblings(client,combined.Token("both-reader"),mixed:true);Require(reply.Success(true)&&combined.Source.LookupQueries==1&&combined.Source.ResourceQueries==1&&combined.Probe.SourceFactories==1&&combined.Probe.SourceOpenAttempts==1&&combined.Probe.HttpEndpoints==2&&combined.Probe.GraphQLEndpoints==1);}
            observe(new{phase="resource_selection",invalid_plan_callbacks=0,resource_only_lookup_work=0,single_transport_service_isolation=true,combined_one_source_one_OpenExisting=true,no_startup_DDL=true});
        });
        await check("mixed lookup and resource server work fully joins before one source disposal even when stop fails",async()=>
        {
            foreach(var stopFails in new[]{false,true})
            {
                var f=await Create();var lookupEntered=Signal();var resourceEntered=Signal();var release=Signal();f.Probe.AfterProviderRead=_=>{lookupEntered.TrySetResult();return release.Task;};f.Probe.AfterResourceProviderRead=_=>{resourceEntered.TrySetResult();return release.Task;};var stop=new IOException("Controlled mixed resource host stop failure.");if(stopFails)f.Probe.StopApplicationAsync=_=>throw stop;var host=await f.Start(new(true,true){ResourceHistoryEnabled=true});using var client=f.Client(host);using var caller=new CancellationTokenSource();var lookup=f.Receipt(client,false,f.Token("both-reader"),caller.Token);var resource=f.Send(client,true,token:f.Token("both-reader"),cancellationToken:caller.Token);var all=Task.WhenAll(lookup,resource);Task? disposal=null;
                try{await Task.WhenAll(lookupEntered.Task,resourceEntered.Task).WaitAsync(Watchdog);Require(f.Probe.ActiveDispatches==2&&f.Probe.SourceLookupCalls==1&&f.Probe.SourceResourceHistoryCalls==1);disposal=host.DisposeAsync().AsTask();await f.Probe.AdmissionClosed.Task.WaitAsync(Watchdog);Require(!disposal.IsCompleted&&f.Probe.SourceDisposals==0&&!f.Source.IsDisposed);release.TrySetResult();if(stopFails)Require(Has(await Failure(()=>disposal).WaitAsync(Watchdog),stop));else await disposal.WaitAsync(Watchdog);Require(f.Probe.ActiveDispatches==0&&f.Probe.CompletedDispatches==2&&f.Probe.DrainCompleted.Task.IsCompleted&&f.Source.IsDisposed&&f.Source.DataSourceDisposals==1&&f.Probe.SourceDisposals==1);var events=f.Probe.Events.ToArray();var drained=Array.IndexOf(events,"host.drained");Require(drained>=0&&drained<Array.IndexOf(events,"source.dispose.started"));await f.Sql().AppQuiescent();}
                finally{caller.Cancel();release.TrySetResult();await Join(all);if(disposal is not null)await Join(disposal);else await Join(host.DisposeAsync().AsTask());}
            }
            observe(new{phase="resource_mixed_ownership",HTTP_lookup_and_GraphQL_resource=true,both_admitted_tasks_joined=true,normal_and_stop_failure=true,one_source_disposal_after_drain=true,no_concurrent_LastBackendPid_identity_claim=true});
        });
        foreach(var graph in new[]{false,true})
        {
            var label=graph?"GraphQL":"HTTP";
            await check(label+" exact resource filters wire bounds and null or configured tokens preserve selection",async()=>
            {
                var f=await Create(false);var ids=new[]{"shared","Shared","\u00e9","e\u0301","resource' OR true--"};var rows=ids.Select((id,i)=>Record(Key(i+1),id:id,title:id)).ToList();rows.Add(Record(Key(20),kind:"other"));var maxKind=new string('r',128);var maxId=new string('\u754c',512);rows.Add(Record(Key(30),kind:maxKind,id:maxId));await f.Append(rows);
                foreach(var timeout in new TimeSpan?[]{null,Budget})
                {
                    await using var host=await f.Start(Options(graph,timeout));using var client=f.Client(host);for(var i=0;i<ids.Length;i++){var reply=await f.Send(client,graph,Q(id:ids[i]),f.Token());Require(reply.Success(graph)&&Keys(reply,graph).SequenceEqual(new[]{Key(i+1)})&&(f.Probe.LastResourceDispatchToken==f.Probe.LastResourceWorkToken)==(timeout is null));}Require(Keys(await f.Send(client,graph,Q(kind:"other"),f.Token()),graph).Single()==Key(20)&&Keys(await f.Send(client,graph,Q(kind:maxKind,id:maxId),f.Token()),graph).Single()==Key(30)&&Keys(await f.Send(client,graph,Q(id:"SHARED"),f.Token()),graph).Length==0&&f.Source.LookupQueries==0);
                }
                observe(new{phase="resource_wire_exact_filters",transport=label,case_unicode_quote_literal_exact=true,max_ASCII_kind128_CJK_id512=true,null_original_and_configured_linked_server_tokens=true,lookup_queries=0});
            });
            await check(label+" adversarial native UUID order survives primitive wire pagination without chronology",async()=>
            {
                var f=await Create(false);var keys=new[]{"ffffffff-ffff-ffff-ffff-ffffffffffff","80000000-0000-0000-0000-000000000000","7fffffff-ffff-ffff-ffff-ffffffffffff","00010000-0000-0000-0000-000000000000","0000ffff-0000-0000-0000-000000000000","00000001-0000-0000-0000-000000000000","00000000-0001-0000-0000-000000000000","00000000-0000-0001-0000-000000000000","00000000-0000-0000-0001-000000000000","00000000-0000-0000-0000-000000000001"}.Select(Guid.Parse).OrderBy(g=>g.ToString("N"),StringComparer.Ordinal).ToArray();await f.Append(keys.Select((key,i)=>Record(key,time:DateTimeOffset.UnixEpoch.AddDays(20000).AddMinutes(-i))));await using var host=await f.Start(Options(graph));using var client=f.Client(host);var received=new List<Guid>();var times=new List<DateTimeOffset>();AuditResourceHistoryCursor? cursor=null;var pages=0;
                do{var page=await f.Send(client,graph,Q(3,cursor),f.Token());Require(page.Success(graph));received.AddRange(Keys(page,graph));times.AddRange(page.Value(graph).GetProperty("entries").EnumerateArray().Select(r=>DateTimeOffset.Parse(r.GetProperty("recordedAtUtc").GetString()??throw new InvalidOperationException(),CultureInfo.InvariantCulture)));cursor=Cursor(page,graph);if(cursor is not null)Require(cursor.AfterReceiptId==received[^1]&&cursor.Tenant=="A"&&cursor.ResourceKind=="entity"&&cursor.ResourceId=="shared");Require(++pages<=5);}while(cursor is not null);Require(received.SequenceEqual(keys)&&times.Zip(times.Skip(1)).All(p=>p.First>p.Second));observe(new{phase="resource_wire_uuid_order",transport=label,adversarial_keys=keys.Length,canonical_GuidN_matches_actual_PG_UUID=true,reversed_recorded_time=true,no_chronology_claim=true});
            });
            await check(label+" default limit fifty changing limits and terminal underfill preserve cursor bounds",async()=>
            {
                var f=await Create(false);await f.Append(Enumerable.Range(1,201).Select(n=>Record(Key(n))));await using var host=await f.Start(Options(graph));using var client=f.Client(host);var raw=graph?JsonSerializer.Serialize(new{query="query { trailResourceHistory(input:"+Input(Q(),includeLimit:false)+") {"+Selection+"} }"}):JsonSerializer.Serialize(new{tenant="A",resourceKind="entity",resourceId="shared"});var defaults=await f.Send(client,graph,token:f.Token(),raw:raw);Require(defaults.Success(graph)&&Keys(defaults,graph).Length==50&&Cursor(defaults,graph)?.AfterReceiptId==Key(50));var all=new List<Guid>();AuditResourceHistoryCursor? cursor=null;foreach(var size in new[]{1,3,2,200}){var reply=await f.Send(client,graph,Q(size,cursor),f.Token());Require(reply.Success(graph));all.AddRange(Keys(reply,graph));cursor=Cursor(reply,graph);}Require(all.SequenceEqual(Enumerable.Range(1,201).Select(Key))&&cursor is null);var max=await f.Send(client,graph,Q(200),f.Token());Require(Keys(max,graph).Length==200&&Cursor(max,graph)?.AfterReceiptId==Key(200));var last=await f.Send(client,graph,Q(200,Cursor(max,graph)),f.Token());Require(Keys(last,graph).SequenceEqual(new[]{Key(201)})&&Cursor(last,graph) is null);var end=await f.Send(client,graph,Q(200,new("A","entity","shared",Key(201))),f.Token());Require(Keys(end,graph).Length==0&&Cursor(end,graph) is null);observe(new{phase="resource_wire_page_limits",transport=label,actual_default50=true,changing_limits=new[]{1,3,2,200},max_page200=true,terminal_underfill_and_empty=true,no_nonterminal_underfilled_source_claim=true,bounded_extra_fixture_rows=201});
            });
            await check(label+" value bookmarks survive inserts and deleted bookmark without snapshot semantics",async()=>
            {
                var f=await Create(false);await f.Append(new[]{Record(Key(10)),Record(Key(20)),Record(Key(30))});await using var host=await f.Start(Options(graph));using var client=f.Client(host);var first=await f.Send(client,graph,Q(2),f.Token());var cursor=Cursor(first,graph)??throw new InvalidOperationException("Expected bookmark.");Require(cursor.AfterReceiptId==Key(20));await f.Append(new[]{Record(Key(15)),Record(Key(25)),Record(Key(35))});await f.Sql().Delete(Key(20));var continued=await f.Send(client,graph,Q(50,cursor),f.Token());Require(continued.Success(graph)&&Keys(continued,graph).SequenceEqual(new[]{Key(25),Key(30),Key(35)})&&Cursor(continued,graph) is null);var constructed=new AuditResourceHistoryCursor("A","entity","shared",Key(22));Require(Keys(await f.Send(client,graph,Q(50,constructed),f.Token()),graph).SequenceEqual(new[]{Key(25),Key(30),Key(35)}));observe(new{phase="resource_wire_mutable_bookmark",transport=label,before_bookmark_insert_not_revisited=true,after_bookmark_insert_visible=true,deleted_or_absent_bookmark_allowed=true,unsigned_position_not_authority_or_snapshot=true});
            });
            await check(label+" empty or pending resource page changes only after explicit indexed publication",async()=>
            {
                var f=await Create(false);await mutate(f.Store);var pending=PayloadCodec.Decode((await f.Store.Payloads()).Single());await using var host=await f.Start(Options(graph));using var client=f.Client(host);var query=Q(kind:pending.Receipt.ResourceKind,id:pending.Receipt.ResourceId);var empty=await f.Send(client,graph,query,f.Token());Require(empty.Success(graph)&&Keys(empty,graph).Length==0&&Cursor(empty,graph) is null);await using(var writer=new PostgresIndexedAuditStorage(connection,f.Store.Schema)){await writer.OpenExistingAsync();Require((await new RelayHost(TenantChangeAuditOutboxRelay.Activate(true,()=>f.Store,()=>writer)).Run()).IsSuccess);}var visible=await f.Send(client,graph,query,f.Token());Require(visible.Success(graph)&&Keys(visible,graph).Single()==pending.Receipt.ReceiptId&&(await f.Store.Counts())==(1,1,0));observe(new{phase="resource_wire_publication",transport=label,pending_empty_success=true,separate_manual_fresh_relay_sink=true,selected_indexed_history_only=true,no_empty_commit_or_legacy_backfill_claim=true});
            });
            await check(label+" immutable read policy projects resource fields NUL and capture provenance",async()=>
            {
                var f=await Create(false);await f.Append(new[]{Record(Key(1),title:"a\0b")});foreach(var mode in new[]{TenantChangeAuditMode.ChangedFields,TenantChangeAuditMode.MetadataOnly})
                {
                    await using var host=await f.Start(Options(graph),Policy(mode));using var client=f.Client(host);var reply=await f.Send(client,graph,token:f.Token(),selection:ProjectionSelection);Require(reply.Success(graph)&&!reply.Body.Contains("SECRET-",StringComparison.Ordinal)&&!reply.Body.Contains("HIDDEN-UNKNOWN",StringComparison.Ordinal));var record=reply.Value(graph).GetProperty("entries").EnumerateArray().Single();Require(record.GetProperty("resourceKind").GetString()=="entity"&&record.GetProperty("capturedMode").GetString()=="BeforeAfterSnapshots"&&record.GetProperty("mode").GetString()==mode.ToString());var fields=record.GetProperty("fields").EnumerateArray().ToArray();if(mode==TenantChangeAuditMode.MetadataOnly)Require(fields.Length==0);else Require(fields.Length==2&&fields.Single(x=>x.GetProperty("name").GetString()=="title").GetProperty("after").GetProperty("text").GetString()=="a\0b"&&fields.Single(x=>x.GetProperty("name").GetString()=="secret").GetProperty("after").GetProperty("kind").GetString()=="Redacted");
                }
                observe(new{phase="resource_wire_projection",transport=label,current_changed_or_metadata_policy=true,captured_snapshot_provenance=true,field_NUL_roundtrip=true,unknown_unchanged_sensitive_values_not_released=true});
            });
            await check(label+" malformed resource bounds envelope or injected authority produce zero resource queries",async()=>
            {
                var f=await Create();await using var host=await f.Start(Options(graph));using var client=f.Client(host);foreach(var request in new AuditResourceHistoryRequest[]{Q(0),Q(201),Q(kind:"Entity"),Q(kind:new string('r',129)),Q(id:" "),Q(id:new string('x',513)),Q(id:"a\0b"),Q(tenant:"bad tenant")}){var invalid=await f.Send(client,graph,request,f.Token());Require(!invalid.Success(graph)&&f.Source.ResourceQueries==0&&f.Probe.ResourceHandlerFactories==0&&f.Probe.SourceResourceHistoryCalls==0);}var raw=graph?JsonSerializer.Serialize(new{query="query { trailResourceHistory(input:{tenant:\"A\",resourceKind:\"entity\",resourceId:\"shared\",roles:[\"admin\"]}) {tenant} }"}):JsonSerializer.Serialize(new{tenant="A",resourceKind="entity",resourceId="shared",roles=new[]{"admin"},principal="both-reader",readTimeout=0});Require(!(await f.Send(client,graph,token:f.Token(),raw:raw)).Success(graph));Require(!(await f.Send(client,graph,token:f.Token(),raw:"[]")).Success(graph)&&f.Source.ResourceQueries==0&&f.Probe.ResourceHandlerFactories==0);observe(new{phase="resource_wire_shape_validation",transport=label,bounded_tenant_kind_id_limit=true,control_chars_and_unknown_authority_fields_rejected=true,resource_queries=0,startup_catalog_not_request_query=true});
            });
            await check(label+" cursor metadata binding errors reject before Core or source while matched DTOs grant nothing",async()=>
            {
                var f=await Create();await using var host=await f.Start(Options(graph));using var client=f.Client(host);foreach(var cursor in new AuditResourceHistoryCursor[]{new("B","entity","shared",Key(1)),new("A","other","shared",Key(1)),new("A","entity","Shared",Key(1)),new("A","entity","shared",Guid.Empty)}){var invalid=await f.Send(client,graph,Q(5,cursor),f.Token());Require(invalid.Error(graph,"validation.failed")&&f.Source.ResourceQueries==0&&f.Probe.ResourceGatewayFactories==0&&f.Probe.ResourceHandlerFactories==0);}var badGuid=graph?JsonSerializer.Serialize(new{query="query { trailResourceHistory(input:{tenant:\"A\",resourceKind:\"entity\",resourceId:\"shared\",continuation:{tenant:\"A\",resourceKind:\"entity\",resourceId:\"shared\",afterReceiptId:\"not-guid\"}}) {tenant} }"}):JsonSerializer.Serialize(new{tenant="A",resourceKind="entity",resourceId="shared",continuation=new{tenant="A",resourceKind="entity",resourceId="shared",afterReceiptId="not-guid"}});Require(!(await f.Send(client,graph,token:f.Token(),raw:badGuid)).Success(graph)&&f.Source.ResourceQueries==0);var matchedB=await f.Send(client,graph,Q(5,new("B","entity","shared",Key(1)),tenant:"B"),f.Token());Require(matchedB.Error(graph,"access.denied")&&f.Source.ResourceQueries==0);observe(new{phase="resource_wire_cursor_validation",transport=label,Ordinal_tenant_kind_id_bound=true,empty_and_malformed_GUID_rejected=true,matched_untrusted_B_metadata_still_denied=true,resource_queries=0,no_signed_cursor_claim=true});
            });
            await check(label+" actual JWT and separate RBAC ABAC resource grant gate the indexed reader",async()=>
            {
                var f=await Create();await using var host=await f.Start(Options(graph,receipt:true));using var client=f.Client(host);foreach(var token in new string?[]{null,wrongJwt.Token("resource-a"),jwt.Token("resource-a",issuer:"urn:wrong"),jwt.Token("resource-a",audience:"wrong"),jwt.Token("resource-a",expired:true),jwt.Token("resource-a",algorithm:"PS256")})Require(!(await f.Send(client,graph,token:token)).Success(graph)&&f.Source.ResourceQueries==0&&f.Probe.ResourceHandlerFactories==0);foreach(var subject in new[]{"no-role","wrong-attribute","receipt-only","history-only","entity-only"})Require((await f.Send(client,graph,token:f.Token(subject))).Error(graph,"access.denied")&&f.Source.ResourceQueries==0);Require((await f.Receipt(client,graph,f.Token("receipt-only"))).Success(graph)&&f.Source.LookupQueries==1&&f.Source.ResourceQueries==0);observe(new{phase="resource_wire_authentication_grants",transport=label,actual_TLS_JWT=true,foreign_crypto_rejected=true,framework_RBAC_ABAC_fresh_facts=true,receipt_history_entity_grants_not_resource_grant=true,denied_resource_queries=0});
            });
            await check(label+" same GUID and resource metadata across tenants require independent fresh membership",async()=>
            {
                var f=await Create();await using var host=await f.Start(Options(graph));using var client=f.Client(host);var denied=await f.Send(client,graph,Q(tenant:"B"),f.Token());Require(denied.Error(graph,"access.denied")&&f.Source.ResourceQueries==0);var a=await f.Send(client,graph,Q(),f.Token("resource-both"));var b=await f.Send(client,graph,Q(tenant:"B"),f.Token("resource-both"));Require(a.Success(graph)&&b.Success(graph)&&Keys(a,graph).Single()==Keys(b,graph).Single()&&a.Value(graph).GetProperty("entries")[0].GetProperty("tenant").GetString()=="A"&&b.Value(graph).GetProperty("entries")[0].GetProperty("tenant").GetString()=="B");var reads=f.Source.ResourceQueries;Require((await f.Send(client,graph,Q(),f.Token("resource-b"))).Error(graph,"access.denied")&&f.Source.ResourceQueries==reads);observe(new{phase="resource_wire_tenant_partition",transport=label,same_receipt_resource_kind_id_A_B=true,separate_fresh_grants_required=true,denial_before_source=true,DTOs_not_membership=true});
            });
            await check(label+" same signed token observes fresh membership resource and policy revocation then regrant",async()=>
            {
                var f=await Create();await using var host=await f.Start(Options(graph));using var client=f.Client(host);var token=f.Token();Require((await f.Send(client,graph,token:token)).Success(graph));var reads=f.Source.ResourceQueries;f.Authority.MembershipRevoked=true;Require((await f.Send(client,graph,token:token)).Error(graph,"access.denied")&&f.Source.ResourceQueries==reads);f.Authority.MembershipRevoked=false;f.Authority.ResourceRevoked=true;Require((await f.Send(client,graph,token:token)).Error(graph,"access.denied")&&f.Source.ResourceQueries==reads);f.Authority.ResourceRevoked=false;f.Authority.PolicyRevoked=true;Require((await f.Send(client,graph,token:token)).Error(graph,"access.denied")&&f.Source.ResourceQueries==reads);f.Authority.PolicyRevoked=false;Require((await f.Send(client,graph,token:token)).Success(graph)&&f.Source.ResourceQueries==reads+1);observe(new{phase="resource_wire_fresh_revocation",transport=label,same_JWT_same_request=true,membership_resource_policy_revoke_before_queries=true,explicit_regrant=true,no_midflight_external_requery_claim=true});
            });
            await check(label+" eight scheduled resource reads and mixed GraphQL siblings keep fresh contexts isolated",async()=>
            {
                var f=await Create();await using var host=await f.Start(Options(graph,receipt:true));using var client=f.Client(host);using var caller=new CancellationTokenSource();var start=Signal();var tasks=Enumerable.Range(0,8).Select(i=>Task.Run(async()=>{await start.Task;var tenant=i%2==0?"A":"B";var page=await f.Send(client,graph,Q(tenant:tenant),f.Token("resource-both"),cancellationToken:caller.Token);Require(page.Success(graph)&&page.Value(graph).GetProperty("entries")[0].GetProperty("tenant").GetString()==tenant);})).ToArray();var all=Task.WhenAll(tasks);start.TrySetResult();try{await all.WaitAsync(Watchdog);}finally{caller.Cancel();start.TrySetResult();await Join(all);}Require(f.Source.ResourceQueries==8);
                if(graph){var reads=f.Source.ResourceQueries;var memberships=f.Authority.MembershipCalls;var deniedB=await f.Siblings(client,f.Token());Require(deniedB.Root.TryGetProperty("errors",out var errors)&&errors.GetArrayLength()>0&&deniedB.Root.GetProperty("data").GetProperty("a").GetProperty("entries")[0].GetProperty("tenant").GetString()=="A"&&f.Source.ResourceQueries==reads+1&&f.Authority.MembershipCalls==memberships+2);var both=await f.Siblings(client,f.Token("resource-both"));Require(both.Success(true)&&both.Root.GetProperty("data").GetProperty("a").GetProperty("entries")[0].GetProperty("tenant").GetString()=="A"&&both.Root.GetProperty("data").GetProperty("b").GetProperty("entries")[0].GetProperty("tenant").GetString()=="B");var before=f.Source.ResourceQueries;var mixed=await f.Siblings(client,f.Token("receipt-only"),mixed:true);Require(mixed.Root.TryGetProperty("errors",out _)&&mixed.Root.GetProperty("data").GetProperty("b").GetProperty("record").GetProperty("tenant").GetString()=="A"&&f.Source.ResourceQueries==before&&f.Source.LookupQueries==1);}
                observe(new{phase="resource_wire_workers_siblings",transport=label,workers=8,all_workers_owned_joined=true,fresh_A_B_resource_fields=graph,mixed_lookup_grant_not_resource_grant=graph,separate_resource_lookup_counters=true});
            });
            await check(label+" actual resource SQL Lock cancellation separately proves private and caller server joins",async()=>
            {
                foreach(var privateBudget in new[]{true,false})
                {
                    var f=await Create();await using var host=await f.Start(Options(graph,privateBudget?Budget:null));using var client=f.Client(host);using var caller=new CancellationTokenSource();var sql=f.Sql();await using var blocker=await sql.Hold();var pending=f.Send(client,graph,token:f.Token(),cancellationToken:caller.Token);var pid=0;
                    try{pid=await sql.Observe(f.Probe,pending,caller.Token).WaitAsync(Watchdog);if(privateBudget){var reply=await pending.WaitAsync(Watchdog);Require(reply.Error(graph,"internal.error")&&f.Probe.LastResourceWorkToken.IsCancellationRequested&&!f.Probe.LastResourceDispatchToken.IsCancellationRequested&&!caller.IsCancellationRequested);}else{caller.Cancel();Require(await Failure(()=>pending).WaitAsync(Watchdog) is OperationCanceledException);await Wait(()=>f.Probe.LastResourceWorkToken.IsCancellationRequested).WaitAsync(Watchdog);}await Wait(()=>f.Probe.ActiveDispatches==0&&f.Probe.CompletedDispatches==1).WaitAsync(Watchdog);Require(f.Probe.ResourceReaderResults==0&&f.Source.LookupQueries==0);}
                    finally{caller.Cancel();await blocker.DisposeAsync();await Join(pending);}
                    await sql.Quiescent(pid);Require((await f.Send(client,graph,token:f.Token())).Success(graph)&&f.Source.ResourceQueries==2);
                }
                observe(new{phase="resource_wire_actual_SQL_cancel",transport=label,private_and_caller_modes=true,exact_resource_tag_Lock_before_signal=true,single_controlled_query_backend_identity=true,server_and_backend_joined=true,manual_reuse=true,no_remote_token_identity_or_delay_cause_claim=true});
            });
            await check(label+" post-SQL held empty and populated pages stay owned until private completion veto",async()=>
            {
                foreach(var present in new[]{true,false})
                {
                    var f=await Create(present);var entered=Signal();var release=Signal();f.Probe.AfterResourceProviderRead=_=>{entered.TrySetResult();return release.Task;};await using var host=await f.Start(Options(graph,Budget));using var client=f.Client(host);using var caller=new CancellationTokenSource();var pending=f.Send(client,graph,token:f.Token(),cancellationToken:caller.Token);
                    try{await entered.Task.WaitAsync(Watchdog);await Wait(()=>f.Probe.LastResourceWorkToken.IsCancellationRequested).WaitAsync(Watchdog);Require(!pending.IsCompleted&&f.Probe.ActiveDispatches==1&&f.Probe.ResourceReaderResults==0&&!f.Source.IsDisposed);release.TrySetResult();Require((await pending.WaitAsync(Watchdog)).Error(graph,"internal.error")&&f.Probe.ResourceReaderResults==0);await Wait(()=>f.Probe.ActiveDispatches==0).WaitAsync(Watchdog);}
                    finally{caller.Cancel();release.TrySetResult();await Join(pending);}
                }
                observe(new{phase="resource_wire_held_completion",transport=label,empty_and_populated_pages=true,token_only_post_SQL_hook=true,uncooperative_work_not_abandoned=true,no_successful_empty_or_page_after_veto=true,not_actual_SQL_wait_evidence=true});
            });
            await check(label+" touched metadata and lookahead poison fail closed before policy with redacted errors",async()=>
            {
                var f=await Create(false);await f.Append(new[]{Record(Key(1)),Record(Key(2))});await using var host=await f.Start(Options(graph),Policy(TenantChangeAuditMode.MetadataOnly));using var client=f.Client(host);await f.Sql().Payload(Key(2),Record(Key(2),"B"));var poison=await f.Send(client,graph,Q(1),f.Token());Require(poison.Error(graph,"internal.error")&&f.Probe.ResourceReaderResults==0&&!poison.Body.Contains(f.Store.Schema,StringComparison.Ordinal));await f.Sql().Payload(Key(2),Record(Key(2)));await f.Sql().Resource(Key(1),"hidden");var filtered=await f.Send(client,graph,Q(5),f.Token());Require(filtered.Success(graph)&&Keys(filtered,graph).SequenceEqual(new[]{Key(2)}));var touched=await f.Send(client,graph,Q(id:"hidden"),f.Token());Require(touched.Error(graph,"internal.error"));await f.Sql().Resource(Key(1),"shared");f.Probe.AfterResourceProviderRead=_=>throw new IOException("SECRET-PROVIDER-DETAIL "+f.Store.Schema);var fault=await f.Send(client,graph,token:f.Token());Require(fault.Error(graph,"internal.error")&&!fault.Body.Contains("SECRET-PROVIDER-DETAIL",StringComparison.Ordinal)&&!fault.Body.Contains(f.Store.Schema,StringComparison.Ordinal));observe(new{phase="resource_wire_integrity_redaction",transport=label,lookahead_physical_A_payload_B_rejected=true,metadata_only_not_bypass=true,selective_query_not_unrelated_corruption_attestation=true,touched_metadata_rejected=true,secret_post_SQL_fault_redacted=true});
            });
            await check(label+" client completion precedes held resource server work and shutdown joins before source disposal",async()=>
            {
                var f=await Create();var entered=Signal();var release=Signal();f.Probe.AfterResourceProviderRead=_=>{entered.TrySetResult();return release.Task;};var host=await f.Start(Options(graph));using var client=f.Client(host);using var caller=new CancellationTokenSource();var pending=f.Send(client,graph,token:f.Token(),cancellationToken:caller.Token);Task? disposal=null;
                try{await entered.Task.WaitAsync(Watchdog);caller.Cancel();Require(await Failure(()=>pending).WaitAsync(Watchdog) is OperationCanceledException);await Wait(()=>f.Probe.LastResourceWorkToken.IsCancellationRequested).WaitAsync(Watchdog);Require(f.Probe.ActiveDispatches==1&&f.Probe.CompletedDispatches==0&&f.Probe.ResourceReaderResults==0&&!f.Source.IsDisposed);disposal=host.DisposeAsync().AsTask();await f.Probe.AdmissionClosed.Task.WaitAsync(Watchdog);Require(!disposal.IsCompleted&&!f.Probe.DrainCompleted.Task.IsCompleted&&f.Probe.SourceDisposals==0&&!f.Source.IsDisposed);release.TrySetResult();await disposal.WaitAsync(Watchdog);Require(f.Probe.ActiveDispatches==0&&f.Probe.CompletedDispatches==1&&f.Probe.SourceDisposals==1&&f.Source.IsDisposed&&f.Source.DataSourceDisposals==1);await f.Sql().AppQuiescent();}
                finally{caller.Cancel();release.TrySetResult();await Join(pending);if(disposal is not null)await Join(disposal);else await Join(host.DisposeAsync().AsTask());}
                observe(new{phase="resource_wire_positive_server_ownership",transport=label,client_completed_while_resource_server_held=true,server_token_cancelled=true,full_dispatch_drain_before_source_disposal=true,backend_quiescent=true,single_source_disposal=true});
            });
        }
    }
    private static bool Has(Exception error,Exception expected)
    {var queue=new Queue<Exception>();var seen=new HashSet<Exception>(ReferenceEqualityComparer.Instance);queue.Enqueue(error);while(queue.Count>0&&seen.Count<32){var next=queue.Dequeue();if(ReferenceEquals(next,expected))return true;if(!seen.Add(next))continue;if(next is AggregateException aggregate)foreach(var child in aggregate.InnerExceptions)queue.Enqueue(child);else if(next.InnerException is{ } inner)queue.Enqueue(inner);}return false;}
    private sealed class SqlProbe(string connection,string schema,Func<PostgresIndexedAuditStorage> source)
    {
        private string Table=>schema+"."+PostgresIndexedAuditStorage.StorageTable;
        private async Task<NpgsqlConnection> Open(){var c=new NpgsqlConnection(connection);try{await c.OpenAsync();return c;}catch{await c.DisposeAsync();throw;}}
        public async Task Delete(Guid key){await using var c=await Open();await using var cmd=new NpgsqlCommand("DELETE FROM "+Table+" WHERE tenant='A' AND receipt=$1",c);cmd.Parameters.AddWithValue(key);Require(await cmd.ExecuteNonQueryAsync()==1);}
        public async Task Payload(Guid key,TenantChangeAuditRecord record){await using var c=await Open();await using var cmd=new NpgsqlCommand("UPDATE "+Table+" SET payload=$1 WHERE tenant='A' AND receipt=$2",c);cmd.Parameters.AddWithValue(PayloadCodec.Encode(record));cmd.Parameters.AddWithValue(key);Require(await cmd.ExecuteNonQueryAsync()==1);}
        public async Task Resource(Guid key,string id){await using var c=await Open();await using var cmd=new NpgsqlCommand("UPDATE "+Table+" SET resource_id=$1 WHERE tenant='A' AND receipt=$2",c);cmd.Parameters.AddWithValue(id);cmd.Parameters.AddWithValue(key);Require(await cmd.ExecuteNonQueryAsync()==1);}
        public async Task<Blocker> Hold(){var c=await Open();var tx=await c.BeginTransactionAsync();try{await using var cmd=new NpgsqlCommand("LOCK TABLE "+Table+" IN ACCESS EXCLUSIVE MODE",c,tx);await cmd.ExecuteNonQueryAsync();return new(c,tx);}catch{await tx.DisposeAsync();await c.DisposeAsync();throw;}}
        public async Task<int> Observe(AuditReceiptTransportProbe probe,Task pending,CancellationToken caller)
        {
            await using var c=await Open();for(var i=0;i<200;i++)
            {
                var actual=source();await using var cmd=new NpgsqlCommand("SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND state='active' AND wait_event_type='Lock' AND query LIKE $2 AND query LIKE $3",c);cmd.Parameters.AddWithValue(actual.ApplicationName);cmd.Parameters.AddWithValue("%"+Table+"%");cmd.Parameters.AddWithValue("%"+PostgresIndexedAuditStorage.ResourceTag+"%");await using(var rows=await cmd.ExecuteReaderAsync()){if(await rows.ReadAsync()){var pid=rows.GetInt32(0);Require(!await rows.ReadAsync()&&!pending.IsCompleted&&!caller.IsCancellationRequested&&!probe.LastResourceWorkToken.IsCancellationRequested&&probe.SourceResourceHistoryCalls==1&&actual.ResourceQueries==1&&actual.LookupQueries==0);return pid;}}Require(!pending.IsCompleted&&!caller.IsCancellationRequested);await Task.Delay(20);
            }
            throw new InvalidOperationException("Exact controlled resource SQL Lock was not observed before cancellation.");
        }
        public async Task Quiescent(int pid)
        {Require(pid>0);await using var c=await Open();for(var i=0;i<100;i++){await using var cmd=new NpgsqlCommand("SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND application_name=$2 AND (state='active' OR wait_event_type='Lock'))",c);cmd.Parameters.AddWithValue(pid);cmd.Parameters.AddWithValue(source().ApplicationName);if((bool)(await cmd.ExecuteScalarAsync())!)return;await Task.Delay(20);}throw new InvalidOperationException("Owned resource backend did not quiesce.");}
        public async Task AppQuiescent()
        {await using var c=await Open();for(var i=0;i<100;i++){await using var cmd=new NpgsqlCommand("SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND (state='active' OR wait_event_type='Lock'))",c);cmd.Parameters.AddWithValue(source().ApplicationName);if((bool)(await cmd.ExecuteScalarAsync())!)return;await Task.Delay(20);}throw new InvalidOperationException("Owned source application did not quiesce.");}
    }
    private sealed class Blocker(NpgsqlConnection connection,NpgsqlTransaction transaction):IAsyncDisposable
    {private bool disposed;public async ValueTask DisposeAsync(){if(disposed)return;disposed=true;try{await transaction.RollbackAsync();}finally{await transaction.DisposeAsync();await connection.DisposeAsync();}}}
}
