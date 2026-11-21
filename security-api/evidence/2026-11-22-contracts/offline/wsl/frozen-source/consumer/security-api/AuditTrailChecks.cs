using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Cehpalon.Engine.Tenancy;

namespace SecurityApi;

public static class AuditTrailChecks
{
    public static async Task<IReadOnlyList<AuditTrailSummary>> Run(TlsFixture tls,JwtFixture signing,Func<string,Func<Task>,Task> reportCheck)
    {
        var summaries=new List<AuditTrailSummary>();var json=new JsonSerializerOptions(JsonSerializerDefaults.Web);
        Task Check(string name,Func<Task> action)=>reportCheck(name,async()=>
        {
            try{await action();}
            catch(Exception error){throw new InvalidOperationException("Audit trail fixture failed: "+error.GetType().FullName+". Credential and domain-value exception details omitted.");}
        });
        void Require(bool value){if(!value)throw new InvalidOperationException("Audit trail assertion failed.");}
        async Task<(HttpStatusCode Status,string Body)> Post(HttpClient client,string path,object body,string? token=null,string? cookie=null)
        {
            using var request=new HttpRequestMessage(HttpMethod.Post,path){Content=JsonContent.Create(body)};
            if(token is not null)request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",token);
            if(cookie is not null)request.Headers.Add("Cookie",cookie);
            using var response=await client.SendAsync(request);return(response.StatusCode,await response.Content.ReadAsStringAsync());
        }
        string HistoryQuery(string tenant="A")=>"query { trailHistory(input: { tenant: "+JsonSerializer.Serialize(tenant)+" }) { tenant nextCursor entries { receiptId recordedAtUtc reportedAtUtc principalIssuer principalSubject authenticationScheme tenant operationId action entityId authorizationResourceVersion beforeEntityVersion afterEntityVersion kind mode capturedMode fields { name wasChanged before { kind text number boolean } after { kind text number boolean } } } } }";
        TrailHistoryResult DecodeHistory(string body,bool graphQL=false)
        {
            if(graphQL){using var document=JsonDocument.Parse(body);body=document.RootElement.GetProperty("data").GetProperty("trailHistory").GetRawText();}
            return JsonSerializer.Deserialize<TrailHistoryResult>(body,json)??throw new InvalidOperationException("No history result.");
        }
        void SafeSink(AuditTrailFixture fixture,Host host)
        {
            var records=fixture.Store!.Snapshot();var text=JsonSerializer.Serialize(records);
            Require(!text.Contains("domain-secret",StringComparison.Ordinal)&&!text.Contains("unallowlisted-domain-internal",StringComparison.Ordinal)&&records.All(r=>r.Fields.All(f=>f.Name!="internal")));
            Require(records.SelectMany(r=>r.Fields).Where(f=>f.Name=="secret").All(f=>f.Before.Kind==TenantChangeValueKind.Redacted&&f.After.Kind==TenantChangeValueKind.Redacted));
            if(host.Audit is not null){var operations=JsonSerializer.Serialize(host.Audit.Snapshot());Require(!operations.Contains("domain-secret",StringComparison.Ordinal)&&!operations.Contains("unallowlisted-domain-internal",StringComparison.Ordinal));}
        }
        foreach(var protection in new[]{"Signed","RSA-OAEP","dir"})
        {
            using var encryption=protection=="Signed"?null:new JweFixture(protection);
            foreach(var mode in new[]{TenantChangeAuditMode.Disabled,TenantChangeAuditMode.MetadataOnly,TenantChangeAuditMode.ChangedFields,TenantChangeAuditMode.BeforeAfterSnapshots})
            {
                var fixture=new AuditTrailFixture(mode){FailValues=mode is TenantChangeAuditMode.Disabled or TenantChangeAuditMode.MetadataOnly,FailSinkCreation=mode==TenantChangeAuditMode.Disabled};
                await using var host=new Host();await host.Start(tls,signing,jweProfile:encryption,trailProfile:fixture);using var client=tls.Client(host.Address);
                string Token(string subject="alice"){var inner=signing.Token(subject);return encryption is null?inner:encryption.Encrypt(inner);}
                var fieldMode=mode is TenantChangeAuditMode.ChangedFields or TenantChangeAuditMode.BeforeAfterSnapshots;
                await Check("trail "+protection+" "+mode+" project mode commits an actual HTTP change and keeps capture lazy",async()=>
                {
                    var result=await Post(client,"/entity/update",new EntityMutationRequest("A","shared","first-A",2.5m,"domain-secret-changed"),Token());
                    Require(result.Status==HttpStatusCode.OK&&fixture.Revision("A")==1&&fixture.Title("A")=="first-A"&&fixture.MutationFactories==1&&fixture.MutationDisposals==1);
                    Require(fixture.FactoryCalls==(mode==TenantChangeAuditMode.Disabled?0:1)&&fixture.ProviderConstructors==fixture.FactoryCalls&&host.TrailModuleFactories==fixture.FactoryCalls&&fixture.ValueFactoryCalls==(fieldMode?1:0));
                    if(mode==TenantChangeAuditMode.Disabled){Require(host.Trail is null&&fixture.Store is null);return;}
                    var record=fixture.Store!.Snapshot().Single();Require(record.Receipt.BeforeEntityVersion=="entity-v0"&&record.Receipt.AfterEntityVersion=="entity-v1"&&record.Receipt.AuthorizationResourceVersion=="r1"&&record.Receipt.Principal.Subject=="alice"&&record.Receipt.AuthenticationScheme=="Bearer"&&record.Mode==mode);
                    Require(record.Fields.Count==(mode==TenantChangeAuditMode.MetadataOnly?0:mode==TenantChangeAuditMode.ChangedFields?3:6));
                    if(fieldMode)
                    {
                        var title=record.Fields.Single(f=>f.Name=="title");Require(title.Before.TextValue=="initial-A"&&title.After.TextValue=="first-A");
                        var amount=record.Fields.Single(f=>f.Name=="amount");Require(amount.Before.DecimalValue==1m&&amount.After.DecimalValue==2.5m);
                        var secret=record.Fields.Single(f=>f.Name=="secret");Require(secret.WasChanged&&secret.Before.Kind==TenantChangeValueKind.Redacted&&secret.After.Kind==TenantChangeValueKind.Redacted);
                        Require(record.Fields.Any(f=>f.Name=="category")== (mode==TenantChangeAuditMode.BeforeAfterSnapshots));
                    }
                    SafeSink(fixture,host);
                });
                await Check("trail "+protection+" "+mode+" GraphQL uses the same change handler and capture configuration",async()=>
                {
                    var result=await Post(client,"/graphql",new{query="mutation { updateEntity(input: { tenant: \"A\", entityId: \"shared\", title: \"second-A\", amount: 3.5, secret: \"domain-secret-second\" }) { tenant entityId entityVersion } }"},Token());
                    Require(result.Status==HttpStatusCode.OK&&!result.Body.Contains("\"errors\"")&&fixture.Revision("A")==2&&fixture.MutationFactories==2&&fixture.MutationDisposals==2&&fixture.ValueFactoryCalls==(fieldMode?2:0));
                    if(mode!=TenantChangeAuditMode.Disabled){Require(fixture.Store!.Snapshot().Length==2);SafeSink(fixture,host);}
                });
                if(mode==TenantChangeAuditMode.Disabled)
                {
                    await Check("trail "+protection+" disabled history is absent without sink or image work",async()=>
                    {
                        Require((await Post(client,"/trail/history",new TrailHistoryRequest("A"),Token("trail-reader"))).Status==HttpStatusCode.NotFound);
                        var result=await Post(client,"/graphql",new{query=HistoryQuery()},Token("trail-reader"));
                        Require(result.Body.Contains("\"errors\"")&&!result.Body.Contains("first-A")&&fixture.FactoryCalls==0&&fixture.ProviderConstructors==0&&fixture.ValueFactoryCalls==0&&fixture.HistoryFactories==0);
                        var count=fixture.MutationFactories;Require((await Post(client,"/entity/update",new EntityMutationRequest("B","shared","wrong",9m,"domain-secret-wrong"),Token())).Status==HttpStatusCode.Forbidden&&fixture.MutationFactories==count);
                    });
                    summaries.Add(new(protection,mode.ToString(),fixture.FactoryCalls,fixture.ProviderConstructors,fixture.ValueFactoryCalls,0,fixture.MutationFactories,fixture.HistoryFactories));continue;
                }
                var store=fixture.Store??throw new InvalidOperationException("Enabled trail store was not activated.");
                await Check("trail "+protection+" "+mode+" distinct HTTP and GraphQL history expose the selected capture format",async()=>
                {
                    var result=await Post(client,"/trail/history",new TrailHistoryRequest("A"),Token("trail-reader"));Require(result.Status==HttpStatusCode.OK);
                    var history=DecodeHistory(result.Body);Require(history.Tenant=="A"&&history.Entries.Length==2&&history.Entries.All(e=>e.Mode==mode.ToString()&&e.CapturedMode==mode.ToString()&&e.PrincipalSubject=="alice"));
                    var graph=await Post(client,"/graphql",new{query=HistoryQuery()},Token("trail-reader"));Require(graph.Status==HttpStatusCode.OK&&!graph.Body.Contains("\"errors\"")&&DecodeHistory(graph.Body,true).Entries.Length==2);
                    Require(!result.Body.Contains("domain-secret")&&!graph.Body.Contains("domain-secret")&&fixture.HistoryFactories==fixture.HistoryDisposals);SafeSink(fixture,host);
                });
                await Check("trail "+protection+" "+mode+" operation-audit history permission cannot read field history",async()=>
                {
                    var before=fixture.HistoryFactories;Require((await Post(client,"/trail/history",new TrailHistoryRequest("A"),Token("auditor"))).Status==HttpStatusCode.Forbidden&&fixture.HistoryFactories==before);
                    var graph=await Post(client,"/graphql",new{query=HistoryQuery()},Token("auditor"));Require(graph.Body.Contains("access.denied")&&fixture.HistoryFactories==before);
                    Require((await Post(client,"/history",new HistoryRequest("A"),Token("trail-reader"))).Status==HttpStatusCode.Forbidden);
                });
                await Check("trail "+protection+" "+mode+" same entity ID keeps tenant state and field history isolated",async()=>
                {
                    var before=fixture.MutationFactories;Require((await Post(client,"/entity/update",new EntityMutationRequest("B","shared","forbidden",5m,"domain-secret-forbidden"),Token())).Status==HttpStatusCode.Forbidden&&fixture.MutationFactories==before);
                    Require((await Post(client,"/entity/update",new EntityMutationRequest("B","shared","only-B",7m,"domain-secret-B-change"),Token("bob"))).Status==HttpStatusCode.OK&&fixture.Revision("A")==2&&fixture.Revision("B")==1);
                    var a=DecodeHistory((await Post(client,"/trail/history",new TrailHistoryRequest("A"),Token("trail-reader"))).Body);
                    var b=DecodeHistory((await Post(client,"/trail/history",new TrailHistoryRequest("B"),Token("trail-reader-b"))).Body);
                    Require(a.Entries.Length==2&&a.Entries.All(e=>e.Tenant=="A")&&b.Entries.Length==1&&b.Entries.All(e=>e.Tenant=="B")&&b.Entries[0].PrincipalSubject=="bob");
                    Require((await Post(client,"/trail/history",new TrailHistoryRequest("B"),Token("trail-reader"))).Status==HttpStatusCode.Forbidden);SafeSink(fixture,host);
                });
                await Check("trail "+protection+" "+mode+" create and delete record missing versus null and provider versions",async()=>
                {
                    var body=new EntityMutationRequest("A","created","created-A",4m,"domain-secret-created");
                    Require((await Post(client,"/entity/create",body,Token())).Status==HttpStatusCode.OK&&fixture.Revision("A","created")==1);
                    Require((await Post(client,"/entity/delete",body,Token())).Status==HttpStatusCode.OK&&fixture.Revision("A","created")==-1);
                    var records=store.Snapshot().Where(r=>r.Receipt.ResourceId=="created").ToArray();Require(records.Length==2&&records[0].Receipt.Kind==TenantChangeKind.Create&&records[1].Receipt.Kind==TenantChangeKind.Delete);
                    Require(records[0].Receipt.BeforeEntityVersion is null&&records[0].Receipt.AfterEntityVersion=="entity-v1"&&records[1].Receipt.BeforeEntityVersion=="entity-v1"&&records[1].Receipt.AfterEntityVersion is null);
                    if(fieldMode){Require(records[0].Fields.Single(f=>f.Name=="notes").Before.Kind==TenantChangeValueKind.Missing&&records[0].Fields.Single(f=>f.Name=="notes").After.Kind==TenantChangeValueKind.Null);Require(records[1].Fields.Single(f=>f.Name=="notes").After.Kind==TenantChangeValueKind.Missing);}
                    else Require(records.All(r=>r.Fields.Count==0)&&fixture.ValueFactoryCalls==0);SafeSink(fixture,host);
                });
                await Check("trail "+protection+" "+mode+" bounded history pagination preserves every authorized receipt",async()=>
                {
                    var first=DecodeHistory((await Post(client,"/trail/history",new TrailHistoryRequest("A",1),Token("trail-reader"))).Body);Require(first.Entries.Length==1&&first.NextCursor is not null);
                    var second=DecodeHistory((await Post(client,"/trail/history",new TrailHistoryRequest("A",1,first.NextCursor),Token("trail-reader"))).Body);Require(second.Entries.Length==1&&second.Entries[0].ReceiptId!=first.Entries[0].ReceiptId);
                    var count=fixture.HistoryFactories;Require((await Post(client,"/trail/history",new TrailHistoryRequest("A",201),Token("trail-reader"))).Status==HttpStatusCode.BadRequest&&fixture.HistoryFactories==count);
                });
                await Check("trail "+protection+" "+mode+" later policy cannot upgrade values that were never captured",async()=>
                {
                    fixture.HistoryPolicy=AuditTrailFixture.BuildPolicy(TenantChangeAuditMode.BeforeAfterSnapshots);
                    try{var history=DecodeHistory((await Post(client,"/trail/history",new TrailHistoryRequest("A"),Token("trail-reader"))).Body);Require(history.Entries.All(e=>e.CapturedMode==mode.ToString()&&e.Mode==mode.ToString()));Require(history.Entries.Take(2).All(e=>e.Fields.Length==(mode==TenantChangeAuditMode.MetadataOnly?0:mode==TenantChangeAuditMode.ChangedFields?3:6)));}
                    finally{fixture.HistoryPolicy=fixture.Policy;}
                });
                await Check("trail "+protection+" "+mode+" current read policy narrows fields and redacts previously visible values",async()=>
                {
                    fixture.HistoryPolicy=AuditTrailFixture.BuildPolicy(TenantChangeAuditMode.BeforeAfterSnapshots,true,true);
                    try{var history=DecodeHistory((await Post(client,"/trail/history",new TrailHistoryRequest("A"),Token("trail-reader"))).Body);Require(history.Entries.All(e=>e.Fields.All(f=>f.Name=="title"&&f.Before.Kind=="Redacted"&&f.After.Kind=="Redacted")));Require(history.Entries.Take(2).All(e=>e.Fields.Length==(fieldMode?1:0)));}
                    finally{fixture.HistoryPolicy=fixture.Policy;}
                });
                await Check("trail "+protection+" "+mode+" removed operation rules suppress stored value payload",async()=>
                {
                    fixture.HistoryPolicy=AuditTrailFixture.BuildPolicy(TenantChangeAuditMode.BeforeAfterSnapshots,noRules:true);
                    try{var history=DecodeHistory((await Post(client,"/trail/history",new TrailHistoryRequest("A"),Token("trail-reader"))).Body);Require(history.Entries.All(e=>e.Fields.Length==0&&e.Mode=="MetadataOnly"&&e.CapturedMode==mode.ToString()));}
                    finally{fixture.HistoryPolicy=fixture.Policy;}
                });
                await Check("trail "+protection+" "+mode+" sink failure after actual mutation reports possible commit without rollback",async()=>
                {
                    var before=fixture.Revision("A");var rows=store.Snapshot().Length;store.Fail=true;
                    try{var result=await Post(client,"/entity/update",new EntityMutationRequest("A","shared","committed-despite-trail-failure",8m,"domain-secret-failed-append"),Token());Require(result.Body.Contains("audit_trail.write_failed_may_have_committed")&&fixture.Revision("A")==before+1&&fixture.Title("A")=="committed-despite-trail-failure"&&store.Snapshot().Length==rows&&!result.Body.Contains("domain-secret"));}
                    finally{store.Fail=false;}
                });
                await Check("trail "+protection+" "+mode+" misbound provider receipt cannot append after an actual domain commit",async()=>
                {
                    var before=fixture.Revision("A");var rows=store.Snapshot().Length;var values=fixture.ValueFactoryCalls;fixture.WrongReceiptVersion=true;
                    try{var result=await Post(client,"/entity/update",new EntityMutationRequest("A","shared","committed-before-receipt-rejection",9m,"domain-secret-receipt"),Token());Require(result.Body.Contains("audit_trail.write_failed_may_have_committed")&&fixture.Revision("A")==before+1&&store.Snapshot().Length==rows&&fixture.ValueFactoryCalls==values);}
                    finally{fixture.WrongReceiptVersion=false;}
                });
                await Check("trail "+protection+" "+mode+" foreign tenant rows from a faulty history provider are withheld",async()=>
                {
                    store.LeakForeignHistory=true;
                    try{var result=await Post(client,"/trail/history",new TrailHistoryRequest("A"),Token("trail-reader"));Require(result.Status==HttpStatusCode.InternalServerError&&result.Body.Contains("internal.error")&&!result.Body.Contains("only-B")&&!result.Body.Contains("domain-secret"));}
                    finally{store.LeakForeignHistory=false;}
                });
                if(fieldMode)
                await Check("trail "+protection+" "+mode+" field projection failure after commit cannot masquerade as unchanged data",async()=>
                {
                    fixture.FailValues=true;var before=fixture.Revision("A");var rows=store.Snapshot().Length;
                    try{var result=await Post(client,"/entity/update",new EntityMutationRequest("A","shared","committed-before-values-failure",10m,"domain-secret-values"),Token());Require(result.Body.Contains("audit_trail.write_failed_may_have_committed")&&fixture.Revision("A")==before+1&&store.Snapshot().Length==rows);}
                    finally{fixture.FailValues=false;}
                });
                Require(fixture.MutationFactories==fixture.MutationDisposals&&fixture.HistoryFactories==fixture.HistoryDisposals);SafeSink(fixture,host);
                summaries.Add(new(protection,mode.ToString(),fixture.FactoryCalls,fixture.ProviderConstructors,fixture.ValueFactoryCalls,store.Snapshot().Length,fixture.MutationFactories,fixture.HistoryFactories));
            }
        }
        await Check("trail project may enable change history while operation envelope persistence is disabled",async()=>
        {
            var fixture=new AuditTrailFixture(TenantChangeAuditMode.MetadataOnly){FailValues=true};await using var host=new Host();await host.Start(tls,signing,audit:false,trailProfile:fixture);using var client=tls.Client(host.Address);
            Require((await Post(client,"/entity/update",new EntityMutationRequest("A","shared","without-operation-envelope",2m,"domain-secret-independent"),signing.Token())).Status==HttpStatusCode.OK);
            Require((await Post(client,"/trail/history",new TrailHistoryRequest("A"),signing.Token("trail-reader"))).Status==HttpStatusCode.OK&&host.Audit is null&&host.AuditFactories==0&&fixture.Store!.Snapshot().Length==1&&fixture.ValueFactoryCalls==0);
            Require((await Post(client,"/history",new HistoryRequest("A"),signing.Token("auditor"))).Status==HttpStatusCode.NotFound);
        });
        await Check("trail established cookie mapping uses the same explicit before-after recorder",async()=>
        {
            var fixture=new AuditTrailFixture(TenantChangeAuditMode.BeforeAfterSnapshots);await using var host=new Host();await host.Start(tls,signing,cookieAuthentication:true,trailProfile:fixture);using var client=tls.Client(host.Address);
            Require((await Post(client,"/entity/update",new EntityMutationRequest("A","shared","cookie-change",2m,"domain-secret-cookie"),cookie:host.FixtureCookie())).Status==HttpStatusCode.OK);
            var history=DecodeHistory((await Post(client,"/trail/history",new TrailHistoryRequest("A"),cookie:host.FixtureCookie("trail-reader"))).Body);
            Require(history.Entries.Length==1&&history.Entries[0].AuthenticationScheme=="fixture-cookie"&&history.Entries[0].Fields.Single(f=>f.Name=="title").After.Text=="cookie-change");SafeSink(fixture,host);
        });
        await Check("trail startup sink failure stops activation before listener or domain handler",async()=>
        {
            var fixture=new AuditTrailFixture(TenantChangeAuditMode.ChangedFields){FailSinkCreation=true};await using var host=new Host();var failed=false;
            try{await host.Start(tls,signing,trailProfile:fixture);}catch(Exception){failed=true;}
            Require(failed&&host.App is null&&host.HostFactories==0&&fixture.FactoryCalls==1&&fixture.ProviderConstructors==0&&fixture.MutationFactories==0);
        });
        await Check("trail observation expiry after actual mutation reports possible commit and never claims unchanged data",async()=>
        {
            var observation=new ObservationFixture();var sessions=new SessionFixture{Clock=observation.Clock};const string sid="private-domain-observation";sessions.Register("alice",sid);
            var fixture=new AuditTrailFixture(TenantChangeAuditMode.BeforeAfterSnapshots);await using var host=new Host();await host.Start(tls,signing,sessionProfile:sessions,observationProfile:observation,trailProfile:fixture);using var client=tls.Client(host.Address);
            observation.StageHook=(stage,_)=>{if(stage=="after-domain-mutation")observation.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(6));};
            var result=await Post(client,"/entity/update",new EntityMutationRequest("A","shared","committed-before-observation-expiry",2m,"domain-secret-observation"),signing.Token(sessionId:sid));
            Require(result.Body.Contains("audit_trail.write_failed_may_have_committed")&&fixture.Revision("A")==1&&fixture.Store!.Snapshot().Length==0&&fixture.ValueFactoryCalls==0&&fixture.MutationFactories==1&&fixture.MutationDisposals==1);
            Require(host.Audit!.Snapshot().Last().Outcome==TenantAuditOutcome.Rejected&&!JsonSerializer.Serialize(host.Audit.Snapshot()).Contains(sid));
        });
        return summaries.AsReadOnly();
    }
}
