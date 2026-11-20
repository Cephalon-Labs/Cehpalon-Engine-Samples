using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Cehpalon.Engine.Tenancy;

namespace SecurityApi;

public static class AuditPreparationChecks
{
    public static async Task<IReadOnlyList<PreparationSummary>> Run(TlsFixture tls,JwtFixture signing,Func<string,Func<Task>,Task> Check)
    {
        var summaries=new List<PreparationSummary>();
        void Require(bool value){if(!value)throw new InvalidOperationException("Preparation consumer assertion failed.");}
        async Task<(HttpStatusCode Status,string Body)> Post(HttpClient client,string path,object body,string? token=null,string? cookie=null,CancellationToken cancellation=default)
        {
            using var request=new HttpRequestMessage(HttpMethod.Post,path){Content=JsonContent.Create(body)};
            if(token is not null)request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",token);
            if(cookie is not null)request.Headers.TryAddWithoutValidation("Cookie",cookie);
            using var response=await client.SendAsync(request,cancellation);return(response.StatusCode,await response.Content.ReadAsStringAsync(cancellation));
        }
        EntityMutationRequest Change(string tenant="A",string entity="shared",string title="prepared-title")=>new(tenant,entity,title,9m,"domain-secret-prepared");
        void Safe(AuditTrailFixture trail)
        {if(trail.Store is null)return;var text=JsonSerializer.Serialize(trail.Store.Snapshot());Require(!text.Contains("domain-secret",StringComparison.Ordinal)&&!text.Contains("unallowlisted-domain-internal",StringComparison.Ordinal));}
        foreach(var fault in new[]{"missing","unknown","action","kind"})
        await Check("preparation catalog policy "+fault+" rejects before sink credentials listener or mutation",async()=>
        {
            var trail=new AuditTrailFixture(TenantChangeAuditMode.ChangedFields);var preparation=new AuditPreparationFixture{PolicyFault=fault};await using var host=new Host();
            var denied=false;try{await host.Start(tls,signing,trailProfile:trail,preparationProfile:preparation);}catch(ArgumentException){denied=true;}
            Require(denied&&host.App is null&&host.HostFactories==0&&host.SecurityFactories==0&&host.AuditFactories==0&&host.KeyProviderCalls==0&&trail.FactoryCalls==0&&trail.ProviderConstructors==0&&trail.MutationFactories==0&&trail.Revision("A")==0);
        });
        foreach(var fault in new[]{"missing","duplicate","infinite"})
        await Check("preparation required operation "+fault+" is bounded and validated before activation",async()=>
        {
            var trail=new AuditTrailFixture(TenantChangeAuditMode.MetadataOnly);var preparation=new AuditPreparationFixture{RequiredFault=fault};await using var host=new Host();
            var denied=false;try{await host.Start(tls,signing,trailProfile:trail,preparationProfile:preparation);}catch(ArgumentException){denied=true;}
            Require(denied&&host.App is null&&host.SecurityFactories==0&&trail.FactoryCalls==0&&preparation.RequiredEnumerations==1&&trail.Revision("A")==0);
        });
        await Check("preparation valid catalog does not promise provider readiness",async()=>
        {
            var trail=new AuditTrailFixture(TenantChangeAuditMode.ChangedFields){FailSinkCreation=true};await using var host=new Host();var failed=false;
            try{await host.Start(tls,signing,trailProfile:trail,preparationProfile:new());}catch(IOException){failed=true;}
            Require(failed&&trail.FactoryCalls==1&&trail.ProviderConstructors==0&&host.KeyProviderCalls==0&&host.App is null&&trail.Revision("A")==0);
        });
        await Check("prepared all-off selection leaves cached registry and providers unconstructed",async()=>
        {
            var trail=new AuditTrailFixture(TenantChangeAuditMode.Disabled){FailSinkCreation=true};var preparation=new AuditPreparationFixture{RequiredFault="poison"};await using var host=new Host();await host.Start(tls,signing,false,false,false,false,trailProfile:trail,preparationProfile:preparation);
            Require(host.App is null&&host.TenantRegistry is null&&host.SecurityFactories==0&&host.HostFactories==0&&trail.FactoryCalls==0&&preparation.RequiredEnumerations==0&&preparation.PrepareCalls==0);
        });
        foreach(var protection in new[]{"Signed","RSA-OAEP","dir"})
        {
            using var encryption=protection=="Signed"?null:new JweFixture(protection);
            string Token(string subject="alice"){var token=signing.Token(subject);return encryption is null?token:encryption.Encrypt(token);}
            foreach(var mode in new[]{TenantChangeAuditMode.Disabled,TenantChangeAuditMode.MetadataOnly,TenantChangeAuditMode.ChangedFields,TenantChangeAuditMode.BeforeAfterSnapshots})
            {
                var trail=new AuditTrailFixture(mode){FailValues=mode is TenantChangeAuditMode.Disabled or TenantChangeAuditMode.MetadataOnly,FailSinkCreation=mode==TenantChangeAuditMode.Disabled};
                var preparation=new AuditPreparationFixture{RequiredFault=mode==TenantChangeAuditMode.Disabled?"poison":"none"};await using var host=new Host();
                await host.Start(tls,signing,jweProfile:encryption,trailProfile:trail,preparationProfile:preparation);using var client=tls.Client(host.Address);
                await Check("prepared "+protection+" "+mode+" cached actual catalog metadata has no handler work",()=>
                {
                    var entries=host.TenantRegistry!.DescribeOperations();var ids=entries.Select(x=>x.OperationId).ToArray();Require(ids.SequenceEqual(ids.Order(StringComparer.Ordinal))&&entries.Count(x=>x.ResourceKind=="entity")==3);
                    Require(entries.Single(x=>x.OperationId=="entity.create").Action=="create"&&entries.Single(x=>x.OperationId=="entity.update").Action=="update"&&entries.Single(x=>x.OperationId=="entity.delete").Action=="delete");
                    Require(trail.MutationFactories==0&&host.Business.Factories==0&&trail.AppendCalls==0&&trail.ValueFactoryCalls==0&&preparation.RequiredEnumerations==(mode==TenantChangeAuditMode.Disabled?0:1));return Task.CompletedTask;
                });
                await Check("prepared "+protection+" "+mode+" HTTP completion uses the same active registry",async()=>
                {
                    var result=await Post(client,"/entity/update",Change(),Token());Require(result.Status==HttpStatusCode.OK&&trail.Revision("A")==1&&trail.MutationFactories==1&&trail.MutationDisposals==1);
                    Require(preparation.PrepareCalls==(mode==TenantChangeAuditMode.Disabled?0:1)&&trail.AppendCalls==(mode==TenantChangeAuditMode.Disabled?0:1)&&trail.ValueFactoryCalls==(mode is TenantChangeAuditMode.ChangedFields or TenantChangeAuditMode.BeforeAfterSnapshots?1:0));Safe(trail);
                });
                await Check("prepared "+protection+" "+mode+" GraphQL remains tenant scoped with the same preparation flow",async()=>
                {
                    var result=await Post(client,"/graphql",new{query="mutation { updateEntity(input: { tenant: \"A\", entityId: \"shared\", title: \"prepared-graphql\", amount: 10, secret: \"domain-secret-prepared-gql\" }) { tenant entityId entityVersion } }"},Token());
                    Require(result.Status==HttpStatusCode.OK&&!result.Body.Contains("\"errors\"",StringComparison.Ordinal)&&trail.Revision("A")==2&&trail.MutationDisposals==2&&preparation.PrepareCalls==(mode==TenantChangeAuditMode.Disabled?0:2));Safe(trail);
                });
                await Check("prepared "+protection+" "+mode+" valid preparation never grants another tenant",async()=>
                {var before=trail.MutationFactories;var result=await Post(client,"/entity/update",Change("B"),Token());Require(result.Status==HttpStatusCode.Forbidden&&trail.MutationFactories==before&&trail.Revision("B")==0);});
                if(mode==TenantChangeAuditMode.Disabled)
                    await Check("prepared "+protection+" disabled skips required poison and all trail activation",async()=>
                    {Require((await Post(client,"/trail/history",new TrailHistoryRequest("A"),Token("auditor"))).Status==HttpStatusCode.NotFound&&trail.FactoryCalls==0&&trail.ProviderConstructors==0&&trail.AppendCalls==0&&trail.ValueFactoryCalls==0&&preparation.PrepareCalls==0&&preparation.RequiredEnumerations==0);});
                else
                    await Check("prepared "+protection+" "+mode+" history still requires separate authority and redacts current fields",async()=>
                    {
                        Require((await Post(client,"/trail/history",new TrailHistoryRequest("A"),Token())).Status==HttpStatusCode.Forbidden);
                        var history=await Post(client,"/trail/history",new TrailHistoryRequest("A"),Token("auditor"));Require(history.Status==HttpStatusCode.OK&&!history.Body.Contains("domain-secret",StringComparison.Ordinal));
                        using var json=JsonDocument.Parse(history.Body);Require(json.RootElement.GetProperty("entries").GetArrayLength()==2);Safe(trail);
                    });
                summaries.Add(new(protection,mode.ToString(),preparation.PrepareCalls,trail.AppendCalls,trail.ValueFactoryCalls,trail.Store?.Snapshot().Length??0,trail.MutationFactories,trail.HistoryFactories));
            }
            foreach(var sameBuilder in new[]{false,true})
            await Check("prepared "+protection+" strict registry origin rejects "+(sameBuilder?"same-builder clone":"independent metadata-identical registry")+" before mutation",async()=>
            {
                var trail=new AuditTrailFixture(TenantChangeAuditMode.ChangedFields);var preparation=new AuditPreparationFixture{SameBuilderAlternative=sameBuilder,DispatchAlternative=true};await using var host=new Host();await host.Start(tls,signing,jweProfile:encryption,trailProfile:trail,preparationProfile:preparation);using var client=tls.Client(host.Address);
                var result=await Post(client,"/entity/update",Change(),Token());Require(result.Status==HttpStatusCode.Forbidden&&trail.Revision("A")==0&&preparation.PrepareCalls==1&&trail.ValueFactoryCalls==0&&trail.AppendCalls==0&&trail.MutationFactories==trail.MutationDisposals);
            });
            await Check("prepared "+protection+" missing dynamic rule denies before effect with ordinary access outcome",async()=>
            {
                var trail=new AuditTrailFixture(TenantChangeAuditMode.ChangedFields);var preparation=new AuditPreparationFixture();await using var host=new Host();await host.Start(tls,signing,jweProfile:encryption,trailProfile:trail,preparationProfile:preparation);using var client=tls.Client(host.Address);
                preparation.RecorderOverride=TenantChangeAuditRecorder.Activate(new(TenantChangeAuditMode.ChangedFields),()=>trail.Store!);
                var result=await Post(client,"/entity/update",Change(),Token());Require(result.Status==HttpStatusCode.Forbidden&&!result.Body.Contains("may_have_committed",StringComparison.Ordinal)&&trail.Revision("A")==0&&trail.AppendCalls==0&&trail.ValueFactoryCalls==0&&host.Audit!.Snapshot().Last().Outcome==TenantAuditOutcome.Denied);
            });
            foreach(var completion in new[]{PreparationCompletion.Replay,PreparationCompletion.Concurrent,PreparationCompletion.FailedFirst,PreparationCompletion.NullFirst,PreparationCompletion.CancelledFirst})
            await Check("prepared "+protection+" "+completion+" consumes once and reports possible effects without repeated append",async()=>
            {
                var trail=new AuditTrailFixture(TenantChangeAuditMode.ChangedFields){FailValues=completion==PreparationCompletion.FailedFirst};var preparation=new AuditPreparationFixture{Completion=completion};await using var host=new Host();await host.Start(tls,signing,jweProfile:encryption,trailProfile:trail,preparationProfile:preparation);using var client=tls.Client(host.Address);
                var result=await Post(client,"/entity/update",Change(),Token());var firstSucceeded=completion is PreparationCompletion.Replay or PreparationCompletion.Concurrent;
                Require(result.Body.Contains("audit_trail.write_failed_may_have_committed",StringComparison.Ordinal)&&trail.Revision("A")==1&&preparation.PrepareCalls==1&&trail.AppendCalls==(firstSucceeded?1:0)&&trail.Store!.Snapshot().Length==(firstSucceeded?1:0));
                Require(trail.ValueFactoryCalls==(firstSucceeded||completion==PreparationCompletion.FailedFirst?1:0)&&preparation.CompletionFailures==(firstSucceeded?1:2)&&host.Audit!.Snapshot().Last().Outcome==TenantAuditOutcome.Rejected);Safe(trail);
            });
            await Check("prepared "+protection+" provider fault after mutation preserves possible commit and owned cleanup",async()=>
            {
                var trail=new AuditTrailFixture(TenantChangeAuditMode.ChangedFields);var preparation=new AuditPreparationFixture();await using var host=new Host();await host.Start(tls,signing,jweProfile:encryption,trailProfile:trail,preparationProfile:preparation);using var client=tls.Client(host.Address);trail.Store!.Fail=true;
                var result=await Post(client,"/entity/update",Change(),Token());Require(result.Body.Contains("audit_trail.write_failed_may_have_committed",StringComparison.Ordinal)&&trail.Revision("A")==1&&trail.AppendCalls==1&&trail.Store.Snapshot().Length==0&&trail.MutationFactories==trail.MutationDisposals&&host.Audit!.Snapshot().Last().Outcome==TenantAuditOutcome.Rejected);
            });
        }
        await Check("prepared original observation expiry before prepare prevents domain mutation",async()=>
        {
            var observation=new ObservationFixture();var sessions=new SessionFixture{Clock=observation.Clock};const string sid="prepared-owned-session";sessions.Register("alice",sid);var trail=new AuditTrailFixture(TenantChangeAuditMode.ChangedFields);var preparation=new AuditPreparationFixture{BeforePrepare=(_,_)=>{observation.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(6));return Task.CompletedTask;}};
            await using var host=new Host();await host.Start(tls,signing,sessionProfile:sessions,observationProfile:observation,trailProfile:trail,preparationProfile:preparation);using var client=tls.Client(host.Address);
            var result=await Post(client,"/entity/update",Change(),signing.Token(sessionId:sid));Require(result.Status==HttpStatusCode.Forbidden&&trail.Revision("A")==0&&trail.AppendCalls==0&&trail.ValueFactoryCalls==0);
        });
        await Check("prepared completion retained beyond its handler cannot append or regain scope",async()=>
        {
            var trail=new AuditTrailFixture(TenantChangeAuditMode.ChangedFields);var preparation=new AuditPreparationFixture{Completion=PreparationCompletion.Deferred};await using var host=new Host();await host.Start(tls,signing,trailProfile:trail,preparationProfile:preparation);using var client=tls.Client(host.Address);
            var result=await Post(client,"/entity/update",Change(),signing.Token());Require(result.Body.Contains("audit_preparation.deferred_fixture",StringComparison.Ordinal)&&trail.Revision("A")==1&&trail.AppendCalls==0);
            var failed=false;try{await preparation.Captured!.CompleteAsync(preparation.CapturedReceipt!,()=>throw new InvalidOperationException("Retained context must not capture values."));}catch(TenantChangeAuditWriteException error){failed=error.MayHaveCommitted;}
            Require(failed&&trail.AppendCalls==0&&trail.ValueFactoryCalls==0&&trail.Store!.Snapshot().Length==0);
        });
        await Check("prepared real cookie ticket and shared registry complete normally",async()=>
        {
            var trail=new AuditTrailFixture(TenantChangeAuditMode.BeforeAfterSnapshots);var preparation=new AuditPreparationFixture();await using var host=new Host();await host.Start(tls,signing,cookieAuthentication:true,trailProfile:trail,preparationProfile:preparation);using var client=tls.Client(host.Address);
            var result=await Post(client,"/entity/update",Change(),cookie:host.FixtureCookie());Require(result.Status==HttpStatusCode.OK&&trail.Store!.Snapshot().Single().Receipt.AuthenticationScheme==host.IdentityScheme&&preparation.PrepareCalls==1&&trail.AppendCalls==1);Safe(trail);
        });
        foreach(var graphql in new[]{false,true})
        await Check("prepared "+(graphql?"GraphQL":"HTTP")+" request cancellation while held before prepare has zero effects",async()=>
        {
            var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var stopped=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var trail=new AuditTrailFixture(TenantChangeAuditMode.ChangedFields);var preparation=new AuditPreparationFixture{BeforePrepare=async(_,ct)=>{entered.TrySetResult();try{await Task.Delay(Timeout.InfiniteTimeSpan,ct);}catch(OperationCanceledException){stopped.TrySetResult();throw;}}};
            await using var host=new Host();await host.Start(tls,signing,trailProfile:trail,preparationProfile:preparation);using var client=tls.Client(host.Address);using var cancel=new CancellationTokenSource();
            object body=graphql?new{query="mutation { updateEntity(input: { tenant: \"A\", entityId: \"shared\", title: \"cancelled\", amount: 1, secret: \"domain-secret-cancelled\" }) { tenant } }"}:Change();
            var pending=Post(client,graphql?"/graphql":"/entity/update",body,signing.Token(),cancellation:cancel.Token);await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));cancel.Cancel();var cancelled=false;try{await pending;}catch(OperationCanceledException){cancelled=true;}await stopped.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Require(cancelled&&trail.Revision("A")==0&&trail.AppendCalls==0&&trail.ValueFactoryCalls==0&&preparation.PrepareCalls==0);
        });
        return summaries.AsReadOnly();
    }
}
