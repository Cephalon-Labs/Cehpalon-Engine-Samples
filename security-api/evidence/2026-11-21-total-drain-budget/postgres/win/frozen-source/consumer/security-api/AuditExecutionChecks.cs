using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Cehpalon.Engine.Tenancy;

namespace SecurityApi;

public static class AuditExecutionChecks
{
    public static async Task<IReadOnlyList<ExecutionSummary>> Run(TlsFixture tls,JwtFixture signing,Func<string,Func<Task>,Task> Check)
    {
        var summaries=new List<ExecutionSummary>();
        void Require(bool value){if(!value)throw new InvalidOperationException("Execution helper consumer assertion failed.");}
        async Task<(HttpStatusCode Status,string Body)> Post(HttpClient client,string path,object body,string? token=null,string? cookie=null,CancellationToken cancellation=default)
        {
            using var request=new HttpRequestMessage(HttpMethod.Post,path){Content=JsonContent.Create(body)};
            if(token is not null)request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",token);
            if(cookie is not null)request.Headers.TryAddWithoutValidation("Cookie",cookie);
            using var response=await client.SendAsync(request,cancellation);return(response.StatusCode,await response.Content.ReadAsStringAsync(cancellation));
        }
        EntityMutationRequest Change(string tenant="A",string entity="shared",string title="executed-title")=>new(tenant,entity,title,9m,"domain-secret-executed");
        object Graph(string tenant="A")=>new{query="mutation { updateEntity(input: { tenant: \""+tenant+"\", entityId: \"shared\", title: \"executed-graphql\", amount: 10, secret: \"domain-secret-executed-gql\" }) { tenant entityId entityVersion } }"};
        void Safe(AuditTrailFixture trail)
        {if(trail.Store is null)return;var text=JsonSerializer.Serialize(trail.Store.Snapshot());Require(!text.Contains("domain-secret",StringComparison.Ordinal)&&!text.Contains("unallowlisted-domain-internal",StringComparison.Ordinal));}
        foreach(var fault in new[]{"missing","unknown","action","kind"})
        await Check("execution profile catalog "+fault+" rejects before provider credential listener or callback",async()=>
        {
            var trail=new AuditTrailFixture(TenantChangeAuditMode.ChangedFields);var execution=new AuditExecutionFixture();await using var host=new Host();var denied=false;
            try{await host.Start(tls,signing,trailProfile:trail,preparationProfile:new(){PolicyFault=fault},executionProfile:execution);}catch(ArgumentException){denied=true;}
            Require(denied&&host.App is null&&host.HostFactories==0&&host.SecurityFactories==0&&host.KeyProviderCalls==0&&trail.FactoryCalls==0&&trail.MutationFactories==0&&execution.MutationCalls==0&&trail.Revision("A")==0);
        });
        await Check("execution all-off profile skips catalog provider callback and host",async()=>
        {
            var trail=new AuditTrailFixture(TenantChangeAuditMode.Disabled){FailSinkCreation=true};var execution=new AuditExecutionFixture();var preparation=new AuditPreparationFixture{RequiredFault="poison"};
            await using var host=new Host();await host.Start(tls,signing,false,false,false,false,trailProfile:trail,preparationProfile:preparation,executionProfile:execution);
            Require(host.App is null&&host.TenantRegistry is null&&host.SecurityFactories==0&&trail.FactoryCalls==0&&preparation.RequiredEnumerations==0&&execution.HelperCalls==0&&execution.MutationCalls==0);
        });
        foreach(var protection in new[]{"Signed","RSA-OAEP","dir"})
        {
            using var encryption=protection=="Signed"?null:new JweFixture(protection);
            string Token(string subject="alice"){var token=signing.Token(subject);return encryption is null?token:encryption.Encrypt(token);}
            foreach(var mode in new[]{TenantChangeAuditMode.Disabled,TenantChangeAuditMode.MetadataOnly,TenantChangeAuditMode.ChangedFields,TenantChangeAuditMode.BeforeAfterSnapshots})
            {
                var trail=new AuditTrailFixture(mode){FailValues=mode is TenantChangeAuditMode.Disabled or TenantChangeAuditMode.MetadataOnly,FailSinkCreation=mode==TenantChangeAuditMode.Disabled};var execution=new AuditExecutionFixture();
                await using var host=new Host();await host.Start(tls,signing,jweProfile:encryption,trailProfile:trail,executionProfile:execution);using var client=tls.Client(host.Address);var enabled=mode!=TenantChangeAuditMode.Disabled;
                await Check("execution "+protection+" "+mode+" lazy cached catalog creates no business or payload work",()=>
                {
                    Require(host.TenantRegistry!.DescribeOperations().Count(x=>x.ResourceKind=="entity")==3&&trail.MutationFactories==0&&execution.HelperCalls==0&&execution.MutationCalls==0&&trail.ValueFactoryCalls==0&&trail.AppendCalls==0);
                    return Task.CompletedTask;
                });
                await Check("execution "+protection+" "+mode+" HTTP awaits audit before typed result",async()=>
                {
                    var result=await Post(client,"/entity/update",Change(),Token());Require(result.Status==HttpStatusCode.OK&&trail.Revision("A")==1&&trail.Revision("B")==0&&trail.MutationFactories==trail.MutationDisposals);
                    using var json=JsonDocument.Parse(result.Body);Require(json.RootElement.GetProperty("entityVersion").GetString()=="entity-v1"&&execution.HelperCalls==(enabled?1:0)&&execution.MutationCalls==(enabled?1:0)&&execution.ResultsReturned==(enabled?1:0)&&trail.AppendCalls==(enabled?1:0));Safe(trail);
                });
                await Check("execution "+protection+" "+mode+" GraphQL uses same checked callback flow",async()=>
                {
                    var result=await Post(client,"/graphql",Graph(),Token());Require(result.Status==HttpStatusCode.OK&&!result.Body.Contains("\"errors\"",StringComparison.Ordinal)&&trail.Revision("A")==2&&execution.ResultsReturned==(enabled?2:0)&&trail.AppendCalls==(enabled?2:0));
                    Require(trail.ValueFactoryCalls==(mode is TenantChangeAuditMode.ChangedFields or TenantChangeAuditMode.BeforeAfterSnapshots?2:0));Safe(trail);
                });
                await Check("execution "+protection+" "+mode+" HTTP and GraphQL deny tenant switch before callback",async()=>
                {
                    var before=execution.MutationCalls;var factories=trail.MutationFactories;
                    Require((await Post(client,"/entity/update",Change("B"),Token())).Status==HttpStatusCode.Forbidden);
                    Require((await Post(client,"/graphql",Graph("B"),Token())).Body.Contains("access.denied",StringComparison.Ordinal)&&execution.MutationCalls==before&&trail.MutationFactories==factories&&trail.Revision("B")==0);
                });
                await Check("execution "+protection+" "+mode+" history retains separate reader authority and capture mode",async()=>
                {
                    if(!enabled){Require((await Post(client,"/trail/history",new TrailHistoryRequest("A"),Token("trail-reader"))).Status==HttpStatusCode.NotFound&&trail.FactoryCalls==0&&trail.ProviderConstructors==0&&trail.ValueFactoryCalls==0);return;}
                    Require((await Post(client,"/trail/history",new TrailHistoryRequest("A"),Token())).Status==HttpStatusCode.Forbidden);
                    Require((await Post(client,"/trail/history",new TrailHistoryRequest("A"),Token("auditor"))).Status==HttpStatusCode.Forbidden);
                    Require((await Post(client,"/trail/history",new TrailHistoryRequest("B"),Token("trail-reader"))).Status==HttpStatusCode.Forbidden);
                    var history=await Post(client,"/trail/history",new TrailHistoryRequest("A"),Token("trail-reader"));Require(history.Status==HttpStatusCode.OK&&!history.Body.Contains("domain-secret",StringComparison.Ordinal));
                    using var json=JsonDocument.Parse(history.Body);var entries=json.RootElement.GetProperty("entries");Require(entries.GetArrayLength()==2);
                    foreach(var entry in entries.EnumerateArray()){Require(entry.GetProperty("capturedMode").GetString()==mode.ToString());var fields=entry.GetProperty("fields");Require(mode==TenantChangeAuditMode.MetadataOnly?fields.GetArrayLength()==0:fields.EnumerateArray().Any(f=>f.GetProperty("name").GetString()=="secret"&&f.GetProperty("before").GetProperty("kind").GetString()=="Redacted"));}Safe(trail);
                });
                summaries.Add(new(protection,mode.ToString(),execution.HelperCalls,execution.MutationCalls,execution.ResultsReturned,trail.AppendCalls,trail.ValueFactoryCalls,trail.Store?.Snapshot().Length??0));
            }
            foreach(var fault in new[]{ExecutionFault.ThrowAfterMutation,ExecutionFault.CancelAfterMutation,ExecutionFault.NullOutcome,ExecutionFault.WrongReceipt})
            await Check("execution "+protection+" "+fault+" preserves partial change without fabricating receipt or retry",async()=>
            {
                var trail=new AuditTrailFixture(TenantChangeAuditMode.ChangedFields);var execution=new AuditExecutionFixture{Fault=fault};await using var host=new Host();await host.Start(tls,signing,jweProfile:encryption,trailProfile:trail,executionProfile:execution);using var client=tls.Client(host.Address);
                var result=await Post(client,"/entity/update",Change(),Token());Require(result.Body.Contains("audit_trail.write_failed_may_have_committed",StringComparison.Ordinal)&&!result.Body.Contains("Controlled private",StringComparison.Ordinal)&&trail.Revision("A")==1&&execution.MutationCalls==1&&execution.ResultsReturned==0&&execution.PossibleCommitFailures==1&&trail.AppendCalls==0&&trail.ValueFactoryCalls==0&&trail.Store!.Snapshot().Length==0&&host.Audit!.Snapshot().Last().Outcome==TenantAuditOutcome.Rejected&&trail.MutationFactories==trail.MutationDisposals);
            });
            foreach(var values in new[]{false,true})
            await Check("execution "+protection+" post-mutation "+(values?"value":"sink")+" failure reports uncertainty once",async()=>
            {
                var trail=new AuditTrailFixture(TenantChangeAuditMode.ChangedFields){FailValues=values};var execution=new AuditExecutionFixture();await using var host=new Host();await host.Start(tls,signing,jweProfile:encryption,trailProfile:trail,executionProfile:execution);using var client=tls.Client(host.Address);trail.Store!.Fail=!values;
                var result=await Post(client,"/entity/update",Change(),Token());Require(result.Body.Contains("audit_trail.write_failed_may_have_committed",StringComparison.Ordinal)&&trail.Revision("A")==1&&execution.MutationCalls==1&&execution.ResultsReturned==0&&execution.PossibleCommitFailures==1&&trail.AppendCalls==(values?0:1)&&trail.ValueFactoryCalls==1&&trail.Store.Snapshot().Length==0);Safe(trail);
            });
        }
        foreach(var foreign in new[]{false,true})
        await Check("execution "+(foreign?"foreign actual registry":"missing dynamic rule")+" denies before mutation callback",async()=>
        {
            var trail=new AuditTrailFixture(TenantChangeAuditMode.ChangedFields);var preparation=new AuditPreparationFixture{DispatchAlternative=foreign,SameBuilderAlternative=foreign};var execution=new AuditExecutionFixture();await using var host=new Host();await host.Start(tls,signing,trailProfile:trail,preparationProfile:preparation,executionProfile:execution);using var client=tls.Client(host.Address);
            if(!foreign)preparation.RecorderOverride=TenantChangeAuditRecorder.Activate(new(TenantChangeAuditMode.ChangedFields),()=>trail.Store!);
            var result=await Post(client,"/entity/update",Change(),signing.Token());Require(result.Status==HttpStatusCode.Forbidden&&!result.Body.Contains("may_have_committed",StringComparison.Ordinal)&&execution.HelperCalls==1&&execution.MutationCalls==0&&execution.PossibleCommitFailures==0&&trail.Revision("A")==0&&trail.ValueFactoryCalls==0&&trail.AppendCalls==0);
        });
        await Check("execution real cookie authentication produces bound receipt and typed result",async()=>
        {
            var trail=new AuditTrailFixture(TenantChangeAuditMode.BeforeAfterSnapshots);var execution=new AuditExecutionFixture();await using var host=new Host();await host.Start(tls,signing,cookieAuthentication:true,trailProfile:trail,executionProfile:execution);using var client=tls.Client(host.Address);
            var result=await Post(client,"/entity/update",Change(),cookie:host.FixtureCookie());Require(result.Status==HttpStatusCode.OK&&execution.ResultsReturned==1&&trail.Store!.Snapshot().Single().Receipt.AuthenticationScheme==host.IdentityScheme);Safe(trail);
        });
        foreach(var afterEffect in new[]{false,true})
        await Check("execution original observation expiry "+(afterEffect?"after mutation denies completion without rollback":"before callback prevents domain effects"),async()=>
        {
            var observation=new ObservationFixture();var sessions=new SessionFixture{Clock=observation.Clock};const string sid="executed-owned-session";sessions.Register("alice",sid);var trail=new AuditTrailFixture(TenantChangeAuditMode.ChangedFields);var execution=new AuditExecutionFixture();
            if(afterEffect)execution.AfterMutation=_=>{observation.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(6));return Task.CompletedTask;};
            else execution.BeforeExecute=(_,_)=>{observation.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(6));return Task.CompletedTask;};
            await using var host=new Host();await host.Start(tls,signing,sessionProfile:sessions,observationProfile:observation,trailProfile:trail,executionProfile:execution);using var client=tls.Client(host.Address);
            var result=await Post(client,"/entity/update",Change(),signing.Token(sessionId:sid));Require(execution.HelperCalls==1&&execution.MutationCalls==(afterEffect?1:0)&&trail.Revision("A")== (afterEffect?1:0)&&execution.ResultsReturned==0&&execution.PossibleCommitFailures==(afterEffect?1:0)&&trail.AppendCalls==0&&trail.ValueFactoryCalls==0&&trail.Store!.Snapshot().Length==0);
            Require(afterEffect?result.Body.Contains("audit_trail.write_failed_may_have_committed",StringComparison.Ordinal):result.Status==HttpStatusCode.Forbidden);
        });
        await Check("execution cancelled mutation returns receipt then required append completes before caller failure",async()=>
        {
            using var cancellation=new CancellationTokenSource();var trail=new AuditTrailFixture(TenantChangeAuditMode.ChangedFields);var execution=new AuditExecutionFixture{MutationCancellation=cancellation,AfterMutation=_=>{cancellation.Cancel();return Task.CompletedTask;}};
            await using var host=new Host();await host.Start(tls,signing,trailProfile:trail,executionProfile:execution);using var client=tls.Client(host.Address);
            var result=await Post(client,"/entity/update",Change(),signing.Token());Require(result.Body.Contains("audit_trail.write_failed_may_have_committed",StringComparison.Ordinal)&&execution.MutationSawCancellation&&execution.MutationCalls==1&&execution.ResultsReturned==0&&trail.AppendCalls==1&&trail.Store!.Snapshot().Length==1&&trail.Revision("A")==1);
        });
        foreach(var cancel in new[]{false,true})
        await Check("execution held append with "+(cancel?"caller cancellation":"live caller")+" withholds result and preserves private sink token",async()=>
        {
            using var cancellation=new CancellationTokenSource();var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var release=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var sinkToken=default(CancellationToken);
            var trail=new AuditTrailFixture(TenantChangeAuditMode.ChangedFields){AppendGate=async(_,ct)=>{sinkToken=ct;entered.TrySetResult();await release.Task.WaitAsync(ct);}};var execution=new AuditExecutionFixture{MutationCancellation=cancellation};
            await using var host=new Host();await host.Start(tls,signing,trailProfile:trail,executionProfile:execution);using var client=tls.Client(host.Address);var pending=Post(client,"/entity/update",Change(),signing.Token());
            try{await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));Require(!pending.IsCompleted&&execution.ResultsReturned==0&&trail.Revision("A")==1&&trail.Store!.Snapshot().Length==0);if(cancel)cancellation.Cancel();Require(!sinkToken.IsCancellationRequested&&execution.ResultsReturned==0);}
            finally{release.TrySetResult();}
            var result=await pending;Require(trail.AppendCalls==1&&trail.Store!.Snapshot().Length==1&&execution.MutationCalls==1&&execution.ResultsReturned==(cancel?0:1));Require(cancel?result.Body.Contains("audit_trail.write_failed_may_have_committed",StringComparison.Ordinal):result.Status==HttpStatusCode.OK);Safe(trail);
        });
        foreach(var graphql in new[]{false,true})
        await Check("execution "+(graphql?"GraphQL":"HTTP")+" abort before helper has no callback or data effects",async()=>
        {
            var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var stopped=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var trail=new AuditTrailFixture(TenantChangeAuditMode.ChangedFields);
            var execution=new AuditExecutionFixture{BeforeExecute=async(_,ct)=>{entered.TrySetResult();try{await Task.Delay(Timeout.InfiniteTimeSpan,ct);}catch(OperationCanceledException){stopped.TrySetResult();throw;}}};
            await using var host=new Host();await host.Start(tls,signing,trailProfile:trail,executionProfile:execution);using var client=tls.Client(host.Address);using var cancel=new CancellationTokenSource();
            var pending=Post(client,graphql?"/graphql":"/entity/update",graphql?Graph():Change(),signing.Token(),cancellation:cancel.Token);await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));cancel.Cancel();var cancelled=false;try{await pending;}catch(OperationCanceledException){cancelled=true;}await stopped.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Require(cancelled&&trail.Revision("A")==0&&execution.HelperCalls==0&&execution.MutationCalls==0&&execution.PossibleCommitFailures==0&&trail.AppendCalls==0&&trail.ValueFactoryCalls==0);
        });
        foreach(var graphql in new[]{false,true})
        await Check("execution "+(graphql?"GraphQL":"HTTP")+" abort inside mutation forwards cancellation and reports possible effects without receipt",async()=>
        {
            var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var stopped=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var trail=new AuditTrailFixture(TenantChangeAuditMode.ChangedFields);
            var execution=new AuditExecutionFixture{AfterMutation=async ct=>{entered.TrySetResult();try{await Task.Delay(Timeout.InfiniteTimeSpan,ct);}catch(OperationCanceledException){stopped.TrySetResult();throw;}}};
            await using var host=new Host();await host.Start(tls,signing,trailProfile:trail,executionProfile:execution);using var client=tls.Client(host.Address);using var cancel=new CancellationTokenSource();
            var pending=Post(client,graphql?"/graphql":"/entity/update",graphql?Graph():Change(),signing.Token(),cancellation:cancel.Token);await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));cancel.Cancel();var cancelled=false;try{await pending;}catch(OperationCanceledException){cancelled=true;}await stopped.Task.WaitAsync(TimeSpan.FromSeconds(5));await execution.Finished.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Require(cancelled&&trail.Revision("A")==1&&execution.MutationCalls==1&&execution.ResultsReturned==0&&execution.PossibleCommitFailures==1&&trail.AppendCalls==0&&trail.ValueFactoryCalls==0&&trail.Store!.Snapshot().Length==0);
        });
        return summaries.AsReadOnly();
    }
}
