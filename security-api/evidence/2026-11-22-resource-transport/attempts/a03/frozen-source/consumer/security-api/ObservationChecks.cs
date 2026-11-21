using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Cehpalon.Engine.Tenancy;

namespace SecurityApi;

public static class ObservationChecks
{
    public static async Task<IReadOnlyList<ObservationSummary>> Run(TlsFixture tls,JwtFixture signing,Func<string,Func<Task>,Task> reportCheck)
    {
        var summaries=new List<ObservationSummary>();
        Task Check(string name,Func<Task> action)=>reportCheck(name,async()=>
        {
            try{await action();}
            catch(Exception error){throw new InvalidOperationException("Observation fixture failed: "+error.GetType().FullName+". Credential-bearing exception details omitted.");}
        });
        void Require(bool value){if(!value)throw new InvalidOperationException("Observation consumer assertion failed.");}
        async Task<(HttpStatusCode Status,string Body)> Post(HttpClient client,string path,object body,string? token=null,string? cookie=null,CancellationToken cancellation=default)
        {
            using var request=new HttpRequestMessage(HttpMethod.Post,path){Content=JsonContent.Create(body)};
            if(token is not null)request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",token);
            if(cookie is not null)request.Headers.Add("Cookie",cookie);
            using var response=await client.SendAsync(request,cancellation);return(response.StatusCode,await response.Content.ReadAsStringAsync(cancellation));
        }
        bool Denied((HttpStatusCode Status,string Body) result,string transport)=>transport=="HTTP"
            ?result.Status==HttpStatusCode.Forbidden&&result.Body.Contains("access.denied")
            :result.Status==HttpStatusCode.OK&&result.Body.Contains("access.denied");
        foreach(var mode in new[]{"Signed","RSA-OAEP","dir"})
        {
            using var encryption=mode=="Signed"?null:new JweFixture(mode);
            var observation=new ObservationFixture();var sessions=new SessionFixture{Clock=observation.Clock};
            var alice="private-observation-"+mode+"-alice";var reporter="private-observation-"+mode+"-reporter";var auditor="private-observation-"+mode+"-auditor";
            sessions.Register("alice",alice);sessions.Register("reporter",reporter);sessions.Register("auditor",auditor);
            await using var host=new Host();await host.Start(tls,signing,jweProfile:encryption,sessionProfile:sessions,observationProfile:observation);using var client=tls.Client(host.Address);
            string Token(string subject="alice",string? sid=null){var inner=signing.Token(subject,sessionId:sid??alice);return encryption is null?inner:encryption.Encrypt(inner);}
            Task<(HttpStatusCode Status,string Body)> Document(string transport,bool write=false)=>Post(client,transport=="HTTP"?(write?"/document/update":"/document/read"):"/graphql",
                transport=="HTTP"?new DocumentRequest("A","shared"):(object)new{query=write?"mutation { updateDocument(input: { tenant: \"A\", resourceId: \"shared\" }) { tenant revision } }":"query { document(input: { tenant: \"A\", resourceId: \"shared\" }) { tenant revision } }"},Token());
            foreach(var transport in new[]{"HTTP","GraphQL"})
            {
                await Check("observation "+mode+" "+transport+" valid original budget permits normal protected work",async()=>
                {
                    var count=host.Business.Factories;var status=sessions.StatusCalls;var result=await Document(transport);
                    Require(result.Status==HttpStatusCode.OK&&!result.Body.Contains("access.denied")&&!result.Body.Contains("\"errors\"")&&result.Body.Contains("A"));
                    Require(host.Business.Factories==count+1&&host.Business.Disposals==host.Business.Factories&&sessions.StatusCalls==status+1);
                });
                foreach(var stage in new[]{"membership","resource","policy","audit"})
                {
                    await Check("observation "+mode+" "+transport+" stalled UTC "+stage+" below original budget remains valid",async()=>
                    {
                        observation.StageHook=(current,_)=>{if(current==stage)observation.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(3));};
                        try{var before=host.Business.Factories;var calls=sessions.StatusCalls;var result=await Document(transport);Require(result.Status==HttpStatusCode.OK&&!result.Body.Contains("\"errors\"")&&host.Business.Factories==before+1&&sessions.StatusCalls==calls+1);}
                        finally{observation.StageHook=null;}
                    });
                    await Check("observation "+mode+" "+transport+" stalled UTC "+stage+" exhaustion denies before business activation",async()=>
                    {
                        observation.StageHook=(current,_)=>{if(current==stage)observation.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(6));};
                        try
                        {
                            var before=host.Business.Factories;var calls=sessions.StatusCalls;var audit=host.Audit!.Count;var result=await Document(transport);var events=host.Audit.Snapshot().Skip(audit).ToArray();
                            Require(Denied(result,transport)&&host.Business.Factories==before&&sessions.StatusCalls==calls+1);
                            Require(events.Count(e=>e.Stage==TenantAuditStage.Authorization)==(stage=="audit"?1:0)&&events.Last().Outcome==TenantAuditOutcome.Denied);
                            Require(!result.Body.Contains(alice)&&!JsonSerializer.Serialize(events).Contains(alice));
                        }
                        finally{observation.StageHook=null;}
                    });
                }
                await Check("observation "+mode+" "+transport+" shorter status lifetime also constrains monotonic admission",async()=>
                {
                    sessions.StatusLifetime=TimeSpan.FromSeconds(2);observation.StageHook=(stage,_)=>{if(stage=="membership")observation.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(3));};
                    try{var before=host.Business.Factories;Require(Denied(await Document(transport),transport)&&host.Business.Factories==before);}
                    finally{observation.StageHook=null;sessions.StatusLifetime=TimeSpan.FromMinutes(2);}
                });
                foreach(var stage in new[]{"after-handler","cleanup"})
                await Check("observation "+mode+" "+transport+" "+stage+" exhaustion withholds success after effects and cleanup",async()=>
                {
                    observation.StageHook=(current,_)=>{if(current==stage)observation.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(6));};
                    try
                    {
                        var count=host.Business.Factories;var revision=host.Business.Revision("A");var audit=host.Audit!.Count;var result=await Document(transport,true);
                        Require(Denied(result,transport)&&host.Business.Factories==count+1&&host.Business.Disposals==host.Business.Factories&&host.Business.Revision("A")==revision+1);
                        Require(host.Audit.Snapshot().Skip(audit).Last().Outcome==TenantAuditOutcome.Denied&&!result.Body.Contains("\"revision\""));
                    }
                    finally{observation.StageHook=null;}
                });
                await Check("observation "+mode+" "+transport+" expired observation does not replace explicit business rejection",async()=>
                {
                    observation.RejectBusiness=true;observation.StageHook=(stage,_)=>{if(stage=="business-rejected")observation.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(6));};
                    try{var audit=host.Audit!.Count;var result=await Document(transport);Require(result.Body.Contains("fixture.rejected")&&!result.Body.Contains("access.denied")&&host.Audit.Snapshot().Skip(audit).Last().Outcome==TenantAuditOutcome.Rejected&&host.Business.Disposals==host.Business.Factories);}
                    finally{observation.RejectBusiness=false;observation.StageHook=null;}
                });
                await Check("observation "+mode+" "+transport+" cleanup fault keeps precedence over expired successful work",async()=>
                {
                    observation.FailCleanup=true;observation.StageHook=(stage,_)=>{if(stage=="cleanup")observation.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(6));};
                    try{var audit=host.Audit!.Count;var result=await Document(transport);Require(result.Body.Contains("internal.error")&&!result.Body.Contains("access.denied")&&!result.Body.Contains("Controlled cleanup")&&host.Audit.Snapshot().Skip(audit).Last().Outcome==TenantAuditOutcome.Faulted&&host.Business.Disposals==host.Business.Factories);}
                    finally{observation.FailCleanup=false;observation.StageHook=null;}
                });
                await Check("observation "+mode+" "+transport+" expired grant await cannot start any tenant child",async()=>
                {
                    observation.StageHook=(stage,_)=>{if(stage=="grant")observation.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(6));};
                    try
                    {
                        var count=host.Business.Factories;var result=await Post(client,transport=="HTTP"?"/document/read-all":"/graphql",transport=="HTTP"?new ReadSetRequest("shared"):(object)new{query="query { readSet(input: { resourceId: \"shared\" }) { results { tenant revision } } }"},Token("reporter",reporter));
                        Require(Denied(result,transport)&&host.Business.Factories==count&&!result.Body.Contains("\"results\""));
                    }
                    finally{observation.StageHook=null;}
                });
                foreach(var location in new[]{"membership","context"})
                await Check("observation "+mode+" "+transport+" original parent budget survives fresh B "+location+" and withholds earlier A rows",async()=>
                {
                    observation.StageHook=(stage,tenant)=>{if(stage=="grant")observation.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(2));if(location=="membership"&&stage=="membership"&&tenant=="B")observation.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(2));};
                    host.Business.ReadSetHook=tenant=>{if(tenant.Value=="A")observation.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(2));};
                    host.Business.ReadSetGate=(tenant,_)=>{if(location=="context"&&tenant.Value=="B")observation.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(2));return Task.CompletedTask;};
                    try
                    {
                        var before=host.Business.Factories;var a=observation.Effects("A");var b=observation.Effects("B");var status=sessions.StatusCalls;var auth=host.SessionAuthenticationCallbacks;
                        var result=await Post(client,transport=="HTTP"?"/document/read-all":"/graphql",transport=="HTTP"?new ReadSetRequest("shared"):(object)new{query="query { readSet(input: { resourceId: \"shared\" }) { results { tenant revision } } }"},Token("reporter",reporter));
                        Require(Denied(result,transport)&&!result.Body.Contains("\"results\"")&&observation.Effects("A")==a+1&&observation.Effects("B")==b);
                        Require(host.Business.Factories==before+(location=="membership"?1:2)&&host.Business.Disposals==host.Business.Factories&&sessions.StatusCalls==status+3&&host.SessionAuthenticationCallbacks==auth+1);
                    }
                    finally{observation.StageHook=null;host.Business.ReadSetHook=null;host.Business.ReadSetGate=null;}
                });
                await Check("observation "+mode+" "+transport+" ordinary cross-tenant denial still has no business activation",async()=>
                {
                    var before=host.Business.Factories;var result=await Post(client,transport=="HTTP"?"/document/read":"/graphql",transport=="HTTP"?new DocumentRequest("B","shared"):(object)new{query="query { document(input: { tenant: \"B\", resourceId: \"shared\" }) { tenant revision } }"},Token());
                    Require(Denied(result,transport)&&host.Business.Factories==before);
                });
            }
            summaries.Add(new(mode,host.Business.Factories,host.Business.Disposals,host.Audit!.Count,sessions.StatusCalls,host.SessionAuthenticationCallbacks,observation.Effects("A"),observation.Effects("B")));
        }
        await Check("observation disabled profile constructs no provider or observation-clock work",async()=>
        {
            var observation=new ObservationFixture();var sessions=new SessionFixture{Clock=observation.Clock};await using var host=new Host();await host.Start(tls,signing,false,false,false,false,true,sessionProfile:sessions,observationProfile:observation);
            Require(host.SecurityFactories==0&&sessions.FactoryCalls==0&&sessions.ProviderConstructors==0&&sessions.StatusCalls==0&&observation.Clock.UtcReads==0&&observation.Clock.TimestampReads==0);
        });
        await Check("observation cookie mapping preserves the same original observation into delayed tenant authorization",async()=>
        {
            var observation=new ObservationFixture();var sessions=new SessionFixture{Clock=observation.Clock};const string sid="private-observation-cookie";sessions.Register("alice",sid,"fixture-cookie");
            await using var host=new Host();await host.Start(tls,signing,cookieAuthentication:true,sessionProfile:sessions,observationProfile:observation);using var client=tls.Client(host.Address);var cookie=host.FixtureCookie(sessionId:sid);
            Require((await Post(client,"/document/read",new DocumentRequest("A","shared"),cookie:cookie)).Status==HttpStatusCode.OK);
            observation.StageHook=(stage,_)=>{if(stage=="membership")observation.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(6));};var before=host.Business.Factories;
            Require((await Post(client,"/document/read",new DocumentRequest("A","shared"),cookie:cookie)).Status==HttpStatusCode.Forbidden&&host.Business.Factories==before);
        });
        await Check("observation nested sources retain shorter inner monotonic lifetime",async()=>
        {
            var observation=new ObservationFixture{InnerLifetime=TimeSpan.FromSeconds(2)};var sessions=new SessionFixture{Clock=observation.Clock};const string sid="private-observation-nested";sessions.Register("alice",sid);
            await using var host=new Host();await host.Start(tls,signing,sessionProfile:sessions,observationProfile:observation);using var client=tls.Client(host.Address);
            observation.StageHook=(stage,_)=>{if(stage=="membership")observation.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(3));};
            Require((await Post(client,"/document/read",new DocumentRequest("A","shared"),signing.Token(sessionId:sid))).Status==HttpStatusCode.Forbidden&&host.Business.Factories==0&&sessions.StatusCalls==2);
        });
        foreach(var transport in new[]{"HTTP","GraphQL"})
        await Check("observation "+transport+" cancellation after observation keeps precedence over exhausted budget",async()=>
        {
            var observation=new ObservationFixture();var sessions=new SessionFixture{Clock=observation.Clock};const string sid="private-observation-cancel";sessions.Register("alice",sid);
            await using var host=new Host();await host.Start(tls,signing,sessionProfile:sessions,observationProfile:observation);using var client=tls.Client(host.Address);using var cancel=new CancellationTokenSource();
            var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var recorded=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            host.Business.DocumentGate=async(_,token)=>{entered.TrySetResult();await Task.Delay(Timeout.InfiniteTimeSpan,token);};
            host.Audit!.AppendHook=entry=>{if(entry.Stage==TenantAuditStage.Terminal)recorded.TrySetResult();};
            var path=transport=="HTTP"?"/document/read":"/graphql";
            object body=transport=="HTTP"?new DocumentRequest("A","shared"):new{query="query { document(input: { tenant: \"A\", resourceId: \"shared\" }) { tenant revision } }"};
            var pending=Post(client,path,body,signing.Token(sessionId:sid),cancellation:cancel.Token);
            try
            {
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));observation.Clock.AdvanceMonotonic(TimeSpan.FromSeconds(6));cancel.Cancel();
                var cancelled=false;try{await pending;}catch(OperationCanceledException){cancelled=true;}
                await recorded.Task.WaitAsync(TimeSpan.FromSeconds(5));Require(cancelled&&host.Business.Factories==1&&host.Business.Disposals==1&&observation.Effects("A")==0&&host.Audit.Snapshot().Last().Outcome==TenantAuditOutcome.Cancelled);
            }
            finally{cancel.Cancel();try{await pending;}catch(OperationCanceledException){}host.Business.DocumentGate=null;host.Audit.AppendHook=null;}
        });
        return summaries.AsReadOnly();
    }
}
