using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Cehpalon.Engine.Tenancy;

namespace SecurityApi;

public static class SessionChecks
{
    public static async Task<IReadOnlyList<SessionObservation>> Run(TlsFixture tls,JwtFixture signing,Func<string,Func<Task>,Task> reportCheck)
    {
        var observations=new List<SessionObservation>();
        Task Check(string name,Func<Task> action)=>reportCheck(name,async()=>
        {
            try{await action();}
            catch(Exception error){throw new InvalidOperationException("Session fixture check failed: "+error.GetType().FullName+". Credential-bearing exception details are omitted.");}
        });
        void Require(bool value){if(!value)throw new InvalidOperationException("Session consumer assertion failed.");}
        async Task<(HttpStatusCode Status,string Body)> Post(HttpClient client,string path,object body,string? token=null,string? cookie=null,CancellationToken cancellation=default)
        {
            using var request=new HttpRequestMessage(HttpMethod.Post,path){Content=JsonContent.Create(body)};
            if(token is not null)request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",token);
            if(cookie is not null)request.Headers.Add("Cookie",cookie);
            using var response=await client.SendAsync(request,cancellation);return(response.StatusCode,await response.Content.ReadAsStringAsync(cancellation));
        }
        async Task AssertAccepted(HttpClient client,string token)
        {
            var result=await Post(client,"/document/read",new DocumentRequest("A","shared"),token);
            Require(result.Status==HttpStatusCode.OK&&result.Body.Contains("\"tenant\":\"A\""));
            result=await Post(client,"/graphql",new{query="query { document(input: { tenant: \"A\", resourceId: \"shared\" }) { tenant revision } }"},token);
            Require(result.Status==HttpStatusCode.OK&&!result.Body.Contains("\"errors\"")&&result.Body.Contains("\"tenant\":\"A\""));
        }
        async Task AssertDenied(Host host,HttpClient client,string token,string sessionId)
        {
            var before=host.Business.Factories;
            var result=await Post(client,"/document/read",new DocumentRequest("A","shared"),token);
            Require(result.Status==HttpStatusCode.Forbidden&&host.Business.Factories==before&&!result.Body.Contains(token)&&!result.Body.Contains(sessionId));
            result=await Post(client,"/graphql",new{query="query { document(input: { tenant: \"A\", resourceId: \"shared\" }) { tenant revision } }"},token);
            Require(result.Body.Contains("access.denied")&&host.Business.Factories==before&&!result.Body.Contains(token)&&!result.Body.Contains(sessionId));
        }
        foreach(var mode in new[]{"Signed","RSA-OAEP","dir"})
        {
            using var encryption=mode=="Signed"?null:new JweFixture(mode);
            var sessions=new SessionFixture();
            var first="private-session-"+mode+"-first";var second="private-session-"+mode+"-second";
            var switcher="private-session-"+mode+"-switcher";var reporter="private-session-"+mode+"-reporter";var auditor="private-session-"+mode+"-auditor";
            sessions.Register("alice",first);sessions.Register("alice",second);sessions.Register("bob",first);sessions.Register("switcher",switcher);sessions.Register("reporter",reporter);sessions.Register("auditor",auditor);
            await using var host=new Host();await host.Start(tls,signing,jweProfile:encryption,sessionProfile:sessions);using var client=tls.Client(host.Address);
            string Token(string subject="alice",string? sid=null,bool duplicate=false)
            {var inner=signing.Token(subject,sessionId:sid,duplicateSession:duplicate);return encryption is null?inner:encryption.Encrypt(inner);}
            var firstToken=Token(sid:first);var secondToken=Token(sid:second);
            await Check("session "+mode+" live authenticated session enters HTTP and GraphQL with one selected provider",async()=>
            {
                var calls=sessions.StatusCalls;await AssertAccepted(client,firstToken);
                Require(sessions.StatusCalls==calls+2&&sessions.FactoryCalls==1&&sessions.ProviderConstructors==1&&host.SessionFactoryCalls==1);
            });
            await Check("session "+mode+" same-user independent login is separately authorized",()=>AssertAccepted(client,secondToken));
            await Check("session "+mode+" active status never grants another tenant",async()=>
            {
                var before=host.Business.Factories;var result=await Post(client,"/document/read",new DocumentRequest("B","shared"),firstToken);
                Require(result.Status==HttpStatusCode.Forbidden&&host.Business.Factories==before);
                result=await Post(client,"/graphql",new{query="query { document(input: { tenant: \"B\", resourceId: \"shared\" }) { tenant revision } }"},firstToken);
                Require(result.Body.Contains("access.denied")&&host.Business.Factories==before);
            });
            foreach(var reply in new[]{SessionReply.Missing,SessionReply.Inactive,SessionReply.WrongIssuer,SessionReply.WrongSubject,SessionReply.WrongScheme,SessionReply.WrongSession,SessionReply.Future,SessionReply.Expired})
            await Check("session "+mode+" rejects status "+reply+" before business",async()=>
            {
                sessions.Reply=reply;try{await AssertDenied(host,client,firstToken,first);}finally{sessions.Reply=SessionReply.Normal;}
            });
            await Check("session "+mode+" unknown authenticated session has no implicit registration",()=>AssertDenied(host,client,Token(sid:"private-session-unknown"),"private-session-unknown"));
            await Check("session "+mode+" missing duplicate and over-limit authenticated claims skip status provider",async()=>
            {
                var calls=sessions.StatusCalls;
                await AssertDenied(host,client,Token(),first);await AssertDenied(host,client,Token(sid:first,duplicate:true),first);
                await AssertDenied(host,client,Token(sid:new string('s',257)),first);Require(sessions.StatusCalls==calls);
            });
            await Check("session "+mode+" anonymous and caller session header cannot create authority",async()=>
            {
                var calls=sessions.StatusCalls;var before=host.Business.Factories;
                using var request=new HttpRequestMessage(HttpMethod.Post,"/document/read"){Content=JsonContent.Create(new DocumentRequest("A","shared"))};request.Headers.Add("X-Session-Id",first);
                using var response=await client.SendAsync(request);Require(response.StatusCode==HttpStatusCode.Unauthorized&&sessions.StatusCalls==calls&&host.Business.Factories==before);
            });
            await Check("session "+mode+" provider faults stay faults with sanitized terminal audit",async()=>
            {
                var before=host.Business.Factories;var start=host.Audit!.Count;sessions.FailLookup=true;
                try
                {
                    var result=await Post(client,"/document/read",new DocumentRequest("A","shared"),firstToken);
                    Require(result.Status==HttpStatusCode.InternalServerError&&!result.Body.Contains("IOException")&&!result.Body.Contains(first));
                    result=await Post(client,"/graphql",new{query="query { document(input: { tenant: \"A\", resourceId: \"shared\" }) { tenant revision } }"},firstToken);
                    Require(result.Body.Contains("\"errors\"")&&!result.Body.Contains("IOException")&&!result.Body.Contains(first)&&host.Business.Factories==before);
                    var rows=host.Audit.Snapshot().Skip(start).ToArray();Require(rows.Length==2&&rows.All(r=>r.Outcome==TenantAuditOutcome.Faulted&&r.AuthorizedTenant is null));
                }
                finally{sessions.FailLookup=false;}
            });
            await Check("session "+mode+" provider failure never creates a cached denial or stale allow",()=>AssertAccepted(client,firstToken));
            await Check("session "+mode+" tenant switching repeats status before destination access",async()=>
            {
                var credential=Token("switcher",switcher);var result=await Post(client,"/tenant/select",new SwitchRequest("B"),credential);
                Require(result.Status==HttpStatusCode.OK);Require((await Post(client,"/document/read",new DocumentRequest("B","shared"),credential)).Status==HttpStatusCode.OK);
                sessions.Revoke("switcher",switcher);var before=host.Business.Factories;
                Require((await Post(client,"/tenant/select",new SwitchRequest("A"),credential)).Status==HttpStatusCode.Forbidden);
                Require((await Post(client,"/document/read",new DocumentRequest("B","shared"),credential)).Status==HttpStatusCode.Forbidden&&host.Business.Factories==before);
            });
            await Check("session "+mode+" one HTTP-context cached ticket still rechecks status for read-set root and each tenant",async()=>
            {
                var calls=sessions.StatusCalls;var authenticated=host.SessionAuthenticationCallbacks;var start=host.Audit!.Count;
                var result=await Post(client,"/document/read-all",new ReadSetRequest("shared"),Token("reporter",reporter));
                Require(result.Status==HttpStatusCode.OK&&result.Body.Contains("\"tenant\":\"A\"")&&result.Body.Contains("\"tenant\":\"B\"")&&sessions.StatusCalls==calls+3&&host.SessionAuthenticationCallbacks==authenticated+1);
                var rows=host.Audit.Snapshot().Skip(start).ToArray();var parent=rows.Single(r=>r.ResourceKind=="tenant-read-set"&&r.Stage==TenantAuditStage.Authorization);
                Require(parent.AuthorizedTenant is null&&rows.Count(r=>r.ParentInvocationId==parent.InvocationId)==4);
            });
            await Check("session "+mode+" revocation between read-set tenants denies later work and withholds earlier rows",async()=>
            {
                var before=host.Business.Factories;var start=host.Audit!.Count;var authenticated=host.SessionAuthenticationCallbacks;
                host.Business.ReadSetHook=tenant=>{if(tenant.Value=="A")sessions.Revoke("reporter",reporter);};
                try
                {
                    var result=await Post(client,"/document/read-all",new ReadSetRequest("shared"),Token("reporter",reporter));
                    Require(result.Status==HttpStatusCode.Forbidden&&!result.Body.Contains("\"results\"")&&!result.Body.Contains("\"tenant\":\"A\"")&&host.Business.Factories==before+1&&host.Business.Factories==host.Business.Disposals&&host.SessionAuthenticationCallbacks==authenticated+1);
                    var rows=host.Audit.Snapshot().Skip(start).ToArray();Require(rows.Last(r=>r.ResourceKind=="tenant-read-set").Outcome==TenantAuditOutcome.Denied&&rows.Any(r=>r.AuthorizedTenant?.Value=="A")&&!rows.Any(r=>r.AuthorizedTenant?.Value=="B"));
                    before=host.Business.Factories;Require((await Post(client,"/graphql",new{query="query { readSet(input: { resourceId: \"shared\" }) { results { tenant revision } } }"},Token("reporter",reporter))).Body.Contains("access.denied")&&host.Business.Factories==before);
                }
                finally{host.Business.ReadSetHook=null;}
            });
            await Check("session "+mode+" revoked login cannot enter either tenant while another login remains valid",async()=>
            {
                sessions.Revoke("alice",first);await AssertDenied(host,client,firstToken,first);await AssertAccepted(client,secondToken);
                var before=host.Business.Factories;Require((await Post(client,"/document/read",new DocumentRequest("B","shared"),firstToken)).Status==HttpStatusCode.Forbidden&&host.Business.Factories==before);
            });
            await Check("session "+mode+" status keys bind the same opaque ID to its exact principal",async()=>
            {
                var result=await Post(client,"/document/read",new DocumentRequest("B","shared"),Token("bob",first));
                Require(result.Status==HttpStatusCode.OK&&result.Body.Contains("\"tenant\":\"B\""));await AssertDenied(host,client,firstToken,first);
            });
            await Check("session "+mode+" new login gets a distinct ID and does not reactivate withdrawn credentials",async()=>
            {
                var fresh="private-session-"+mode+"-new-login";sessions.Register("alice",fresh);await AssertAccepted(client,Token(sid:fresh));await AssertDenied(host,client,firstToken,first);
                var rejected=false;try{sessions.Register("alice",first);}catch(InvalidOperationException){rejected=true;}Require(rejected);
            });
            await Check("session "+mode+" tenant history is session-checked and contains no session identifier",async()=>
            {
                var credential=Token("auditor",auditor);var result=await Post(client,"/history",new HistoryRequest("A"),credential);
                Require(result.Status==HttpStatusCode.OK&&!result.Body.Contains("private-session-")&&!JsonSerializer.Serialize(host.Audit!.Snapshot()).Contains("private-session-"));
                sessions.Revoke("auditor",auditor);var before=host.Business.Factories;
                Require((await Post(client,"/history",new HistoryRequest("A"),credential)).Status==HttpStatusCode.Forbidden&&host.Business.Factories==before);
            });
            observations.Add(new(mode,host.Business.Factories,host.Business.Disposals,host.Audit!.Count,host.SessionFactoryCalls,sessions.StatusCalls,host.SessionAuthenticationCallbacks,sessions.ProviderConstructors));
        }
        await Check("disabled security invokes neither session factory nor status provider",async()=>
        {
            var sessions=new SessionFixture();await using var host=new Host();await host.Start(tls,signing,false,false,false,false,true,sessionProfile:sessions);
            Require(host.Sessions is null&&host.SessionFactoryCalls==0&&sessions.FactoryCalls==0&&sessions.ProviderConstructors==0&&sessions.StatusCalls==0&&host.SecurityFactories==0);
        });
        await Check("trusted session factory failure aborts before host listener or business creation",async()=>
        {
            var sessions=new SessionFixture{FailCreation=true};await using var host=new Host();var failed=false;
            try{await host.Start(tls,signing,sessionProfile:sessions);}catch(IOException){failed=true;}
            Require(failed&&host.App is null&&host.HostFactories==0&&host.Business.Factories==0&&sessions.FactoryCalls==1&&sessions.ProviderConstructors==0&&sessions.StatusCalls==0);
        });
        await Check("actual encrypted cookie ticket mapping rechecks the configured session on each operation",async()=>
        {
            var sessions=new SessionFixture();const string id="private-session-cookie";sessions.Register("alice",id,"fixture-cookie");
            await using var host=new Host();await host.Start(tls,signing,cookieAuthentication:true,sessionProfile:sessions);using var client=tls.Client(host.Address);
            var credential=host.FixtureCookie(sessionId:id);Require((await Post(client,"/document/read",new DocumentRequest("A","shared"),cookie:credential)).Status==HttpStatusCode.OK);
            Require((await Post(client,"/graphql",new{query="query { document(input: { tenant: \"A\", resourceId: \"shared\" }) { tenant revision } }"},cookie:credential)).Body.Contains("\"tenant\":\"A\""));
            sessions.Revoke("alice",id,"fixture-cookie");var before=host.Business.Factories;
            Require((await Post(client,"/document/read",new DocumentRequest("A","shared"),cookie:credential)).Status==HttpStatusCode.Forbidden);
            Require((await Post(client,"/graphql",new{query="query { document(input: { tenant: \"A\", resourceId: \"shared\" }) { tenant revision } }"},cookie:credential)).Body.Contains("access.denied")&&host.Business.Factories==before&&sessions.StatusCalls==4);
            Require((await Post(client,"/document/read",new DocumentRequest("A","shared"),cookie:host.FixtureCookie())).Status==HttpStatusCode.Forbidden&&sessions.StatusCalls==4);
        });
        await Check("revocation after a fresh observation does not undo already admitted business work",async()=>
        {
            var sessions=new SessionFixture();const string id="private-session-admitted";sessions.Register("alice",id);
            await using var host=new Host();await host.Start(tls,signing,sessionProfile:sessions);using var client=tls.Client(host.Address);
            var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var release=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            host.Business.DocumentGate=async(_,token)=>{entered.TrySetResult();await release.Task.WaitAsync(token);};
            var credential=signing.Token(sessionId:id);var pending=Post(client,"/document/read",new DocumentRequest("A","shared"),credential);
            try
            {
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));sessions.Revoke("alice",id);release.TrySetResult();
                Require((await pending).Status==HttpStatusCode.OK&&host.Business.Factories==1&&host.Business.Disposals==1);await AssertDenied(host,client,credential,id);
            }
            finally{release.TrySetResult();await pending;host.Business.DocumentGate=null;}
        });
        foreach(var transport in new[]{"HTTP","GraphQL"})
        await Check(transport+" client abort reaches an in-flight trusted session lookup before business creation",async()=>
        {
            var sessions=new SessionFixture();const string id="private-session-cancelled";sessions.Register("alice",id);
            await using var host=new Host();await host.Start(tls,signing,sessionProfile:sessions);using var client=tls.Client(host.Address);using var cancel=new CancellationTokenSource();
            var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var stopped=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            sessions.LookupGate=async(_,token)=>
            {
                entered.TrySetResult();try{await Task.Delay(Timeout.InfiniteTimeSpan,token);}catch(OperationCanceledException){stopped.TrySetResult();throw;}
            };
            var path=transport=="HTTP"?"/document/read":"/graphql";
            object body=transport=="HTTP"?new DocumentRequest("A","shared"):new{query="query { document(input: { tenant: \"A\", resourceId: \"shared\" }) { tenant revision } }"};
            var pending=Post(client,path,body,signing.Token(sessionId:id),cancellation:cancel.Token);
            try
            {
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));cancel.Cancel();var cancelled=false;try{await pending;}catch(OperationCanceledException){cancelled=true;}
                await stopped.Task.WaitAsync(TimeSpan.FromSeconds(5));Require(cancelled&&host.Business.Factories==0);
            }
            finally{cancel.Cancel();try{await pending;}catch(OperationCanceledException){}sessions.LookupGate=null;}
        });
        return observations.AsReadOnly();
    }
}
