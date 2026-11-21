using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Cehpalon.Engine.Tenancy;
using Microsoft.IdentityModel.Tokens;

namespace SecurityApi;

public static class KeyRingChecks
{
    public static async Task<IReadOnlyList<KeyRingObservation>> Run(TlsFixture tls,JwtFixture signing,Func<string,Func<Task>,Task> reportCheck)
    {
        var observations=new List<KeyRingObservation>();
        Task Check(string name,Func<Task> action)=>reportCheck(name,async()=>
        {
            try{await action();}
            catch(Exception error){throw new InvalidOperationException("Key ring fixture check failed: "+error.GetType().FullName+". Credential-bearing exception details are omitted.");}
        });
        void Require(bool value){if(!value)throw new InvalidOperationException("Key ring consumer assertion failed.");}
        async Task<(HttpStatusCode Status,string Body)> Post(HttpClient client,string path,object body,string token)
        {
            using var request=new HttpRequestMessage(HttpMethod.Post,path){Content=JsonContent.Create(body)};request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",token);
            using var response=await client.SendAsync(request);return(response.StatusCode,await response.Content.ReadAsStringAsync());
        }
        async Task AssertAccepted(HttpClient client,string token)
        {
            var response=await Post(client,"/document/read",new DocumentRequest("A","shared"),token);
            Require(response.Status==HttpStatusCode.OK&&response.Body.Contains("\"tenant\":\"A\""));
            var graph=await Post(client,"/graphql",new{query="query { document(input: { tenant: \"A\", resourceId: \"shared\" }) { tenant revision } }"},token);
            Require(graph.Status==HttpStatusCode.OK&&!graph.Body.Contains("\"errors\"")&&graph.Body.Contains("\"tenant\":\"A\""));
        }
        async Task AssertDenied(Host host,HttpClient client,string token)
        {
            var before=host.Business.Factories;
            var response=await Post(client,"/document/read",new DocumentRequest("A","shared"),token);
            Require(response.Status==HttpStatusCode.Unauthorized&&host.Business.Factories==before&&!response.Body.Contains(token)&&!response.Body.Contains("IDX",StringComparison.Ordinal));
            var graph=await Post(client,"/graphql",new{query="query { document(input: { tenant: \"A\", resourceId: \"shared\" }) { tenant revision } }"},token);
            Require(graph.Status==HttpStatusCode.Unauthorized&&host.Business.Factories==before);
        }
        foreach(var mode in new[]{"Signed","RSA-OAEP","dir"})
        {
            using var fixture=new KeyRingFixture(mode);await using var host=new Host();await host.Start(tls,signing,keyRingProfile:fixture);using var client=tls.Client(host.Address);
            var originalApplication=host.App;var oldToken=fixture.Token();var newToken=fixture.Token(true,true);
            await Check("rotating "+mode+" initial snapshot accepts old credential and denies not-yet-published key",async()=>
            {
                await AssertAccepted(client,oldToken);await AssertDenied(host,client,newToken);
                Require(host.KeyRingProviderCalls==1&&host.KeyProviderCalls==0&&host.DecryptionKeyProviderCalls==0&&fixture.Ring!.Version==1);
            });
            await Check("rotating "+mode+" publishes overlap atomically without restarting the host",async()=>
            {
                var before=fixture.Ring!.Version;var published=fixture.Publish(true,true,true,true);Require(published>before&&published==fixture.Ring.Version);
                await AssertAccepted(client,oldToken);await AssertAccepted(client,newToken);
                if(mode!="Signed"){await AssertAccepted(client,fixture.Token(true,false));await AssertAccepted(client,fixture.Token(false,true));}
                Require(ReferenceEquals(host.App,originalApplication)&&host.HostFactories==1&&host.SecurityFactories==1&&host.KeyRingProviderCalls==1);
            });
            await Check("rotating "+mode+" retires the old signing key before new HTTP and GraphQL business work",async()=>
            {
                fixture.Publish(false,true,true,true);await AssertDenied(host,client,oldToken);await AssertAccepted(client,newToken);
                if(mode!="Signed"){await AssertDenied(host,client,fixture.Token(false,true));await AssertAccepted(client,fixture.Token(true,false));}
            });
            if(mode!="Signed")await Check("rotating "+mode+" retires decryption independently of the inner signing key",async()=>
            {
                fixture.Publish(false,true,false,true);await AssertDenied(host,client,fixture.Token(true,false));await AssertAccepted(client,newToken);
            });
            await Check("rotating "+mode+" rejects invalid publication without replacing the coherent valid snapshot",async()=>
            {
                var version=fixture.Ring!.Version;var rejected=false;
                try{fixture.Publish(false,false,false,true);}catch(ArgumentException){rejected=true;}
                Require(rejected&&fixture.Ring.Version==version);await AssertAccepted(client,newToken);
            });
            await Check("rotating "+mode+" rejects stale control-plane expected version without losing active keys",async()=>
            {
                var version=fixture.Ring!.Version;var rejected=false;
                try{fixture.Publish(false,true,false,true,version-1);}catch(InvalidOperationException){rejected=true;}
                Require(rejected&&fixture.Ring.Version==version);await AssertAccepted(client,newToken);
            });
            await Check("rotating "+mode+" preserves active snapshot on a failing trusted key enumeration",async()=>
            {
                var version=fixture.Ring!.Version;var failed=false;
                try{fixture.Ring.Publish(version,FailingKeys(fixture.Signing(true,false)),mode=="Signed"?null:[fixture.Decryption(true)],fixture.Clock.GetUtcNow().AddSeconds(-1),fixture.Clock.GetUtcNow().AddMinutes(1));}
                catch(IOException){failed=true;}
                Require(failed&&fixture.Ring.Version==version);await AssertAccepted(client,newToken);
            });
            await Check("rotating "+mode+" keeps tenant selection read-set scope and linked audit after key retirement",async()=>
            {
                var before=host.Business.Factories;
                Require((await Post(client,"/document/read",new DocumentRequest("B","shared"),newToken)).Status==HttpStatusCode.Forbidden&&host.Business.Factories==before);
                var switcher=fixture.Token(true,true,"switcher");Require((await Post(client,"/tenant/select",new SwitchRequest("B"),switcher)).Status==HttpStatusCode.OK);
                Require((await Post(client,"/document/read",new DocumentRequest("B","shared"),switcher)).Status==HttpStatusCode.OK);
                var start=host.Audit!.Count;var set=await Post(client,"/document/read-all",new ReadSetRequest("shared"),fixture.Token(true,true,"reporter"));
                Require(set.Status==HttpStatusCode.OK&&set.Body.Contains("\"tenant\":\"A\"")&&set.Body.Contains("\"tenant\":\"B\""));
                var events=host.Audit.Snapshot().Skip(start).ToArray();var parent=events.Single(e=>e.ResourceKind=="tenant-read-set"&&e.Stage==TenantAuditStage.Authorization);
                Require(parent.AuthorizedTenant is null&&events.Count(e=>e.ParentInvocationId==parent.InvocationId)==4&&host.Business.Factories==host.Business.Disposals);
                var graph=await Post(client,"/graphql",new{query="query { document(input: { tenant: \"B\", resourceId: \"shared\" }) { tenant revision } }"},newToken);
                Require(graph.Body.Contains("access.denied"));
            });
            await Check("rotating "+mode+" still withholds partial rows on later membership revocation",async()=>
            {
                var before=host.Business.Factories;host.Business.ReadSetHook=t=>{if(t.Value=="A")host.Authority!.RevokeB=true;};
                try
                {
                    var response=await Post(client,"/document/read-all",new ReadSetRequest("shared"),fixture.Token(true,true,"reporter"));
                    Require(response.Status==HttpStatusCode.Forbidden&&!response.Body.Contains("\"results\"")&&!response.Body.Contains("\"tenant\":\"A\"")&&host.Business.Factories==before+1&&host.Business.Factories==host.Business.Disposals);
                }
                finally{host.Business.ReadSetHook=null;host.Authority!.RevokeB=false;}
            });
            await Check("rotating "+mode+" explicit withdrawal denies previously valid credentials with no old-key fallback",async()=>
            {
                var version=fixture.Ring!.Version;Require(fixture.Ring.Withdraw(version)>version);await AssertDenied(host,client,newToken);await AssertDenied(host,client,oldToken);
            });
            await Check("rotating "+mode+" trusted publication after withdrawal resumes only its selected keys",async()=>
            {
                fixture.Publish(false,true,false,true);await AssertAccepted(client,newToken);await AssertDenied(host,client,oldToken);
            });
            await Check("rotating "+mode+" disposal permanently denies future authentication",async()=>
            {
                fixture.Ring!.Dispose();await AssertDenied(host,client,newToken);var rejected=false;
                try{fixture.Publish(false,true,false,true);}catch(ObjectDisposedException){rejected=true;}
                Require(rejected&&host.Business.Factories==host.Business.Disposals);
            });
            observations.Add(new(mode,host.Business.Factories,host.Business.Disposals,host.Audit!.Count,host.KeyRingProviderCalls));
        }
        foreach(var mode in new[]{"Signed","dir"})
        await Check("rotating "+mode+" expired snapshot fails closed while the credential itself remains unexpired",async()=>
        {
            using var fixture=new KeyRingFixture(mode);await using var host=new Host();await host.Start(tls,signing,keyRingProfile:fixture);using var client=tls.Client(host.Address);
            var token=fixture.Token();await AssertAccepted(client,token);fixture.Clock.Advance(TimeSpan.FromMinutes(2));await AssertDenied(host,client,token);
        });
        await Check("disabled rotating security never creates or reads the fixture key ring",async()=>
        {
            using var fixture=new KeyRingFixture("dir");await using var host=new Host();await host.Start(tls,signing,false,false,false,false,true,keyRingProfile:fixture);
            Require(fixture.Ring is null&&host.KeyRingProviderCalls==0&&host.KeyProviderCalls==0&&host.DecryptionKeyProviderCalls==0&&host.SecurityFactories==0);
        });
        await Check("rotating and static fixture profiles cannot be mixed before activation",async()=>
        {
            using var fixture=new KeyRingFixture("Signed");using var staticProfile=new JweFixture("dir");await using var host=new Host();
            var rejected=false;try{await host.Start(tls,signing,jweProfile:staticProfile,keyRingProfile:fixture);}catch(ArgumentException){rejected=true;}
            Require(rejected&&host.HostFactories==0&&host.KeyRingProviderCalls==0&&fixture.Ring is null);
        });
        await Check("trusted ring factory failure stops startup before a listener or business factory",async()=>
        {
            using var fixture=new KeyRingFixture("Signed"){FailCreation=true};await using var host=new Host();var failed=false;
            try{await host.Start(tls,signing,keyRingProfile:fixture);}catch(IOException){failed=true;}
            Require(failed&&host.App is null&&fixture.Ring is null&&host.Business.Factories==0&&host.KeyRingProviderCalls==1&&host.KeyProviderCalls==0);
        });
        await Check("key withdrawal governs future authentication and does not roll back already admitted tenant work",async()=>
        {
            using var fixture=new KeyRingFixture("Signed");await using var host=new Host();await host.Start(tls,signing,keyRingProfile:fixture);using var client=tls.Client(host.Address);
            var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var release=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            host.Business.DocumentGate=async(_,token)=>{entered.TrySetResult();await release.Task.WaitAsync(token);};
            var credential=fixture.Token();var request=Post(client,"/document/read",new DocumentRequest("A","shared"),credential);
            try
            {
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));fixture.Ring!.Withdraw(fixture.Ring.Version);release.TrySetResult();
                Require((await request).Status==HttpStatusCode.OK&&host.Business.Factories==1&&host.Business.Disposals==1);
                await AssertDenied(host,client,credential);
            }
            finally{release.TrySetResult();await request;host.Business.DocumentGate=null;}
        });
        return observations.AsReadOnly();
    }
    private static IEnumerable<SecurityKey> FailingKeys(SecurityKey first){yield return first;throw new IOException("Controlled trusted-provider enumeration failure.");}
}

public sealed record KeyRingObservation(string Protection,int BusinessFactories,int BusinessDisposals,int AuditEvents,int RingProviderCalls);
