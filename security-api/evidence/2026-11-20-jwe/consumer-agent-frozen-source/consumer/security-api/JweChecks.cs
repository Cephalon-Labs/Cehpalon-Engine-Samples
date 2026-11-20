using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Cehpalon.Engine.Tenancy;

namespace SecurityApi;

public static class JweChecks
{
    public static async Task<IReadOnlyList<JweProfileObservation>> Run(TlsFixture tls,JwtFixture signing,Func<string,Func<Task>,Task> reportCheck)
    {
        var observations=new List<JweProfileObservation>();
        Task Check(string name,Func<Task> action)=>reportCheck(name,async()=>
        {
            try{await action();}
            catch(Exception error){throw new InvalidOperationException("JWE fixture check failed: "+error.GetType().FullName+". Credential-bearing exception details are omitted.");}
        });
        void Require(bool value){if(!value)throw new InvalidOperationException("JWE consumer assertion failed.");}
        async Task<(HttpStatusCode Status,string Body)> Post(HttpClient client,string path,object body,string token)
        {
            using var request=new HttpRequestMessage(HttpMethod.Post,path){Content=JsonContent.Create(body)};
            request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",token);
            using var response=await client.SendAsync(request);return(response.StatusCode,await response.Content.ReadAsStringAsync());
        }
        foreach(var algorithm in new[]{"RSA-OAEP","dir"})
        {
            using var fixture=new JweFixture(algorithm);using var wrong=new JweFixture(algorithm);await using var host=new Host();
            await host.Start(tls,signing,jweProfile:fixture);using var client=tls.Client(host.Address);
            var request=new DocumentRequest("A","shared");
            await Check("configured JWE "+algorithm+" decrypts signed inner JWT through HTTP and GraphQL",async()=>
            {
                var token=fixture.Token(signing);Require(token.Count(c=>c=='.')==4);
                Require((await Post(client,"/document/read",request,token)).Status==HttpStatusCode.OK);
                var graph=await Post(client,"/graphql",new{query="query { document(input: { tenant: \"A\", resourceId: \"shared\" }) { tenant revision } }"},token);
                Require(graph.Status==HttpStatusCode.OK&&!graph.Body.Contains("\"errors\"")&&graph.Body.Contains("\"tenant\":\"A\""));
                Require(host.KeyProviderCalls==1&&host.DecryptionKeyProviderCalls==1&&host.Business.Factories==host.Business.Disposals);
            });
            foreach(var mutation in new[]{"plaintext-downgrade","wrong-decryption-key","unknown-kid","key-algorithm","content-algorithm","ciphertext","tag","unsigned-inner","wrong-inner-signature","wrong-inner-issuer","wrong-inner-audience","expired-inner","outer-type","missing-content-type","compression"})
            await Check("configured JWE "+algorithm+" rejects "+mutation+" before business factories",async()=>
            {
                var valid=fixture.Token(signing);using var otherSigner=new JwtFixture();
                var token=mutation switch{
                    "plaintext-downgrade"=>signing.Token(),"wrong-decryption-key"=>wrong.Token(signing),
                    "unknown-kid"=>JweFixture.Header(valid,"kid","unregistered"),
                    "key-algorithm"=>JweFixture.Header(valid,"alg","RSA1_5"),"content-algorithm"=>JweFixture.Header(valid,"enc","A128GCM"),
                    "ciphertext"=>JweFixture.Tamper(valid,3),"tag"=>JweFixture.Tamper(valid,4),
                    "unsigned-inner"=>fixture.Encrypt(JweFixture.UnsignedInner()),"wrong-inner-signature"=>fixture.Token(otherSigner),
                    "wrong-inner-issuer"=>fixture.Token(signing,inner:signing.Token(issuer:"urn:wrong")),
                    "wrong-inner-audience"=>fixture.Token(signing,inner:signing.Token(audience:"wrong")),
                    "expired-inner"=>fixture.Token(signing,inner:signing.Token(expired:true)),
                    "outer-type"=>JweFixture.Header(valid,"typ","JWT"),"missing-content-type"=>JweFixture.Header(valid,"cty",null),
                    _=>JweFixture.Header(valid,"zip","DEF")};
                var before=host.Business.Factories;var response=await Post(client,"/document/read",request,token);
                Require(response.Status==HttpStatusCode.Unauthorized&&host.Business.Factories==before);
                Require(!response.Body.Contains(token)&&!response.Body.Contains("IDX",StringComparison.Ordinal));
            });
            await Check("configured JWE "+algorithm+" retains tenant denial selection and granted read-set audit",async()=>
            {
                var before=host.Business.Factories;
                Require((await Post(client,"/document/read",new DocumentRequest("B","shared"),fixture.Token(signing))).Status==HttpStatusCode.Forbidden&&host.Business.Factories==before);
                var switcher=fixture.Token(signing,"switcher");Require((await Post(client,"/tenant/select",new SwitchRequest("B"),switcher)).Status==HttpStatusCode.OK);
                Require((await Post(client,"/document/read",new DocumentRequest("B","shared"),switcher)).Status==HttpStatusCode.OK);
                var start=host.Audit!.Count;var set=await Post(client,"/document/read-all",new ReadSetRequest("shared"),fixture.Token(signing,"reporter"));
                Require(set.Status==HttpStatusCode.OK&&set.Body.Contains("\"tenant\":\"A\"")&&set.Body.Contains("\"tenant\":\"B\""));
                var events=host.Audit.Snapshot().Skip(start).ToArray();var parent=events.Single(e=>e.ResourceKind=="tenant-read-set"&&e.Stage==TenantAuditStage.Authorization);
                Require(parent.AuthorizedTenant is null&&events.Count(e=>e.ParentInvocationId==parent.InvocationId)==4&&host.Business.Factories==host.Business.Disposals);
                var graph=await Post(client,"/graphql",new{query="query { document(input: { tenant: \"B\", resourceId: \"shared\" }) { tenant revision } }"},fixture.Token(signing));
                Require(graph.Body.Contains("access.denied"));
            });
            await Check("configured JWE "+algorithm+" withholds partial rows after later tenant revocation",async()=>
            {
                var before=host.Business.Factories;var disposed=host.Business.Disposals;
                host.Business.ReadSetHook=t=>{if(t.Value=="A")host.Authority!.RevokeB=true;};
                try
                {
                    var result=await Post(client,"/document/read-all",new ReadSetRequest("shared"),fixture.Token(signing,"reporter"));
                    Require(result.Status==HttpStatusCode.Forbidden&&!result.Body.Contains("\"results\"")&&!result.Body.Contains("\"tenant\":\"A\""));
                    Require(host.Business.Factories==before+1&&host.Business.Disposals==disposed+1);
                }
                finally{host.Authority!.RevokeB=false;host.Business.ReadSetHook=null;}
            });
            observations.Add(new(algorithm,fixture.ContentEncryptionAlgorithm,host.Business.Factories,host.Business.Disposals,host.Audit!.Count,host.KeyProviderCalls,host.DecryptionKeyProviderCalls));
        }
        await Check("signed-only consumer does not accept an encrypted credential",async()=>
        {
            using var fixture=new JweFixture("dir");await using var host=new Host();await host.Start(tls,signing);using var client=tls.Client(host.Address);
            Require((await Post(client,"/document/read",new DocumentRequest("A","shared"),fixture.Token(signing))).Status==HttpStatusCode.Unauthorized&&host.Business.Factories==0&&host.DecryptionKeyProviderCalls==0);
        });
        await Check("conflicting JWE and cookie fixture settings reject before activation or key access",async()=>
        {
            using var fixture=new JweFixture("dir");await using var host=new Host();
            try{await host.Start(tls,signing,cookieAuthentication:true,jweProfile:fixture);throw new InvalidOperationException("Conflicting authentication settings activated.");}
            catch(ArgumentException){Require(host.HostFactories==0&&host.SecurityFactories==0&&host.KeyProviderCalls==0&&host.DecryptionKeyProviderCalls==0);}
        });
        await Check("disabled JWE security never loads signing or private decryption key providers",async()=>
        {
            using var fixture=new JweFixture("dir");await using var host=new Host();await host.Start(tls,signing,false,false,false,false,true,jweProfile:fixture);
            Require(host.SecurityFactories==0&&host.KeyProviderCalls==0&&host.DecryptionKeyProviderCalls==0&&host.AuthenticationServices==0);
        });
        return observations.AsReadOnly();
    }
}

public sealed record JweProfileObservation(string KeyManagementAlgorithm,string ContentEncryptionAlgorithm,int BusinessFactories,int BusinessDisposals,int AuditEvents,int SigningKeyProviderCalls,int DecryptionKeyProviderCalls);
