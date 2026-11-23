using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using SecurityApi;
using Host=SecurityApi.Host;

if(!Cehpalon.Samples.SampleRunArguments.TryReport(args,"security-api",out var output,out var usageExit)) return usageExit;
var checks=new List<object>();var passed=0;var failed=0;
void Require(bool value){if(!value)throw new InvalidOperationException("Consumer assertion failed.");}
async Task Check(string name,Func<Task> action)
{
    try{await action();passed++;checks.Add(new{name,passed=true});}
    catch(Exception error){failed++;checks.Add(new{name,passed=false,error=error.ToString()});}
}
using var tls=new TlsFixture();using var jwt=new JwtFixture();using var otherKey=new JwtFixture();
await Check("protected routes cannot compose with security explicitly disabled",async()=>
{
    await using var h=new Host();try{await h.Start(tls,jwt,security:false);throw new InvalidOperationException("Unsafe composition started.");}
    catch(ArgumentException){Require(h.HostFactories==0&&h.SecurityFactories==0&&h.AuditFactories==0&&h.App is null);}
});
await Check("all modules disabled performs no module-owned activation",async()=>
{
    await using var h=new Host();await h.Start(tls,jwt,false,false,false,false);
    Require(h.App is null&&h.HostFactories==0&&h.SecurityFactories==0&&h.AuditFactories==0);
});
await Check("public profile skips authentication policy audit and GraphQL services",async()=>
{
    await using var h=new Host();await h.Start(tls,jwt,false,false,false,false,true);using var client=tls.Client(h.Address);
    Require((await client.GetAsync("/health")).IsSuccessStatusCode&&h.SecurityFactories==0&&h.AuditFactories==0&&h.AuthenticationServices==0&&h.GraphQLServices==0);
    Require((await client.PostAsJsonAsync("/document/read",new DocumentRequest("A","shared"))).StatusCode==HttpStatusCode.NotFound);
});
await using var host=new Host();await host.Start(tls,jwt);using var http=tls.Client(host.Address);
async Task<(HttpStatusCode Status,string Body)> Post(string path,object body,string? token,HttpClient? target=null,string? cookie=null)
{
    using var request=new HttpRequestMessage(HttpMethod.Post,path){Content=JsonContent.Create(body)};
    if(token is not null)request.Headers.Authorization=new("Bearer",token);
    if(cookie is not null)request.Headers.Add("Cookie",cookie);
    using var response=await (target??http).SendAsync(request);return(response.StatusCode,await response.Content.ReadAsStringAsync());
}
async Task<(HttpStatusCode Status,string Body)> Graph(string field,string tenant,string? token,bool mutation=false)
    =>await Post("/graphql",new{query=(mutation?"mutation":"query")+" { "+field+"(input: { tenant: \""+tenant+"\", resourceId: \"shared\" }) { tenant revision } }"},token);
var read=new DocumentRequest("A","shared");var alice=jwt.Token();var bob=jwt.Token("bob");
await Check("actual TLS signed JWT and generated HTTP gateway allow combined policy",async()=>
{
    var result=await Post("/document/read",read,alice);Require(result.Status==HttpStatusCode.OK&&JsonDocument.Parse(result.Body).RootElement.GetProperty("tenant").GetString()=="A");
    Require(host.Audit!.Count==2&&host.Business.Factories==1&&host.Business.Disposals==1);
});
foreach(var invalid in new[]{"anonymous","forged-key","issuer","audience","expired","duplicate-sub","type"})
await Check("HTTP rejects "+invalid+" before business work",async()=>
{
    var before=host.Business.Factories;var token=invalid switch{
        "anonymous"=>null,"forged-key"=>otherKey.Token(),"issuer"=>jwt.Token(issuer:"urn:wrong"),"audience"=>jwt.Token(audience:"wrong"),
        "expired"=>jwt.Token(expired:true),"duplicate-sub"=>jwt.Token(duplicateSubject:true),_=>jwt.Token(type:"JWT")};
    var result=await Post("/document/read",read,token);Require(result.Status is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden&&host.Business.Factories==before);
});
await Check("RBAC-only and ABAC-only can be selected independently",async()=>
{
    var noRole=jwt.Token("no-role");var wrongDepartment=jwt.Token("wrong-department");
    Require((await Post("/document/rbac",read,wrongDepartment)).Status==HttpStatusCode.OK);
    Require((await Post("/document/abac",read,noRole)).Status==HttpStatusCode.OK);
    var before=host.Business.Factories;
    Require((await Post("/document/rbac",read,noRole)).Status==HttpStatusCode.Forbidden);
    Require((await Post("/document/abac",read,wrongDepartment)).Status==HttpStatusCode.Forbidden&&host.Business.Factories==before);
});
await Check("combined policy denies absent role or department separately",async()=>
{
    var before=host.Business.Factories;
    Require((await Post("/document/read",read,jwt.Token("no-role"))).Status==HttpStatusCode.Forbidden);
    Require((await Post("/document/read",read,jwt.Token("wrong-department"))).Status==HttpStatusCode.Forbidden&&host.Business.Factories==before);
});
await Check("fresh authority revocation denies an otherwise valid JWT",async()=>
{
    host.Authority!.ReaderRevoked=true;var before=host.Business.Factories;
    try{Require((await Post("/document/read",read,alice)).Status==HttpStatusCode.Forbidden&&host.Business.Factories==before);}
    finally{host.Authority.ReaderRevoked=false;}
});
await Check("HTTP cross-tenant A to B and B to A deny before factories",async()=>
{
    var before=host.Business.Factories;
    Require((await Post("/document/read",new DocumentRequest("B","shared"),alice)).Status==HttpStatusCode.Forbidden);
    Require((await Post("/document/read",read,bob)).Status==HttpStatusCode.Forbidden&&host.Business.Factories==before);
    Require((await Post("/document/read",new DocumentRequest("B","shared"),bob)).Status==HttpStatusCode.OK);
});
await Check("GraphQL uses same generated gateway and combined policy",async()=>
{
    var result=await Graph("document","A",alice);Require(result.Status==HttpStatusCode.OK&&!result.Body.Contains("\"errors\"")&&result.Body.Contains("\"tenant\":\"A\""));
});
foreach(var denied in new[]{"cross-tenant","role","attribute"})
await Check("GraphQL rejects "+denied+" before factories",async()=>
{
    var before=host.Business.Factories;var result=await Graph("document",denied=="cross-tenant"?"B":"A",jwt.Token(denied=="role"?"no-role":denied=="attribute"?"wrong-department":"alice"));
    Require(result.Body.Contains("access.denied")&&host.Business.Factories==before);
});
await Check("GraphQL invalid signature and anonymous calls cannot reach business",async()=>
{
    var before=host.Business.Factories;
    Require((await Graph("document","A",otherKey.Token())).Status==HttpStatusCode.Unauthorized);
    Require((await Graph("document","A",null)).Status==HttpStatusCode.Unauthorized&&host.Business.Factories==before);
});
await Check("HTTP and GraphQL mutations preserve tenant scope and audit outcomes",async()=>
{
    var before=host.Audit!.Count;var first=await Post("/document/update",read,alice);var second=await Graph("updateDocument","A",alice,true);
    Require(first.Status==HttpStatusCode.OK&&JsonDocument.Parse(first.Body).RootElement.GetProperty("revision").GetInt32()==1);
    Require(!second.Body.Contains("\"errors\"")&&second.Body.Contains("\"revision\":2")&&host.Audit.Count==before+4);
    var b=await Post("/document/read",new DocumentRequest("B","shared"),bob);Require(JsonDocument.Parse(b.Body).RootElement.GetProperty("revision").GetInt32()==0);
});
await Check("history has separate role and returns only authorized tenant records",async()=>
{
    var before=host.Business.Factories;
    Require((await Post("/history",new HistoryRequest("A"),alice)).Status==HttpStatusCode.Forbidden&&host.Business.Factories==before);
    var result=await Post("/history",new HistoryRequest("A"),jwt.Token("auditor"));var json=JsonDocument.Parse(result.Body).RootElement;
    Require(result.Status==HttpStatusCode.OK&&json.GetProperty("tenant").GetString()=="A"&&json.GetProperty("count").GetInt32()>0);
    before=host.Business.Factories;Require((await Post("/history",new HistoryRequest("B"),jwt.Token("auditor"))).Status==HttpStatusCode.Forbidden&&host.Business.Factories==before);
});
await Check("GraphQL history uses the same checked tenant reader",async()=>
{
    var result=await Post("/graphql",new{query="query { history(input: { tenant: \"A\", limit: 10 }) { tenant count outcomes } }"},jwt.Token("auditor"));
    Require(!result.Body.Contains("\"errors\"")&&result.Body.Contains("\"tenant\":\"A\""));
});
await Check("history pagination returns a bounded page and usable cursor",async()=>
{
    var first=await Post("/history",new HistoryRequest("A",1),jwt.Token("auditor"));var page=JsonDocument.Parse(first.Body).RootElement;
    Require(first.Status==HttpStatusCode.OK&&page.GetProperty("count").GetInt32()==1);
    var cursor=page.GetProperty("nextCursor").GetString();Require(cursor is not null);
    var second=await Post("/history",new HistoryRequest("A",1,cursor),jwt.Token("auditor"));
    Require(second.Status==HttpStatusCode.OK&&JsonDocument.Parse(second.Body).RootElement.GetProperty("count").GetInt32()==1);
});
await Check("required audit outage blocks write and redacts provider details",async()=>
{
    var before=host.Business.Factories;host.Audit!.Fail=true;
    try{var result=await Post("/document/update",read,alice);Require(result.Status==HttpStatusCode.InternalServerError&&host.Business.Factories==before&&!result.Body.Contains("Fixture audit unavailable"));}
    finally{host.Audit.Fail=false;}
});
await Check("audit metadata has matching pairs and excludes authentication secrets",()=>
{
    var entries=host.Audit!.Snapshot();var text=JsonSerializer.Serialize(entries);
    Require(!text.Contains(alice)&&!text.Contains("Bearer")&&!text.Contains("SigningCredentials")&&entries.All(e=>e.AuthorizedTenant is not null||e.Principal is null));
    foreach(var group in entries.Where(e=>e.AuthorizedTenant is not null).GroupBy(e=>e.InvocationId))Require(group.Count()==2&&group.Count(e=>e.Stage==Cehpalon.Engine.Tenancy.TenantAuditStage.Terminal)==1);
    Require(host.Business.Factories==host.Business.Disposals);return Task.CompletedTask;
});
await Check("audit and GraphQL disabled create no owned stores/services/endpoints",async()=>
{
    await using var h=new Host();await h.Start(tls,jwt,graphql:false,audit:false);using var client=tls.Client(h.Address);
    using var request=new HttpRequestMessage(HttpMethod.Post,"/document/read"){Content=JsonContent.Create(read)};request.Headers.Authorization=new("Bearer",alice);
    Require((await client.SendAsync(request)).IsSuccessStatusCode&&h.Audit is null&&h.AuditFactories==0&&h.GraphQLServices==0);
    Require((await client.PostAsJsonAsync("/graphql",new{query="{x}"})).StatusCode==HttpStatusCode.NotFound);
    Require((await client.PostAsJsonAsync("/history",new HistoryRequest("A"))).StatusCode==HttpStatusCode.NotFound);
});
await Check("default public JWKS pins key ID and algorithm without fallback",async()=>
{
    var before=host.Business.Factories;
    Require((await Post("/document/read",read,jwt.Token(kid:"unknown-key"))).Status==HttpStatusCode.Unauthorized);
    Require((await Post("/document/read",read,jwt.Token(algorithm:"PS256"))).Status==HttpStatusCode.Unauthorized&&host.Business.Factories==before);
    Require(host.KeyProviderCalls==1);
});
await Check("one login switches A to B and following requests select independently",async()=>
{
    var login=jwt.Token("switcher");
    Require((await Post("/tenant/select",new SwitchRequest("A"),login)).Status==HttpStatusCode.OK);
    var selected=await Post("/tenant/select",new SwitchRequest("B"),login);
    Require(selected.Status==HttpStatusCode.OK&&JsonDocument.Parse(selected.Body).RootElement.GetProperty("tenant").GetString()=="B");
    var b=await Post("/document/read",new DocumentRequest("B","shared"),login);
    var a=await Post("/document/read",read,login);
    Require(JsonDocument.Parse(b.Body).RootElement.GetProperty("tenant").GetString()=="B"&&JsonDocument.Parse(a.Body).RootElement.GetProperty("tenant").GetString()=="A");
});
await Check("unauthorized destination denies switch without changing login authority",async()=>
{
    var before=host.Business.Factories;
    Require((await Post("/tenant/select",new SwitchRequest("B"),alice)).Status==HttpStatusCode.Forbidden&&host.Business.Factories==before);
    Require((await Post("/document/read",read,alice)).Status==HttpStatusCode.OK);
    before=host.Business.Factories;Require((await Post("/tenant/select",new SwitchRequest("*"),alice)).Status==HttpStatusCode.BadRequest&&host.Business.Factories==before);
});
await Check("switch does not cache a grant across destination membership revocation",async()=>
{
    var login=jwt.Token("switcher");Require((await Post("/tenant/select",new SwitchRequest("B"),login)).Status==HttpStatusCode.OK);
    host.Authority!.RevokeB=true;var before=host.Business.Factories;
    try
    {
        Require((await Post("/document/read",new DocumentRequest("B","shared"),login)).Status==HttpStatusCode.Forbidden&&host.Business.Factories==before);
        Require((await Post("/document/read",read,login)).Status==HttpStatusCode.OK);
    }
    finally{host.Authority.RevokeB=false;}
});
await Check("parallel requests retain independent A and B checked contexts",async()=>
{
    var both=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var release=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var entered=0;
    host.Business.DocumentGate=async(_,token)=>{if(Interlocked.Increment(ref entered)==2)both.TrySetResult();await release.Task.WaitAsync(token);};
    var login=jwt.Token("switcher");var a=Post("/document/read",read,login);var b=Post("/document/read",new DocumentRequest("B","shared"),login);
    try
    {
        await both.Task.WaitAsync(TimeSpan.FromSeconds(5));release.TrySetResult();var results=await Task.WhenAll(a,b);
        Require(results.All(r=>r.Status==HttpStatusCode.OK));
        Require(JsonDocument.Parse(results[0].Body).RootElement.GetProperty("tenant").GetString()=="A"&&JsonDocument.Parse(results[1].Body).RootElement.GetProperty("tenant").GetString()=="B");
    }
    finally{release.TrySetResult();await Task.WhenAll(a,b);host.Business.DocumentGate=null;}
});
await Check("single-tenant memberships do not imply an aggregate read grant",async()=>
{
    var before=host.Business.Factories;var result=await Post("/document/read-all",new ReadSetRequest("shared"),jwt.Token("switcher"));
    Require(result.Status==HttpStatusCode.Forbidden&&!result.Body.Contains("\"results\"")&&host.Business.Factories==before);
});
await Check("parallel GraphQL sibling fields keep A and B request contexts isolated",async()=>
{
    var both=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var release=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var entered=0;
    host.Business.DocumentGate=async(_,token)=>{if(Interlocked.Increment(ref entered)==2)both.TrySetResult();await release.Task.WaitAsync(token);};
    var call=Post("/graphql",new{query="query { a: document(input: { tenant: \"A\", resourceId: \"shared\" }) { tenant revision } b: document(input: { tenant: \"B\", resourceId: \"shared\" }) { tenant revision } }"},jwt.Token("switcher"));
    try
    {
        await both.Task.WaitAsync(TimeSpan.FromSeconds(5));release.TrySetResult();var result=await call;
        var json=JsonDocument.Parse(result.Body).RootElement;Require(!json.TryGetProperty("errors",out _));
        Require(json.GetProperty("data").GetProperty("a").GetProperty("tenant").GetString()=="A"&&json.GetProperty("data").GetProperty("b").GetProperty("tenant").GetString()=="B");
    }
    finally{release.TrySetResult();await call;host.Business.DocumentGate=null;}
});
await Check("explicit read grant returns all and only its authorized tenants",async()=>
{
    var result=await Post("/document/read-all",new ReadSetRequest("shared"),jwt.Token("reporter"));
    var rows=JsonDocument.Parse(result.Body).RootElement.GetProperty("results").EnumerateArray().ToArray();
    Require(result.Status==HttpStatusCode.OK&&rows.Length==2&&rows.Select(r=>r.GetProperty("tenant").GetString()).Order().SequenceEqual(new[]{"A","B"}));
    result=await Post("/document/read-all",new ReadSetRequest("shared"),jwt.Token("limited-reporter"));
    rows=JsonDocument.Parse(result.Body).RootElement.GetProperty("results").EnumerateArray().ToArray();
    Require(result.Status==HttpStatusCode.OK&&rows.Length==1&&rows[0].GetProperty("tenant").GetString()=="A");
});
await Check("caller subset cannot expand the trusted read set or use wildcard",async()=>
{
    var result=await Post("/document/read-all",new ReadSetRequest("shared",["B"]),jwt.Token("reporter"));
    var rows=JsonDocument.Parse(result.Body).RootElement.GetProperty("results").EnumerateArray().ToArray();Require(result.Status==HttpStatusCode.OK&&rows.Length==1&&rows[0].GetProperty("tenant").GetString()=="B");
    var before=host.Business.Factories;
    Require((await Post("/document/read-all",new ReadSetRequest("shared",["B"]),jwt.Token("limited-reporter"))).Status==HttpStatusCode.Forbidden);
    Require((await Post("/document/read-all",new ReadSetRequest("shared",["*"]),jwt.Token("reporter"))).Status==HttpStatusCode.BadRequest);
    Require((await Post("/document/read-all",new ReadSetRequest("shared",["A","A"]),jwt.Token("reporter"))).Status==HttpStatusCode.BadRequest&&host.Business.Factories==before);
});
await Check("GraphQL uses generated switch and read-set gateways",async()=>
{
    var selected=await Post("/graphql",new{query="mutation { selectTenant(input: { tenant: \"B\" }) { tenant } }"},jwt.Token("switcher"));
    Require(!selected.Body.Contains("\"errors\"")&&selected.Body.Contains("\"tenant\":\"B\""));
    var all=await Post("/graphql",new{query="query { readSet(input: { resourceId: \"shared\" }) { results { tenant revision } } }"},jwt.Token("reporter"));
    Require(!all.Body.Contains("\"errors\"")&&all.Body.Contains("\"tenant\":\"A\"")&&all.Body.Contains("\"tenant\":\"B\""));
    var before=host.Business.Factories;
    var denied=await Post("/graphql",new{query="query { readSet(input: { resourceId: \"shared\" }) { results { tenant revision } } }"},jwt.Token("alice"));
    Require(denied.Body.Contains("access.denied")&&host.Business.Factories==before);
});
await Check("late tenant denial discards partial response and retains parent audit lineage",async()=>
{
    var first=host.Audit!.Count;var before=host.Business.Factories;var disposed=host.Business.Disposals;
    host.Business.ReadSetHook=tenant=>{if(tenant.Value=="A")host.Authority!.RevokeB=true;};
    try
    {
        var result=await Post("/document/read-all",new ReadSetRequest("shared"),jwt.Token("reporter"));
        Require(result.Status==HttpStatusCode.Forbidden&&!result.Body.Contains("\"results\"")&&!result.Body.Contains("\"tenant\":\"A\""));
        Require(host.Business.Factories==before+1&&host.Business.Disposals==disposed+1);
        var events=host.Audit.Snapshot().Skip(first).ToArray();var root=events.Single(e=>e.ResourceKind=="tenant-read-set"&&e.Stage==Cehpalon.Engine.Tenancy.TenantAuditStage.Authorization);
        Require(root.AuthorizedTenant is null&&root.ParentInvocationId is null);
        Require(events.Single(e=>e.InvocationId==root.InvocationId&&e.Stage==Cehpalon.Engine.Tenancy.TenantAuditStage.Terminal).Outcome==Cehpalon.Engine.Tenancy.TenantAuditOutcome.Denied);
        Require(events.Where(e=>e.ResourceKind!="tenant-read-set").All(e=>e.ParentInvocationId==root.InvocationId));
    }
    finally{host.Authority!.RevokeB=false;host.Business.ReadSetHook=null;}
});
await Check("successful read set requires root audit before reads and closes every child",async()=>
{
    var before=host.Business.Factories;var first=host.Audit!.Count;
    host.Audit.AppendHook=e=>{if(e.ResourceKind=="tenant-read-set"&&e.Stage==Cehpalon.Engine.Tenancy.TenantAuditStage.Authorization)Require(host.Business.Factories==before);};
    try
    {
        Require((await Post("/document/read-all",new ReadSetRequest("shared"),jwt.Token("reporter"))).Status==HttpStatusCode.OK);
        var events=host.Audit.Snapshot().Skip(first).ToArray();var roots=events.Where(e=>e.ResourceKind=="tenant-read-set").ToArray();
        Require(roots.Length==2&&roots.All(e=>e.AuthorizedTenant is null)&&roots[^1].Outcome==Cehpalon.Engine.Tenancy.TenantAuditOutcome.Succeeded);
        var children=events.Where(e=>e.ParentInvocationId==roots[0].InvocationId).ToArray();Require(children.Length==4&&children.Select(e=>e.AuthorizedTenant!.Value).Distinct().Count()==2);
        Require(host.Business.Factories==host.Business.Disposals);
    }
    finally{host.Audit.AppendHook=null;}
});
await Check("read sets preserve tenant checks when audit and GraphQL are disabled",async()=>
{
    await using var h=new Host();await h.Start(tls,jwt,graphql:false,audit:false);using var client=tls.Client(h.Address);
    var result=await Post("/document/read-all",new ReadSetRequest("shared"),jwt.Token("reporter"),client);
    Require(result.Status==HttpStatusCode.OK&&h.AuditFactories==0&&h.Audit is null&&h.GraphQLServices==0&&h.Business.Factories==2&&h.Business.Disposals==2);
});
foreach(var algorithm in new[]{"RS256","PS256","ES256","HS256"})
{
    using var profile=new JwtProfileFixture(algorithm);using var wrongKey=new JwtProfileFixture(algorithm);await using var h=new Host();
    await h.Start(tls,jwt,jwtProfile:profile);using var client=tls.Client(h.Address);
    await Check("configured "+algorithm+" profile authenticates HTTP and GraphQL",async()=>
    {
        Require((await Post("/document/read",read,profile.Token(),client)).Status==HttpStatusCode.OK);
        var graph=await Post("/graphql",new{query="query { document(input: { tenant: \"A\", resourceId: \"shared\" }) { tenant revision } }"},profile.Token(),client);
        Require(graph.Status==HttpStatusCode.OK&&!graph.Body.Contains("\"errors\"")&&h.KeyProviderCalls==1);
    });
    await Check("configured "+algorithm+" profile rejects unsigned wrong key and unknown kid",async()=>
    {
        var before=h.Business.Factories;
        Require((await Post("/document/read",read,wrongKey.Token(),client)).Status==HttpStatusCode.Unauthorized);
        Require((await Post("/document/read",read,profile.Token(unsigned:true),client)).Status==HttpStatusCode.Unauthorized);
        Require((await Post("/document/read",read,profile.Token(kid:"not-in-profile"),client)).Status==HttpStatusCode.Unauthorized&&h.Business.Factories==before);
    });
}
await Check("disabled security never loads a configured authentication key provider",async()=>
{
    using var profile=new JwtProfileFixture("HS256");await using var h=new Host();await h.Start(tls,jwt,false,false,false,false,true,jwtProfile:profile);
    Require(h.SecurityFactories==0&&h.KeyProviderCalls==0&&h.AuthenticationServices==0);
});
await Check("actual cookie handler maps a live encrypted ticket without JWT or persistent keys",async()=>
{
    await using var h=new Host();await h.Start(tls,jwt,cookieAuthentication:true);using var client=tls.Client(h.Address);
    var cookie=h.FixtureCookie();var result=await Post("/document/read",read,null,client,cookie);
    Require(result.Status==HttpStatusCode.OK&&h.KeyProviderCalls==0&&h.IdentityScheme=="fixture-cookie");
    var graph=await Post("/graphql",new{query="query { document(input: { tenant: \"A\", resourceId: \"shared\" }) { tenant revision } }"},null,client,cookie);
    Require(graph.Status==HttpStatusCode.OK&&!graph.Body.Contains("\"errors\""));
    var before=h.Business.Factories;
    Require((await Post("/document/read",read,null,client,cookie+"!")).Status==HttpStatusCode.Unauthorized);
    Require((await Post("/document/read",read,null,client,h.FixtureCookie(expired:true))).Status==HttpStatusCode.Unauthorized);
    Require((await Post("/document/read",read,alice,client)).Status==HttpStatusCode.Unauthorized&&h.Business.Factories==before);
    Require((await Post("/document/read",new DocumentRequest("B","shared"),null,client,cookie)).Status==HttpStatusCode.Forbidden&&h.Business.Factories==before);
});
var jweProfiles=await JweChecks.Run(tls,jwt,Check);
var keyRingProfiles=await KeyRingChecks.Run(tls,jwt,Check);
var sessionProfiles=await SessionChecks.Run(tls,jwt,Check);
var observationProfiles=await ObservationChecks.Run(tls,jwt,Check);
var auditTrailProfiles=await AuditTrailChecks.Run(tls,jwt,Check);
var preparationProfiles=await AuditPreparationChecks.Run(tls,jwt,Check);
var executionProfiles=await AuditExecutionChecks.Run(tls,jwt,Check);
Directory.CreateDirectory(Path.GetDirectoryName(output)!);
await using(var stream=new FileStream(output,FileMode.CreateNew))await JsonSerializer.SerializeAsync(stream,new{passed,failed,checks,scope="Local ephemeral TLS/JWT fixture; no external IdP or durable audit provider qualification",businessFactories=host.Business.Factories,businessDisposals=host.Business.Disposals,auditEvents=host.Audit!.Count,jweProfiles,keyRingProfiles,sessionProfiles,observationProfiles,auditTrailProfiles,preparationProfiles,executionProfiles});
Console.WriteLine(JsonSerializer.Serialize(new{passed,failed,output}));return failed==0?0:1;
