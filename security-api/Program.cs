using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using SecurityApi;
using Host=SecurityApi.Host;

var output=Path.GetFullPath(args.Single(a=>a.StartsWith("--output=",StringComparison.Ordinal))[9..]);
if(File.Exists(output))throw new IOException("Retain previous output.");
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
async Task<(HttpStatusCode Status,string Body)> Post(string path,object body,string? token)
{
    using var request=new HttpRequestMessage(HttpMethod.Post,path){Content=JsonContent.Create(body)};
    if(token is not null)request.Headers.Authorization=new("Bearer",token);
    using var response=await http.SendAsync(request);return(response.StatusCode,await response.Content.ReadAsStringAsync());
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
Directory.CreateDirectory(Path.GetDirectoryName(output)!);
await using(var stream=new FileStream(output,FileMode.CreateNew))await JsonSerializer.SerializeAsync(stream,new{passed,failed,checks,scope="Local ephemeral TLS/JWT fixture; no external IdP or durable audit provider qualification",businessFactories=host.Business.Factories,businessDisposals=host.Business.Disposals,auditEvents=host.Audit!.Count});
Console.WriteLine(JsonSerializer.Serialize(new{passed,failed,output}));return failed==0?0:1;
