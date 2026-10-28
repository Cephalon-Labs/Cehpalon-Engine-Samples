using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using SmallApi;

var output=Path.GetFullPath(args.Single(a=>a.StartsWith("--output=",StringComparison.Ordinal))[9..]);
if(File.Exists(output)) throw new IOException("Use a new report path.");
var checks=new List<object>();var passed=0;var failed=0;
void Require(bool ok,string message) {if(!ok) throw new InvalidOperationException(message);}
async Task Check(string name,Func<Task> test)
{
    try {await test();checks.Add(new{name,passed=true});passed++;}
    catch(Exception e) {checks.Add(new{name,passed=false,error=e.ToString()});failed++;}
}
using var tls=new TlsFixture();using var jwt=new JwtFixture();
await Check("invalid configuration fails before host/module factories",async()=>
{
    await using var host=new FixtureHost();
    try {await host.Start(FixtureHost.Config(true,false).Replace("RequestReply","Unsupported"),tls,jwt);throw new Exception("Invalid profile started");}
    catch(ArgumentException) { }
    Require(host.Counters.HostFactories==0 && host.Counters.ForbiddenFactories==0 && host.Application is null,"Invalid config did work");
});
await Check("unsupported worker profile fails before host/module factories",async()=>
{
    await using var host=new FixtureHost();
    try {await host.Start(FixtureHost.Config(true,false,true),tls,jwt);throw new Exception("Worker activated");}
    catch(ArgumentException) { }
    Require(host.Counters.HostFactories==0 && host.Counters.ForbiddenFactories==0,"Unsupported module did work");
});
await Check("all entrypoints disabled creates no WebApplication/listener/services",async()=>
{
    await using var host=new FixtureHost();await host.Start(FixtureHost.Config(false,false),tls,jwt);
    Require(host.Counters.HostFactories==0 && host.Counters.Endpoints==0 && host.Counters.GraphQLServices==0 && host.Counters.ForbiddenFactories==0 && host.Application is null,"Disabled host activated");
});

var profiles=new List<object>();
foreach(var graphql in new[]{false,true})
{
    var name=graphql?"api-graphql":"api-only";
    await using var host=new FixtureHost();var clock=Stopwatch.StartNew();await host.Start(FixtureHost.Config(true,graphql),tls,jwt);clock.Stop();
    using var client=tls.Client(host.Address);
    async Task<(int Status,JsonElement Json)> Send(string operation,object input,string? token=null,bool gql=false,CancellationToken ct=default)
    {
        var (field,selection,mutation)=operation switch
        {
            "get"=>("catalogItem","tenant id label revision amountMinorUnits",false),
            "list"=>("catalogPage","items { tenant id label revision amountMinorUnits }",false),
            "set"=>("setLabel","tenant id label revision amountMinorUnits",true),_=>throw new ArgumentException()
        };
        // Variables are serialized, never inserted into executable query source.
        var type=operation switch{"get"=>"GetItemInput!","list"=>"ListItemsInput!",_=>"SetLabelInput!"};
        using var request=new HttpRequestMessage(HttpMethod.Post,gql?"/graphql":"/api/catalog/"+operation);
        request.Content=JsonContent.Create(gql?(object)new{query=$"{(mutation?"mutation":"query")}($input: {type}) {{ {field}(input: $input) {{ {selection} }} }}",variables=new{input}}:input);
        if(token is not null) request.Headers.Authorization=new("Bearer",token);
        request.Headers.Add("X-Tenant","tenant-b");request.Headers.Add("X-Role","admin");request.Headers.Add("X-Subject","bob");
        using var response=await client.SendAsync(request,ct);
        var body=await response.Content.ReadAsStringAsync(ct);
        return ((int)response.StatusCode,string.IsNullOrWhiteSpace(body)?JsonSerializer.SerializeToElement(new{}):JsonDocument.Parse(body).RootElement.Clone());
    }
    string? Code((int Status,JsonElement Json) response,bool gql)
    {
        if(gql && response.Json.TryGetProperty("errors",out var errors)) return errors[0].GetProperty("extensions").GetProperty("code").GetString();
        return response.Json.TryGetProperty("code",out var code)?code.GetString():null;
    }
    JsonElement Value((int Status,JsonElement Json) response,string op,bool gql) => gql?response.Json.GetProperty("data").GetProperty(op switch{"get"=>"catalogItem","list"=>"catalogPage",_=>"setLabel"}):response.Json;
    await Check(name+": strict custom CA trust and hostname",async()=>{using var response=await client.GetAsync("/health");Require(response.IsSuccessStatusCode,"TLS health failed");});
    await Check(name+": wrong TLS hostname rejected",async()=>
    {
        using var bad=tls.Client(host.Address,"wrong-host.invalid");
        try {using var response=await bad.GetAsync("/health");throw new Exception("Wrong hostname accepted");}catch(HttpRequestException) { }
    });
    await Check(name+": untrusted TLS fixture CA rejected",async()=>
    {
        using var untrusted=new HttpClient(new SocketsHttpHandler{UseProxy=false});
        try {using var response=await untrusted.GetAsync(new Uri(host.Address,"/health"));throw new Exception("Untrusted CA accepted");}catch(HttpRequestException) { }
    });
    foreach(var gql in graphql?new[]{false,true}:new[]{false})
    {
        var wire=name+(gql?"/graphql":"/http");
        await Check(wire+": anonymous/bad JWT denies before business",async()=>
        {
            using var other=new JwtFixture();var before=host.Store.Work;
            foreach(var token in new string?[]{null,other.Token(),jwt.Token(issuer:"urn:wrong"),jwt.Token(audience:"wrong"),jwt.Token(expired:true),jwt.Token(duplicateSubject:true),jwt.Token(type:"JWT"),jwt.Token(subject:" "),jwt.Token(subject:"bad\nsubject")})
                Require((await Send("get",new GetItem("tenant-a",1),token,gql)).Status==401,"Bad token accepted");
            Require(host.Store.Work==before,"Unauthenticated business work");
        });
        await Check(wire+": same ID A/B remains isolated despite metadata",async()=>
        {
            var a=Value(await Send("get",new GetItem("tenant-a",1),jwt.Token(),gql),"get",gql);
            var b=Value(await Send("get",new GetItem("tenant-b",1),jwt.Token("bob"),gql),"get",gql);
            Require(a.GetProperty("tenant").GetString()=="tenant-a" && b.GetProperty("tenant").GetString()=="tenant-b","Tenant crossed");
        });
        await Check(wire+": both cross-tenant directions deny with zero business",async()=>
        {
            var before=host.Store.Work;
            foreach(var (subject,tenant) in new[]{("alice","tenant-b"),("bob","tenant-a")})
            {
                var response=await Send("get",new GetItem(tenant,1),jwt.Token(subject),gql);
                Require(Code(response,gql)=="access.denied" && response.Status==(gql?200:403),"Cross tenant did not deny safely");
            }
            Require(host.Store.Work==before,"Cross-tenant business work");
        });
        await Check(wire+": revocation/owner mismatch/default policy deny",async()=>
        {
            foreach(var variant in new[]{"revoked","owner","policy"})
            {
                var before=host.Store.Work;host.Store.Revoked=variant=="revoked";host.Store.WrongOwner=variant=="owner";host.Store.MissingPolicy=variant=="policy";
                try {Require(Code(await Send("get",new GetItem("tenant-a",1),jwt.Token(),gql),gql)=="access.denied","Authority mismatch accepted");Require(host.Store.Work==before,"Denied authority reached business");}
                finally {host.Store.Revoked=false;host.Store.WrongOwner=false;host.Store.MissingPolicy=false;}
            }
            Require(Code(await Send("get",new GetItem("tenant-a",1),jwt.Token(),gql),gql) is null,"Grant did not recover on fresh resolution");
        });
        await Check(wire+": validation precedes business mutation",async()=>
        {
            var before=host.Store.Work;
            Require(Code(await Send("get",new GetItem("tenant-a",0),jwt.Token(),gql),gql)=="validation.failed","Bad ID accepted");
            Require(Code(await Send("list",new ListItems("tenant-a",500),jwt.Token(),gql),gql)=="validation.failed","Bad page accepted");
            Require(Code(await Send("set",new SetLabel("tenant-a",1,0,new string('x',65)),jwt.Token(),gql),gql)=="validation.failed","Bad label accepted");
            Require(host.Store.Work==before,"Invalid input reached business");
        });
        await Check(wire+": not-found/list/update/conflict semantics",async()=>
        {
            Require(Code(await Send("get",new GetItem("tenant-a",10001),jwt.Token(),gql),gql)=="resource.not_found","Notfound changed");
            var page=Value(await Send("list",new ListItems("tenant-a",499),jwt.Token(),gql),"list",gql).GetProperty("items");
            Require(page.GetArrayLength()==20 && page[0].GetProperty("id").GetInt32()==9981,"Pagination differs");
            var current=Value(await Send("get",new GetItem("tenant-a",2),jwt.Token(),gql),"get",gql).GetProperty("revision").GetInt32();
            var updated=Value(await Send("set",new SetLabel("tenant-a",2,current,"fixture-label"),jwt.Token(),gql),"set",gql);
            Require(updated.GetProperty("revision").GetInt32()==current+1,"Update revision changed");
            Require(Code(await Send("set",new SetLabel("tenant-a",2,current,"stale"),jwt.Token(),gql),gql)=="resource.conflict","Conflict changed");
            var other=Value(await Send("get",new GetItem("tenant-b",2),jwt.Token("bob"),gql),"get",gql);
            Require(other.GetProperty("revision").GetInt32()==0 && host.Store.Count==20000,"Write crossed tenant or grew data");
        });
        await Check(wire+": abort observed and no delayed mutation",async()=>
        {
            host.Store.DelayWrites=true;host.Store.WriteEntered=CatalogStore.NewSignal();host.Store.CancelObserved=CatalogStore.NewSignal();var before=host.Store.Writes;
            try
            {
                using var cancel=new CancellationTokenSource();var pending=Send("set",new SetLabel("tenant-a",3,0,"cancelled"),jwt.Token(),gql,cancel.Token);
                await host.Store.WriteEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));cancel.Cancel();
                try {await pending;throw new Exception("Cancelled request completed");}catch(OperationCanceledException) { }
                await host.Store.CancelObserved.Task.WaitAsync(TimeSpan.FromSeconds(2));
                Require(host.Store.Writes==before,"Cancelled write mutated");
            }
            finally {host.Store.DelayWrites=false;}
        });
        await Check(wire+": malformed/oversized body does no business",async()=>
        {
            var before=host.Store.Work;
            foreach(var text in new[]{"{",new string(' ',16*1024+1)})
            {
                using var req=new HttpRequestMessage(HttpMethod.Post,gql?"/graphql":"/api/catalog/get"){Content=new StringContent(text,Encoding.UTF8,"application/json")};req.Headers.Authorization=new("Bearer",jwt.Token());
                using var response=await client.SendAsync(req);Require((int)response.StatusCode>=400,"Invalid body accepted");
            }
            Require(host.Store.Work==before,"Bad body reached business");
        });
    }
    await Check(name+": disabled endpoints/schema/IDE/WS remain absent",async()=>
    {
        foreach(var path in graphql?new[]{"/graphql?query={__typename}","/graphql?sdl","/graphql/schema.graphql","/graphql/ui"}:new[]{"/graphql","/graphql?query={__typename}"})
        {using var req=new HttpRequestMessage(HttpMethod.Get,path);req.Headers.Authorization=new("Bearer",jwt.Token());using var res=await client.SendAsync(req);Require(!res.IsSuccessStatusCode,"Unexpected exposure: "+path);}
        if(!graphql) Require(host.Counters.GraphQLFactories==0 && host.Counters.GraphQLServices==0,"Disabled GraphQL registered services");
        Require(host.Counters.ForbiddenFactories==0,"Disabled provider module activated");
    });
    if(!graphql) await Check(name+": 10000 requests keep disabled modules at zero",async()=>
    {
        var token=jwt.Token();
        await Parallel.ForEachAsync(Enumerable.Range(1,10000),new ParallelOptions{MaxDegreeOfParallelism=16},async(id,ct)=>
        {
            var response=await Send("get",new GetItem("tenant-a",id),token,false,ct);
            Require(response.Status==200 && response.Json.GetProperty("id").GetInt32()==id,"Activation corpus result differs");
        });
        Require(host.Counters.GraphQLFactories==0 && host.Counters.GraphQLServices==0 && host.Counters.ForbiddenFactories==0,"Disabled module activated during requests");
    });
    if(graphql) await Check(name+": introspection disabled",async()=>
    {
        using var req=new HttpRequestMessage(HttpMethod.Post,"/graphql"){Content=JsonContent.Create(new{query="{ __schema { types { name } } }"})};req.Headers.Authorization=new("Bearer",jwt.Token());
        using var response=await client.SendAsync(req);var body=await response.Content.ReadAsStringAsync();Require(body.Contains("errors",StringComparison.Ordinal) && !body.Contains("\"types\"",StringComparison.Ordinal),"Schema exposed");
    });
    await Check(name+": shutdown owns handlers and closes listener",async()=>
    {
        var address=host.Address;await host.DisposeAsync();
        Require(host.Store.Factories==host.Store.Disposals && host.Counters.ForbiddenFactories==0,"Resources leaked");
        using var socket=new Socket(SocketType.Stream,ProtocolType.Tcp);
        try {await socket.ConnectAsync(IPAddress.Loopback,address.Port);throw new Exception("Listener remains open");}catch(SocketException) { }
    });
    profiles.Add(new{name,startupMilliseconds=clock.Elapsed.TotalMilliseconds,counters=host.Counters,store=new{host.Store.Count,host.Store.Factories,host.Store.Reads,host.Store.Writes,host.Store.Disposals}});
}
await Check("GraphQL-only keeps API entrypoint disabled",async()=>
{
    await using var host=new FixtureHost();await host.Start(FixtureHost.Config(false,true),tls,jwt);
    using var client=tls.Client(host.Address);
    using var request=new HttpRequestMessage(HttpMethod.Post,"/api/catalog/get"){Content=JsonContent.Create(new GetItem("tenant-a",1))};request.Headers.Authorization=new("Bearer",jwt.Token());
    using var response=await client.SendAsync(request);Require(response.StatusCode==HttpStatusCode.NotFound && host.Counters.ApiFactories==0 && host.Store.Factories==0,"Disabled API did work");
    using var gql=new HttpRequestMessage(HttpMethod.Post,"/graphql"){Content=JsonContent.Create(new{query="{catalogItem(input:{tenant:\"tenant-a\",id:1}){id tenant}}"})};gql.Headers.Authorization=new("Bearer",jwt.Token());
    using var result=await client.SendAsync(gql);var body=await result.Content.ReadAsStringAsync();Require(result.IsSuccessStatusCode && !body.Contains("errors",StringComparison.Ordinal),"GraphQL-only failed");
    Require(host.Counters.ApiFactories==0 && host.Counters.ForbiddenFactories==0,"GraphQL implicitly activated API");
});
Directory.CreateDirectory(Path.GetDirectoryName(output)!);
await using(var file=new FileStream(output,FileMode.CreateNew,FileAccess.Write)) await JsonSerializer.SerializeAsync(file,new{observedAtUtc=DateTimeOffset.UtcNow,framework=RuntimeInformation.FrameworkDescription,os=RuntimeInformation.OSDescription,
    scope="Protected localhost HTTPS fixture, pinned JWT validation, generated Core gateway, tenant dispatcher, synthetic in-memory data. Not W0 public benchmark, real IdP/provider, supported-Windows, production, or full performance gate.",passed,failed,checks,profiles},new JsonSerializerOptions{WriteIndented=true,IncludeFields=true});
Console.WriteLine($"Small API protected consumer: {passed}/{passed+failed}");return failed==0?0:1;
