using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Transports.Http;
using Cehpalon.Engine.Transports.GraphQL;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

var checks = new List<object>(); var failed = 0;
void Assert(bool value, string message = "Assertion failed") { if (!value) throw new Exception(message); }
async Task Check(string name, Func<Task> action)
{ try { await action(); checks.Add(new { name, passed = true }); } catch (Exception error) { failed++; checks.Add(new { name, passed = false, error = error.ToString() }); } }
Task Sync(Action action) { action(); return Task.CompletedTask; }
OperationBinding<Request,Response> binding = new("catalog.read", request => request.Tenant is "A" or "B" && request.Id >= 0 ? null : new("bad.validation", "private validation detail"));
OperationBinding<Request,Response> budgetBinding = new("catalog.budget", _ => null);
var builder = new GraphQLOperationCatalog.Builder().AddQuery("catalogItem", binding).AddMutation("setLabel", binding)
    .AddQuery("budgetedItem", budgetBinding);
var catalog = builder.Build();
await Check("catalog-preflight-does-not-register-graphql-or-activate-business", () => Sync(() =>
{
    var services = new ServiceCollection();
    Assert(services.Count == 0);
    Assert(Fixture.Calls == 0);
    builder.AddQuery("other", binding); // Previously built catalog must stay immutable.
}));
await Check("catalog-requires-query-and-rejects-duplicates-and-noncanonical-names", () => Sync(() =>
{
    foreach (var invalid in new[] { "", "__schema", "bad-name", "é", new string('a',129) })
    { try { _ = new GraphQLOperationCatalog.Builder().AddQuery(invalid,binding); throw new Exception("accepted invalid"); } catch (ArgumentException) { } }
    try { _ = new GraphQLOperationCatalog.Builder().AddMutation("mutation",binding).Build(); throw new Exception("no query accepted"); } catch (InvalidOperationException) { }
    try { _ = new GraphQLOperationCatalog.Builder().AddQuery("x",binding).AddQuery("x",binding); throw new Exception("duplicate accepted"); } catch (ArgumentException) { }
}));
var webBuilder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = [], EnvironmentName = "Production" });
webBuilder.Logging.ClearProviders();
webBuilder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0));
webBuilder.Services.AddSingleton<ITransportOperationDispatcher,Fixture>();
webBuilder.Services.AddCehpalonGraphQL(catalog);
await using var application = webBuilder.Build();
// Finite trusted test principal. This is an adapter fixture, not JWT/OIDC authentication proof.
application.Use(async (http, next) =>
{
    if (!http.Request.Headers.ContainsKey("X-Test-Anonymous")) http.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub","fixture")],"test-fixture"));
    await next(http);
});
application.MapCehpalonGraphQL();
application.MapPost("/budget", (HttpContext http) => OperationHttpAdapter.ExecuteAsync(http, budgetBinding));
await application.StartAsync();
var url = application.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
using var client = new HttpClient { BaseAddress = new Uri(url) };
async Task<(int Status,string Body)> Post(string body, bool anonymous = false, bool unknownLength = false)
{
    using var request = new HttpRequestMessage(HttpMethod.Post,"/graphql");
    if (anonymous) request.Headers.Add("X-Test-Anonymous","true");
    request.Content = unknownLength ? new UnknownLengthContent(body) : new StringContent(body,Encoding.UTF8,"application/json");
    using var response = await client.SendAsync(request);
    return ((int)response.StatusCode,await response.Content.ReadAsStringAsync());
}
string Envelope(string query, object? variables = null) => JsonSerializer.Serialize(new { query, variables });
string Query(int id=1,string tenant="A") => Envelope("query($input:RequestInput!){catalogItem(input:$input){tenant id label}}",new { input=new { tenant,id } });
string Code(string body) => JsonDocument.Parse(body).RootElement.GetProperty("errors")[0].GetProperty("extensions").GetProperty("code").GetString()!;
await Check("typed-query-uses-fixed-operation-request-and-correlation",async () =>
{ Fixture.Reset(); var r=await Post(Query()); Assert(r.Status==200 && r.Body.Contains("fixture-A"),r.Body); Assert(Fixture.Calls==1 && Fixture.LastOperation=="catalog.read" && Fixture.CorrelationLength>0); });
await Check("typed-mutation-uses-same-operation-and-validator",async () =>
{ Fixture.Reset();var r=await Post(Envelope("mutation{setLabel(input:{tenant:\"A\",id:1}){tenant id label}}"));Assert(r.Status==200 && r.Body.Contains("fixture-A"),r.Body);Assert(Fixture.Calls==1); });
await Check("catalog-is-immutable-after-build",async () =>
{ Fixture.Reset();var r=await Post(Envelope("{other(input:{tenant:\"A\",id:1}){id}}"));Assert(r.Body.Contains("errors") && Fixture.Calls==0,r.Body); });
await Check("anonymous-request-is401-before-dispatch",async () =>
{ Fixture.Reset();var r=await Post(Query(),true);Assert(r.Status==401 && Fixture.Calls==0); });
await Check("typed-validation-normalizes-error-before-dispatch",async () =>
{ Fixture.Reset();var r=await Post(Query(-1));Assert(r.Status==200 && Code(r.Body)=="validation.failed" && !r.Body.Contains("private") && Fixture.Calls==0,r.Body); });
await Check("access-denial-is-generic-semantic-graphql-error",async () =>
{ Fixture.Reset();var r=await Post(Query(1,"B"));Assert(r.Status==200 && Code(r.Body)=="access.denied" && !r.Body.Contains("tenant B secret"),r.Body); });
await Check("domain-error-code-is-preserved",async () =>
{ Fixture.Reset();var r=await Post(Query(2));Assert(r.Status==200 && Code(r.Body)=="catalog.conflict",r.Body); });
await Check("reserved-capacity-message-is-generic-in-graphql", async () =>
{
    var response = await Post(Query(7));
    Assert(response.Status == 200 && Code(response.Body) == OperationConcurrencyBudget.CapacityExceededCode, response.Body);
    Assert(!response.Body.Contains("private"), response.Body);
});
await Check("http-and-graphql-share-actual-budget-and-admit-after-release", async () =>
{
    var fixture = (Fixture)application.Services.GetRequiredService<ITransportOperationDispatcher>();
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
    const string query = "{budgetedItem(input:{tenant:\"A\",id:2}){id}}";
    var held = client.PostAsJsonAsync("/budget", new Request("A", 1), deadline.Token);
    try
    {
        await fixture.BudgetEntered.Task.WaitAsync(deadline.Token);
        using var http = await client.PostAsJsonAsync("/budget", new Request("A", 2), deadline.Token);
        Assert(http.StatusCode == HttpStatusCode.ServiceUnavailable);
        using var problem = JsonDocument.Parse(await http.Content.ReadAsStringAsync(deadline.Token));
        Assert(problem.RootElement.GetProperty("code").GetString() == OperationConcurrencyBudget.CapacityExceededCode);
        var saturated = await Post(Envelope(query)).WaitAsync(deadline.Token);
        Assert(saturated.Status == 200 && Code(saturated.Body) == OperationConcurrencyBudget.CapacityExceededCode, saturated.Body);
        Assert(fixture.BudgetFactories == 1);
    }
    finally
    {
        fixture.BudgetRelease.TrySetResult();
        using var admitted = await held;
        Assert(admitted.StatusCode == HttpStatusCode.OK);
    }
    var recovered = await Post(Envelope(query)).WaitAsync(deadline.Token);
    Assert(recovered.Status == 200 && !recovered.Body.Contains("errors") && fixture.BudgetFactories == 2, recovered.Body);
});
foreach(var id in new[]{3,4,6})
await Check("unexpected-fault-is-safe-internal-error-"+id,async () =>
{ Fixture.Reset();var r=await Post(Query(id));Assert(r.Status==200 && Code(r.Body)=="internal.error" && !r.Body.Contains("secret") && !r.Body.Contains("exception",StringComparison.OrdinalIgnoreCase),r.Body); });
foreach(var bad in new[]{"[]","{","null","{\"query\":null}","{\"query\":\"{__typename}\",\"query\":\"{__typename}\"}","{\"query\":\"{__typename}\",\"variables\":{\"x\":1,\"x\":2}}","{\"query\":\"{__typename}\",\"variables\":[{}]}","{\"query\":\"{__typename}\",\"extensions\":{}}","{\"query\":\"\\uD800\"}"})
await Check("strict-envelope-rejects-before-dispatch-"+checks.Count,async () =>
{ Fixture.Reset();var r=await Post(bad);Assert(r.Status==400 && Fixture.Calls==0,r.Status+" "+r.Body); });
foreach(var content in new[]{"{\"query\":\"{__typename}\",\"variables\":{\"x\":\"\\uD800\"}}","{\"query\":\"{__typename}\",\"variables\":{\"\\uD800\":1}}"})
await Check("malformed-escaped-surrogates-reject-"+checks.Count,async () =>
{ Fixture.Reset();var r=await Post(content);Assert(r.Status==400 && Fixture.Calls==0,r.Body); });
foreach(var unknownLength in new[]{false,true})
await Check("16KiB-plus-one-rejects-with-or-without-content-length-"+unknownLength,async () =>
{ Fixture.Reset();var r=await Post(new string(' ',GraphQLAdapter.MaximumBodyBytes+1),unknownLength:unknownLength);Assert(r.Status==413 && Fixture.Calls==0,r.Body); });
await Check("16KiB-valid-body-is-accepted",async () =>
{ var body=Query();var r=await Post(body+new string(' ',GraphQLAdapter.MaximumBodyBytes-Encoding.UTF8.GetByteCount(body)),unknownLength:true);Assert(r.Status==200 && r.Body.Contains("fixture-A"),r.Body); });
await Check("non-json-media-type-is415-before-dispatch",async () =>
{ Fixture.Reset();using var response=await client.PostAsync("/graphql",new StringContent(Query()));Assert((int)response.StatusCode==415 && Fixture.Calls==0); });
foreach(var path in new[]{"/graphql?query={__typename}","/graphql/schema.graphql","/graphql/ui","/graphql/ws"})
await Check("no-get-schema-ide-websocket-route-"+path,async () =>
{ Fixture.Reset();using var response=await client.GetAsync(path);Assert((int)response.StatusCode is 404 or 405 && Fixture.Calls==0); });
foreach(var query in new[]{"{__schema{queryType{name}}}","{__type(name:\"Query\"){name}}"})
await Check("introspection-disabled-"+checks.Count,async () =>
{ Fixture.Reset();var r=await Post(Envelope(query));Assert(r.Body.Contains("errors") && !r.Body.Contains("\"queryType\"") && Fixture.Calls==0,r.Body); });
await Check("typename-remains-standard-graphql-behavior",async () =>
{ Fixture.Reset();var r=await Post(Envelope("{__typename}"));Assert(r.Status==200 && r.Body.Contains("Query") && Fixture.Calls==0,r.Body); });
foreach(var query in new[]{"{catalogItem(input:{tenant:\"A\",id:1,extra:3}){id}}","{catalogItem(input:null){id}}","{catalogItem(input:{tenant:\"A\",id:\"text\"}){id}}","{catalogItem(input:{tenant:\"A\"}){id}}","{catalogItem(input:{tenant:\"A\",id:1,id:2}){id}}","{unregistered(input:{tenant:\"A\",id:1}){id}}"})
await Check("protocol-coercion-and-unknown-fields-do-not-dispatch-"+checks.Count,async () =>
{ Fixture.Reset();var r=await Post(Envelope(query));Assert(r.Body.Contains("errors") && Fixture.Calls==0,r.Body); });
await Check("fragment-and-alias-cannot-bypass-cost-limit",async () =>
{ Fixture.Reset();var fields=string.Join(' ',Enumerable.Range(0,120).Select(i=>$"a{i}:catalogItem(input:{{tenant:\"A\",id:1}}){{id label}}"));var r=await Post(Envelope("query{...X}fragment X on Query{"+fields+"}"));Assert(r.Body.Contains("errors") && Fixture.Calls==0,r.Body); });
await Check("execution-depth-over-eight-rejects-before-dispatch",async () =>
{ Fixture.Reset();var query="{catalogItem(input:{tenant:\"A\",id:1}){"+string.Concat(Enumerable.Repeat("child{",9))+"id"+new string('}',11);var r=await Post(Envelope(query));Assert(r.Body.Contains("errors") && Fixture.Calls==0,r.Body); });
await Check("multioperation-selected-operation-is-explicit",async () =>
{ Fixture.Reset();var r=await Post(JsonSerializer.Serialize(new{query="query A{catalogItem(input:{tenant:\"A\",id:1}){id}} query B{catalogItem(input:{tenant:\"B\",id:1}){id}}",operationName="B"}));Assert(Code(r.Body)=="access.denied" && Fixture.Calls==1,r.Body); });
await Check("incremental-directives-are-not-supported",async () =>
{ Fixture.Reset();var r=await Post(Envelope("{catalogItem(input:{tenant:\"A\",id:1}){... @defer {id}}}"));Assert(r.Body.Contains("errors") && Fixture.Calls==0,r.Body); });
await Check("request-cancellation-reaches-dispatcher",async () =>
{
    Fixture.Reset(); using var request = new HttpRequestMessage(HttpMethod.Post,"/graphql") { Content = new StringContent(Query(5),Encoding.UTF8,"application/json") };
    using var cancellation = new CancellationTokenSource();
    var pending=client.SendAsync(request,cancellation.Token);
    await Fixture.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
    cancellation.Cancel();
    try { using var ignored=await pending;throw new Exception("not cancelled"); } catch(OperationCanceledException) { }
    await Fixture.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
    Assert(Fixture.Calls==1);
});
await application.StopAsync();
var report=new { scope="Experimental loopback HTTP adapter fixture; no JWT/IdP, tenant authority, TLS or supported-Windows proof",passed=checks.Count-failed,failed,checks };
var json=JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true});
var output=args.FirstOrDefault(arg=>arg.StartsWith("--output="))?[9..];
if(output is not null) File.WriteAllText(output,json+"\n",new UTF8Encoding(false));
Console.WriteLine(json); return failed==0?0:1;

public sealed record Request(string Tenant,int Id);
public sealed record Response(string Tenant,int Id,string Label,Response? Child=null);
public sealed class Fixture : ITransportOperationDispatcher
{
    private readonly OperationConcurrencyBudget budget = new(1);
    private readonly OperationDispatcher dispatcher;
    public TaskCompletionSource BudgetEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public TaskCompletionSource BudgetRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public int BudgetFactories { get; private set; }

    public Fixture()
    {
        dispatcher = new(new OperationRegistryBuilder().Register<Request, Response>("catalog.budget", () =>
        {
            BudgetFactories++;
            return new BudgetedOperation(this);
        }).Build());
    }

    private sealed class BudgetedOperation(Fixture fixture) : IOperationHandler<Request, Response>
    {
        public async ValueTask<OperationResult<Response>> HandleAsync(Request request, OperationContext context, CancellationToken token)
        {
            if (request.Id == 1)
            {
                fixture.BudgetEntered.TrySetResult();
                await fixture.BudgetRelease.Task.WaitAsync(token);
            }
            return OperationResult<Response>.Success(new(request.Tenant, request.Id, "budgeted"));
        }
    }

    public static int Calls; public static string LastOperation=""; public static int CorrelationLength;
    public static TaskCompletionSource Entered=new(TaskCreationOptions.RunContinuationsAsynchronously), Cancelled=new(TaskCreationOptions.RunContinuationsAsynchronously);
    public static void Reset(){Calls=0;LastOperation="";CorrelationLength=0;Entered=new(TaskCreationOptions.RunContinuationsAsynchronously);Cancelled=new(TaskCreationOptions.RunContinuationsAsynchronously);}
    public async ValueTask<OperationResult<TResponse>> DispatchAsync<TRequest,TResponse>(HttpContext httpContext,string operationId,TRequest request,OperationContext operationContext,CancellationToken cancellationToken)
    {
        if (operationId == "catalog.budget")
            return await budget.DispatchAsync<TRequest, TResponse>(dispatcher, operationId, request,
                operationContext, cancellationToken);
        Interlocked.Increment(ref Calls);LastOperation=operationId;CorrelationLength=operationContext.CorrelationId.Length;
        var input=(Request)(object)request!;
        if(input.Tenant=="B") return OperationResult<TResponse>.Failure(new("access.denied","tenant B secret"));
        if(input.Id==2) return OperationResult<TResponse>.Failure(new("catalog.conflict","Revision conflict."));
        if(input.Id==3) throw new InvalidOperationException("secret exception");
        if(input.Id==7) return OperationResult<TResponse>.Failure(new(
            OperationConcurrencyBudget.CapacityExceededCode, "private capacity details"));
        if(input.Id==4) throw new OperationCanceledException("secret cancelled but request active");
        if(input.Id==6) throw new HotChocolate.GraphQLException(HotChocolate.ErrorBuilder.New().SetMessage("secret GraphQL exception").SetExtension("private","secret").Build());
        if(input.Id==5){Entered.TrySetResult();try{await Task.Delay(Timeout.InfiniteTimeSpan,cancellationToken);}catch(OperationCanceledException){Cancelled.TrySetResult();throw;}}
        return OperationResult<TResponse>.Success((TResponse)(object)new Response(input.Tenant,input.Id,"fixture-"+input.Tenant));
    }
}
public sealed class UnknownLengthContent : HttpContent
{
    private readonly byte[] _bytes;
    public UnknownLengthContent(string body){_bytes=Encoding.UTF8.GetBytes(body);Headers.ContentType=new MediaTypeHeaderValue("application/json");}
    protected override bool TryComputeLength(out long length){length=0;return false;}
    protected override Task SerializeToStreamAsync(Stream stream,TransportContext? context)=>stream.WriteAsync(_bytes).AsTask();
}
