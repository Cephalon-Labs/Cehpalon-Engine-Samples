using System.Diagnostics;
using Cehpalon.Engine.Core;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;


namespace PortableConsumers.Generated;

public static class SelfTest
{
public static async Task<int> RunLiveMetrics(string output)
{
    output = Path.GetFullPath(output);
    if (File.Exists(output)) throw new IOException("Use a new report path.");
    var cases = new List<Dictionary<string, object?>>();
    object? disabled = null;
    var passed = true;
    try
    {
        using var tls = new TlsFixture();
        using var jwt = new JwtFixture();
        string Config(string file) => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, file), Encoding.UTF8);
        foreach (var tenantLimited in new[] { false, true })
        {
            var samples = new List<object>();
            var result = new Dictionary<string, object?>
            {
                ["tenantLimited"] = tenantLimited, ["status"] = "started", ["collections"] = samples
            };
            cases.Add(result);
            await using var host = new FixtureHost();
            await host.Start(Config("appsettings.graphql.json"), tls, jwt, 8, tenantLimited ? 4 : null);
            using var client = tls.Client(host.Address);
            client.Timeout = Timeout.InfiniteTimeSpan;
            var aliceToken = jwt.Token();
            var bobToken = jwt.Token("bob");
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
            using var samplerStop = new CancellationTokenSource();
            var collectionGate = new object();
            var values = new Dictionary<string, int>(5, StringComparer.Ordinal);
            var lastClosed = 0;
            var callbacks = 0;
            var invalid = 0;
            var midpoint = CatalogStore.NewSignal();
            var midpointRelease = CatalogStore.NewSignal();
            var midpointObserved = CatalogStore.NewSignal();
            var overlapObserved = CatalogStore.NewSignal();
            var halfDrivers = 0;
            var store = host.Store;
            var release = CatalogStore.NewSignal();
            store.WriteRelease = release;
            store.DelayWrites = true;
            var meterName = tenantLimited ? "Cehpalon.SmallApi.TenantBudgetProof" : "Cehpalon.SmallApi.CoreBudgetProof";
            using var listener = new System.Diagnostics.Metrics.MeterListener();
            var names = new HashSet<string>(StringComparer.Ordinal);
            listener.InstrumentPublished = (instrument, observer) =>
            {
                if (instrument.Meter.Name != meterName) return;
                if (!names.Add(instrument.Name)) throw new InvalidOperationException("Duplicate instrument.");
                observer.EnableMeasurementEvents(instrument);
            };
            listener.SetMeasurementEventCallback<int>((instrument, value, tags, _) =>
            {
                var valid = instrument.Name switch
                {
                    "cehpalon.operation_budget.active" => value is >= 0 and <= 8,
                    "cehpalon.operation_budget.capacity" => value == 8,
                    "cehpalon.operation_budget.closed" => value is 0 or 1,
                    "cehpalon.operation_budget.active_tenants" => tenantLimited && value is >= 0 and <= 2,
                    "cehpalon.operation_budget.tenant_capacity" => tenantLimited && value == 4,
                    _ => false
                };
                if (!valid || !tags.IsEmpty || !values.TryAdd(instrument.Name, value)) invalid++;
                callbacks++;
            });
            listener.Start();
            using var meter = host.CreateBudgetMetrics(meterName)
                ?? throw new InvalidOperationException("Configured budget has no meter.");
            var expectedCallbacks = tenantLimited ? 5 : 3;
            if (names.Count != expectedCallbacks || callbacks != 0 || store.Work != 0)
                throw new InvalidOperationException("Meter registration performed unexpected work.");

            Dictionary<string, int> Collect(string phase)
            {
                lock (collectionGate)
                {
                    values.Clear();
                    callbacks = 0;
                    var allocated = GC.GetAllocatedBytesForCurrentThread();
                    var started = Stopwatch.GetTimestamp();
                    listener.RecordObservableInstruments();
                    var elapsed = Stopwatch.GetTimestamp() - started;
                    var bytes = GC.GetAllocatedBytesForCurrentThread() - allocated;
                    var observed = new Dictionary<string, int>(values, StringComparer.Ordinal);
                    var reads = Volatile.Read(ref store.Reads);
                    samples.Add(new { index = samples.Count, phase, startedTicks = started, elapsedTicks = elapsed,
                        allocatedBytes = bytes, callbacks, values = observed, businessReads = reads });
                    if (invalid != 0 || callbacks != expectedCallbacks || observed["cehpalon.operation_budget.closed"] < lastClosed)
                        throw new InvalidOperationException("Metric bounds, tags or closure ordering differed.");
                    lastClosed = observed["cehpalon.operation_budget.closed"];
                    if (phase == "periodic" && reads == 200) midpointObserved.TrySetResult();
                    if (phase == "periodic" && observed["cehpalon.operation_budget.active"] == 5)
                        overlapObserved.TrySetResult();
                    return observed;
                }
            }

            void Controlled(string phase, int active, int closed, int activeTenants)
            {
                var observed = Collect(phase);
                if (observed["cehpalon.operation_budget.active"] != active
                    || observed["cehpalon.operation_budget.closed"] != closed
                    || tenantLimited && observed["cehpalon.operation_budget.active_tenants"] != activeTenants)
                    throw new InvalidOperationException("Controlled metric state differed.");
            }

            async Task<(int Status, string? Code)> Post(string path, object input, string subject, bool graphQL)
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(input) };
                request.Headers.Authorization = new("Bearer", subject == "alice" ? aliceToken : bobToken);
                request.Headers.Add("X-Tenant", subject == "alice" ? "tenant-b" : "tenant-a");
                using var response = await client.SendAsync(request, deadline.Token);
                using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(deadline.Token));
                var root = body.RootElement;
                string? code = graphQL
                    ? root.TryGetProperty("errors", out var errors) ? errors[0].GetProperty("extensions").GetProperty("code").GetString() : null
                    : root.TryGetProperty("code", out var errorCode) ? errorCode.GetString() : null;
                if (response.StatusCode == HttpStatusCode.OK && code is null)
                {
                    var value = graphQL ? root.GetProperty("data").GetProperty("catalogItem") : root;
                    if (value.GetProperty("id").GetInt32() != 1
                        || value.GetProperty("tenant").GetString() != (subject == "alice" ? "tenant-a" : "tenant-b"))
                        throw new InvalidOperationException("Successful response had the wrong tenant or item.");
                }
                return ((int)response.StatusCode, code);
            }

            Task<(int Status, string? Code)> Read(string subject, string tenant, bool graphQL)
            {
                var input = new GetItem(tenant, 1);
                return graphQL
                    ? Post("/graphql", new { query = "query($input:GetItemInput!){catalogItem(input:$input){id tenant}}", variables = new { input } }, subject, true)
                    : Post("/api/catalog/get", input, subject, false);
            }

            Controlled("ready", 0, 0, 0);
            var held = Post("/api/catalog/set", new SetLabel("tenant-a", 1, 0, "metrics-shutdown"), "alice", false);
            Task? sampler = null;
            Task[] drivers = [];
            Task<(int Status, string? Code)>[] overlap = [];
            try
            {
                await store.WriteEntered.Task.WaitAsync(deadline.Token);
                Controlled("held", 1, 0, 1);
                sampler = Task.Run(async () =>
                {
                    try
                    {
                        while (true)
                        {
                            await Task.Delay(10, samplerStop.Token);
                            Collect("periodic");
                        }
                    }
                    catch (OperationCanceledException) when (samplerStop.IsCancellationRequested) { }
                });
                drivers = Enumerable.Range(0, 4).Select(async driver =>
                {
                    var subject = driver % 2 == 0 ? "alice" : "bob";
                    var tenant = driver % 2 == 0 ? "tenant-a" : "tenant-b";
                    for (var i = 0; i < 100; i++)
                    {
                        if (await Read(subject, tenant, graphQL: driver >= 2) != (200, null))
                            throw new InvalidOperationException("An authorized traffic request failed.");
                        if (i == 49)
                        {
                            if (Interlocked.Increment(ref halfDrivers) == 4) midpoint.TrySetResult();
                            await midpointRelease.Task.WaitAsync(deadline.Token);
                        }
                    }
                }).ToArray();
                await midpoint.Task.WaitAsync(deadline.Token);
                if (store.Reads != 200) throw new InvalidOperationException("Midpoint traffic count differs.");
                Controlled("midpoint", 1, 0, 1);
                await midpointObserved.Task.WaitAsync(deadline.Token);
                midpointRelease.SetResult();
                await Task.WhenAll(drivers).WaitAsync(deadline.Token);
                foreach (var graphQL in new[] { false, true })
                {
                    var denial = graphQL ? 200 : 403;
                    if (await Read("alice", "tenant-b", graphQL) != (denial, "access.denied")
                        || await Read("bob", "tenant-a", graphQL) != (denial, "access.denied"))
                        throw new InvalidOperationException("Cross-tenant denial changed with metrics enabled.");
                }
                store.ReadRelease = CatalogStore.NewSignal();
                store.ReadsEntered = CatalogStore.NewSignal();
                overlap = Enumerable.Range(0, 4).Select(driver => Read(
                    driver % 2 == 0 ? "alice" : "bob", driver % 2 == 0 ? "tenant-a" : "tenant-b", driver >= 2)).ToArray();
                await store.ReadsEntered.Task.WaitAsync(deadline.Token);
                Controlled("overlap", 5, 0, 2);
                await overlapObserved.Task.WaitAsync(deadline.Token);
                var stopping = host.DisposeAsync().AsTask();
                Controlled("closing", 5, 1, 2);
                if (stopping.IsCompleted) throw new InvalidOperationException("Shutdown did not wait for the held operations.");
                store.ReadRelease.SetResult();
                release.SetResult();
                await stopping.WaitAsync(deadline.Token);
                if (await held != (200, null)) throw new InvalidOperationException("Held write failed.");
            }
            finally
            {
                midpointRelease.TrySetResult();
                store.ReadRelease?.TrySetResult();
                release.TrySetResult();
                samplerStop.Cancel();
                if (sampler is not null) await sampler.WaitAsync(TimeSpan.FromSeconds(5));
                await Task.WhenAll(drivers).WaitAsync(TimeSpan.FromSeconds(5));
                await Task.WhenAll(overlap).WaitAsync(TimeSpan.FromSeconds(5));
                await held.WaitAsync(TimeSpan.FromSeconds(5));
            }
            Controlled("stopped", 0, 1, 0);
            foreach (var reading in overlap)
                if (await reading != (200, null)) throw new InvalidOperationException("Overlapping read failed.");
            if (store.ReadWaits != 4 || store.Factories != 405 || store.Disposals != 405 || store.Reads != 404 || store.Writes != 1
                || host.Counters.HostDisposals != 1 || host.Counters.ForbiddenFactories != 0)
                throw new InvalidOperationException("Business work or owned shutdown counts differed.");
            meter.Dispose();
            values.Clear();
            callbacks = 0;
            listener.RecordObservableInstruments();
            if (callbacks != 0) throw new InvalidOperationException("Disposed meter emitted a measurement.");
            result["status"] = "passed";
            result["metricNames"] = names.Order().ToArray();
            result["crossTenantDenials"] = 4;
            result["trafficReads"] = 400;
            result["overlapReads"] = 4;
            result["postDisposalCallbacks"] = callbacks;
            result["store"] = new { store.Factories, store.Disposals, store.Reads, store.Writes };
            result["hostDisposals"] = host.Counters.HostDisposals;
        }
        await using var off = new FixtureHost();
        await off.Start(Config("appsettings.off.json"), tls, jwt, 8, 4);
        using var offMeter = off.CreateBudgetMetrics("Cehpalon.SmallApi.DisabledBudgetProof");
        if (offMeter is not null || off.Counters.HostFactories != 0 || off.Application is not null)
            throw new InvalidOperationException("Disabled profile created a meter or host.");
        disabled = new { meterCreated = offMeter is not null, off.Counters.HostFactories, hasApplication = off.Application is not null };
    }
    catch (Exception)
    {
        passed = false;
    }
    Directory.CreateDirectory(Path.GetDirectoryName(output)!);
    await using var file = new FileStream(output, FileMode.CreateNew, FileAccess.Write);
    await JsonSerializer.SerializeAsync(file, new { status = passed ? "passed" : "failed", cases, disabled,
        framework = RuntimeInformation.FrameworkDescription, os = RuntimeInformation.OSDescription,
        stopwatchFrequency = Stopwatch.Frequency, requestedDelayMilliseconds = 10,
        scope = "Protected fixture HTTPS traffic with explicit collection and controlled midpoint/shutdown" });
    return passed ? 0 : 1;
}

public static async Task<int> RunDrain(string output)
{
    output = Path.GetFullPath(output);
    if (File.Exists(output)) throw new IOException("Use a new report path.");
    using var tls = new TlsFixture();
    using var jwt = new JwtFixture();
    var configuration = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "appsettings.json"), Encoding.UTF8);
    var observations = new List<object>();
    foreach (var tenantLimited in new[] { false, true })
    {
        await using var host = new FixtureHost();
        await host.Start(configuration, tls, jwt, 2, tenantLimited ? 1 : null);
        using var client = tls.Client(host.Address);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/catalog/set")
        {
            Content = JsonContent.Create(new SetLabel("tenant-a", 1, 0, "during-shutdown"))
        };
        request.Headers.Authorization = new("Bearer", jwt.Token());
        var store = host.Store;
        var release = CatalogStore.NewSignal();
        store.WriteRelease = release;
        store.DelayWrites = true;
        var pending = client.SendAsync(request, deadline.Token);
        OperationConcurrencySnapshot? held = null, closing = null;
        try
        {
            await store.WriteEntered.Task.WaitAsync(deadline.Token);
            held = host.CapacitySnapshot;
            var stopping = host.DisposeAsync().AsTask();
            closing = host.CapacitySnapshot;
            if (held != new OperationConcurrencySnapshot(2, 1, false)
                || closing != new OperationConcurrencySnapshot(2, 1, true))
                throw new InvalidOperationException("Snapshot did not reflect the admitted write and closed admission.");
            if (stopping.IsCompleted || store.Writes != 0 || store.Disposals != 0)
                throw new InvalidOperationException("Shutdown did not wait for the admitted write.");
            release.SetResult();
            await stopping.WaitAsync(deadline.Token);
        }
        finally
        {
            release.TrySetResult();
        }
        using var response = await pending;
        if (response.StatusCode != HttpStatusCode.OK || store.Factories != 1 || store.Writes != 1
            || store.Disposals != 1 || host.Counters.HostDisposals != 1)
            throw new InvalidOperationException("The admitted write or its owned cleanup did not complete.");
        var completed = host.CapacitySnapshot;
        if (completed != new OperationConcurrencySnapshot(2, 0, true)
            || tenantLimited && host.TenantCapacitySnapshot?.ActiveTenants != 0)
            throw new InvalidOperationException("Snapshot retained active capacity after cleanup.");
        observations.Add(new { tenantLimited, http = (int)response.StatusCode, store.Factories, store.Writes,
            store.Disposals, host.Counters.HostDisposals, waitedForRelease = true,
            held, closing, completed, tenantCapacity = host.TenantCapacitySnapshot });
    }

    Directory.CreateDirectory(Path.GetDirectoryName(output)!);
    await using var file = new FileStream(output, FileMode.CreateNew, FileAccess.Write);
    await JsonSerializer.SerializeAsync(file, new { status = "passed", observations });
    return 0;
}

public static async Task<int> RunCapacity(string output, bool tenantLimited = false)
{
    output = Path.GetFullPath(output);
    if (File.Exists(output)) throw new IOException("Use a new report path.");
    using var tls = new TlsFixture();
    using var jwt = new JwtFixture();
    await using var host = new FixtureHost();
    var configuration = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "appsettings.graphql.json"), Encoding.UTF8);
    var totalLimit = tenantLimited ? 2 : 1;
    int? tenantLimit = tenantLimited ? 1 : null;
    await host.Start(configuration, tls, jwt, totalLimit, tenantLimit);
    using var client = tls.Client(host.Address);
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(25));
    var store = host.Store;
    var release = CatalogStore.NewSignal();
    store.WriteRelease = release;
    store.DelayWrites = true;

    async Task<(HttpStatusCode Status, string? Code)> Post(string path, object body, string subject, bool graphQL = false)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body) };
        request.Headers.Authorization = new("Bearer", jwt.Token(subject));
        using var response = await client.SendAsync(request, deadline.Token);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(deadline.Token));
        var root = json.RootElement;
        string? code = graphQL
            ? root.TryGetProperty("errors", out var errors) ? errors[0].GetProperty("extensions").GetProperty("code").GetString() : null
            : root.TryGetProperty("code", out var value) ? value.GetString() : null;
        return (response.StatusCode, code);
    }

    Task<(HttpStatusCode Status, string? Code)> Read(string subject, string tenant, bool graphQL)
    {
        var input = new GetItem(tenant, 1);
        return graphQL
            ? Post("/graphql", new { query = "query($input:GetItemInput!){catalogItem(input:$input){id}}", variables = new { input } }, subject, true)
            : Post("/api/catalog/get", input, subject);
    }

    var peerTenantReads = 0;
    var pending = Post("/api/catalog/set", new SetLabel("tenant-a", 1, 0, "held"), "alice");
    try
    {
        await store.WriteEntered.Task.WaitAsync(deadline.Token);
        foreach (var graphQL in new[] { false, true })
        {
            var denial = graphQL ? HttpStatusCode.OK : HttpStatusCode.Forbidden;
            if (await Read("alice", "tenant-b", graphQL) != (denial, "access.denied")
                || await Read("bob", "tenant-a", graphQL) != (denial, "access.denied"))
                throw new InvalidOperationException("Tenant denial changed under saturation.");
            var overload = graphQL ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable;
            if (await Read("alice", "tenant-a", graphQL) != (overload, OperationConcurrencyBudget.CapacityExceededCode))
                throw new InvalidOperationException("The transport did not share the expected budget.");
            if (tenantLimited)
            {
                if (await Read("bob", "tenant-b", graphQL) != (HttpStatusCode.OK, null))
                    throw new InvalidOperationException("Another tenant could not use spare host capacity.");
                peerTenantReads++;
            }
        }
        if (store.Factories != 1 + peerTenantReads || store.Reads != peerTenantReads || store.Writes != 0
            || store.Disposals != peerTenantReads || (tenantLimited && peerTenantReads != 2))
            throw new InvalidOperationException("Rejected work reached business or the held operation ended prematurely.");
    }
    finally
    {
        release.TrySetResult();
        await pending;
    }
    if (await pending != (HttpStatusCode.OK, null)
        || await Read("alice", "tenant-a", graphQL: true) != (HttpStatusCode.OK, null))
        throw new InvalidOperationException("An operation failed after releasing capacity.");
    await host.DisposeAsync();
    if (store.Factories != 2 + peerTenantReads || store.Disposals != 2 + peerTenantReads || store.Reads != 1 + peerTenantReads || store.Writes != 1
        || host.Counters.HostDisposals != 1 || host.Counters.ForbiddenFactories != 0)
        throw new InvalidOperationException("The admitted work and host did not clean up exactly once.");

    Directory.CreateDirectory(Path.GetDirectoryName(output)!);
    await using var file = new FileStream(output, FileMode.CreateNew, FileAccess.Write);
    await JsonSerializer.SerializeAsync(file, new
    {
        status = "passed", maximumConcurrentOperations = totalLimit, maximumConcurrentOperationsPerTenant = tenantLimit, peerTenantReads,
        saturated = new { http = 503, graphQL = 200, code = OperationConcurrencyBudget.CapacityExceededCode },
        crossTenantDenials = 4, store = new { store.Factories, store.Disposals, store.Reads, store.Writes }
    });
    return 0;
}

public static async Task<int> Run(string output)
{
output=Path.GetFullPath(output);
string Config(string filename)=>File.ReadAllText(Path.Combine(AppContext.BaseDirectory,filename),Encoding.UTF8);
var scenarios=new Dictionary<string,object>();
if(File.Exists(output)) throw new IOException("Use a new report path.");
var checks=new List<object>();var passed=0;var failed=0;
void Require(bool ok,string message) {if(!ok) throw new InvalidOperationException(message);}
async Task Check(string name,Func<Task> test)
{
    try {await test();checks.Add(new{name,passed=true});passed++;}
    catch(Exception) {checks.Add(new{name,passed=false,error="Self-test assertion or fixture operation failed."});failed++;}
}
using var tls=new TlsFixture();using var jwt=new JwtFixture();
await Check("invalid configuration fails before host/module factories",async()=>
{
    await using var host=new FixtureHost();
    try {await host.Start(Config("appsettings.json").Replace("RequestReply","Unsupported"),tls,jwt);throw new Exception("Invalid profile started");}
    catch(ArgumentException) { }
    Require(host.Counters.HostFactories==0 && host.Counters.ForbiddenFactories==0 && host.Application is null,"Invalid config did work");
    scenarios["invalid"]=new{counters=host.Counters,hasApplication=host.Application is not null};
});
await Check("unsupported worker profile fails before host/module factories",async()=>
{
    await using var host=new FixtureHost();
    try {await host.Start(Config("appsettings.json").Replace("\"worker\": { \"Enabled\": false }","\"worker\": { \"Enabled\": true }"),tls,jwt);throw new Exception("Worker activated");}
    catch(ArgumentException) { }
    Require(host.Counters.HostFactories==0 && host.Counters.ForbiddenFactories==0,"Unsupported module did work");
    scenarios["worker"]=new{counters=host.Counters,hasApplication=host.Application is not null};
});
await Check("all entrypoints disabled creates no WebApplication/listener/services",async()=>
{
    await using var host=new FixtureHost();await host.Start(Config("appsettings.off.json"),tls,jwt);
    Require(host.Counters.HostFactories==0 && host.Counters.Endpoints==0 && host.Counters.GraphQLServices==0 && host.Counters.ForbiddenFactories==0 && host.Application is null,"Disabled host activated");
    scenarios["off"]=new{counters=host.Counters,hasApplication=host.Application is not null};
});

var profiles=new List<object>();
foreach(var graphql in new[]{false,true})
{
    var crossTenantDeniedRequests=0;
    var name=graphql?"api-graphql":"api-only";
    await using var host=new FixtureHost();var clock=Stopwatch.StartNew();await host.Start(Config(graphql?"appsettings.graphql.json":"appsettings.json"),tls,jwt);clock.Stop();
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
                foreach (var operation in new[] { "get", "list", "set" })
                {
                    object input=operation switch { "get"=>new GetItem(tenant,1), "list"=>new ListItems(tenant,0), _=>new SetLabel(tenant,1,0,"forged-cross-tenant") };
                    var response=await Send(operation,input,jwt.Token(subject),gql);
                    Require(Code(response,gql)=="access.denied" && response.Status==(gql?200:403),"Cross tenant did not deny safely");
                    crossTenantDeniedRequests++;
                }
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
    profiles.Add(new{name,crossTenantDeniedRequests,startupMilliseconds=clock.Elapsed.TotalMilliseconds,counters=host.Counters,store=new{host.Store.Count,host.Store.Factories,host.Store.Reads,host.Store.Writes,host.Store.Disposals}});
}
await Check("GraphQL-only keeps API entrypoint disabled",async()=>
{
    await using var host=new FixtureHost();await host.Start(Config("appsettings.graphql-only.json"),tls,jwt);
    using var client=tls.Client(host.Address);
    using var request=new HttpRequestMessage(HttpMethod.Post,"/api/catalog/get"){Content=JsonContent.Create(new GetItem("tenant-a",1))};request.Headers.Authorization=new("Bearer",jwt.Token());
    using var response=await client.SendAsync(request);Require(response.StatusCode==HttpStatusCode.NotFound && host.Counters.ApiFactories==0 && host.Store.Factories==0,"Disabled API did work");
    using var gql=new HttpRequestMessage(HttpMethod.Post,"/graphql"){Content=JsonContent.Create(new{query="{catalogItem(input:{tenant:\"tenant-a\",id:1}){id tenant}}"})};gql.Headers.Authorization=new("Bearer",jwt.Token());
    using var result=await client.SendAsync(gql);var body=await result.Content.ReadAsStringAsync();Require(result.IsSuccessStatusCode && !body.Contains("errors",StringComparison.Ordinal),"GraphQL-only failed");
    Require(host.Counters.ApiFactories==0 && host.Counters.ForbiddenFactories==0,"GraphQL implicitly activated API");
    await host.DisposeAsync();
    Require(host.Store.Factories==host.Store.Disposals && host.Counters.HostDisposals==1,"GraphQL-only cleanup did not complete");
    scenarios["graphqlOnly"]=new{counters=host.Counters,hasApplication=host.Application is not null,store=new{host.Store.Factories,host.Store.Disposals}};
});
Directory.CreateDirectory(Path.GetDirectoryName(output)!);
await using(var file=new FileStream(output,FileMode.CreateNew,FileAccess.Write)) await JsonSerializer.SerializeAsync(file,new{observedAtUtc=DateTimeOffset.UtcNow,framework=RuntimeInformation.FrameworkDescription,os=RuntimeInformation.OSDescription,
    scope="Protected localhost HTTPS fixture, pinned JWT validation, generated Core gateway, tenant dispatcher, synthetic in-memory data. Not W0 public benchmark, real IdP/provider, supported-Windows, production, or full performance gate.",passed,failed,checks,profiles,scenarios},new JsonSerializerOptions{WriteIndented=true,IncludeFields=true});
Console.WriteLine($"Small API protected consumer: {passed}/{passed+failed}");return failed==0?0:1;

}
}
