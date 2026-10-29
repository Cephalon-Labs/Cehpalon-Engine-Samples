using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using HotChocolate.Execution;
using HotChocolate.Language;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using PortableConsumers.Generated;

var consumer = Path.GetFullPath(args[0]);
var output = Path.GetFullPath(args[1]);
var resultPath = Path.GetFullPath(args[2]);
var dotnet = Path.GetFullPath(args[3]);
var consumerAssembly = Path.GetFullPath(args[4]);
var cases = new List<object>();
var observations = new List<object>();
var failed = 0;
void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
async Task Check(string name, Func<Task> test)
{
    try { await test(); cases.Add(new { name, passed = true }); }
    catch (Exception error) { failed++; cases.Add(new { name, passed = false, error = error.ToString() }); }
}
var profiles = new[] { (Name:"api", File:"appsettings.json", Api:true, GraphQL:false),
    (Name:"both", File:"appsettings.graphql.json", Api:true, GraphQL:true),
    (Name:"graphql", File:"appsettings.graphql-only.json", Api:false, GraphQL:true) };
using var tls = new TlsFixture();
using var jwt = new JwtFixture();
foreach (var profile in profiles)
{
    await using var host = new FixtureHost();
    await host.Start(File.ReadAllText(Path.Combine(consumer, profile.File)), tls, jwt);
    using var client = tls.Client(host.Address);
    var openapiPath = Path.Combine(output, "export-" + profile.Name, "openapi.json");
    JsonNode? openapi = profile.Api ? JsonNode.Parse(File.ReadAllText(openapiPath))! : null;
    JsonNode Schema(string operation, bool request, int status = 200)
    {
        var post = openapi!["paths"]!["/api/catalog/" + operation]!["post"]!;
        return request ? post["requestBody"]!["content"]!["application/json"]!["schema"]!
            : post["responses"]![status.ToString(System.Globalization.CultureInfo.InvariantCulture)]!["content"]![status == 200 ? "application/json" : "application/problem+json"]!["schema"]!;
    }
    async Task<(int Status, JsonNode? Body, string? ContentType)> Send(string path, object body, string? subject = "alice", string? explicitToken = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body) };
        if (subject is not null || explicitToken is not null) request.Headers.Authorization = new("Bearer", explicitToken ?? jwt.Token(subject!));
        request.Headers.Add("X-Tenant", "tenant-b"); request.Headers.Add("X-Subject", "bob"); request.Headers.Add("X-Role", "admin");
        using var response = await client.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        return ((int)response.StatusCode, string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text), response.Content.Headers.ContentType?.MediaType);
    }
    if (profile.Api)
    {
        await Check(profile.Name + ": OpenAPI routes equal actual mapped POST endpoints", () =>
        {
            var mapped = ((IEndpointRouteBuilder)host.Application!).DataSources.SelectMany(x => x.Endpoints)
                .OfType<RouteEndpoint>().Where(e => e.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods.Contains("POST") == true)
                .Select(e => e.RoutePattern.RawText!).Where(p => p.StartsWith("/api/", StringComparison.Ordinal)).Order(StringComparer.Ordinal).ToArray();
            Require(mapped.SequenceEqual(openapi!["paths"]!.AsObject().Select(x => x.Key).Order(StringComparer.Ordinal)), "Export/runtime paths differ.");
            return Task.CompletedTask;
        });
        await Check(profile.Name + ": actual authenticated get/list/set requests and successful responses satisfy exported shape", async () =>
        {
            foreach (var (operation, input) in new (string,object)[] {
                ("get", new { tenant="tenant-a", id=1 }), ("list", new { tenant="tenant-a", page=0 }),
                ("set", new { tenant="tenant-a", id=2, expectedRevision=0, label="schema-proof" }) })
            {
                var node = JsonSerializer.SerializeToNode(input)!;
                Require(Shape.Accept(Schema(operation, true), node), "Valid request disagrees with exported schema: " + operation);
                var response = await Send("/api/catalog/" + operation, input);
                Require(response.Status == 200 && response.ContentType == "application/json" && Shape.Accept(Schema(operation, false), response.Body), "Actual response disagrees with exported schema: " + operation);
                if (operation == "list") Require(response.Body!["items"]!.AsArray().Count == 20, "Nested array response changed.");
                else Require(response.Body!["amountMinorUnits"]!.GetValue<long>() > 0, "Int64 field did not survive wire serialization.");
                observations.Add(new { profile=profile.Name, operation, response.Status, response.ContentType, body=response.Body });
            }
        });
        await Check(profile.Name + ": exported request shapes reject missing/null/unmapped properties and array root, matching actual adapter", async () =>
        {
            foreach (var input in new JsonNode?[] { JsonNode.Parse("{\"tenant\":\"tenant-a\"}"),
                JsonNode.Parse("{\"tenant\":null,\"id\":1}"), JsonNode.Parse("{\"tenant\":\"tenant-a\",\"id\":1,\"unknown\":true}"), new JsonArray(), null })
            {
                Require(!Shape.Accept(Schema("get", true), input), "Export accepted a structurally invalid request.");
                var before = host.Store.Work;
                using var request = new HttpRequestMessage(HttpMethod.Post, "/api/catalog/get") { Content = new StringContent(input?.ToJsonString() ?? "null", Encoding.UTF8, "application/json") };
                request.Headers.Authorization = new("Bearer", jwt.Token());
                using var response = await client.SendAsync(request);
                Require((int)response.StatusCode == 400 && host.Store.Work == before, "Adapter accepted invalid shape or did business.");
            }
        });
        await Check(profile.Name + ": shape-valid id0 still fails custom validation before business", async () =>
        {
            var invalid = new { tenant="tenant-a", id=0 };
            Require(Shape.Accept(Schema("get", true), JsonSerializer.SerializeToNode(invalid)), "Schema incorrectly pretends to model custom id predicate.");
            var before = host.Store.Work; var response = await Send("/api/catalog/get", invalid);
            Require(response.Status == 400 && response.Body?["code"]?.GetValue<string>() == "validation.failed"
                && response.ContentType == "application/problem+json" && Shape.Accept(Schema("get", false, 400), response.Body) && host.Store.Work == before,
                "Custom validator / error envelope differed.");
            observations.Add(new { profile=profile.Name, operation="schema-valid-custom-invalid", response.Status, body=response.Body });
        });
        await Check(profile.Name + ": schema-valid cross-tenant requests deny both directions before business", async () =>
        {
            foreach (var (tenant, subject) in new[] { ("tenant-b", "alice"), ("tenant-a", "bob") })
            {
                var input = new { tenant, id=1 }; Require(Shape.Accept(Schema("get", true), JsonSerializer.SerializeToNode(input)), "Tenant policy leaked into JSON shape.");
                var before = host.Store.Work; var response = await Send("/api/catalog/get", input, subject);
                Require(response.Status == 403 && response.ContentType == "application/problem+json" && response.Body?["code"]?.GetValue<string>() == "access.denied"
                    && Shape.Accept(Schema("get", false, 403), response.Body) && host.Store.Work == before, "Cross-tenant error/authority disagreed with contract.");
                observations.Add(new { profile=profile.Name, operation="cross-tenant", tenant, subject, response.Status, body=response.Body });
            }
        });
        await Check(profile.Name + ": OpenAPI documents unauthenticated response without invented body schema", async () =>
        {
            var before = host.Store.Work; var response = await Send("/api/catalog/get", new { tenant="tenant-a",id=1 }, null);
            Require(response.Status == 401 && host.Store.Work == before, "Anonymous request did work.");
            Require(openapi!["paths"]!["/api/catalog/get"]!["post"]!["responses"]!["401"]!["content"] is null, "401 advertised a mandatory invented envelope.");
        });
        await Check(profile.Name + ": API-only GraphQL remains absent with no vendor registration", async () =>
        {
            if (profile.GraphQL) return;
            var response = await Send("/graphql", new { query="{ __typename }" });
            Require(response.Status == 404 && host.Counters.GraphQLFactories == 0 && host.Counters.GraphQLServices == 0, "Offline artifact work enabled runtime GraphQL.");
        });
    }
    if (profile.GraphQL)
    {
        await Check(profile.Name + ": exported SDL AST equals complete actual enabled runtime schema AST", async () =>
        {
            var executor = await host.Application!.Services.GetRequiredService<IRequestExecutorProvider>().GetExecutorAsync();
            var actual = Utf8GraphQLParser.Parse(executor.Schema.ToString()).ToString();
            var exported = Utf8GraphQLParser.Parse(File.ReadAllText(Path.Combine(output, "export-" + profile.Name, "schema.graphql"))).ToString();
            Require(actual == exported, "Export/runtime schema AST differs.");
            observations.Add(new { profile=profile.Name, actualSchema=actual, astIdentical=true });
        });
        await Check(profile.Name + ": actual GraphQL query and cross-tenant error preserve typed schema and authority", async () =>
        {
            string Query(string tenant) => "{ catalogItem(input:{tenant:\"" + tenant + "\",id:1}){tenant id label revision amountMinorUnits} }";
            var own = await Send("/graphql", new { query=Query("tenant-a") });
            Require(own.Status == 200 && own.Body?["errors"] is null && own.Body?["data"]?["catalogItem"]?["tenant"]?.GetValue<string>() == "tenant-a", "Actual GraphQL shape/owner request failed.");
            var before = host.Store.Work; var cross = await Send("/graphql", new { query=Query("tenant-b") });
            Require(cross.Status == 200 && cross.Body?["errors"]?[0]?["extensions"]?["code"]?.GetValue<string>() == "access.denied" && host.Store.Work == before, "GraphQL crossed tenant after offline export.");
        });
        await Check(profile.Name + ": offline schema file does not enable public introspection or schema download", async () =>
        {
            var response = await Send("/graphql", new { query="{ __schema { types { name } } }" });
            Require(response.Body?["errors"] is not null && !response.Body!.ToJsonString().Contains("\"types\"", StringComparison.Ordinal), "Introspection exposed.");
            foreach (var path in new[] { "/graphql?sdl", "/graphql/schema.graphql", "/graphql/ui", "/graphql?query={__typename}" })
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, path); request.Headers.Authorization = new("Bearer", jwt.Token());
                using var result = await client.SendAsync(request); Require(!result.IsSuccessStatusCode, "Offline export enabled HTTP exposure: " + path);
            }
        });
        if (!profile.Api)
            await Check(profile.Name + ": GraphQL-only still has no API mapping or handler work on API route", async () =>
            {
                var before = host.Store.Work; var response = await Send("/api/catalog/get", new { tenant="tenant-a", id=1 });
                Require(response.Status == 404 && host.Counters.ApiFactories == 0 && host.Store.Work == before, "GraphQL-only enabled API.");
            });
    }
    await Check(profile.Name + ": actual enabled host closes listener and balances handler disposal", async () =>
    {
        var address = host.Address; await host.DisposeAsync();
        Require(host.Store.Factories == host.Store.Disposals && host.Counters.HostDisposals == 1 && host.Counters.ForbiddenFactories == 0, "Owned cleanup changed.");
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        try { await socket.ConnectAsync(IPAddress.Loopback, address.Port); throw new InvalidOperationException("Listener remains open."); }
        catch (SocketException) { }
    });
}
await Check("late publication write denial preserves real GraphQL schema/provider cleanup counters", async () =>
{
    var parent = OperatingSystem.IsWindows() ? Path.Combine(output, "owned-readonly-export-parent")
        : Path.Combine(Path.GetTempPath(), "cehpalon-contract-readonly-" + Guid.NewGuid().ToString("N"));
    Require(!Directory.Exists(parent) && !File.Exists(parent), "Use a new owned permission fixture.");
    Directory.CreateDirectory(parent);
    DirectorySecurity? originalDacl = null;
    UnixFileMode? originalMode = null;
    var destination = Path.Combine(parent, "new-contracts");
    Process? process = null;
    try
    {
        if (OperatingSystem.IsWindows())
        {
            var directory = new DirectoryInfo(parent);
            // Access-only save/restore does not request owner mutation privileges.
            originalDacl = directory.GetAccessControl(AccessControlSections.Access);
            var sid = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException();
            var restricted = new DirectorySecurity();
            restricted.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            restricted.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.ReadAndExecute,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            directory.SetAccessControl(restricted);
            var observed = directory.GetAccessControl(AccessControlSections.Access);
            var rules = observed.GetAccessRules(true,true,typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
            Require(observed.AreAccessRulesProtected && rules.Length == 1 && rules[0].IdentityReference == sid
                && rules[0].AccessControlType == AccessControlType.Allow && (rules[0].FileSystemRights & FileSystemRights.Write) == 0,
                "Owned permission fixture is not read/execute-only.");
        }
        else
        {
            originalMode = File.GetUnixFileMode(parent);
            File.SetUnixFileMode(parent, UnixFileMode.UserRead | UnixFileMode.UserExecute);
            Require(File.GetUnixFileMode(parent) == (UnixFileMode.UserRead | UnixFileMode.UserExecute), "Native permission fixture is not Unix0500.");
        }
        var start = new ProcessStartInfo(dotnet) { UseShellExecute=false, RedirectStandardOutput=true, RedirectStandardError=true };
        foreach (var argument in new[] { consumerAssembly, "--export-contracts", "--config", Path.Combine(consumer,"appsettings.graphql.json"), "--output", destination }) start.ArgumentList.Add(argument);
        process = Process.Start(start) ?? throw new InvalidOperationException("Child exporter did not start.");
        var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        await process.WaitForExitAsync(timeout.Token);
        var outText = await stdout; var errorText = await stderr;
        Require(process.ExitCode == 3 && string.IsNullOrWhiteSpace(outText) && !Directory.Exists(destination), "Export unexpectedly published into denied parent.");
        var result = JsonNode.Parse(errorText)!; var counters = result["counters"]!;
        Require(result["code"]?.GetValue<string>() == "export.failure"
            && counters["GraphQLProvidersCreated"]?.GetValue<int>() == 1 && counters["GraphQLProvidersDisposed"]?.GetValue<int>() == 1
            && counters["GraphQLSchemaBuilds"]?.GetValue<int>() == 1 && counters["GraphQLRegistrations"]?.GetValue<int>() == 1,
            "Late failure falsely hid schema construction or failed to await provider disposal.");
        foreach (var metric in new[] { "HandlerFactoryCalls", "DispatchCalls", "HostFactories", "TlsReads", "AuthorityCalls" })
            Require(counters[metric]?.GetValue<int>() == 0, "Late failed export did unexpected work: " + metric);
        observations.Add(new { phase="late-publication-denied", expectedExit=3, stdout=outText, stderr=result,
            permissionPolicy=OperatingSystem.IsWindows()?"current-user-only protected read/execute DACL":"native Unix0500 parent",
            outputAbsent=true, secrets=false });
    }
    finally
    {
        if (process is not null) { if (!process.HasExited) { process.Kill(); await process.WaitForExitAsync(); } process.Dispose(); }
        if (OperatingSystem.IsWindows() && originalDacl is not null) new DirectoryInfo(parent).SetAccessControl(originalDacl);
        if (!OperatingSystem.IsWindows() && originalMode is not null) File.SetUnixFileMode(parent, originalMode.Value);
    }
});
var report = new { passed=cases.Count-failed, failed, scope="Actual generated runtime HTTPS routes/SDL AST/JSON-shape differential fixture; independent bounded keyword interpreter is not an arbitrary JSON Schema validator or tenant authority.",
    checks=cases, observations, schemaKeywords=Shape.Used.Order(StringComparer.Ordinal).ToArray() };
File.WriteAllText(resultPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented=true }) + "\n", new UTF8Encoding(false));
Console.WriteLine(JsonSerializer.Serialize(new { report.passed, report.failed }));
return failed == 0 ? 0 : 1;

static class Shape
{
    internal static readonly HashSet<string> Used = new(StringComparer.Ordinal);
    private static readonly HashSet<string> Supported = new(["$id","$schema","$comment","title","description","type","properties","required","additionalProperties","items","minimum","maximum","format","pattern","enum","const","allOf","anyOf","oneOf","$ref","$defs"], StringComparer.Ordinal);
    internal static bool Accept(JsonNode schema, JsonNode? value) => Match(schema, value, schema);
    private static bool Match(JsonNode schema, JsonNode? value, JsonNode root)
    {
        if (schema is JsonValue boolean && boolean.TryGetValue<bool>(out var pass)) return pass;
        foreach (var item in schema.AsObject())
        {
            Used.Add(item.Key); if (!Supported.Contains(item.Key)) throw new InvalidOperationException("Unimplemented schema keyword: " + item.Key);
        }
        if (schema["$id"] is not null) root = schema;
        if (schema["$ref"] is JsonValue reference)
        {
            var text = reference.GetValue<string>(); if (!text.StartsWith("#/", StringComparison.Ordinal)) throw new InvalidOperationException("Unsupported schema reference.");
            JsonNode? target = root;
            foreach (var part in text[2..].Split('/')) target = target?[part.Replace("~1", "/", StringComparison.Ordinal).Replace("~0", "~", StringComparison.Ordinal)];
            if (target is null || !Match(target, value, root)) return false;
        }
        if (schema["allOf"] is JsonArray all && !all.All(s => Match(s!, value, root))) return false;
        if (schema["anyOf"] is JsonArray any && !any.Any(s => Match(s!, value, root))) return false;
        if (schema["oneOf"] is JsonArray one && one.Count(s => Match(s!, value, root)) != 1) return false;
        var kind = value?.GetValueKind() ?? JsonValueKind.Null;
        bool Is(string type) => type switch {
            "object" => kind==JsonValueKind.Object, "array" => kind==JsonValueKind.Array, "string" => kind==JsonValueKind.String,
            "integer" => kind==JsonValueKind.Number && decimal.TryParse(value!.ToJsonString(), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var n) && decimal.Truncate(n)==n,
            "number" => kind==JsonValueKind.Number, "boolean" => kind is JsonValueKind.True or JsonValueKind.False, "null" => kind==JsonValueKind.Null,
            _ => throw new InvalidOperationException("Unknown schema type.") };
        if (schema["type"] is JsonArray union) { if (!union.Any(t => Is(t!.GetValue<string>()))) return false; }
        else if (schema["type"] is JsonValue type && !Is(type.GetValue<string>())) return false;
        if (schema["enum"] is JsonArray options && !options.Any(o => JsonNode.DeepEquals(o,value))) return false;
        if (schema["const"] is JsonNode constant && !JsonNode.DeepEquals(constant,value)) return false;
        if (kind==JsonValueKind.Object)
        {
            var obj=value!.AsObject(); var properties=schema["properties"]?.AsObject();
            if (schema["required"] is JsonArray required && required.Any(p => !obj.ContainsKey(p!.GetValue<string>()))) return false;
            foreach (var item in obj)
            {
                if (properties?.TryGetPropertyValue(item.Key,out var property)==true) { if (!Match(property!,item.Value,root)) return false; }
                else if (schema["additionalProperties"] is JsonValue restriction && restriction.TryGetValue<bool>(out var allow) && !allow) return false;
            }
        }
        if (kind==JsonValueKind.Array && schema["items"] is JsonNode items && value!.AsArray().Any(item => !Match(items,item,root))) return false;
        if (kind==JsonValueKind.Number)
        {
            var number=decimal.Parse(value!.ToJsonString(), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture);
            if (schema["minimum"] is JsonNode min && number < decimal.Parse(min.ToJsonString(),System.Globalization.CultureInfo.InvariantCulture)) return false;
            if (schema["maximum"] is JsonNode max && number > decimal.Parse(max.ToJsonString(),System.Globalization.CultureInfo.InvariantCulture)) return false;
            if (schema["format"]?.GetValue<string>() is string format)
            {
                if (format=="int32" && (number<int.MinValue || number>int.MaxValue)) return false;
                if (format=="int64" && (number<long.MinValue || number>long.MaxValue)) return false;
                if (format is not ("int32" or "int64" or "float" or "double" or "decimal")) throw new InvalidOperationException("Unimplemented numeric format.");
            }
        }
        if (kind==JsonValueKind.String && schema["pattern"] is JsonNode pattern && !System.Text.RegularExpressions.Regex.IsMatch(value!.GetValue<string>(),pattern.GetValue<string>(),System.Text.RegularExpressions.RegexOptions.CultureInvariant)) return false;
        return true;
    }
}
