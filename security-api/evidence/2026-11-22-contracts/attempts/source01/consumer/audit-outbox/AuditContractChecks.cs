extern alias securityapi;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Cehpalon.Engine.Tenancy;
using Cehpalon.Engine.Transports.Http;
using HotChocolate.Execution;
using Microsoft.Extensions.DependencyInjection;
using securityapi::SecurityApi;

namespace AuditOutbox;

public static partial class ResourceTransportChecks
{
    private static readonly JsonSerializerOptions ContractJson = new(JsonSerializerDefaults.Web);
    private const string ContractViewScalars = "receiptId recordedAtUtc reportedAtUtc principalIssuer principalSubject authenticationScheme tenant operationId action resourceKind resourceId authorizationResourceVersion beforeEntityVersion afterEntityVersion kind mode capturedMode";
    private const string ContractCursorFields = "tenant resourceKind resourceId afterReceiptId";
    private static string ContractResourceSelection(string entryFields) => "tenant entries { " + entryFields + " } nextCursor { " + ContractCursorFields + " }";
    private static AuditReceiptTransportOptions ContractOptions(bool http = true, bool graph = true, bool receipt = true, bool resource = true)
        => new(http, graph) { ReceiptLookupEnabled = receipt, ResourceHistoryEnabled = resource };
    private static string ContractSha(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    private static JsonObject ContractOpenApi(AuditReadContractArtifacts artifacts) => JsonNode.Parse(artifacts.Files["openapi.json"])!.AsObject();
    private static JsonNode ContractRequestSchema(JsonObject api, string path) => api["paths"]![path]!["post"]!["requestBody"]!["content"]!["application/json"]!["schema"]!;
    private static JsonNode ContractResponseSchema(JsonObject api, string path, string status = "200")
        => api["paths"]![path]!["post"]!["responses"]![status]!["content"]![status == "200" ? "application/json" : "application/problem+json"]!["schema"]!;
    private static JsonNode ContractResource(JsonNode node)
        => node is JsonObject obj && obj["allOf"] is JsonArray array ? array.OfType<JsonObject>().First(x => x.ContainsKey("$id")) : node;
    private static JsonNode ContractWithoutId(JsonNode node) { var clone = node.DeepClone().AsObject(); clone.Remove("$id"); return clone; }
    private static bool ContractContainsProperty(JsonNode? node, string name)
    {
        if (node is JsonObject obj)
        {
            if (obj["properties"] is JsonObject props && props.ContainsKey(name)) return true;
            return obj.Any(x => ContractContainsProperty(x.Value, name));
        }
        return node is JsonArray array && array.Any(x => ContractContainsProperty(x, name));
    }
    private static JsonNode ContractProperty(JsonNode node, string name)
    {
        if (node is JsonObject obj)
        {
            if (obj["properties"] is JsonObject props && props[name] is { } found) return found;
            foreach (var child in obj) if (child.Value is { } value && ContractContainsProperty(value, name)) return ContractProperty(value, name);
        }
        if (node is JsonArray array)
            foreach (var child in array) if (child is { } value && ContractContainsProperty(value, name)) return ContractProperty(value, name);
        throw new InvalidOperationException("Expected serializer-derived property.");
    }
    private static bool ContractType(string type, JsonElement value) => type switch
    {
        "null" => value.ValueKind == JsonValueKind.Null, "object" => value.ValueKind == JsonValueKind.Object,
        "array" => value.ValueKind == JsonValueKind.Array, "string" => value.ValueKind == JsonValueKind.String,
        "boolean" => value.ValueKind is JsonValueKind.True or JsonValueKind.False,
        "number" => value.ValueKind == JsonValueKind.Number,
        "integer" => value.ValueKind == JsonValueKind.Number && value.TryGetDecimal(out var number) && decimal.Truncate(number) == number,
        _ => throw new InvalidOperationException("Unsupported schema type in bounded fixture checker.")
    };
    // Deliberately bounded shape checker, not a general JSON Schema implementation.
    // GraphQL selection subsets validate only selected properties; exact SDL parity is checked separately.
    private static bool ContractShape(JsonNode schema, JsonElement value, bool required = true, JsonNode? resource = null, int depth = 0)
    {
        if (depth > 64) throw new InvalidOperationException("Unexpected recursive fixture schema.");
        if (schema is not JsonObject obj) return schema.GetValue<bool>();
        if (resource is null || obj.ContainsKey("$id")) resource = schema;
        if (obj["$ref"] is { } reference)
        {
            var pointer = reference.GetValue<string>();
            if (!pointer.StartsWith('#')) throw new InvalidOperationException("Only local fixture schema references are supported.");
            JsonNode target = resource;
            foreach (var part in pointer[1..].Split('/', StringSplitOptions.RemoveEmptyEntries)) target = target[part.Replace("~1", "/").Replace("~0", "~")]!;
            if (!ContractShape(target, value, required, resource, depth + 1)) return false;
        }
        if (obj["allOf"] is JsonArray all && !all.All(x => ContractShape(x!, value, required, resource, depth + 1))) return false;
        if (obj["anyOf"] is JsonArray any && !any.Any(x => ContractShape(x!, value, required, resource, depth + 1))) return false;
        if (obj["type"] is JsonValue type && !ContractType(type.GetValue<string>(), value)) return false;
        if (obj["type"] is JsonArray types && !types.Any(x => ContractType(x!.GetValue<string>(), value))) return false;
        if (value.ValueKind == JsonValueKind.Object)
        {
            if (required && obj["required"] is JsonArray names && names.Any(x => !value.TryGetProperty(x!.GetValue<string>(), out _))) return false;
            if (obj["properties"] is JsonObject properties)
            {
                foreach (var property in value.EnumerateObject())
                    if (properties[property.Name] is { } propertySchema)
                    { if (!ContractShape(propertySchema, property.Value, required, resource, depth + 1)) return false; }
                    else if (obj["additionalProperties"] is JsonValue additional && additional.TryGetValue<bool>(out var allowed) && !allowed) return false;
            }
        }
        if (value.ValueKind == JsonValueKind.Array && obj["items"] is { } items)
            foreach (var item in value.EnumerateArray()) if (!ContractShape(items, item, required, resource, depth + 1)) return false;
        return true;
    }
    private static void ContractNoBusinessExecution(AuditReadContractExportCounters counters)
        => Require(counters.HandlerFactoryCalls == 0 && counters.DispatchCalls == 0);
    private static async Task<(int Exit, string Stdout, string Stderr)> ContractCli(params string[] args)
    {
        using var process = new Process { StartInfo = new(Environment.ProcessPath ?? throw new InvalidOperationException("Missing runtime executable.")) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true } };
        process.StartInfo.ArgumentList.Add(typeof(ResourceTransportChecks).Assembly.Location);
        foreach (var arg in args) process.StartInfo.ArgumentList.Add(arg);
        Require(process.Start()); var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
        try { await process.WaitForExitAsync().WaitAsync(Watchdog); return (process.ExitCode, await stdout, await stderr); }
        finally { if (!process.HasExited) process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); await Task.WhenAll(stdout, stderr); }
    }

    public static async Task<int> RunContractCommandAsync(string[] args)
    {
        var arguments = args.Select(x => x.Split('=', 2)).ToDictionary(x => x[0], x => x[1], StringComparer.Ordinal);
        var phase = arguments["--verify-audit-contracts"]; if (phase is not ("offline" or "wire")) throw new ArgumentException("Unknown contract verification phase.");
        var output = Path.GetFullPath(arguments["--output"]); if (File.Exists(output) || Directory.Exists(output)) throw new IOException("Retain prior contract result.");
        var proof = Path.Combine(Path.GetDirectoryName(output)!, "contract-proof"); if (Directory.Exists(proof) || File.Exists(proof)) throw new IOException("Retain prior contract proof."); Directory.CreateDirectory(proof);
        var checks = new List<object>(); var observations = new List<object>(); var schemas = new List<string>(); var passed = 0; var failed = 0;
        async Task CheckContract(string name, Func<Task> action)
        { try { await action(); passed++; checks.Add(new { name, passed = true }); } catch (Exception error) { failed++; checks.Add(new { name, passed = false, error_type = error.GetType().FullName, error = error.Message }); } }
        if (phase == "offline") await ContractOffline(CheckContract, proof, observations.Add);
        else
        {
            var connectionFile = Path.GetFullPath(arguments["--connection-file"]); var connection = (await File.ReadAllTextAsync(connectionFile)).Trim();
            await ContractWire(CheckContract, proof, connection, connectionFile, schemas, observations.Add);
        }
        Require(checks.Count == 8);
        await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { phase, passed, failed, checks, observations, schemas,
            scope = "Eight targeted audit-contract checks per phase; existing332-provider/651-security suites are reused baseline, not rerun or added to these totals.",
            shape_checker = "Bounded type/required/properties/items/allOf/anyOf/local-ref fixture checks; not a general JSON Schema validator. GraphQL subset shapes and exact actual SDL are separate.",
            topology = phase == "offline" ? "No database/connection-file/TLS configuration supplied to actual export CLI" : OperatingSystem.IsWindows() ? "Windows.NET through owned loopback/stdio proxy to WSL PostgreSQL" : "WSL.NET direct owned loopback PostgreSQL" }, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"Audit contracts {phase}: {passed}/{checks.Count}"); return failed == 0 ? 0 : 1;
    }

    private static async Task ContractOffline(Func<string, Func<Task>, Task> check, string proof, Action<object> observe)
    {
        await check("offline contract selection matrix and pure selected configuration", async () =>
        {
            var variants = 0;
            foreach (var http in new[] { false, true }) foreach (var graph in new[] { false, true })
            foreach (var receipt in new[] { false, true }) foreach (var resource in new[] { false, true })
            {
                var selected = (http || graph) && (receipt || resource); var counters = new AuditReadContractExportCounters();
                var value = await AuditReadContractExport.BuildArtifactsAsync(ContractOptions(http, graph, receipt, resource), counters);
                Require(value.Files.ContainsKey("manifest.json") && value.Files.ContainsKey("openapi.json") == (selected && http) && value.Files.ContainsKey("schema.graphql") == (selected && graph));
                Require(counters.HttpSchemaOperations == (selected && http ? (receipt ? 1 : 0) + (resource ? 1 : 0) : 0));
                Require(counters.GraphQLProvidersCreated == (selected && graph ? 1 : 0) && counters.GraphQLProvidersDisposed == counters.GraphQLProvidersCreated && counters.GraphQLSchemaBuilds == counters.GraphQLProvidersCreated); ContractNoBusinessExecution(counters); variants++;
            }
            foreach (var invalid in new[] { ContractOptions() with { SecurityEnabled = false }, ContractOptions() with { ReadTimeout = TimeSpan.Zero }, ContractOptions() with { ConcurrencyLimits = new(1, 2) } })
            { var counters = new AuditReadContractExportCounters(); Require(await Failure(() => AuditReadContractExport.BuildArtifactsAsync(invalid, counters)).WaitAsync(Watchdog) is ArgumentException); Require(counters.GraphQLProvidersCreated == 0 && counters.HttpSchemaOperations == 0); ContractNoBusinessExecution(counters); }
            var inert = await AuditReadContractExport.BuildArtifactsAsync(new(false, false, false, TimeSpan.FromTicks(-1)) { ConcurrencyLimits = new(0, -1), ResourceHistoryEnabled = true }); Require(inert.Files.Count == 1);
            observe(new { phase = "contract_offline_selection", variants, selected_validation_is_pure = true, all_off_manifest_only = true });
        });
        await check("offline HTTP schemas preserve actual serializer required nullable Guid and string shapes", async () =>
        {
            var artifacts = await AuditReadContractExport.BuildArtifactsAsync(ContractOptions(graph: false)); var api = ContractOpenApi(artifacts); var ids = new HashSet<string>(StringComparer.Ordinal);
            Require(api["openapi"]!.GetValue<string>() == "3.1.0");
            foreach (var path in new[] { AuditReceiptTransportHost.LookupPath, AuditReceiptTransportHost.ResourceHistoryPath })
            {
                var request = ContractRequestSchema(api, path); var response = ContractResponseSchema(api, path);
                Require(!ContractShape(request, JsonSerializer.SerializeToElement<object?>(null)) && ContractShape(response, JsonSerializer.SerializeToElement<object?>(null)));
                Require(ids.Add(ContractResource(request)["$id"]!.GetValue<string>()) && ids.Add(ContractResource(response)["$id"]!.GetValue<string>()));
                Require(ContractContainsProperty(response, "receiptId") && ContractContainsProperty(response, "recordedAtUtc") && ContractContainsProperty(response, "number"));
                var statuses = api["paths"]![path]!["post"]!["responses"]!.AsObject(); Require(statuses.ContainsKey("503"));
                foreach (var status in statuses.Where(x => x.Value?["content"] is not null)) if (status.Key != "200") Require(ids.Add(ContractResource(ContractResponseSchema(api, path, status.Key))["$id"]!.GetValue<string>()));
            }
            Require(JsonNode.DeepEquals(ContractWithoutId(ContractResource(ContractRequestSchema(api, AuditReceiptTransportHost.ResourceHistoryPath))), OperationHttpAdapter.ExportJsonSchema<AuditResourceHistoryRequest>()));
            Require(JsonNode.DeepEquals(ContractWithoutId(ContractResource(ContractResponseSchema(api, AuditReceiptTransportHost.LookupPath))), OperationHttpAdapter.ExportJsonSchema<AuditReceiptLookupResponse>()));
            var guid = ContractProperty(ContractRequestSchema(api, AuditReceiptTransportHost.LookupPath), "receiptId"); Require(guid["format"]?.GetValue<string>() == "uuid");
            var recorded = ContractProperty(ContractResponseSchema(api, AuditReceiptTransportHost.LookupPath), "recordedAtUtc"); Require(recorded["format"] is null);
            var number = ContractProperty(ContractResponseSchema(api, AuditReceiptTransportHost.LookupPath), "number"); Require(ContractShape(number, JsonSerializer.SerializeToElement("1.25")) && !ContractShape(number, JsonSerializer.SerializeToElement(1.25m)));
            Require(new AuditResourceHistoryRequest("A", "entity", "shared").Limit == 50);
            var omitted = JsonSerializer.SerializeToElement(new { tenant = "A", resourceKind = "entity", resourceId = "shared" }); Require(ContractShape(ContractRequestSchema(api, AuditReceiptTransportHost.ResourceHistoryPath), omitted));
            observe(new { phase = "contract_offline_http_shapes", serializer_metadata_exact = true, request_object_only = true, nullable_success_root = true, Guid_request_not_string_output_format = true, string_date_and_decimal_views = true, custom_validators_not_schema_authority = true });
        });
        await check("offline SDL selection and selected provider cleanup including schema failure", async () =>
        {
            foreach (var receipt in new[] { false, true }) foreach (var resource in new[] { false, true })
            {
                var counters = new AuditReadContractExportCounters(); var value = await AuditReadContractExport.BuildArtifactsAsync(ContractOptions(false, true, receipt, resource), counters);
                if (receipt || resource)
                { var sdl = Encoding.UTF8.GetString(value.Files["schema.graphql"]); Require(sdl.Contains("trailReceipt(", StringComparison.Ordinal) == receipt && sdl.Contains("trailResourceHistory(", StringComparison.Ordinal) == resource && counters.GraphQLProvidersCreated == 1 && counters.GraphQLProvidersDisposed == 1 && counters.GraphQLSchemaBuilds == 1 && counters.GraphQLServices > 0); }
                else Require(counters.GraphQLRegistrations == 0 && counters.GraphQLProvidersCreated == 0);
                ContractNoBusinessExecution(counters);
            }
            var fault = new IOException("Owned contract schema control."); var broken = new AuditReadContractExportCounters { BeforeGraphQLSchemaBuild = () => throw fault };
            var error = await Failure(() => AuditReadContractExport.BuildArtifactsAsync(ContractOptions(false, true), broken)).WaitAsync(Watchdog); Require(ReferenceEquals(error, fault) && broken.GraphQLProvidersCreated == 1 && broken.GraphQLProvidersDisposed == 1 && broken.GraphQLSchemaBuilds == 0); ContractNoBusinessExecution(broken);
            observe(new { phase = "contract_offline_graphql", actual_vendor_SDL = true, selected_provider_created_and_disposed = true, disabled_registration_zero = true, failure_provider_joined = true, forbidden_dispatch = 0 });
        });
        await check("offline detached files and metadata mutation leave later exports unchanged", async () =>
        {
            var first = await AuditReadContractExport.BuildArtifactsAsync(ContractOptions()); var original = first.Files.ToDictionary(x => x.Key, x => x.Value.ToArray(), StringComparer.Ordinal);
            first.Files["openapi.json"][0] ^= 1; first.Files["schema.graphql"][0] ^= 1;
            var schema = OperationHttpAdapter.ExportJsonSchema<AuditResourceHistoryRequest>(); schema.AsObject()["x-untrusted-mutation"] = true;
            var next = await AuditReadContractExport.BuildArtifactsAsync(ContractOptions()); Require(original.All(x => next.Files[x.Key].SequenceEqual(x.Value)) && !OperationHttpAdapter.ExportJsonSchema<AuditResourceHistoryRequest>().AsObject().ContainsKey("x-untrusted-mutation"));
            observe(new { phase = "contract_offline_detached", changed_caller_owned_bytes = true, later_catalog_serializer_and_artifacts_unchanged = true });
        });
        await check("offline deterministic UTF8 LF payload bytes and manifest hashes", async () =>
        {
            var first = await AuditReadContractExport.BuildArtifactsAsync(ContractOptions()); var second = await AuditReadContractExport.BuildArtifactsAsync(ContractOptions()); Require(first.Files.All(x => second.Files[x.Key].SequenceEqual(x.Value)));
            using var manifest = JsonDocument.Parse(first.Files["manifest.json"]);
            foreach (var artifact in manifest.RootElement.GetProperty("artifacts").EnumerateArray())
            { var bytes = first.Files[artifact.GetProperty("name").GetString()!]; Require(artifact.GetProperty("bytes").GetInt64() == bytes.LongLength && artifact.GetProperty("sha256").GetString() == ContractSha(bytes) && !Encoding.UTF8.GetString(bytes).Contains('\r')); }
            var destination = Path.Combine(proof, "deterministic"); await AuditReadContractExport.PublishAsync(ContractOptions(), destination);
            Require(first.Files.All(x => File.ReadAllBytes(Path.Combine(destination, x.Key)).SequenceEqual(x.Value)));
            observe(new { phase = "contract_offline_determinism", independent_pure_calls_identical = true, hashes_and_lengths_exact = true, manifest_contains_structural_metadata_only = true });
        });
        await check("offline new directory publication never overwrites prior file or directory", async () =>
        {
            var directory = Path.Combine(proof, "existing-directory"); Directory.CreateDirectory(directory); var sentinel = Path.Combine(directory, "sentinel.txt"); await File.WriteAllTextAsync(sentinel, "retained-output");
            var file = Path.Combine(proof, "existing-file"); await File.WriteAllTextAsync(file, "retained-file");
            foreach (var path in new[] { directory, file, Path.Combine(proof, "absent-parent", "output") }) Require(await Failure(() => AuditReadContractExport.PublishAsync(ContractOptions(), path)).WaitAsync(Watchdog) is IOException or ArgumentException);
            Require(await File.ReadAllTextAsync(sentinel) == "retained-output" && await File.ReadAllTextAsync(file) == "retained-file");
            observe(new { phase = "contract_offline_publication", existing_file_and_directory_retained = true, missing_parent_rejected = true, create_new_promotion = true, hostile_filesystem_race_not_claimed = true });
        });
        await check("offline actual CLI requires no connection TLS or authentication configuration", async () =>
        {
            var destination = Path.Combine(proof, "cli-both"); var positive = await ContractCli("--export-audit-contracts=" + destination, "--resource=true");
            await File.WriteAllTextAsync(Path.Combine(proof, "cli-positive.stdout.txt"), positive.Stdout); await File.WriteAllTextAsync(Path.Combine(proof, "cli-positive.stderr.txt"), positive.Stderr);
            Require(positive.Exit == 0 && File.Exists(Path.Combine(destination, "openapi.json")) && File.Exists(Path.Combine(destination, "schema.graphql")));
            var old = File.ReadAllBytes(Path.Combine(destination, "manifest.json"));
            var negatives = new[] {
                new[] { "--export-audit-contracts=" + Path.Combine(proof, "cli-invalid"), "--resource=not-a-boolean" },
                new[] { "--export-audit-contracts=" + destination, "--resource=true" },
                new[] { "--export-audit-contracts" },
                new[] { "--export-audit-contracts=" + Path.Combine(proof, "cli-duplicate"), "--resource=true", "--resource=false" },
                new[] { "--export-audit-contracts=" + Path.Combine(proof, "cli-unknown"), "--unexpected-secret=CONTRACT-ARGUMENT-SENTINEL" }
            };
            for (var index = 0; index < negatives.Length; index++)
            {
                var negative = await ContractCli(negatives[index]);
                await File.WriteAllTextAsync(Path.Combine(proof, $"cli-negative-{index}.stdout.txt"), negative.Stdout);
                await File.WriteAllTextAsync(Path.Combine(proof, $"cli-negative-{index}.stderr.txt"), negative.Stderr);
                Require(negative.Exit == 2 && string.IsNullOrWhiteSpace(negative.Stdout));
                using var rejected = JsonDocument.Parse(negative.Stderr);
                Require(rejected.RootElement.GetProperty("status").GetString() == "failed" && rejected.RootElement.GetProperty("code").GetString() == "audit.contract_export_rejected" &&
                    rejected.RootElement.GetProperty("message").GetString() == "Audit contract export rejected; input, paths, credentials and vendor exception details are omitted." &&
                    rejected.RootElement.GetProperty("counters").GetProperty("HandlerFactoryCalls").GetInt32() == 0 && rejected.RootElement.GetProperty("counters").GetProperty("DispatchCalls").GetInt32() == 0);
                Require(!negative.Stderr.Contains(proof, StringComparison.Ordinal) && !negative.Stderr.Contains("CONTRACT-ARGUMENT-SENTINEL", StringComparison.Ordinal));
            }
            Require(!Directory.Exists(Path.Combine(proof, "cli-invalid")) && !Directory.Exists(Path.Combine(proof, "cli-duplicate")) && !Directory.Exists(Path.Combine(proof, "cli-unknown")) && File.ReadAllBytes(Path.Combine(destination, "manifest.json")).SequenceEqual(old));
            observe(new { phase = "contract_offline_cli", separate_dotnet_process = true, no_connection_TLS_or_auth_args = true, malformed_and_overwrite_errors_bounded = true, prior_output_unchanged = true });
        });
        await check("offline typed selected IDs are subset of six generated registrations without factories", async () =>
        {
            var value = await AuditReadContractExport.BuildArtifactsAsync(ContractOptions()); using var manifest = JsonDocument.Parse(value.Files["manifest.json"]);
            var generated = manifest.RootElement.GetProperty("generatedOperationIds").EnumerateArray().Select(x => x.GetString()!).ToHashSet(StringComparer.Ordinal);
            Require(generated.SetEquals(new[] { "outbox.drain", "outbox.relay", "outbox.status", "trail.history", "trail.lookup", "trail.resource-history" }));
            var selected = manifest.RootElement.GetProperty("selectedOperationIds").EnumerateArray().Select(x => x.GetString()!).ToArray(); Require(selected.Length == 2 && selected.All(generated.Contains));
            var catalog = AuditReadTransportCatalog.Create(ContractOptions()); Require(catalog.Operations.Select(x => x.OperationId).ToHashSet(StringComparer.Ordinal).SetEquals(selected));
            ContractNoBusinessExecution(value.Counters);
            observe(new { phase = "contract_offline_generated_subset", actual_generated_ids = 6, selected_wire_ids = 2, handler_factory_and_dispatch_calls = 0, wire_and_internal_gateway_types_not_equated = true, no_runtime_activation_from_export_API = true });
        });
    }

    private static async Task ContractWire(Func<string, Func<Task>, Task> check, string proof, string connection, string connectionFile, List<string> schemas, Action<object> observe)
    {
        using var tls = new TlsFixture(); using var jwt = new JwtFixture();
        async Task<Fixture> Create()
        {
            var store = new PostgresStore(connection, "ac_" + Guid.NewGuid().ToString("N")); await store.Initialize(); schemas.Add(store.Schema);
            await using (var provision = await IndexedProfileComposition.ActivateAsync(IndexedProfileComposition.Configuration(true), store.Schema, IndexedProfileOpenMode.CreateNew, _ => ValueTask.FromResult(connection), new()))
            { var writer = provision.Storage ?? throw new InvalidOperationException("Missing contract fixture writer."); await writer.AppendOnceAsync(Record(Key(1)), default); await writer.AppendOnceAsync(Record(Key(1), "B"), default); }
            return new(store, connection, connectionFile, tls, jwt);
        }
        foreach (var graph in new[] { false, true })
        {
            var label = graph ? "GraphQL" : "HTTP";
            await check(label + " exported selected contracts match actual complete and selected response shapes", async () =>
            {
                var options = ContractOptions(); var artifacts = await AuditReadContractExport.BuildArtifactsAsync(options); var api = ContractOpenApi(artifacts);
                var f = await Create(); await using var host = await f.Start(options); using var client = f.Client(host);
                var resourceSchema = ContractResponseSchema(api, AuditReceiptTransportHost.ResourceHistoryPath); var lookupSchema = ContractResponseSchema(api, AuditReceiptTransportHost.LookupPath);
                var resource = await f.Send(client, graph, token: f.Token("both-reader"), selection: ContractResourceSelection(ContractViewScalars)); Require(resource.Success(graph) && ContractShape(resourceSchema, resource.Value(graph), !graph));
                Reply receipt;
                if (graph)
                {
                    var query = "query { trailReceipt(input:{tenant:\"A\",receiptId:\"" + Key(1) + "\"}) {tenant record{" + ContractViewScalars + "}} }";
                    receipt = await f.Send(client, true, token: f.Token("both-reader"), raw: JsonSerializer.Serialize(new { query }));
                    Require(receipt.Success(true) && ContractShape(lookupSchema, receipt.Root.GetProperty("data").GetProperty("trailReceipt"), false));
                    foreach (var side in new[] { "before", "after" })
                    { var fields = await f.Send(client, true, token: f.Token("both-reader"), selection: ContractResourceSelection("fields { name wasChanged " + side + " { kind text number boolean } }")); Require(fields.Success(true) && ContractShape(resourceSchema, fields.Value(true), false)); }
                    var executor = await host.App!.Services.GetRequiredService<IRequestExecutorProvider>().GetExecutorAsync();
                    Require(Encoding.UTF8.GetString(artifacts.Files["schema.graphql"]) == executor.Schema.ToString().Replace("\r\n", "\n").TrimEnd() + "\n");
                    using var noSchema = new HttpRequestMessage(HttpMethod.Get, "/graphql?sdl"); noSchema.Headers.Authorization = new("Bearer", f.Token("both-reader")); using var deniedSchema = await client.SendAsync(noSchema); Require(deniedSchema.StatusCode == HttpStatusCode.MethodNotAllowed);
                    var introspection = await f.Send(client, true, token: f.Token("both-reader"), raw: JsonSerializer.Serialize(new { query = "query { __schema { queryType { name } } }" })); Require(!introspection.Success(true));
                }
                else { receipt = await f.Receipt(client, false, f.Token("both-reader")); Require(receipt.Success(false) && ContractShape(lookupSchema, receipt.Root)); }
                Require(f.Probe.SourceFactories == 1 && f.Probe.SourceOpenAttempts == 1 && host.Plan.ActivationOrder.Count > 0);
                var directory = Path.Combine(proof, graph ? "wire-graphql" : "wire-http"); Directory.CreateDirectory(directory); foreach (var file in artifacts.Files) await File.WriteAllBytesAsync(Path.Combine(directory, file.Key), file.Value);
                observe(new { phase = "contract_wire_parity", transport = label, HTTP_full_JSON_and_GraphQL_selected_shapes = true, complete_type_surface_actual_SDL = graph, schema_requests_and_introspection_remain_disabled = graph, generated_checked_gateway_and_one_source = true });
            });
            await check(label + " resource-only export and runtime omit lookup and disabled transport work", async () =>
            {
                var options = ContractOptions(!graph, graph, false, true); var artifacts = await AuditReadContractExport.BuildArtifactsAsync(options); var f = await Create(); await using var host = await f.Start(options); using var client = f.Client(host);
                if (graph) Require(!Encoding.UTF8.GetString(artifacts.Files["schema.graphql"]).Contains("trailReceipt(", StringComparison.Ordinal)); else Require(!ContractOpenApi(artifacts)["paths"]!.AsObject().ContainsKey(AuditReceiptTransportHost.LookupPath));
                Require(!(await f.Receipt(client, graph, f.Token("receipt-only"))).Success(graph)); Require((await f.Send(client, !graph, token: f.Token())).Status == HttpStatusCode.NotFound);
                Require(f.Source.LookupQueries == 0 && f.Probe.HandlerFactories == 0 && f.Probe.GatewayFactories == 0 && f.Probe.ResourceHandlerFactories == 0 && (f.Probe.GraphQLServices > 0) == graph);
                Require((await f.Send(client, graph, token: f.Token())).Success(graph));
                observe(new { phase = "contract_wire_disabled", transport = label, exported_and_runtime_lookup_absent = true, disabled_transport_absent = true, disabled_lookup_handler_and_source = 0, GraphQL_services_only_when_selected = true });
            });
            await check(label + " exported metadata never expands same-ID tenant grants or cursor binding", async () =>
            {
                var f = await Create(); await using var host = await f.Start(ContractOptions(!graph, graph)); using var client = f.Client(host);
                var exported = await AuditReadContractExport.BuildArtifactsAsync(ContractOptions()); Require(exported.Files.Count == 3);
                var denied = await f.Send(client, graph, Q(tenant: "B"), f.Token()); Require(denied.Error(graph, "access.denied") && f.Source.ResourceQueries == 0 && f.Probe.ResourceHandlerFactories == 0);
                var sameLoginToken = f.Token("resource-both"); var a = await f.Send(client, graph, Q(), sameLoginToken); var b = await f.Send(client, graph, Q(tenant: "B"), sameLoginToken);
                Require(a.Success(graph) && b.Success(graph) && Keys(a, graph).Single() == Keys(b, graph).Single() && a.Value(graph).GetProperty("entries")[0].GetProperty("tenant").GetString() == "A" && b.Value(graph).GetProperty("entries")[0].GetProperty("tenant").GetString() == "B");
                var queries = f.Source.ResourceQueries; var handlers = f.Probe.ResourceHandlerFactories; var bad = Q(cursor: new("B", "entity", "shared", Key(1)));
                Require((await f.Send(client, graph, bad, f.Token("resource-both"))).Error(graph, "validation.failed") && f.Source.ResourceQueries == queries && f.Probe.ResourceHandlerFactories == handlers);
                observe(new { phase = "contract_wire_tenant_isolation", transport = label, same_receipt_resource_ID_A_B = true, same_authenticated_principal_separate_grants = true, forged_and_cross_bound_requests_no_query = true, artifacts_not_authority = true });
            });
            await check(label + " catalog extraction preserves fresh authority sibling isolation and shared capacity", async () =>
            {
                var f = await Create(); var options = ContractOptions() with { ConcurrencyLimits = new(1, 1) }; await using var host = await f.Start(options); using var client = f.Client(host);
                foreach (var revocation in new[] { "membership", "resource", "policy" })
                {
                    f.Authority.MembershipRevoked = revocation == "membership"; f.Authority.ResourceRevoked = revocation == "resource"; f.Authority.PolicyRevoked = revocation == "policy";
                    Require((await f.Send(client, graph, token: f.Token())).Error(graph, "access.denied") && f.Source.ResourceQueries == 0 && f.Probe.ResourceHandlerFactories == 0);
                }
                f.Authority.MembershipRevoked = false; f.Authority.ResourceRevoked = false; f.Authority.PolicyRevoked = false;
                if (graph)
                { var memberships = f.Authority.MembershipCalls; var siblings = await f.Siblings(client, f.Token()); Require(siblings.Root.GetProperty("errors").GetArrayLength() >= 1 && siblings.Root.GetProperty("data").GetProperty("a").GetProperty("entries")[0].GetProperty("tenant").GetString() == "A" && f.Authority.MembershipCalls == memberships + 2); }
                var hold = new AdmissionHold(1); f.Probe.AfterResourceProviderRead = hold.After; using var caller = new CancellationTokenSource(); var pending = f.Send(client, graph, token: f.Token("both-reader"), cancellationToken: caller.Token);
                try
                {
                    await hold.Entered(1); AdmissionCounts(host, 1, 1); var queries = f.Source.ResourceQueries; var lookups = f.Source.LookupQueries; var handlers = f.Probe.HandlerFactories;
                    var capacity = await f.Receipt(client, !graph, f.Token("both-reader")); Capacity(capacity, !graph); Require(f.Source.ResourceQueries == queries && f.Source.LookupQueries == lookups && f.Probe.HandlerFactories == handlers);
                    hold.Release(); Require((await pending.WaitAsync(Watchdog)).Success(graph)); AdmissionCounts(host, 0, 0); Require((await f.Receipt(client, !graph, f.Token("both-reader"))).Success(!graph));
                }
                finally { caller.Cancel(); hold.Release(); await Join(pending); }
                Require(f.Probe.BudgetFactories == 1); AdmissionCounts(host, 0, 0); await f.Sql().AppQuiescent();
                observe(new { phase = "contract_wire_authority_and_capacity", transport = label, fresh_membership_resource_policy = true, GraphQL_per_field_authority = graph, one_shared_cross_protocol_budget = true, positive_post_SQL_hold_not_SQL_running_claim = true, rejection_before_handler_query = true, release_recovery_and_join = true });
            });
        }
    }
}
