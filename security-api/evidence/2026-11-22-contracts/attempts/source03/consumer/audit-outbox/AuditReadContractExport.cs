using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Transports.GraphQL;
using Cehpalon.Engine.Transports.Http;
using HotChocolate.Execution;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace AuditOutbox;

public sealed class AuditReadContractExportCounters
{
    public int HttpSchemaOperations, GraphQLRegistrations, GraphQLServices, GraphQLSchemaBuilds;
    public int GraphQLProvidersCreated, GraphQLProvidersDisposed, HandlerFactoryCalls, DispatchCalls;
    /// <summary>Trusted failure control only; no provider/payload exposure and never serialized.</summary>
    [JsonIgnore] public Action? BeforeGraphQLSchemaBuild;
}

public sealed class AuditReadContractArtifacts
{
    public IReadOnlyDictionary<string, byte[]> Files { get; }
    public AuditReadContractExportCounters Counters { get; }
    internal AuditReadContractArtifacts(SortedDictionary<string, byte[]> files, AuditReadContractExportCounters counters)
    { Files = new ReadOnlyDictionary<string, byte[]>(files); Counters = counters; }
}

/// <summary>Explicit offline structural export. Does not activate the host or confer authority.</summary>
public static class AuditReadContractExport
{
    static readonly UTF8Encoding Utf8 = new(false, true);
    static readonly JsonSerializerOptions Json = new() { IncludeFields = true, WriteIndented = true, NewLine = "\n" };

    public static async Task<AuditReadContractArtifacts> BuildArtifactsAsync(AuditReceiptTransportOptions options,
        AuditReadContractExportCounters? counters = null)
    {
        counters ??= new();
        var plan = AuditReceiptTransportHost.CompilePlan(options);
        AuditReceiptTransportHost.ValidateSelectedReadSettings(options);
        var catalog = AuditReadTransportCatalog.Create(options);
        var registry = new OperationRegistryBuilder();
        Cehpalon.Engine.Generated.OperationRegistrations.RegisterAll(registry, new ForbiddenFactory(counters));
        var generated = registry.Build().OperationIds;
        var selected = catalog.Operations.Select(x => x.OperationId).Order(StringComparer.Ordinal).ToArray();
        if (selected.Any(id => !generated.Contains(id, StringComparer.Ordinal)))
            throw new InvalidOperationException("Selected audit catalog operation is not generated.");
        var enabled = plan.ActivationOrder.ToHashSet(StringComparer.Ordinal);
        var http = enabled.Contains("receipt.http"); var graph = enabled.Contains("receipt.graphql");
        var files = new SortedDictionary<string, byte[]>(StringComparer.Ordinal);
        if (http) files.Add("openapi.json", Utf8.GetBytes(OpenApi(catalog, counters).ToJsonString(Json) + "\n"));
        if (graph) files.Add("schema.graphql", await GraphQLSchema(catalog, counters).ConfigureAwait(false));
        var artifacts = files.Select(x => new { name = x.Key, bytes = x.Value.LongLength, sha256 = Convert.ToHexStringLower(SHA256.HashData(x.Value)) }).ToArray();
        files.Add("manifest.json", Utf8.GetBytes(JsonSerializer.Serialize(new
        {
            schemaVersion = 1, profile = "audit-read", activationOrder = plan.ActivationOrder,
            generatedOperationIds = generated, selectedOperationIds = selected,
            httpOperationIds = http ? selected : [], graphqlOperationIds = graph ? selected : [],
            transports = catalog.Operations.Select(x => new { operationId = x.OperationId, httpPath = http ? x.HttpPath : null, graphqlField = graph ? x.GraphQLField : null }).ToArray(),
            artifacts, counters,
            limits = new[] {
                "Structural wire contracts only; CLR ranges, custom semantic/cursor validation, duplicate-name/Unicode/body/depth checks and fresh tenant authority remain separate.",
                "The HTTP document covers selected audit-read business POST routes only, not the GraphQL HTTP envelope or deployment security configuration.",
                "Generic bearer metadata does not choose an algorithm, issuer, audience or operation grant. Artifacts confer no tenant authority.",
                "Selected GraphQL export explicitly constructs/disposes an offline provider. No host, source, budget, TLS/key/credential read or dispatcher/authority call occurs.",
                "Network introspection/schema endpoints remain disabled. Publication assumes trusted plain parents and does not provide a hostile filesystem race sandbox.",
                "Unsigned bookmarks, cooperative read/capacity lifetimes and all experimental M0/provider/production limitations remain unchanged." }
        }, Json) + "\n"));
        return new(files, counters);
    }

    static async Task<byte[]> GraphQLSchema(AuditReadTransportCatalog catalog, AuditReadContractExportCounters counters)
    {
        var services = new ServiceCollection(); services.AddLogging();
        services.AddSingleton<ITransportOperationDispatcher>(new ForbiddenDispatcher(counters));
        counters.GraphQLRegistrations++;
        services.AddCehpalonGraphQL(catalog.GraphQL());
        counters.GraphQLServices = services.Count(x => (x.ServiceType.FullName ?? "").StartsWith("HotChocolate.", StringComparison.Ordinal));
        var provider = services.BuildServiceProvider(); counters.GraphQLProvidersCreated++;
        Exception? failure = null;
        try
        {
            counters.BeforeGraphQLSchemaBuild?.Invoke();
            var executor = await provider.GetRequiredService<IRequestExecutorProvider>().GetExecutorAsync().ConfigureAwait(false);
            counters.GraphQLSchemaBuilds++;
            return Utf8.GetBytes(executor.Schema.ToString().Replace("\r\n", "\n").TrimEnd() + "\n");
        }
        catch (Exception error) { failure = error; throw; }
        finally
        {
            try { await provider.DisposeAsync().ConfigureAwait(false); counters.GraphQLProvidersDisposed++; }
            catch (Exception cleanup) when (failure is not null)
            { throw new AggregateException("Offline schema export and provider cleanup failed.", failure, cleanup); }
        }
    }

    static JsonObject OpenApi(AuditReadTransportCatalog catalog, AuditReadContractExportCounters counters)
    {
        var paths = new JsonObject();
        foreach (var exposure in catalog.Exposures)
        {
            counters.HttpSchemaOperations++;
            var responses = new JsonObject {
                ["200"] = new JsonObject { ["description"] = "Projected successful audit read", ["content"] = Content("application/json", Resource(exposure.ResponseSchema(), "response:" + exposure.OperationId)) } };
            foreach (var code in new[] { "400", "403", "404", "409", "413", "415", "422", "500", "503" })
                responses[code] = new JsonObject { ["description"] = "Adapter protocol, validation, authority, capacity or handler error",
                    ["content"] = Content("application/problem+json", ObjectEnvelope(Resource(OperationHttpAdapter.ExportErrorJsonSchema(), "error:" + exposure.OperationId + ":" + code))) };
            responses["401"] = new JsonObject { ["description"] = "Authentication challenge; framework may emit no response body" };
            responses["405"] = new JsonObject { ["description"] = "Method rejected; framework may emit no response body" };
            paths[exposure.Path] = new JsonObject { ["post"] = new JsonObject {
                ["operationId"] = exposure.OperationId, ["security"] = new JsonArray(new JsonObject { ["Bearer"] = new JsonArray() }),
                ["requestBody"] = new JsonObject { ["required"] = true, ["content"] = Content("application/json", ObjectEnvelope(Resource(exposure.RequestSchema(), "request:" + exposure.OperationId))) },
                ["responses"] = responses, ["x-cehpalon-maximum-body-bytes"] = OperationHttpAdapter.MaximumBodyBytes, ["x-cehpalon-shape-only"] = true } };
        }
        return new JsonObject {
            ["openapi"] = "3.1.0", ["jsonSchemaDialect"] = "https://json-schema.org/draft/2020-12/schema",
            ["info"] = new JsonObject { ["title"] = "Experimental indexed audit reads", ["version"] = "1",
                ["description"] = "Selected audit-read POST routes only. Structural schemas do not fully model semantic validation, parser restrictions, read policy or fresh tenant authority." },
            ["paths"] = paths, ["components"] = new JsonObject { ["securitySchemes"] = new JsonObject { ["Bearer"] = new JsonObject {
                ["type"] = "http", ["scheme"] = "bearer", ["description"] = "Application-established JWT bearer trust and fresh tenant authorization are required; algorithm/issuer/audience/grants remain application configuration." } } } };
    }
    static JsonObject Content(string mediaType, JsonNode schema) => new() { [mediaType] = new JsonObject { ["schema"] = schema } };
    static JsonObject ObjectEnvelope(JsonNode schema) => new() { ["allOf"] = new JsonArray(new JsonObject { ["type"] = "object" }, schema) };
    static JsonNode Resource(JsonNode schema, string id)
    {
        if (schema is not JsonObject value) throw new InvalidOperationException("Expected object JSON Schema resource.");
        value["$id"] = "urn:cehpalon:audit-read:" + id; return value;
    }

    public static async Task<AuditReadContractArtifacts> PublishAsync(AuditReceiptTransportOptions options, string destination,
        AuditReadContractExportCounters? counters = null)
    {
        var target = ValidateDestination(destination);
        var artifacts = await BuildArtifactsAsync(options, counters).ConfigureAwait(false);
        Publish(target, artifacts.Files); return artifacts;
    }
    static string ValidateDestination(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal) || path.StartsWith(@"\\.\", StringComparison.Ordinal)) throw new IOException("Unsupported path.");
        var destination = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (destination.StartsWith(@"\\?\", StringComparison.Ordinal) || destination.StartsWith(@"\\.\", StringComparison.Ordinal)) throw new IOException("Unsupported path.");
        var parent = Path.GetDirectoryName(destination);
        if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent)) throw new IOException("Existing parent required.");
        PlainAncestors(destination); Absent(destination); return destination;
    }
    static void Publish(string destination, IReadOnlyDictionary<string, byte[]> files)
    {
        var parent = Path.GetDirectoryName(destination)!;
        var stage = Path.Combine(parent, ".cehpalon-audit-contracts-" + Guid.NewGuid().ToString("N"));
        PlainAncestors(parent); Absent(stage); Directory.CreateDirectory(stage);
        // Failed or partial staging is deliberately retained for inspection; never delete or reuse it.
        foreach (var pair in files)
        {
            PlainAncestors(stage);
            using var file = new FileStream(Path.Combine(stage, pair.Key), FileMode.CreateNew, FileAccess.Write, FileShare.None);
            file.Write(pair.Value); file.Flush(flushToDisk: true);
        }
        PlainAncestors(parent); PlainAncestors(stage); Absent(destination); Directory.Move(stage, destination);
    }
    static void Absent(string path)
    { try { _ = File.GetAttributes(path); } catch (FileNotFoundException) { return; } catch (DirectoryNotFoundException) { return; } throw new IOException("Destination already exists."); }
    static void PlainAncestors(string path)
    {
        for (var current = Path.GetFullPath(path); !string.IsNullOrEmpty(current); current = Path.GetDirectoryName(current))
        { try { if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new IOException("Plain parent required."); } catch (FileNotFoundException) { } catch (DirectoryNotFoundException) { } }
    }

    public static async Task<int> RunCommandAsync(string[] args)
    {
        var counters = new AuditReadContractExportCounters();
        try
        {
            var flags = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var arg in args)
            {
                var split = arg.Split('=', 2);
                if (split.Length != 2 || !flags.TryAdd(split[0], split[1])) throw new ArgumentException("Invalid export arguments.");
            }
            var allowed = new HashSet<string>(["--export-audit-contracts", "--http", "--graphql", "--receipt", "--resource", "--security"], StringComparer.Ordinal);
            if (flags.Keys.Any(x => !allowed.Contains(x)) || !flags.TryGetValue("--export-audit-contracts", out var destination)) throw new ArgumentException("Invalid export arguments.");
            bool Flag(string name, bool fallback) => !flags.TryGetValue(name, out var text) ? fallback : text switch { "true" => true, "false" => false, _ => throw new ArgumentException("Invalid boolean export option.") };
            var options = new AuditReceiptTransportOptions(Flag("--http", true), Flag("--graphql", true), Flag("--security", true)) {
                ReceiptLookupEnabled = Flag("--receipt", true), ResourceHistoryEnabled = Flag("--resource", false) };
            var artifacts = await PublishAsync(options, destination, counters).ConfigureAwait(false);
            Console.WriteLine(JsonSerializer.Serialize(new { status = "passed", files = artifacts.Files.Keys.ToArray(), counters }, Json)); return 0;
        }
        catch
        {
            Console.Error.WriteLine(JsonSerializer.Serialize(new { status = "failed", code = "audit.contract_export_rejected",
                message = "Audit contract export rejected; input, paths, credentials and vendor exception details are omitted.", counters }, Json)); return 2;
        }
    }
    sealed class ForbiddenFactory(AuditReadContractExportCounters counters) : IOperationHandlerFactory
    { public THandler Create<THandler>() where THandler : class { counters.HandlerFactoryCalls++; throw new InvalidOperationException("Offline export cannot construct operation handlers."); } }
    sealed class ForbiddenDispatcher(AuditReadContractExportCounters counters) : ITransportOperationDispatcher
    {
        public ValueTask<OperationResult<TResponse>> DispatchAsync<TRequest, TResponse>(HttpContext http, string id, TRequest request, OperationContext context, CancellationToken token)
        { counters.DispatchCalls++; throw new InvalidOperationException("Offline export cannot dispatch."); }
    }
}
