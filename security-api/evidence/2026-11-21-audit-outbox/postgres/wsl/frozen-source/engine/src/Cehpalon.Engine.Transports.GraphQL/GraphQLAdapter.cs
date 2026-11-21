using System.Text.Json;
using HotChocolate.AspNetCore;
using HotChocolate.Execution.Configuration;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Cehpalon.Engine.Transports.GraphQL;

/// <summary>Opt-in GraphQL HTTP adapter. Call neither method when the module is disabled.</summary>
public static class GraphQLAdapter
{
    public const int MaximumBodyBytes = 16 * 1024;

    public static IRequestExecutorBuilder AddCehpalonGraphQL(this IServiceCollection services, GraphQLOperationCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(catalog);
        services.AddHttpContextAccessor();
        var builder = services.AddGraphQLServer()
            .AddQueryType(catalog.QueryType())
            .DisableIntrospection(true)
            .AddMaxExecutionDepthRule(8)
            .ModifyOptions(options => { options.EnableDefer = false; options.EnableStream = false; })
            .ModifyRequestOptions(options => options.IncludeExceptionDetails = false)
            .ModifyCostOptions(options =>
            {
                options.MaxFieldCost = 1000;
                options.MaxTypeCost = 1000;
                options.EnforceCostLimits = true;
            });
        if (catalog.MutationType() is { } mutation) builder.AddMutationType(mutation);
        return builder;
    }

    public static IEndpointConventionBuilder MapCehpalonGraphQL(this IEndpointRouteBuilder endpoints, string path = "/graphql")
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        if (string.IsNullOrEmpty(path) || !path.StartsWith('/') || path.Contains('{') || path.Contains('*') || path.Contains('?'))
            throw new ArgumentException("Use a literal absolute endpoint path.", nameof(path));
        var endpoint = endpoints.MapGraphQLHttp(path).WithOptions(options =>
        {
            options.EnableGetRequests = false;
            options.EnableSchemaRequests = false;
            options.EnableMultipartRequests = false;
            options.Batching = AllowedBatching.None;
        });
        endpoint.Add(builder =>
        {
            var next = builder.RequestDelegate ?? throw new InvalidOperationException("GraphQL HTTP delegate is unavailable.");
            builder.RequestDelegate = http => GuardAsync(http, next);
        });
        return endpoint;
    }

    private static async Task GuardAsync(HttpContext http, RequestDelegate next)
    {
        if (!HttpMethods.IsPost(http.Request.Method)) { http.Response.StatusCode = StatusCodes.Status405MethodNotAllowed; return; }
        if (!http.User.Identities.Any(identity => identity.IsAuthenticated)) { http.Response.StatusCode = StatusCodes.Status401Unauthorized; return; }
        if (!http.Request.HasJsonContentType()) { http.Response.StatusCode = StatusCodes.Status415UnsupportedMediaType; return; }
        if (http.Request.ContentLength > MaximumBodyBytes) { http.Response.StatusCode = StatusCodes.Status413PayloadTooLarge; return; }
        using var body = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var read = await http.Request.Body.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, MaximumBodyBytes + 1 - (int)body.Length)), http.RequestAborted).ConfigureAwait(false);
            if (read == 0) break;
            body.Write(buffer, 0, read);
            if (body.Length > MaximumBodyBytes) { http.Response.StatusCode = StatusCodes.Status413PayloadTooLarge; return; }
        }
        try
        {
            var bytes = body.GetBuffer().AsMemory(0, (int)body.Length);
            if (!HasValidStringEncoding(bytes.Span)) { http.Response.StatusCode = StatusCodes.Status400BadRequest; return; }
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
            if (!IsSupportedEnvelope(document.RootElement) || !IsUnique(document.RootElement))
            { http.Response.StatusCode = StatusCodes.Status400BadRequest; return; }
        }
        catch (JsonException) { http.Response.StatusCode = StatusCodes.Status400BadRequest; return; }
        catch (InvalidOperationException) { http.Response.StatusCode = StatusCodes.Status400BadRequest; return; }
        var original = http.Request.Body;
        body.Position = 0;
        http.Request.Body = body;
        http.Request.ContentLength = body.Length;
        try { await next(http).ConfigureAwait(false); }
        finally { http.Request.Body = original; }
    }

    private static bool HasValidStringEncoding(ReadOnlySpan<byte> json)
    {
        var reader = new Utf8JsonReader(json, new JsonReaderOptions { MaxDepth = 32 });
        while (reader.Read())
        {
            if (reader.TokenType is not (JsonTokenType.String or JsonTokenType.PropertyName)) continue;
            if (!ValidUnicode(reader.GetString()!)) return false;
            // JsonDocument may replace an escaped lone surrogate in a property name. Inspect raw escapes as well.
            var text = reader.ValueSpan;
            for (var index = 0; index < text.Length; index++)
            {
                if (text[index] != '\\') continue;
                index++;
                if (text[index] != 'u') continue;
                var unit = HexUnit(text.Slice(index + 1, 4));
                index += 4;
                if (unit is >= 0xDC00 and <= 0xDFFF) return false;
                if (unit is < 0xD800 or > 0xDBFF) continue;
                if (index + 6 >= text.Length || text[index + 1] != '\\' || text[index + 2] != 'u') return false;
                var low = HexUnit(text.Slice(index + 3, 4));
                if (low is < 0xDC00 or > 0xDFFF) return false;
                index += 6;
            }
        }
        return true;
    }

    private static int HexUnit(ReadOnlySpan<byte> value)
    {
        var result = 0;
        foreach (var digit in value) result = result * 16 + (digit <= '9' ? digit - '0' : (digit | 32) - 'a' + 10);
        return result;
    }

    private static bool IsSupportedEnvelope(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("query", out var query) || query.ValueKind != JsonValueKind.String)
            return false;
        foreach (var property in root.EnumerateObject())
        {
            if (property.Name == "query") continue;
            if (property.Name == "variables" && property.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Null) continue;
            if (property.Name == "operationName" && property.Value.ValueKind is JsonValueKind.String or JsonValueKind.Null) continue;
            return false;
        }
        return true;
    }

    private static bool IsUnique(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
                if (!names.Add(property.Name) || !ValidUnicode(property.Name) || !IsUnique(property.Value)) return false;
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray()) if (!IsUnique(item)) return false;
        else if (element.ValueKind == JsonValueKind.String && !ValidUnicode(element.GetString()!)) return false;
        return true;
    }

    private static bool ValidUnicode(string value)
    {
        for (var index = 0; index < value.Length; index++)
        {
            if (!char.IsSurrogate(value[index])) continue;
            if (!char.IsHighSurrogate(value[index]) || index + 1 >= value.Length || !char.IsLowSurrogate(value[++index])) return false;
        }
        return true;
    }
}
