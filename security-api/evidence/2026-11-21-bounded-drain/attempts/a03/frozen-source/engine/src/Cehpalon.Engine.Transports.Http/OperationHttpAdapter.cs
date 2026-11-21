using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Nodes;
using System.Text.Json.Schema;
using Cehpalon.Engine.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;

namespace Cehpalon.Engine.Transports.Http;

/// <summary>Bounded, authenticated JSON POST adapter. The application owns protocol authentication and tenant dispatch wiring.</summary>
public static class OperationHttpAdapter
{
    public const int MaximumBodyBytes = 16 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        NumberHandling = JsonNumberHandling.Strict,
        RespectNullableAnnotations = true,
        RespectRequiredConstructorParameters = true,
        MaxDepth = 32
    };

    /// <summary>
    /// Export a detached structural schema using the adapter's actual serializer policy.
    /// This executes no validator/handler and grants no tenant authority. Object-only
    /// request envelopes, byte/Unicode checks and semantic validators remain separate.
    /// </summary>
    public static JsonNode ExportJsonSchema<TContract>() => ExportJsonSchema(typeof(TContract), JsonOptions);

    /// <summary>Export the actual adapter-created problem envelope without executing an operation.</summary>
    public static JsonNode ExportErrorJsonSchema() => ExportJsonSchema(
        ErrorPayload(400, TransportErrors.ValidationFailed()).GetType(), JsonSerializerOptions.Default);

    private static JsonNode ExportJsonSchema(Type contract, JsonSerializerOptions policy)
    {
        // Resolve metadata on a copy: do not expose or mutate shared serializer options.
        var options = new JsonSerializerOptions(policy);
        options.MakeReadOnly(populateMissingResolver: true);
        return options.GetJsonSchemaAsNode(contract, new JsonSchemaExporterOptions
        {
            // A generic T cannot retain a caller's top-level T? annotation. Core
            // permits nullable successful responses, so retain the BCL null-oblivious
            // default. Hosts add the adapter's object-only request envelope separately.
            TreatNullObliviousAsNonNullable = false
        });
    }

    /// <summary>Map only when the API module is enabled. Mapping does not instantiate a dispatcher or business handler.</summary>
    public static RouteHandlerBuilder MapOperation<TRequest, TResponse>(this IEndpointRouteBuilder endpoints,
        string pattern, OperationBinding<TRequest, TResponse> binding)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentException.ThrowIfNullOrWhiteSpace(pattern);
        if (!pattern.StartsWith('/') || pattern.Contains('?') || pattern.Contains('#'))
            throw new ArgumentException("An operation route must be an absolute path without query or fragment.", nameof(pattern));
        Func<HttpContext, Task> handler = context => ExecuteAsync(context, binding);
        return endpoints.MapPost(pattern, (Delegate)handler).RequireAuthorization();
    }

    /// <summary>
    /// Execute a mapped operation. The authenticated principal check also applies when called directly.
    /// Hosts must never construct an authenticated principal from unvalidated caller headers.
    /// </summary>
    public static async Task ExecuteAsync<TRequest, TResponse>(HttpContext context, OperationBinding<TRequest, TResponse> binding)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(binding);
        var cancellationToken = context.RequestAborted;
        cancellationToken.ThrowIfCancellationRequested();
        if (!context.User.Identities.Any(identity => identity.IsAuthenticated))
        {
            await WriteErrorAsync(context, 401, new OperationError("authentication.required", "Authentication required."));
            return;
        }
        if (!HttpMethods.IsPost(context.Request.Method))
        {
            context.Response.Headers.Allow = "POST";
            await WriteErrorAsync(context, 405, new OperationError("request.method", "POST is required."));
            return;
        }
        if (!IsSupportedContentType(context.Request) || context.Request.Headers.ContentEncoding.Count != 0)
        {
            await WriteErrorAsync(context, 415, new OperationError("request.content_type", "UTF-8 JSON is required."));
            return;
        }
        if (context.Request.ContentLength > MaximumBodyBytes)
        {
            await WriteTooLargeAsync(context);
            return;
        }

        try
        {
            var body = new byte[MaximumBodyBytes + 1];
            var length = 0;
            while (length < body.Length)
            {
                var count = await context.Request.Body.ReadAsync(body.AsMemory(length), cancellationToken);
                if (count == 0) break;
                length += count;
            }
            if (length > MaximumBodyBytes)
            {
                await WriteTooLargeAsync(context);
                return;
            }

            TRequest? request;
            try
            {
                using var document = JsonDocument.Parse(body.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 32 });
                if (document.RootElement.ValueKind != JsonValueKind.Object || !HasUnambiguousJson(document.RootElement))
                    throw new JsonException();
                request = document.RootElement.Deserialize<TRequest>(JsonOptions);
                if (request is null) throw new JsonException();
            }
            catch (JsonException)
            {
                await WriteErrorAsync(context, 400, TransportErrors.ValidationFailed());
                return;
            }
            if (binding.Validate(request) is not null)
            {
                // Validation details may encode request values; transport errors intentionally stay generic.
                await WriteErrorAsync(context, 400, TransportErrors.ValidationFailed());
                return;
            }

            cancellationToken.ThrowIfCancellationRequested();
            var dispatcher = context.RequestServices.GetRequiredService<ITransportOperationDispatcher>();
            var correlationId = context.TraceIdentifier;
            if (string.IsNullOrWhiteSpace(correlationId) || correlationId.Length > 256) correlationId = Guid.NewGuid().ToString("N");
            var result = await dispatcher.DispatchAsync<TRequest, TResponse>(context, binding.OperationId, request,
                new OperationContext(correlationId), cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            if (result.IsSuccess)
            {
                // Serialize before starting the response so serialization faults do not expose partial data.
                var payload = JsonSerializer.SerializeToUtf8Bytes(result.Value, JsonOptions);
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json; charset=utf-8";
                await context.Response.Body.WriteAsync(payload, cancellationToken);
            }
            else
            {
                var error = TransportErrors.ForClient(result.Error);
                await WriteErrorAsync(context, ErrorStatusCode(error), error);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) when (!context.Response.HasStarted)
        {
            await WriteErrorAsync(context, 500, TransportErrors.InternalError());
        }
    }

    public static int ErrorStatusCode(OperationError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return error.Code switch
        {
            TransportErrors.AccessDeniedCode => 403,
            TransportErrors.ValidationCode => 400,
            "resource.not_found" => 404,
            "resource.conflict" => 409,
            OperationConcurrencyBudget.CapacityExceededCode => 503,
            TransportErrors.InternalCode => 500,
            _ => 422
        };
    }

    private static bool IsSupportedContentType(HttpRequest request)
    {
        if (!MediaTypeHeaderValue.TryParse(request.ContentType, out var mediaType)) return false;
        if (!mediaType.MediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase)) return false;
        var charset = mediaType.Charset.Value;
        return string.IsNullOrEmpty(charset) || charset.Equals("utf-8", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasUnambiguousJson(JsonElement element)
    {
        // JsonDocument accepts escaped lone surrogates but accessing their decoded text throws.
        // Keep this normalization inside structural validation, separate from trusted converters/validators.
        try { return IsUnambiguous(element); }
        catch (InvalidOperationException) { return false; }
    }

    private static bool IsUnambiguous(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
                if (!names.Add(property.Name) || !ValidUnicode(property.Name) || !IsUnambiguous(property.Value)) return false;
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray()) if (!IsUnambiguous(item)) return false;
        }
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

    private static Task WriteTooLargeAsync(HttpContext context)
        => WriteErrorAsync(context, 413, new OperationError("request.too_large", "Request body exceeds 16384 bytes."));

    private static async Task WriteErrorAsync(HttpContext context, int status, OperationError error)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(ErrorPayload(status, error));
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/problem+json; charset=utf-8";
        await context.Response.Body.WriteAsync(payload, context.RequestAborted);
    }

    private static object ErrorPayload(int status, OperationError error) => new
    {
        type = "about:blank", title = error.Message, status, code = error.Code
    };
}
