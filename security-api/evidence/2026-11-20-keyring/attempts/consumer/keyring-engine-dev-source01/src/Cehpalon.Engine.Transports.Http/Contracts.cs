using Cehpalon.Engine.Core;
using Microsoft.AspNetCore.Http;

namespace Cehpalon.Engine.Transports.Http;

/// <summary>Explicit typed transport contract. Validation must be pure and must not perform business/authority work.</summary>
public sealed class OperationBinding<TRequest, TResponse>
{
    private readonly Func<TRequest, OperationError?> validate;

    public OperationBinding(string operationId, Func<TRequest, OperationError?> validate)
    {
        OperationId = Core.OperationId.RequireValid(operationId);
        this.validate = validate ?? throw new ArgumentNullException(nameof(validate));
    }

    public string OperationId { get; }
    public OperationError? Validate(TRequest request) => validate(request);
}

/// <summary>
/// Host-owned invocation bridge. Protected hosts must authenticate using their configured protocol implementation,
/// then resolve fresh identity/tenant authority and invoke TenantOperationDispatcher. HttpContext and correlation
/// metadata themselves grant no tenant authority. Implementations must honor the supplied request cancellation.
/// </summary>
public interface ITransportOperationDispatcher
{
    ValueTask<OperationResult<TResponse>> DispatchAsync<TRequest, TResponse>(
        HttpContext httpContext, string operationId, TRequest request,
        OperationContext operationContext, CancellationToken cancellationToken);
}

public static class TransportErrors
{
    public const string ValidationCode = "validation.failed";
    public const string AccessDeniedCode = "access.denied";
    public const string CancelledCode = "operation.cancelled";
    public const string InternalCode = "internal.error";
    public static OperationError ValidationFailed() => new(ValidationCode, "Request validation failed.");
    public static OperationError AccessDenied() => new(AccessDeniedCode, "Access denied.");
    public static OperationError InternalError() => new(InternalCode, "An internal error occurred.");

    private static readonly OperationError CapacityUnavailable = new(
        OperationConcurrencyBudget.CapacityExceededCode, "Operation capacity is temporarily unavailable.");

    /// <summary>Use fixed public messages for reserved authority and capacity failures.</summary>
    public static OperationError ForClient(OperationError error) => error.Code switch
    {
        AccessDeniedCode => AccessDenied(),
        OperationConcurrencyBudget.CapacityExceededCode => CapacityUnavailable,
        _ => error
    };
}
