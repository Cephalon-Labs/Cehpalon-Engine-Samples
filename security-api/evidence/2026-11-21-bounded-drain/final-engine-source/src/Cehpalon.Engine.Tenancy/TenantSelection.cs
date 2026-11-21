using Cehpalon.Engine.Core;

namespace Cehpalon.Engine.Tenancy;

/// <summary>Untrusted destination selection. It does not change the authenticated principal or a global current tenant.</summary>
public sealed class TenantSelectionRequest
{
    public TenantSelectionRequest(TenantId tenant) => Tenant = tenant ?? throw new ArgumentNullException(nameof(tenant));
    public TenantId Tenant { get; }
}

/// <summary>A successful selection observation, not a reusable authorization token.</summary>
public sealed class TenantSelectionResult
{
    internal TenantSelectionResult(TenantId tenant) => Tenant = tenant;
    public TenantId Tenant { get; }
}

public static class TenantSelectionRegistration
{
    /// <summary>Register destination selection under fresh normal tenant authority checks.</summary>
    public static TenantOperationRegistryBuilder RegisterTenantSelection(this TenantOperationRegistryBuilder builder,
        string operationId = "tenant.select")
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.Register<TenantSelectionRequest, TenantSelectionResult>(operationId, "select", "tenant",
            request => new(request.Tenant), request => new(request.Tenant, request.Tenant.Value), () => new SelectionHandler());
    }

    private sealed class SelectionHandler : ITenantOperationHandler<TenantSelectionRequest, TenantSelectionResult>
    {
        public ValueTask<OperationResult<TenantSelectionResult>> HandleAsync(TenantSelectionRequest request,
            TenantOperationContext context, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            context.DemandAccess(request.Tenant, "tenant", request.Tenant.Value, "select");
            return ValueTask.FromResult(OperationResult<TenantSelectionResult>.Success(new(context.Tenant)));
        }
    }
}
