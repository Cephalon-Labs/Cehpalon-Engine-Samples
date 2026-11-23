using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;

namespace Business.OrderReplay;

internal sealed class ProofFailure(string message) : Exception(message);

internal sealed record Envelope(string Tenant, Guid EventId, Guid OrderId, string Sku, int Quantity,
    string EventType, int SchemaVersion, int AggregateVersion, string TraceId);

internal static class ReplayFixture
{
    internal static readonly TenantId Alpha = new("A");
    internal static readonly TenantId Beta = new("B");
    internal static readonly Envelope Expected = new(Alpha.Value,
        Guid.Parse("00000000-0000-0000-0000-000000000201"), Guid.Parse("00000000-0000-0000-0000-000000000101"),
        "fixture-sku", 2, "order.placed", 1, 0, "00000000000000000000000000000101");
    internal const string Place = "orders.place";
    internal const string Publish = "orders.publish";
    internal const string Reserve = "orders.reserve";
    internal const string Inspect = "orders.inspect";
    internal const string Resource = "order";
    internal static readonly string OrderKey = Expected.OrderId.ToString("D");
    private static readonly OperationContext Correlation = new("order-replay-fixture");

    internal static void Require(bool condition, string message)
    {
        if (!condition) throw new ProofFailure(message);
    }

    internal static async Task<T> ScopedAsync<T>(TenantId tenant, string operation,
        Func<TenantOperationContext, CancellationToken, Task<T>> execute, CancellationToken token)
    {
        var result = await DispatchAsync(tenant, tenant, operation, execute, token);
        Require(result.IsSuccess, "The selected scoped operation was denied.");
        return result.Value;
    }

    internal static async Task<OperationResult<T>> DispatchAsync<T>(TenantId allowed, TenantId requested, string operation,
        Func<TenantOperationContext, CancellationToken, Task<T>> execute, CancellationToken token)
    {
        var registry = new TenantOperationRegistryBuilder()
            .Register<Request, T>(operation, operation, Resource, request => request,
                request => new(request.Tenant, OrderKey), () => new Handler<T>(execute))
            .Build();
        var authority = new FixtureAuthority(allowed, operation);
        var security = new TenantSecurityServices(authority, new(["fixture"], ["fixture"]), authority, authority,
            TimeSpan.FromSeconds(15), authority);
        return await new TenantOperationDispatcher(registry, security)
            .DispatchAsync<Request, T>(operation, new(requested), Correlation, token);
    }

    private sealed record Request(TenantId Tenant);

    private sealed class Handler<T>(Func<TenantOperationContext, CancellationToken, Task<T>> execute)
        : ITenantOperationHandler<Request, T>
    {
        public async ValueTask<OperationResult<T>> HandleAsync(Request request, TenantOperationContext context, CancellationToken token) =>
            OperationResult<T>.Success(await execute(context, token));
    }

    private sealed class FixtureAuthority(TenantId allowed, string operation)
        : IIdentitySource, ITenantMembershipSource, IResourceScopeSource, ITenantAccessPolicy
    {
        private readonly PrincipalId principal = new("fixture", allowed.Value);
        private readonly DateTimeOffset validAt = DateTimeOffset.UtcNow;

        public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult<IdentitySnapshot?>(new(principal, "fixture", validAt.AddMinutes(-1), validAt.AddMinutes(1)));

        public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot identity, TenantId tenant,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult<TenantMembershipSnapshot?>(principal.Equals(identity.Principal) && allowed.Equals(tenant)
                ? new(principal, allowed, true, validAt.AddMinutes(-1), validAt.AddMinutes(1), "fixture-v1") : null);

        public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId tenant, string kind, string id,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult<ResourceScopeSnapshot?>(allowed.Equals(tenant) && kind == Resource && id == OrderKey
                ? new(allowed, kind, id, "fixture-v1") : null);

        public ValueTask<bool> IsAllowedAsync(TenantAccessRequest request, CancellationToken cancellationToken) =>
            ValueTask.FromResult(request.Tenant.Equals(allowed) && request.Action == operation);
    }
}
