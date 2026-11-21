using System.Runtime.ExceptionServices;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;

namespace Cehpalon.Engine.Tenancy;

public sealed class TenantReadSetRequest
{
    internal TenantReadSetRequest(IdentitySnapshot identity, string operationId, string resourceKind, string resourceId)
        => (Identity, OperationId, ResourceKind, ResourceId) = (identity, operationId, resourceKind, resourceId);
    public IdentitySnapshot Identity { get; }
    public string OperationId { get; }
    public string ResourceKind { get; }
    public string ResourceId { get; }
}

/// <summary>Data from a configured trusted grant source. Constructing it is not authorization.</summary>
public sealed class TenantReadSetSnapshot
{
    public const int MaximumTenants = 64;
    public TenantReadSetSnapshot(PrincipalId principal, string operationId, string resourceKind, string resourceId,
        IEnumerable<TenantId> tenants, DateTimeOffset notBeforeUtc, DateTimeOffset expiresAtUtc, string version)
    {
        Principal = principal ?? throw new ArgumentNullException(nameof(principal));
        OperationId = Cehpalon.Engine.Core.OperationId.RequireValid(operationId);
        ResourceKind = Cehpalon.Engine.Core.OperationId.RequireValid(resourceKind);
        ResourceId = Values.Opaque(resourceId, 512, nameof(resourceId)); Version = Values.Opaque(version, 128, nameof(version));
        if (expiresAtUtc <= notBeforeUtc) throw new ArgumentException("Read-set validity must be a positive interval.");
        ArgumentNullException.ThrowIfNull(tenants);
        var copy = tenants.Take(MaximumTenants + 1).ToArray();
        if (copy.Length is < 1 or > MaximumTenants || copy.Any(t => t is null) || copy.Distinct().Count() != copy.Length)
            throw new ArgumentException("A read grant needs 1 to 64 exact unique tenants.", nameof(tenants));
        Tenants = Array.AsReadOnly(copy); NotBeforeUtc = notBeforeUtc.ToUniversalTime(); ExpiresAtUtc = expiresAtUtc.ToUniversalTime();
    }
    public PrincipalId Principal { get; }
    public string OperationId { get; }
    public string ResourceKind { get; }
    public string ResourceId { get; }
    public IReadOnlyList<TenantId> Tenants { get; }
    public DateTimeOffset NotBeforeUtc { get; }
    public DateTimeOffset ExpiresAtUtc { get; }
    public string Version { get; }
}

public interface ITenantReadSetSource
{
    /// <summary>Resolve a fresh explicit read-set grant; null denies. Do not derive it from caller tenant/header/role assertions.</summary>
    ValueTask<TenantReadSetSnapshot?> ResolveAsync(TenantReadSetRequest request, CancellationToken cancellationToken);
}

public sealed class TenantReadValue<TResponse>
{
    internal TenantReadValue(TenantId tenant, TResponse value) => (Tenant, Value) = (tenant, value);
    public TenantId Tenant { get; }
    public TResponse Value { get; }
}

public sealed class TenantReadSetResult<TResponse>
{
    internal TenantReadSetResult(List<TenantReadValue<TResponse>> values) => Results = Array.AsReadOnly(values.ToArray());
    public IReadOnlyList<TenantReadValue<TResponse>> Results { get; }
}

/// <summary>
/// Trusted read-only registration. The framework fixes action=read and supplies a checked tenant context;
/// trusted application code must keep the handler/data port read-only and freeze mutable request graphs.
/// </summary>
public sealed class TenantReadSetOperation<TQuery, TResponse>
{
    private readonly Func<TQuery, TQuery> freeze;
    private readonly Func<TQuery, string> select;
    private readonly TenantOperationRegistry registry;
    public TenantReadSetOperation(string operationId, string resourceKind, Func<TQuery, TQuery> freezeRequest,
        Func<TQuery, string> selectResourceId, Func<ITenantOperationHandler<TQuery, TResponse>> factory)
    {
        OperationId = Cehpalon.Engine.Core.OperationId.RequireValid(operationId);
        ResourceKind = Cehpalon.Engine.Core.OperationId.RequireValid(resourceKind);
        freeze = freezeRequest ?? throw new ArgumentNullException(nameof(freezeRequest));
        select = selectResourceId ?? throw new ArgumentNullException(nameof(selectResourceId));
        ArgumentNullException.ThrowIfNull(factory);
        registry = new TenantOperationRegistryBuilder().Register<Invocation, TResponse>(OperationId, "read", ResourceKind,
            invocation => new(invocation.Tenant, freeze(invocation.Query), invocation.ResourceId),
            invocation => new(invocation.Tenant, invocation.ResourceId), () => new QueryHandler(factory, ResourceKind)).Build();
    }
    public string OperationId { get; }
    public string ResourceKind { get; }
    internal TQuery Freeze(TQuery query) => freeze(query);
    internal string Select(TQuery query) => Values.Opaque(select(query), 512, "resourceId");
    internal ValueTask<OperationResult<TResponse>> DispatchAsync(TQuery query, string resourceId, TenantId tenant,
        TenantSecurityServices services, TenantOperationConcurrencyBudget? budget, OperationContext correlation, CancellationToken token)
    {
        var dispatcher = budget is null ? new TenantOperationDispatcher(registry, services)
            : TenantOperationDispatcher.WithTenantConcurrencyBudget(registry, services, budget);
        return dispatcher.DispatchAsync<Invocation, TResponse>(OperationId, new(tenant, query, resourceId), correlation, token);
    }
    private sealed record Invocation(TenantId Tenant, TQuery Query, string ResourceId);
    private sealed class QueryHandler : ITenantOperationHandler<Invocation, TResponse>, IAsyncDisposable
    {
        private readonly ITenantOperationHandler<TQuery, TResponse> owned;
        private readonly string kind;
        internal QueryHandler(Func<ITenantOperationHandler<TQuery, TResponse>> factory, string kind)
        { owned = factory() ?? throw new InvalidOperationException("Read handler factory returned null."); this.kind = kind; }
        public async ValueTask<OperationResult<TResponse>> HandleAsync(Invocation request, TenantOperationContext context, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); context.DemandAccess(request.Tenant, kind, request.ResourceId, "read");
            var result = await owned.HandleAsync(request.Query, context, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested(); context.DemandAccess(request.Tenant, kind, request.ResourceId, "read");
            return result;
        }
        public async ValueTask DisposeAsync()
        {
            if (owned is IAsyncDisposable asyncDisposable) await asyncDisposable.DisposeAsync().ConfigureAwait(false);
            else if (owned is IDisposable disposable) disposable.Dispose();
        }
    }
}

/// <summary>
/// Bounded sequential read fanout over explicit grants and the normal tenant boundary.
/// Never returns partial data. Earlier permitted reads may execute before a later denial/fault.
/// This is not an atomic cross-provider snapshot, write coordinator or universal admin bypass.
/// </summary>
public sealed class TenantReadSetDispatcher
{
    private readonly TenantSecurityServices services;
    private readonly ITenantReadSetSource source;
    private readonly TenantOperationConcurrencyBudget? budget;
    public TenantReadSetDispatcher(TenantSecurityServices services, ITenantReadSetSource source,
        TenantOperationConcurrencyBudget? concurrencyBudget = null)
    {
        this.services = services ?? throw new ArgumentNullException(nameof(services));
        this.source = source ?? throw new ArgumentNullException(nameof(source)); budget = concurrencyBudget;
    }
    public async ValueTask<OperationResult<TenantReadSetResult<TResponse>>> DispatchAsync<TQuery, TResponse>(
        TenantReadSetOperation<TQuery, TResponse> operation, TQuery request, OperationContext correlation,
        IEnumerable<TenantId>? requestedTenants = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(operation); ArgumentNullException.ThrowIfNull(correlation);
        cancellationToken.ThrowIfCancellationRequested();
        using var run = new ReadRun(services);
        OperationResult<TenantReadSetResult<TResponse>>? result = null; Exception? failure = null;
        try { result = await ExecuteAsync(operation, request, correlation, requestedTenants, run, cancellationToken).ConfigureAwait(false); }
        catch (TenantAuditWriteException error) when (ReferenceEquals(error, run.RootAuthorizationFailure)) { throw; }
        catch (Exception error) { failure = error; }
        if (services.Audit is not null)
        {
            var outcome = failure is OperationCanceledException ? TenantAuditOutcome.Cancelled : failure is not null ? TenantAuditOutcome.Faulted
                : result!.IsSuccess ? TenantAuditOutcome.Succeeded : result.Error.Code == "access.denied" ? TenantAuditOutcome.Denied : TenantAuditOutcome.Rejected;
            try { await services.Audit.AppendAsync(run.Entry(operation.OperationId, TenantAuditStage.Terminal, outcome), run.MayHaveExecuted).ConfigureAwait(false); }
            catch (TenantAuditWriteException auditFailure) when (failure is not null)
            { throw new AggregateException("Tenant read set and required audit persistence failed.", failure, auditFailure); }
        }
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
        cancellationToken.ThrowIfCancellationRequested();
        // Audit records the processing outcome at its observation point. Audit persistence and response
        // delivery are not atomic: an expired lease after the required write still withholds all rows.
        if (result!.IsSuccess)
        {
            try { run.DemandActive(); }
            catch (TenantAccessDeniedException) { return Denied<TResponse>(); }
        }
        return result;
    }
    private async ValueTask<OperationResult<TenantReadSetResult<TResponse>>> ExecuteAsync<TQuery, TResponse>(
        TenantReadSetOperation<TQuery, TResponse> operation, TQuery request, OperationContext correlation,
        IEnumerable<TenantId>? requestedTenants, ReadRun run, CancellationToken token)
    {
        // Snapshot both caller-controlled inputs before any identity/authority await.
        var query = operation.Freeze(request); var resourceId = operation.Select(query);
        var subset = requestedTenants?.Take(TenantReadSetSnapshot.MaximumTenants + 1).ToArray();
        if (subset is not null && (subset.Length is < 1 or > TenantReadSetSnapshot.MaximumTenants || subset.Any(t => t is null)
            || subset.Distinct().Count() != subset.Length)) return Denied<TResponse>();
        token.ThrowIfCancellationRequested(); var started = services.TimeProvider.GetUtcNow();
        var identity = await services.IdentitySource.ResolveAsync(token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        if (!services.IdentityTrust.IsAccepted(identity, services.TimeProvider.GetUtcNow())) return Denied<TResponse>();
        run.Identity = identity;
        var grant = await source.ResolveAsync(new(identity!, operation.OperationId, operation.ResourceKind, resourceId), token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested(); var now = services.TimeProvider.GetUtcNow();
        if (grant is null || !grant.Principal.Equals(identity!.Principal) || !StringComparer.Ordinal.Equals(grant.OperationId, operation.OperationId)
            || !StringComparer.Ordinal.Equals(grant.ResourceKind, operation.ResourceKind) || !StringComparer.Ordinal.Equals(grant.ResourceId, resourceId)
            || now < started || grant.NotBeforeUtc > now || now >= grant.ExpiresAtUtc || !services.IdentityTrust.IsAccepted(identity, now)) return Denied<TResponse>();
        if (subset is not null && subset.Any(t => !grant.Tenants.Contains(t))) return Denied<TResponse>();
        var selected = subset ?? grant.Tenants.ToArray(); run.Grant = grant;
        var maximum = services.MaximumLeaseLifetime.Ticks > DateTimeOffset.MaxValue.Ticks - now.UtcTicks
            ? DateTimeOffset.MaxValue : now.Add(services.MaximumLeaseLifetime);
        var expires = identity!.ExpiresAtUtc < grant.ExpiresAtUtc ? identity.ExpiresAtUtc : grant.ExpiresAtUtc;
        if (maximum < expires) expires = maximum;
        run.Start = now; run.Expires = expires; run.Lease = new(services.TimeProvider, now, expires, identity);
        if (services.Audit is not null)
        {
            try { await services.Audit.AppendAsync(run.Entry(operation.OperationId, TenantAuditStage.Authorization, TenantAuditOutcome.Authorized), false).ConfigureAwait(false); }
            catch (TenantAuditWriteException error) { run.RootAuthorizationFailure = error; throw; }
        }
        var childServices = new TenantSecurityServices(new PinnedIdentitySource(services.IdentitySource, run), services.IdentityTrust,
            services.Memberships, services.Resources, services.MaximumLeaseLifetime, services.Policy, services.TimeProvider,
            services.Audit?.ForParent(run.Id));
        var values = new List<TenantReadValue<TResponse>>(selected.Length);
        foreach (var tenant in selected)
        {
            token.ThrowIfCancellationRequested();
            try { run.DemandActive(); }
            catch (TenantAccessDeniedException) { return Denied<TResponse>(); }
            run.MayHaveExecuted = true;
            var child = await operation.DispatchAsync(query, resourceId, tenant, childServices, budget, correlation, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            try { run.DemandActive(); }
            catch (TenantAccessDeniedException) { return Denied<TResponse>(); }
            if (!child.IsSuccess) return child.Error.Code == "access.denied" ? Denied<TResponse>()
                : OperationResult<TenantReadSetResult<TResponse>>.Failure(new("tenant.read_set_failed", "The tenant read set could not be completed."));
            values.Add(new(tenant, child.Value));
        }
        return OperationResult<TenantReadSetResult<TResponse>>.Success(new(values));
    }
    private static OperationResult<TenantReadSetResult<TResponse>> Denied<TResponse>()
        => OperationResult<TenantReadSetResult<TResponse>>.Failure(new("access.denied", "Access denied."));
    private sealed class ReadRun(TenantSecurityServices services) : IDisposable
    {
        internal readonly Guid Id = services.Audit is null ? Guid.Empty : Guid.NewGuid();
        internal IdentitySnapshot? Identity; internal TenantReadSetSnapshot? Grant; internal AuthorizationLease? Lease;
        internal DateTimeOffset Start, Expires; internal bool MayHaveExecuted; internal TenantAuditWriteException? RootAuthorizationFailure;
        internal void DemandActive() => (Lease ?? throw new TenantAccessDeniedException()).DemandActive();
        internal TenantAuditEvent Entry(string operationId, TenantAuditStage stage, TenantAuditOutcome outcome)
            => new(Id, stage, outcome, services.TimeProvider.GetUtcNow(), operationId, "read", "tenant-read-set", Identity?.Principal,
                resourceId: Grant?.Version, parentInvocationId: services.Audit?.ParentInvocationId);
        public void Dispose() => Lease?.Dispose();
    }
    private sealed class PinnedIdentitySource(IIdentitySource source, ReadRun run) : IIdentitySource
    {
        public async ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken cancellationToken)
        {
            try { run.DemandActive(); } catch (TenantAccessDeniedException) { return null; }
            var fresh = await source.ResolveAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            try { run.DemandActive(); } catch (TenantAccessDeniedException) { return null; }
            if (fresh is null || !fresh.Principal.Equals(run.Identity!.Principal)
                || !StringComparer.Ordinal.Equals(fresh.AuthenticationScheme, run.Identity.AuthenticationScheme)
                || !StringComparer.Ordinal.Equals(fresh.SessionId, run.Identity.SessionId)) return null;
            var before = fresh.NotBeforeUtc > run.Start ? fresh.NotBeforeUtc : run.Start;
            var after = fresh.ExpiresAtUtc < run.Expires ? fresh.ExpiresAtUtc : run.Expires;
            return after > before ? fresh.WithValidity(before, after).IntersectValidity(run.Identity) : null;
        }
    }
}
