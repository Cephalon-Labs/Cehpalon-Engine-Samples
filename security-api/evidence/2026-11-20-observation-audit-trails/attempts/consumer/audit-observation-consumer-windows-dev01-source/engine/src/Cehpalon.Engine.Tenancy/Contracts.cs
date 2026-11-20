using System.Diagnostics.Metrics;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;

namespace Cehpalon.Engine.Tenancy;

public sealed class TenantId : IEquatable<TenantId>
{
    public TenantId(string value)
    {
        if (value is null || value.Length is < 1 or > 128 || !AlphaNumeric(value[0]) || value.Any(c=>!AlphaNumeric(c) && c is not ('_' or '.' or '-')))
            throw new ArgumentException("Tenant ID must match [A-Za-z0-9][A-Za-z0-9_.-]{0,127}.",nameof(value));
        Value=value;
    }
    private static bool AlphaNumeric(char value)=>value is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9';
    public string Value { get; }
    public bool Equals(TenantId? other)=>other is not null && StringComparer.Ordinal.Equals(Value,other.Value);
    public override bool Equals(object? other)=>other is TenantId id && Equals(id);
    public override int GetHashCode()=>StringComparer.Ordinal.GetHashCode(Value);
    public override string ToString()=>Value;
}

/// <summary>Untrusted request selection, not proof of membership or resource ownership.</summary>
public sealed class TenantTarget
{
    public TenantTarget(TenantId tenant,string resourceId)
    { Tenant=tenant??throw new ArgumentNullException(nameof(tenant)); ResourceId=Values.Opaque(resourceId,512,nameof(resourceId)); }
    public TenantId Tenant { get; }
    public string ResourceId { get; }
}

/// <summary>A representation from the configured authoritative membership source; construction is not authority.</summary>
public sealed class TenantMembershipSnapshot
{
    public TenantMembershipSnapshot(PrincipalId principal,TenantId tenant,bool isActive,DateTimeOffset notBeforeUtc,DateTimeOffset expiresAtUtc,string version)
    {
        Principal=principal??throw new ArgumentNullException(nameof(principal)); Tenant=tenant??throw new ArgumentNullException(nameof(tenant));
        if(expiresAtUtc<=notBeforeUtc) throw new ArgumentException("Membership validity must be a non-empty interval.");
        IsActive=isActive; NotBeforeUtc=notBeforeUtc.ToUniversalTime(); ExpiresAtUtc=expiresAtUtc.ToUniversalTime(); Version=Values.Opaque(version,128,nameof(version));
    }
    public PrincipalId Principal { get; }
    public TenantId Tenant { get; }
    public bool IsActive { get; }
    public DateTimeOffset NotBeforeUtc { get; }
    public DateTimeOffset ExpiresAtUtc { get; }
    public string Version { get; }
}

/// <summary>Actual tenant and version returned by the trusted resource source, not a caller-supplied ownership assertion.</summary>
public sealed class ResourceScopeSnapshot
{
    public ResourceScopeSnapshot(TenantId tenant,string kind,string resourceId,string version)
    { Tenant=tenant??throw new ArgumentNullException(nameof(tenant)); Kind=OperationId.RequireValid(kind); ResourceId=Values.Opaque(resourceId,512,nameof(resourceId)); Version=Values.Opaque(version,128,nameof(version)); }
    public TenantId Tenant { get; }
    public string Kind { get; }
    public string ResourceId { get; }
    public string Version { get; }
}

public interface ITenantMembershipSource
{
    ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot identity,TenantId requestedTenant,CancellationToken cancellationToken);
}
public interface IResourceScopeSource
{
    ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId requestedTenant,string kind,string resourceId,CancellationToken cancellationToken);
}
public interface ITenantAccessPolicy
{
    ValueTask<bool> IsAllowedAsync(TenantAccessRequest request,CancellationToken cancellationToken);
}

/// <summary>A trusted policy may bound the operation lease by the validity of its authority facts.</summary>
public interface ILeasedTenantAccessPolicy : ITenantAccessPolicy
{
    ValueTask<TenantPolicyDecision> EvaluateAsync(TenantAccessRequest request,CancellationToken cancellationToken);
}

public sealed record TenantPolicyDecision(bool IsAllowed,DateTimeOffset NotBeforeUtc,DateTimeOffset ExpiresAtUtc)
{
    public static TenantPolicyDecision Denied { get; }=new(false,DateTimeOffset.MinValue,DateTimeOffset.MinValue);
}

public sealed class TenantAccessRequest
{
    internal TenantAccessRequest(string operationId,string action,IdentitySnapshot identity,TenantMembershipSnapshot membership,ResourceScopeSnapshot resource)
        =>(OperationId,Action,Identity,Membership,Resource)=(operationId,action,identity,membership,resource);
    public string OperationId { get; }
    public string Action { get; }
    public IdentitySnapshot Identity { get; }
    public TenantMembershipSnapshot Membership { get; }
    public ResourceScopeSnapshot Resource { get; }
    public TenantId Tenant=>Membership.Tenant;
}

public interface ITenantOperationHandler<TRequest,TResponse>
{
    ValueTask<OperationResult<TResponse>> HandleAsync(TRequest request,TenantOperationContext context,CancellationToken cancellationToken);
}

public sealed class TenantAccessDeniedException : Exception
{
    public TenantAccessDeniedException():base("Access denied.") { }
}

/// <summary>Checked, operation-bound in-process context. Not a token, sandbox or atomic provider/revocation guarantee.</summary>
public sealed class TenantOperationContext
{
    private readonly AuthorizationLease lease;
    private readonly object origin;
    internal TenantOperationContext(TenantAccessRequest access,OperationContext correlation,AuthorizationLease lease,object origin)
    { Access=access; Correlation=correlation; this.lease=lease; this.origin=origin; }
    internal TenantAccessRequest Access { get; }
    public string OperationId=>Access.OperationId;
    public string Action=>Access.Action;
    public IdentitySnapshot Identity=>Access.Identity;
    public TenantMembershipSnapshot Membership=>Access.Membership;
    public ResourceScopeSnapshot Resource=>Access.Resource;
    public TenantId Tenant=>Access.Tenant;
    public OperationContext Correlation { get; }
    public void DemandAccess(TenantId tenant,string kind,string resourceId,string action)
    {
        if(!Tenant.Equals(tenant) || !StringComparer.Ordinal.Equals(Resource.Kind,kind) || !StringComparer.Ordinal.Equals(Resource.ResourceId,resourceId) || !StringComparer.Ordinal.Equals(Action,action)) throw new TenantAccessDeniedException();
        lease.DemandActive();
    }
    internal void DemandBinding(object expectedOrigin,string operationId)
    {
        if(!ReferenceEquals(origin,expectedOrigin) || !StringComparer.Ordinal.Equals(OperationId,operationId)) throw new TenantAccessDeniedException();
        lease.DemandActive();
    }
}

internal sealed class AuthorizationLease(TimeProvider timeProvider,DateTimeOffset notBeforeUtc,DateTimeOffset expiresAtUtc,IdentitySnapshot? identity = null) : IDisposable
{
    private int active=1;
    private readonly long started=timeProvider.GetTimestamp();
    private readonly TimeSpan maximumElapsed=expiresAtUtc-notBeforeUtc;
    internal void DemandActive()
    {
        if(Volatile.Read(ref active)==0) throw new TenantAccessDeniedException();
        try
        {
            var now=timeProvider.GetUtcNow();
            var elapsed=timeProvider.GetElapsedTime(started,timeProvider.GetTimestamp());
            if(now<notBeforeUtc || now>=expiresAtUtc || elapsed<TimeSpan.Zero || elapsed>=maximumElapsed ||
                identity is not null && !identity.SatisfiesObservationConstraints())
            { Interlocked.Exchange(ref active,0); throw new TenantAccessDeniedException(); }
        }
        catch { Interlocked.Exchange(ref active,0); throw; }
        if(Volatile.Read(ref active)==0) throw new TenantAccessDeniedException();
    }
    public void Dispose()=>Interlocked.Exchange(ref active,0);
}

internal static class Values
{
    internal static string Opaque(string value,int maximum,string name)
    {
        if(string.IsNullOrWhiteSpace(value) || value.Length>maximum) throw new ArgumentException("Value is empty or exceeds its bound.",name);
        for(var i=0;i<value.Length;i++)
        {
            var c=value[i];
            if(char.IsControl(c) || char.IsLowSurrogate(c) || char.IsHighSurrogate(c) && (i+1>=value.Length || !char.IsLowSurrogate(value[++i]))) throw new ArgumentException("Value contains control characters or malformed UTF16.",name);
        }
        return value;
    }
}

/// <summary>Aggregate capacity observation containing counts only, with no tenant identities.</summary>
public readonly record struct TenantOperationConcurrencySnapshot(
    OperationConcurrencySnapshot Total, int MaximumConcurrentOperationsPerTenant, int ActiveTenants);

/// <summary>Limits total and per-tenant in-flight business operations after fresh tenant authorization.</summary>
public sealed class TenantOperationConcurrencyBudget
{
    private readonly object gate = new();
    private readonly Dictionary<TenantId, int> activeByTenant = new();
    private int active;
    // Low 31 bits hold operations, bits 32-62 hold tenants, and the sign bit closes admissions.
    private long snapshotState;
    private TaskCompletionSource? drained;

    public TenantOperationConcurrencyBudget(int maximumConcurrentOperations, int maximumConcurrentOperationsPerTenant)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumConcurrentOperations);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumConcurrentOperationsPerTenant);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maximumConcurrentOperationsPerTenant, maximumConcurrentOperations);
        MaximumConcurrentOperations = maximumConcurrentOperations;
        MaximumConcurrentOperationsPerTenant = maximumConcurrentOperationsPerTenant;
    }

    public int MaximumConcurrentOperations { get; }
    public int MaximumConcurrentOperationsPerTenant { get; }

    /// <summary>Read a coherent aggregate published by the admission, release or close operation.</summary>
    public TenantOperationConcurrencySnapshot GetSnapshot()
    {
        var observed = Volatile.Read(ref snapshotState);
        return new(new(MaximumConcurrentOperations, (int)(observed & int.MaxValue), observed < 0),
            MaximumConcurrentOperationsPerTenant, (int)((observed >> 32) & int.MaxValue));
    }

    /// <summary>Create aggregate gauges without tenant tags. The caller owns and disposes the meter.</summary>
    public Meter CreateMetrics(string meterName = "Cehpalon.Engine.Tenancy.Budget")
    {
        var meter = new Meter(meterName);
        try
        {
            meter.CreateObservableGauge("cehpalon.operation_budget.active", () => GetSnapshot().Total.ActiveOperations, "{operation}");
            meter.CreateObservableGauge("cehpalon.operation_budget.capacity", () => MaximumConcurrentOperations, "{operation}");
            meter.CreateObservableGauge("cehpalon.operation_budget.closed", () => GetSnapshot().Total.IsAdmissionClosed ? 1 : 0,
                description: "One after admission is permanently closed, otherwise zero.");
            meter.CreateObservableGauge("cehpalon.operation_budget.active_tenants", () => GetSnapshot().ActiveTenants, "{tenant}");
            meter.CreateObservableGauge("cehpalon.operation_budget.tenant_capacity", () => MaximumConcurrentOperationsPerTenant, "{operation}");
            return meter;
        }
        catch
        {
            meter.Dispose();
            throw;
        }
    }

    // Called only while holding gate. Readers observe one complete published state.
    private void PublishSnapshot()
    {
        var state = ((long)activeByTenant.Count << 32) | (uint)active;
        if (drained is not null)
            state |= long.MinValue;
        Volatile.Write(ref snapshotState, state);
    }

    /// <summary>Close all tenant admissions permanently and wait until admitted cleanup completes.</summary>
    /// <remarks>Cancellation only cancels this wait. Admitted work continues and admissions stay closed.</remarks>
    public Task DrainAsync(CancellationToken cancellationToken = default)
    {
        Task completion;
        lock (gate)
        {
            drained ??= new(TaskCreationOptions.RunContinuationsAsynchronously);
            PublishSnapshot();
            if (active == 0)
                drained.TrySetResult();

            completion = drained.Task;
        }

        return completion.WaitAsync(cancellationToken);
    }

    internal async ValueTask<OperationResult<TResponse>> DispatchAsync<TRequest, TResponse>(
        TenantId authorizedTenant, OperationDispatcher dispatcher, string operationId, TRequest request,
        OperationContext correlation, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!TryAdmit(authorizedTenant))
        {
            token.ThrowIfCancellationRequested();
            return Rejected<TResponse>.Result;
        }

        try
        {
            return await dispatcher.DispatchAsync<TRequest, TResponse>(operationId, request, correlation, token)
                .ConfigureAwait(false);
        }
        finally
        {
            lock (gate)
            {
                var remaining = activeByTenant[authorizedTenant] - 1;
                if (remaining == 0)
                    activeByTenant.Remove(authorizedTenant);
                else
                    activeByTenant[authorizedTenant] = remaining;
                active--;
                PublishSnapshot();
                if (active == 0)
                    drained?.TrySetResult();
            }
        }
    }

    private bool TryAdmit(TenantId tenant)
    {
        lock (gate)
        {
            if (drained is not null || active >= MaximumConcurrentOperations)
                return false;

            activeByTenant.TryGetValue(tenant, out var current);
            if (current >= MaximumConcurrentOperationsPerTenant)
                return false;

            activeByTenant[tenant] = current + 1;
            active++;
            PublishSnapshot();
            return true;
        }
    }

    private static class Rejected<T>
    {
        internal static readonly OperationResult<T> Result = OperationResult<T>.Failure(
            new OperationError(OperationConcurrencyBudget.CapacityExceededCode, "Operation capacity is temporarily unavailable."));
    }
}
