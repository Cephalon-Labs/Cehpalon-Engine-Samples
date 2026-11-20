using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;

namespace Cehpalon.Engine.Tenancy;

public enum TenantAuditStage { Authorization, Terminal }
public enum TenantAuditOutcome { Authorized, Denied, Succeeded, Rejected, Cancelled, Faulted }

/// <summary>Structured history metadata only. Constructors/data are not authorization capabilities.</summary>
public sealed class TenantAuditEvent
{
    public TenantAuditEvent(Guid invocationId, TenantAuditStage stage, TenantAuditOutcome outcome,
        DateTimeOffset observedAtUtc, string operationId, string action, string resourceKind,
        PrincipalId? principal = null, TenantId? authorizedTenant = null, string? resourceId = null, Guid? parentInvocationId = null)
    {
        if (invocationId == Guid.Empty) throw new ArgumentException("Invocation ID cannot be empty.", nameof(invocationId));
        if (parentInvocationId == Guid.Empty || parentInvocationId == invocationId)
            throw new ArgumentException("Parent invocation must be a different non-empty ID.", nameof(parentInvocationId));
        if (!Enum.IsDefined(stage) || !Enum.IsDefined(outcome) ||
            (stage == TenantAuditStage.Authorization) != (outcome == TenantAuditOutcome.Authorized))
            throw new ArgumentException("Invalid audit stage/outcome combination.");
        if (authorizedTenant is not null && (principal is null || resourceId is null))
            throw new ArgumentException("Authorized tenant records require a principal and resource.");
        InvocationId = invocationId; Stage = stage; Outcome = outcome; ObservedAtUtc = observedAtUtc.ToUniversalTime();
        ParentInvocationId = parentInvocationId;
        OperationId = Cehpalon.Engine.Core.OperationId.RequireValid(operationId);
        Action = Cehpalon.Engine.Core.OperationId.RequireValid(action); ResourceKind = Cehpalon.Engine.Core.OperationId.RequireValid(resourceKind);
        Principal = principal; AuthorizedTenant = authorizedTenant;
        ResourceId = resourceId is null ? null : Values.Opaque(resourceId, 512, nameof(resourceId));
    }
    public Guid InvocationId { get; }
    public Guid? ParentInvocationId { get; }
    public TenantAuditStage Stage { get; }
    public TenantAuditOutcome Outcome { get; }
    public DateTimeOffset ObservedAtUtc { get; }
    public string OperationId { get; }
    public string Action { get; }
    public string ResourceKind { get; }
    public PrincipalId? Principal { get; }
    public TenantId? AuthorizedTenant { get; }
    public string? ResourceId { get; }
}

/// <summary>
/// Trusted persistence boundary. Await durable acceptance as required by your application and honor
/// cancellation. InvocationId/Stage is an idempotency key. There is no automatic retry or payload logging.
/// </summary>
public interface ITenantAuditSink
{
    ValueTask AppendAsync(TenantAuditEvent entry, CancellationToken cancellationToken);
}

public sealed class TenantAuditWriteException : Exception
{
    internal TenantAuditWriteException(bool operationMayHaveExecuted, Exception inner)
        : base("Required audit persistence failed.", inner) => OperationMayHaveExecuted = operationMayHaveExecuted;
    public bool OperationMayHaveExecuted { get; }
}

/// <summary>Opt-in required audit persistence. The consumer owns the sink lifetime.</summary>
public sealed class TenantAuditServices
{
    public TenantAuditServices(ITenantAuditSink sink, TimeSpan? writeTimeout = null)
    {
        Sink = sink ?? throw new ArgumentNullException(nameof(sink)); WriteTimeout = writeTimeout ?? TimeSpan.FromSeconds(5);
        if (WriteTimeout <= TimeSpan.Zero || WriteTimeout > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(writeTimeout), "Audit write timeout must be positive and at most one minute.");
    }
    public ITenantAuditSink Sink { get; }
    public TimeSpan WriteTimeout { get; }
    internal Guid? ParentInvocationId { get; private init; }
    internal TenantAuditServices ForParent(Guid invocationId) => new(Sink, WriteTimeout) { ParentInvocationId = invocationId };
    internal async ValueTask AppendAsync(TenantAuditEvent entry, bool mayHaveExecuted)
    {
        using var timeout = new CancellationTokenSource(WriteTimeout);
        try
        {
            await Sink.AppendAsync(entry, timeout.Token).ConfigureAwait(false);
            timeout.Token.ThrowIfCancellationRequested();
        }
        catch (Exception failure) { throw new TenantAuditWriteException(mayHaveExecuted, failure); }
    }
}

public sealed class TenantAuditHistoryPage
{
    public TenantAuditHistoryPage(IEnumerable<TenantAuditEvent> entries, string? nextCursor = null)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var copy = entries.Take(201).ToArray();
        if (copy.Length > 200 || copy.Any(e => e is null)) throw new ArgumentException("History pages contain at most 200 non-null records.", nameof(entries));
        Entries = Array.AsReadOnly(copy); NextCursor = nextCursor is null ? null : Values.Opaque(nextCursor, 512, nameof(nextCursor));
    }
    public IReadOnlyList<TenantAuditEvent> Entries { get; }
    public string? NextCursor { get; }
}

public interface ITenantAuditHistorySource
{
    ValueTask<TenantAuditHistoryPage> ReadAsync(TenantId authorizedTenant, int limit, string? cursor, CancellationToken cancellationToken);
}

/// <summary>Tenant-wide history requires an active audit-history/tenant/read operation scope.</summary>
public sealed class TenantAuditHistoryReader
{
    private readonly ITenantAuditHistorySource source;
    public TenantAuditHistoryReader(ITenantAuditHistorySource source) => this.source = source ?? throw new ArgumentNullException(nameof(source));
    public async ValueTask<TenantAuditHistoryPage> ReadAsync(TenantOperationContext context, int limit = 50,
        string? cursor = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context); ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(limit, 200);
        if (cursor is not null) Values.Opaque(cursor, 512, nameof(cursor));
        context.DemandAccess(context.Tenant, "audit-history", "tenant", "read"); cancellationToken.ThrowIfCancellationRequested();
        var page = await source.ReadAsync(context.Tenant, limit, cursor, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested(); context.DemandAccess(context.Tenant, "audit-history", "tenant", "read");
        if (page is null || page.Entries.Count > limit || page.Entries.Any(e => !context.Tenant.Equals(e.AuthorizedTenant)))
            throw new InvalidOperationException("Audit history source returned an invalid tenant page.");
        return page;
    }
}
