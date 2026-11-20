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


// Domain change trails are explicit application/provider reports, separate from automatic operation metadata.
public enum TenantChangeAuditMode { Disabled, MetadataOnly, ChangedFields, BeforeAfterSnapshots }
public enum TenantChangeKind { Create, Update, Delete }
public enum TenantChangeValueKind { Missing, Null, Text, Boolean, Decimal, Redacted }

/// <summary>Closed bounded scalar; no arbitrary object graph, serializer callback or raw JSON is retained.</summary>
public sealed class TenantChangeValue : IEquatable<TenantChangeValue>
{
    private TenantChangeValue(TenantChangeValueKind kind, string? text = null, bool? boolean = null, decimal? number = null)
        => (Kind, TextValue, BooleanValue, DecimalValue) = (kind, text, boolean, number);
    public TenantChangeValueKind Kind { get; }
    public string? TextValue { get; }
    public bool? BooleanValue { get; }
    public decimal? DecimalValue { get; }
    public static TenantChangeValue Missing { get; } = new(TenantChangeValueKind.Missing);
    public static TenantChangeValue Null { get; } = new(TenantChangeValueKind.Null);
    public static TenantChangeValue Redacted { get; } = new(TenantChangeValueKind.Redacted);
    public static TenantChangeValue Text(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length > 4096) throw new ArgumentException("Trail text exceeds its bound.", nameof(value));
        // Values may contain ordinary whitespace but never malformed UTF16.
        for (var i = 0; i < value.Length; i++)
            if (char.IsLowSurrogate(value[i]) || char.IsHighSurrogate(value[i]) && (i + 1 >= value.Length || !char.IsLowSurrogate(value[++i])))
                throw new ArgumentException("Trail text contains malformed UTF16.", nameof(value));
        return new(TenantChangeValueKind.Text, value);
    }
    public static TenantChangeValue Boolean(bool value) => new(TenantChangeValueKind.Boolean, boolean: value);
    public static TenantChangeValue Number(decimal value) => new(TenantChangeValueKind.Decimal, number: value);
    public bool Equals(TenantChangeValue? other) => other is not null && Kind == other.Kind &&
        StringComparer.Ordinal.Equals(TextValue, other.TextValue) && BooleanValue == other.BooleanValue && DecimalValue == other.DecimalValue;
    public override bool Equals(object? obj) => obj is TenantChangeValue value && Equals(value);
    public override int GetHashCode() => HashCode.Combine(Kind, TextValue, BooleanValue, DecimalValue);
}

public sealed class TenantChangeState
{
    public const int MaximumFields = 64;
    public TenantChangeState(IEnumerable<KeyValuePair<string, TenantChangeValue>> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        var copy = fields.Take(MaximumFields + 1).ToArray();
        if (copy.Length > MaximumFields) throw new ArgumentException("At most64 trail fields are supported.", nameof(fields));
        var map = new Dictionary<string, TenantChangeValue>(StringComparer.Ordinal);
        foreach (var field in copy)
            if (!map.TryAdd(Values.Opaque(field.Key, 128, nameof(fields)), field.Value ?? throw new ArgumentException("Trail values cannot be null objects.")))
                throw new ArgumentException("Duplicate trail field.", nameof(fields));
        if (map.Values.Sum(v => v.TextValue?.Length ?? 0) > 32768) throw new ArgumentException("Trail state exceeds aggregate text bound.", nameof(fields));
        Fields = new System.Collections.ObjectModel.ReadOnlyDictionary<string, TenantChangeValue>(map);
    }
    public IReadOnlyDictionary<string, TenantChangeValue> Fields { get; }
    public static TenantChangeState Empty { get; } = new([]);
}
public sealed class TenantChangeStates
{
    public TenantChangeStates(TenantChangeState before, TenantChangeState after)
        => (Before, After) = (before ?? throw new ArgumentNullException(nameof(before)), after ?? throw new ArgumentNullException(nameof(after)));
    public TenantChangeState Before { get; }
    public TenantChangeState After { get; }
}
public sealed class TenantChangeFieldRule
{
    public TenantChangeFieldRule(string name, bool redact = false) => (Name, Redact) = (Values.Opaque(name, 128, nameof(name)), redact);
    public string Name { get; }
    public bool Redact { get; }
}
public sealed class TenantChangeAuditRule
{
    public TenantChangeAuditRule(string operationId, string action, string resourceKind, IEnumerable<TenantChangeFieldRule>? fields = null)
    {
        OperationId = Cehpalon.Engine.Core.OperationId.RequireValid(operationId); Action = Cehpalon.Engine.Core.OperationId.RequireValid(action);
        ResourceKind = Cehpalon.Engine.Core.OperationId.RequireValid(resourceKind);
        var copy = fields?.Take(65).ToArray() ?? [];
        if (copy.Length > 64 || copy.Any(x => x is null) || copy.Select(x => x.Name).Distinct(StringComparer.Ordinal).Count() != copy.Length)
            throw new ArgumentException("Rules require at most64 unique non-null fields.", nameof(fields));
        Fields = Array.AsReadOnly(copy.OrderBy(x => x.Name, StringComparer.Ordinal).ToArray());
    }
    public string OperationId { get; }
    public string Action { get; }
    public string ResourceKind { get; }
    public IReadOnlyList<TenantChangeFieldRule> Fields { get; }
}

/// <summary>Immutable exact project rules. Empty/unmatched rules deny recording; unknown history rules expose metadata only.</summary>
public sealed class TenantChangeAuditPolicy
{
    public TenantChangeAuditPolicy(TenantChangeAuditMode mode = TenantChangeAuditMode.MetadataOnly, IEnumerable<TenantChangeAuditRule>? rules = null)
    {
        if (!Enum.IsDefined(mode)) throw new ArgumentOutOfRangeException(nameof(mode));
        Mode = mode; var copy = rules?.Take(129).ToArray() ?? [];
        if (copy.Length > 128 || copy.Any(x => x is null) || copy.Select(Key).Distinct().Count() != copy.Length)
            throw new ArgumentException("Policies require at most128 unique non-null rules.", nameof(rules));
        Rules = Array.AsReadOnly(copy);
    }
    private static (string, string, string) Key(TenantChangeAuditRule r) => (r.OperationId, r.Action, r.ResourceKind);
    public TenantChangeAuditMode Mode { get; }
    public IReadOnlyList<TenantChangeAuditRule> Rules { get; }
    internal TenantChangeAuditRule? Find(TenantChangeReceipt receipt) => Rules.FirstOrDefault(r =>
        StringComparer.Ordinal.Equals(r.OperationId, receipt.OperationId) && StringComparer.Ordinal.Equals(r.Action, receipt.Action) &&
        StringComparer.Ordinal.Equals(r.ResourceKind, receipt.ResourceKind));
    internal TenantChangeAuditRecord Project(TenantChangeAuditRecord record)
    {
        var rule = Find(record.Receipt);
        if (Mode is TenantChangeAuditMode.Disabled or TenantChangeAuditMode.MetadataOnly || rule is null)
            return new(record.Receipt, record.RecordedAtUtc, TenantChangeAuditMode.MetadataOnly, [], record.CapturedMode);
        var projected = new List<TenantChangeField>();
        foreach (var field in record.Fields)
        {
            var allowed = rule.Fields.FirstOrDefault(f => StringComparer.Ordinal.Equals(f.Name, field.Name));
            if (allowed is null || Mode == TenantChangeAuditMode.ChangedFields && !field.WasChanged) continue;
            projected.Add(allowed.Redact ? new(field.Name, TenantChangeValue.Redacted, TenantChangeValue.Redacted, field.WasChanged) : field);
        }
        var effective = record.Mode == TenantChangeAuditMode.MetadataOnly ? TenantChangeAuditMode.MetadataOnly
            : Mode == TenantChangeAuditMode.ChangedFields || record.Mode == TenantChangeAuditMode.ChangedFields ? TenantChangeAuditMode.ChangedFields : TenantChangeAuditMode.BeforeAfterSnapshots;
        return new(record.Receipt, record.RecordedAtUtc, effective, projected, record.CapturedMode);
    }
}

/// <summary>Provider/application-reported receipt. Construction is not proof of database commit or tenant authority.</summary>
public sealed class TenantChangeReceipt
{
    public TenantChangeReceipt(Guid receiptId, PrincipalId principal, string authenticationScheme, TenantId tenant,
        string operationId, string action, string resourceKind, string resourceId, string authorizationResourceVersion,
        TenantChangeKind kind, string? beforeEntityVersion = null, string? afterEntityVersion = null, DateTimeOffset? reportedAtUtc = null)
    {
        if (receiptId == Guid.Empty) throw new ArgumentException("Receipt ID cannot be empty.", nameof(receiptId));
        if (!Enum.IsDefined(kind)) throw new ArgumentOutOfRangeException(nameof(kind));
        if (kind == TenantChangeKind.Create && beforeEntityVersion is not null || kind == TenantChangeKind.Delete && afterEntityVersion is not null)
            throw new ArgumentException("Create has no before version; delete has no after version.");
        ReceiptId = receiptId; Principal = principal ?? throw new ArgumentNullException(nameof(principal));
        AuthenticationScheme = new IdentitySnapshot(principal, authenticationScheme, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddSeconds(1)).AuthenticationScheme;
        Tenant = tenant ?? throw new ArgumentNullException(nameof(tenant)); OperationId = Cehpalon.Engine.Core.OperationId.RequireValid(operationId);
        Action = Cehpalon.Engine.Core.OperationId.RequireValid(action); ResourceKind = Cehpalon.Engine.Core.OperationId.RequireValid(resourceKind);
        ResourceId = Values.Opaque(resourceId, 512, nameof(resourceId)); AuthorizationResourceVersion = Values.Opaque(authorizationResourceVersion, 128, nameof(authorizationResourceVersion));
        Kind = kind; BeforeEntityVersion = beforeEntityVersion is null ? null : Values.Opaque(beforeEntityVersion, 128, nameof(beforeEntityVersion));
        AfterEntityVersion = afterEntityVersion is null ? null : Values.Opaque(afterEntityVersion, 128, nameof(afterEntityVersion));
        ReportedAtUtc = reportedAtUtc?.ToUniversalTime();
    }
    public Guid ReceiptId { get; }
    public PrincipalId Principal { get; }
    public string AuthenticationScheme { get; }
    public TenantId Tenant { get; }
    public string OperationId { get; }
    public string Action { get; }
    public string ResourceKind { get; }
    public string ResourceId { get; }
    public string AuthorizationResourceVersion { get; }
    public TenantChangeKind Kind { get; }
    public string? BeforeEntityVersion { get; }
    public string? AfterEntityVersion { get; }
    public DateTimeOffset? ReportedAtUtc { get; }
}
public sealed class TenantChangeField
{
    public TenantChangeField(string name, TenantChangeValue before, TenantChangeValue after)
        : this(name, before, after, !Equals(before, after)) { }
    public TenantChangeField(string name, TenantChangeValue before, TenantChangeValue after, bool wasChanged)
    {
        Name = Values.Opaque(name, 128, nameof(name)); Before = before ?? throw new ArgumentNullException(nameof(before)); After = after ?? throw new ArgumentNullException(nameof(after));
        if (before.Kind != TenantChangeValueKind.Redacted && after.Kind != TenantChangeValueKind.Redacted && wasChanged == before.Equals(after))
            throw new ArgumentException("Unredacted values must agree with change metadata.");
        WasChanged = wasChanged;
    }
    public string Name { get; }
    public TenantChangeValue Before { get; }
    public TenantChangeValue After { get; }
    public bool WasChanged { get; }
}
public sealed class TenantChangeAuditRecord
{
    public TenantChangeAuditRecord(TenantChangeReceipt receipt, DateTimeOffset recordedAtUtc, TenantChangeAuditMode mode, IEnumerable<TenantChangeField> fields, TenantChangeAuditMode? capturedMode = null)
    {
        Receipt = receipt ?? throw new ArgumentNullException(nameof(receipt)); ArgumentNullException.ThrowIfNull(fields);
        if (!Enum.IsDefined(mode) || mode == TenantChangeAuditMode.Disabled) throw new ArgumentOutOfRangeException(nameof(mode));
        CapturedMode = capturedMode ?? mode;
        if (!Enum.IsDefined(CapturedMode) || CapturedMode == TenantChangeAuditMode.Disabled || (int)mode > (int)CapturedMode)
            throw new ArgumentException("Read projection cannot upgrade the original capture mode.", nameof(capturedMode));
        var copy = fields.Take(65).ToArray();
        if (copy.Length > 64 || copy.Any(x => x is null) || copy.Select(x => x.Name).Distinct(StringComparer.Ordinal).Count() != copy.Length ||
            mode == TenantChangeAuditMode.MetadataOnly && copy.Length != 0 || mode == TenantChangeAuditMode.ChangedFields && copy.Any(x => !x.WasChanged))
            throw new ArgumentException("Invalid bounded trail field projection.", nameof(fields));
        if (copy.Sum(x => (x.Before.TextValue?.Length ?? 0) + (x.After.TextValue?.Length ?? 0)) > 65536)
            throw new ArgumentException("Trail record exceeds aggregate text bound.", nameof(fields));
        RecordedAtUtc = recordedAtUtc.ToUniversalTime(); Mode = mode; Fields = Array.AsReadOnly(copy);
    }
    public TenantChangeReceipt Receipt { get; }
    public DateTimeOffset RecordedAtUtc { get; }
    public TenantChangeAuditMode Mode { get; }
    public TenantChangeAuditMode CapturedMode { get; }
    public IReadOnlyList<TenantChangeField> Fields { get; }
}
public interface ITenantChangeAuditSink
{
    ValueTask AppendAsync(TenantChangeAuditRecord record, CancellationToken cancellationToken);
}
public sealed class TenantChangeAuditWriteException : Exception
{
    internal TenantChangeAuditWriteException(Exception inner) : base("Required change-trail persistence or checked-scope completion failed; the reported change may already be committed.", inner) { }
    public bool MayHaveCommitted => true;
}

/// <summary>Explicit required change recording. No inferred CDC, retry, rollback, outbox or verified operation-invocation linkage.</summary>
public sealed class TenantChangeAuditRecorder
{
    private readonly TenantChangeAuditPolicy policy;
    private readonly ITenantChangeAuditSink sink;
    private readonly TimeSpan timeout;
    private readonly TimeProvider clock;
    private TenantChangeAuditRecorder(TenantChangeAuditPolicy policy, ITenantChangeAuditSink sink, TimeSpan? writeTimeout, TimeProvider? timeProvider)
    {
        this.policy = policy; this.sink = sink; timeout = writeTimeout ?? TimeSpan.FromSeconds(5); clock = timeProvider ?? TimeProvider.System;
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(1)) throw new ArgumentOutOfRangeException(nameof(writeTimeout));
    }
    public static TenantChangeAuditRecorder? Activate(TenantChangeAuditPolicy policy, Func<ITenantChangeAuditSink>? sinkFactory = null,
        TimeSpan? writeTimeout = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.Mode == TenantChangeAuditMode.Disabled) return null;
        ArgumentNullException.ThrowIfNull(sinkFactory);
        if (writeTimeout is { } bound && (bound <= TimeSpan.Zero || bound > TimeSpan.FromMinutes(1))) throw new ArgumentOutOfRangeException(nameof(writeTimeout));
        return new(policy, sinkFactory() ?? throw new ArgumentException("The trusted trail sink factory returned null."), writeTimeout, timeProvider);
    }
    public async ValueTask RecordAsync(TenantOperationContext context, TenantChangeReceipt receipt,
        Func<TenantChangeStates>? valuesFactory = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context); ArgumentNullException.ThrowIfNull(receipt);
        try
        {
            Demand(context, receipt); cancellationToken.ThrowIfCancellationRequested();
            var rule = policy.Find(receipt) ?? throw new TenantAccessDeniedException();
            var fields = new List<TenantChangeField>();
            if (policy.Mode != TenantChangeAuditMode.MetadataOnly && rule.Fields.Count != 0)
            {
                var states = valuesFactory?.Invoke() ?? throw new ArgumentException("This capture mode requires a trusted state factory.", nameof(valuesFactory));
                if (receipt.Kind == TenantChangeKind.Create && states.Before.Fields.Count != 0 || receipt.Kind == TenantChangeKind.Delete && states.After.Fields.Count != 0)
                    throw new ArgumentException("Create/delete state shape does not match the reported change.");
                foreach (var field in rule.Fields)
                {
                    var before = states.Before.Fields.TryGetValue(field.Name, out var b) ? b : TenantChangeValue.Missing;
                    var after = states.After.Fields.TryGetValue(field.Name, out var a) ? a : TenantChangeValue.Missing;
                    var changed = !before.Equals(after);
                    if (policy.Mode == TenantChangeAuditMode.ChangedFields && !changed) continue;
                    fields.Add(field.Redact ? new(field.Name, TenantChangeValue.Redacted, TenantChangeValue.Redacted, changed) : new(field.Name, before, after, changed));
                }
            }
            var record = new TenantChangeAuditRecord(receipt, clock.GetUtcNow(), policy.Mode, fields);
            Demand(context, receipt); cancellationToken.ThrowIfCancellationRequested();
            using var deadline = new CancellationTokenSource(timeout);
            await sink.AppendAsync(record, deadline.Token).ConfigureAwait(false);
            deadline.Token.ThrowIfCancellationRequested(); cancellationToken.ThrowIfCancellationRequested(); Demand(context, receipt);
        }
        catch (Exception error) { throw new TenantChangeAuditWriteException(error); }
    }
    private static void Demand(TenantOperationContext context, TenantChangeReceipt receipt)
    {
        context.DemandAccess(receipt.Tenant, receipt.ResourceKind, receipt.ResourceId, receipt.Action);
        if (!context.Identity.Principal.Equals(receipt.Principal) || !StringComparer.Ordinal.Equals(context.Identity.AuthenticationScheme, receipt.AuthenticationScheme) ||
            !StringComparer.Ordinal.Equals(context.OperationId, receipt.OperationId) || !StringComparer.Ordinal.Equals(context.Resource.Version, receipt.AuthorizationResourceVersion))
            throw new TenantAccessDeniedException();
    }
}
public sealed class TenantChangeAuditPage
{
    public TenantChangeAuditPage(IEnumerable<TenantChangeAuditRecord> entries, string? nextCursor = null)
    {
        ArgumentNullException.ThrowIfNull(entries); var copy = entries.Take(201).ToArray();
        if (copy.Length > 200 || copy.Any(x => x is null)) throw new ArgumentException("Trail pages contain at most200 non-null records.", nameof(entries));
        Entries = Array.AsReadOnly(copy); NextCursor = nextCursor is null ? null : Values.Opaque(nextCursor, 512, nameof(nextCursor));
    }
    public IReadOnlyList<TenantChangeAuditRecord> Entries { get; }
    public string? NextCursor { get; }
}
public interface ITenantChangeAuditHistorySource
{
    ValueTask<TenantChangeAuditPage> ReadAsync(TenantId authorizedTenant, int limit, string? cursor, CancellationToken cancellationToken);
}
public sealed class TenantChangeAuditHistoryReader
{
    private readonly ITenantChangeAuditHistorySource source;
    private readonly TenantChangeAuditPolicy policy;
    public TenantChangeAuditHistoryReader(ITenantChangeAuditHistorySource source, TenantChangeAuditPolicy policy)
    {
        this.source = source ?? throw new ArgumentNullException(nameof(source)); this.policy = policy ?? throw new ArgumentNullException(nameof(policy));
        if (policy.Mode == TenantChangeAuditMode.Disabled) throw new ArgumentException("A disabled trail reader must not be activated.", nameof(policy));
    }
    public static TenantChangeAuditHistoryReader? Activate(TenantChangeAuditPolicy policy, Func<ITenantChangeAuditHistorySource>? sourceFactory = null)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.Mode == TenantChangeAuditMode.Disabled) return null;
        ArgumentNullException.ThrowIfNull(sourceFactory);
        return new(sourceFactory() ?? throw new ArgumentException("The trusted trail source factory returned null."), policy);
    }
    public async ValueTask<TenantChangeAuditPage> ReadAsync(TenantOperationContext context, int limit = 50, string? cursor = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context); ArgumentOutOfRangeException.ThrowIfLessThan(limit, 1); ArgumentOutOfRangeException.ThrowIfGreaterThan(limit, 200);
        if (cursor is not null) Values.Opaque(cursor, 512, nameof(cursor));
        context.DemandAccess(context.Tenant, "audit-trail", "tenant", "read"); cancellationToken.ThrowIfCancellationRequested();
        var page = await source.ReadAsync(context.Tenant, limit, cursor, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested(); context.DemandAccess(context.Tenant, "audit-trail", "tenant", "read");
        if (page is null || page.Entries.Count > limit || page.Entries.Any(x => !context.Tenant.Equals(x.Receipt.Tenant)))
            throw new InvalidOperationException("Trail source returned an invalid tenant page.");
        var projected = new TenantChangeAuditPage(page.Entries.Select(policy.Project), page.NextCursor);
        context.DemandAccess(context.Tenant, "audit-trail", "tenant", "read");
        return projected;
    }
}
