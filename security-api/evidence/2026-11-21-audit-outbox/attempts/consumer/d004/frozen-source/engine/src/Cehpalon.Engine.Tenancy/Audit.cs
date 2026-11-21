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
/// <summary>One trusted provider transaction must contain every Session effect and staged record.</summary>
public interface ITenantChangeAuditTransaction<TSession> : IAsyncDisposable
{
    TSession Session { get; }
    ValueTask StageAsync(TenantChangeAuditRecord record, CancellationToken cancellationToken);
    ValueTask CommitAsync(CancellationToken cancellationToken);
    ValueTask RollbackAsync(CancellationToken cancellationToken);
}
public interface ITenantChangeAuditTransactionProvider<TSession>
{
    /// <summary>Returns an uncommitted tenant-bound transaction; a failing Begin must clean up its own resources.</summary>
    ValueTask<ITenantChangeAuditTransaction<TSession>> BeginAsync(TenantId tenant, CancellationToken cancellationToken);
}
public enum TenantChangeAuditTransactionOutcome { NotStarted, RolledBack, RollbackUnknown, CommitUnknown, Committed }
/// <summary>Outcomes describe the trusted transaction only, never arbitrary effects outside its Session.</summary>
public sealed class TenantChangeAuditTransactionException : Exception
{
    internal TenantChangeAuditTransactionException(TenantChangeAuditTransactionOutcome outcome,
        Exception? primary, Exception? rollback, Exception? disposal)
        : base("Transactional audit completion failed; inspect the transaction outcome before reconciling or retrying.",
            Combine(primary, rollback, disposal))
    { Outcome = outcome; PrimaryFailure = primary; RollbackFailure = rollback; DisposalFailure = disposal; }
    private static Exception Combine(params Exception?[] failures)
    { var present = failures.OfType<Exception>().ToArray(); return present.Length == 1 ? present[0] : new AggregateException(present); }
    public TenantChangeAuditTransactionOutcome Outcome { get; }
    public Exception? PrimaryFailure { get; }
    public Exception? RollbackFailure { get; }
    public Exception? DisposalFailure { get; }
    public bool MayHaveCommitted => Outcome is not (TenantChangeAuditTransactionOutcome.NotStarted or TenantChangeAuditTransactionOutcome.RolledBack);
}
/// <summary>Opt-in orchestration of a provider-owned business transaction and redacted audit outbox row.</summary>
public sealed class TenantChangeAuditOutboxExecutor<TSession>
{
    private readonly TenantChangeAuditPolicy policy;
    private readonly TenantOperationRegistry registry;
    private readonly ITenantChangeAuditTransactionProvider<TSession> provider;
    private readonly TimeSpan timeout;
    private readonly TimeProvider clock;
    private TenantChangeAuditOutboxExecutor(TenantChangeAuditPolicy policy, TenantOperationRegistry registry,
        ITenantChangeAuditTransactionProvider<TSession> provider, TimeSpan timeout, TimeProvider clock)
    { this.policy = policy; this.registry = registry; this.provider = provider; this.timeout = timeout; this.clock = clock; }
    public static TenantChangeAuditOutboxExecutor<TSession>? ActivateValidated(TenantChangeAuditPolicy policy,
        TenantOperationRegistry? registry, IEnumerable<string>? requiredOperationIds,
        Func<ITenantChangeAuditTransactionProvider<TSession>>? providerFactory = null,
        TimeSpan? transactionTimeout = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.Mode == TenantChangeAuditMode.Disabled) return null;
        ArgumentNullException.ThrowIfNull(registry); ArgumentNullException.ThrowIfNull(requiredOperationIds);
        ArgumentNullException.ThrowIfNull(providerFactory);
        var timeout = RequireBound(transactionTimeout ?? TimeSpan.FromSeconds(5), nameof(transactionTimeout));
        TenantChangeAuditRecorder.ValidateCatalog(policy, registry, requiredOperationIds);
        return new(policy, registry, providerFactory() ?? throw new ArgumentException("The transaction provider factory returned null."),
            timeout, timeProvider ?? TimeProvider.System);
    }
    internal static TimeSpan RequireBound(TimeSpan value, string name)
    { if (value <= TimeSpan.Zero || value > TimeSpan.FromMinutes(1)) throw new ArgumentOutOfRangeException(name); return value; }
    public async ValueTask<TResult> ExecuteAsync<TResult>(TenantOperationContext context,
        Func<TSession, CancellationToken, ValueTask<TenantChangeAuditMutation<TResult>>> mutation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(mutation);
        TenantChangeAuditRecorder.DemandPreparation(policy, registry, context, cancellationToken);
        ITenantChangeAuditTransaction<TSession>? transaction = null;
        Exception? primary = null, rollback = null, disposal = null;
        var outcome = TenantChangeAuditTransactionOutcome.NotStarted;
        TenantChangeReceipt? committedReceipt = null;
        TResult result = default!;
        try
        {
            transaction = await provider.BeginAsync(context.Tenant, cancellationToken).ConfigureAwait(false)
                ?? throw new ArgumentException("The transaction provider returned no transaction.");
            outcome = TenantChangeAuditTransactionOutcome.RollbackUnknown;
            TenantChangeAuditRecorder.DemandPreparation(policy, registry, context, cancellationToken);
            var session = transaction.Session;
            if (session is null) throw new ArgumentException("The transaction provider returned no business session.");
            TenantChangeAuditRecorder.DemandPreparation(policy, registry, context, cancellationToken);
            var change = await mutation(session, cancellationToken).ConfigureAwait(false)
                ?? throw new ArgumentException("The trusted mutation returned no change receipt.", nameof(mutation));
            committedReceipt = change.Receipt;
            var record = TenantChangeAuditRecorder.BuildCheckedRecord(policy, registry, clock, context, change.Receipt,
                change.ValuesFactory, cancellationToken);
            await transaction.StageAsync(record, cancellationToken).ConfigureAwait(false);
            TenantChangeAuditRecorder.DemandReceipt(context, change.Receipt, registry);
            cancellationToken.ThrowIfCancellationRequested();
            // No rollback can establish non-commit after CommitAsync has been invoked.
            outcome = TenantChangeAuditTransactionOutcome.CommitUnknown;
            using (var commitDeadline = new CancellationTokenSource(timeout))
            {
                await transaction.CommitAsync(commitDeadline.Token).ConfigureAwait(false);
                outcome = TenantChangeAuditTransactionOutcome.Committed;
                commitDeadline.Token.ThrowIfCancellationRequested();
            }
            TenantChangeAuditRecorder.DemandReceipt(context, change.Receipt, registry);
            cancellationToken.ThrowIfCancellationRequested();
            result = change.Result;
        }
        catch (Exception failure)
        {
            primary = failure;
            if (transaction is not null && outcome is not (TenantChangeAuditTransactionOutcome.CommitUnknown or TenantChangeAuditTransactionOutcome.Committed))
            {
                try
                {
                    using var rollbackDeadline = new CancellationTokenSource(timeout);
                    await transaction.RollbackAsync(rollbackDeadline.Token).ConfigureAwait(false);
                    rollbackDeadline.Token.ThrowIfCancellationRequested();
                    outcome = TenantChangeAuditTransactionOutcome.RolledBack;
                }
                catch (Exception rollbackFailure) { rollback = rollbackFailure; outcome = TenantChangeAuditTransactionOutcome.RollbackUnknown; }
            }
        }
        finally
        {
            if (transaction is not null)
                try { await transaction.DisposeAsync().ConfigureAwait(false); }
                catch (Exception disposalFailure) { disposal = disposalFailure; }
        }
        if (primary is null && disposal is null)
        {
            try
            {
                TenantChangeAuditRecorder.DemandReceipt(context, committedReceipt!, registry);
                cancellationToken.ThrowIfCancellationRequested();
            }
            catch (Exception completionFailure) { primary = completionFailure; }
        }
        if (primary is not null || disposal is not null)
            throw new TenantChangeAuditTransactionException(outcome, primary, rollback, disposal);
        return result;
    }
}
/// <summary>Provider-reported claim data, not authority. The provider must fence tenant/lease/receipt/expiry on acknowledgement.</summary>
public sealed class TenantChangeAuditOutboxLease
{
    public TenantChangeAuditOutboxLease(TenantId tenant, Guid leaseId, DateTimeOffset expiresAtUtc,
        IEnumerable<TenantChangeAuditRecord> records)
    {
        Tenant = tenant ?? throw new ArgumentNullException(nameof(tenant));
        if (leaseId == Guid.Empty) throw new ArgumentException("Lease ID cannot be empty.", nameof(leaseId));
        ArgumentNullException.ThrowIfNull(records);
        var copy = records.Take(129).ToArray();
        if (copy.Length > 128 || copy.Any(x => x is null || !x.Receipt.Tenant.Equals(tenant)) ||
            copy.Select(x => x.Receipt.ReceiptId).Distinct().Count() != copy.Length)
            throw new ArgumentException("A claim contains at most128 unique records belonging to one tenant.", nameof(records));
        LeaseId = leaseId; ExpiresAtUtc = expiresAtUtc.ToUniversalTime(); Records = Array.AsReadOnly(copy);
    }
    public TenantId Tenant { get; }
    public Guid LeaseId { get; }
    public DateTimeOffset ExpiresAtUtc { get; }
    public IReadOnlyList<TenantChangeAuditRecord> Records { get; }
}
public interface ITenantChangeAuditOutboxSource
{
    ValueTask<TenantChangeAuditOutboxLease?> ClaimAsync(TenantId tenant, int maximum, TimeSpan leaseDuration, CancellationToken cancellationToken);
    ValueTask<bool> AcknowledgeAsync(TenantChangeAuditOutboxLease lease, Guid receiptId, CancellationToken cancellationToken);
    ValueTask ReleaseAsync(TenantChangeAuditOutboxLease lease, CancellationToken cancellationToken);
}
public interface ITenantChangeAuditIdempotentSink
{
    /// <summary>Same tenant/receipt ID and same payload must succeed idempotently; conflicting payload must fail.</summary>
    ValueTask AppendOnceAsync(TenantChangeAuditRecord record, CancellationToken cancellationToken);
}
public sealed class TenantChangeAuditOutboxRelayException : Exception
{
    internal TenantChangeAuditOutboxRelayException(int acknowledged, bool attempted, Exception? primary, Exception? release)
        : base("Outbox delivery or fenced claim cleanup failed; delivery may be repeated.",
            primary is not null && release is not null ? new AggregateException(primary, release) : primary ?? release)
    { AcknowledgedCount = acknowledged; MayHaveDelivered = attempted; PrimaryFailure = primary; ReleaseFailure = release; }
    public int AcknowledgedCount { get; }
    public bool MayHaveDelivered { get; }
    public Exception? PrimaryFailure { get; }
    public Exception? ReleaseFailure { get; }
}
/// <summary>Explicit bounded at-least-once relay. It installs no timer, background worker or tenant authority.</summary>
public sealed class TenantChangeAuditOutboxRelay
{
    private readonly ITenantChangeAuditOutboxSource source;
    private readonly ITenantChangeAuditIdempotentSink sink;
    private readonly TimeSpan leaseDuration;
    private readonly TimeProvider clock;
    private TenantChangeAuditOutboxRelay(ITenantChangeAuditOutboxSource source, ITenantChangeAuditIdempotentSink sink,
        TimeSpan leaseDuration, TimeProvider clock)
    { this.source = source; this.sink = sink; this.leaseDuration = leaseDuration; this.clock = clock; }
    public static TenantChangeAuditOutboxRelay? Activate(bool enabled,
        Func<ITenantChangeAuditOutboxSource>? sourceFactory = null, Func<ITenantChangeAuditIdempotentSink>? sinkFactory = null,
        TimeSpan? leaseDuration = null, TimeProvider? timeProvider = null)
    {
        if (!enabled) return null;
        ArgumentNullException.ThrowIfNull(sourceFactory); ArgumentNullException.ThrowIfNull(sinkFactory);
        var bound = TenantChangeAuditOutboxExecutor<object>.RequireBound(leaseDuration ?? TimeSpan.FromSeconds(15), nameof(leaseDuration));
        return new(sourceFactory() ?? throw new ArgumentException("The outbox source factory returned null."),
            sinkFactory() ?? throw new ArgumentException("The idempotent sink factory returned null."), bound, timeProvider ?? TimeProvider.System);
    }
    private static void Demand(TenantOperationContext context)
        => context.DemandAccess(context.Tenant, "audit-outbox", "tenant", "relay");
    public async ValueTask<int> RelayAsync(TenantOperationContext context, int maximum = 128, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (maximum < 1 || maximum > 128) throw new ArgumentOutOfRangeException(nameof(maximum));
        cancellationToken.ThrowIfCancellationRequested(); Demand(context);
        var startedUtc = clock.GetUtcNow(); var started = clock.GetTimestamp();
        var lease = await source.ClaimAsync(context.Tenant, maximum, leaseDuration, cancellationToken).ConfigureAwait(false);
        if (lease is null) { cancellationToken.ThrowIfCancellationRequested(); Demand(context); return 0; }
        var acknowledged = 0; var attempted = false; var invalid = false;
        Exception? primary = null, release = null;
        void DemandLease()
        {
            if (invalid) throw new TenantAccessDeniedException();
            try
            {
                var now = clock.GetUtcNow(); var elapsed = clock.GetElapsedTime(started, clock.GetTimestamp());
                if (!lease.Tenant.Equals(context.Tenant) || lease.Records.Count > maximum || now < startedUtc ||
                    now >= lease.ExpiresAtUtc || elapsed < TimeSpan.Zero || elapsed >= leaseDuration)
                    throw new TenantAccessDeniedException();
            }
            catch { invalid = true; throw; }
        }
        try
        {
            cancellationToken.ThrowIfCancellationRequested(); Demand(context); DemandLease();
            foreach (var record in lease.Records)
            {
                cancellationToken.ThrowIfCancellationRequested(); Demand(context); DemandLease();
                attempted = true;
                await sink.AppendOnceAsync(record, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested(); Demand(context); DemandLease();
                if (!await source.AcknowledgeAsync(lease, record.Receipt.ReceiptId, cancellationToken).ConfigureAwait(false))
                    throw new InvalidOperationException("The provider rejected the fenced outbox acknowledgement.");
                acknowledged++;
                cancellationToken.ThrowIfCancellationRequested(); Demand(context); DemandLease();
            }
        }
        catch (Exception failure) { primary = failure; }
        finally
        {
            try
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await source.ReleaseAsync(lease, cleanup.Token).ConfigureAwait(false);
                cleanup.Token.ThrowIfCancellationRequested();
            }
            catch (Exception releaseFailure) { release = releaseFailure; }
        }
        if (primary is null && release is null)
        {
            try { cancellationToken.ThrowIfCancellationRequested(); Demand(context); DemandLease(); }
            catch (Exception completionFailure) { primary = completionFailure; }
        }
        if (primary is not null || release is not null)
            throw new TenantChangeAuditOutboxRelayException(acknowledged, attempted, primary, release);
        return acknowledged;
    }
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
    private readonly TenantOperationRegistry? validatedRegistry;
    private TenantChangeAuditRecorder(TenantChangeAuditPolicy policy, ITenantChangeAuditSink sink, TimeSpan? writeTimeout, TimeProvider? timeProvider, TenantOperationRegistry? validatedRegistry = null)
    {
        this.policy = policy; this.sink = sink; this.validatedRegistry = validatedRegistry; timeout = writeTimeout ?? TimeSpan.FromSeconds(5); clock = timeProvider ?? TimeProvider.System;
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
    /// <summary>
    /// Validate actual frozen registration metadata and explicit audited operation requirements before loading the sink.
    /// A validated recorder accepts checked contexts only from this exact registry instance.
    /// Disabled mode skips the catalog, required enumeration and provider factory entirely.
    /// </summary>
    public static TenantChangeAuditRecorder? ActivateValidated(TenantChangeAuditPolicy policy, TenantOperationRegistry? registry,
        IEnumerable<string>? requiredOperationIds, Func<ITenantChangeAuditSink>? sinkFactory = null,
        TimeSpan? writeTimeout = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.Mode == TenantChangeAuditMode.Disabled) return null;
        ArgumentNullException.ThrowIfNull(registry); ArgumentNullException.ThrowIfNull(requiredOperationIds);
        ArgumentNullException.ThrowIfNull(sinkFactory);
        if (writeTimeout is { } bound && (bound <= TimeSpan.Zero || bound > TimeSpan.FromMinutes(1)))
            throw new ArgumentOutOfRangeException(nameof(writeTimeout));
        ValidateCatalog(policy, registry, requiredOperationIds);
        return new(policy, sinkFactory() ?? throw new ArgumentException("The trusted trail sink factory returned null."),
            writeTimeout, timeProvider, registry);
    }
    internal static void ValidateCatalog(TenantChangeAuditPolicy policy, TenantOperationRegistry registry, IEnumerable<string> requiredOperationIds)
    {
        var actual = registry.DescribeOperations().ToDictionary(x => x.OperationId, StringComparer.Ordinal);
        foreach (var rule in policy.Rules)
            if (!actual.TryGetValue(rule.OperationId, out var registered) ||
                !StringComparer.Ordinal.Equals(rule.Action, registered.Action) ||
                !StringComparer.Ordinal.Equals(rule.ResourceKind, registered.ResourceKind))
                throw new ArgumentException("An audit rule does not match the registered operation/action/resource kind: " + rule.OperationId, nameof(policy));
        var required = requiredOperationIds.Take(129).ToArray();
        if (required.Length > 128) throw new ArgumentException("At most128 required audited operations are supported.", nameof(requiredOperationIds));
        var distinct = new HashSet<string>(StringComparer.Ordinal);
        foreach (var operationId in required)
        {
            Cehpalon.Engine.Core.OperationId.RequireValid(operationId);
            if (!distinct.Add(operationId)) throw new ArgumentException("Required audited operation IDs must be unique.", nameof(requiredOperationIds));
            if (!actual.ContainsKey(operationId) || !policy.Rules.Any(x => StringComparer.Ordinal.Equals(x.OperationId, operationId)))
                throw new ArgumentException("A required audited operation is not registered with a matching audit rule: " + operationId, nameof(requiredOperationIds));
        }
    }
    /// <summary>
    /// Check cancellation, live scope, exact validated registry and rule before the application mutates data.
    /// This does not reserve storage, perform provider I/O or authorize a future commit.
    /// </summary>
    public TenantChangeAuditPreparation Prepare(TenantOperationContext context, CancellationToken cancellationToken = default)
    {
        DemandPreparation(policy, validatedRegistry, context, cancellationToken);
        return new(this, context);
    }
    internal static void DemandPreparation(TenantChangeAuditPolicy policy, TenantOperationRegistry? registry,
        TenantOperationContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context); cancellationToken.ThrowIfCancellationRequested();
        DemandCheckedContext(context, registry);
        if (!policy.Rules.Any(x => StringComparer.Ordinal.Equals(x.OperationId, context.OperationId) &&
            StringComparer.Ordinal.Equals(x.Action, context.Action) && StringComparer.Ordinal.Equals(x.ResourceKind, context.Resource.Kind)))
            throw new TenantAccessDeniedException();
        cancellationToken.ThrowIfCancellationRequested();
    }
    internal static void DemandCheckedContext(TenantOperationContext context, TenantOperationRegistry? registry)
    {
        context.DemandAccess(context.Tenant, context.Resource.Kind, context.Resource.ResourceId, context.Action);
        registry?.DemandContextBinding(context);
    }
    /// <summary>
    /// Prepare before invoking one trusted mutation, then await its required trail before returning its result.
    /// Once invocation starts, every failure conservatively reports possible committed effects. A returned
    /// receipt's completion uses the private write deadline independently of pending caller cancellation;
    /// cancellation is checked again before returning. No receipt can be invented when the mutation throws.
    /// This does not make mutation and trail persistence atomic or provide retries or rollback.
    /// </summary>
    public async ValueTask<TResult> ExecuteAsync<TResult>(TenantOperationContext context,
        Func<CancellationToken, ValueTask<TenantChangeAuditMutation<TResult>>> mutation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(mutation);
        var preparation = Prepare(context, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var changed = await mutation(cancellationToken).ConfigureAwait(false)
                ?? throw new ArgumentException("The trusted mutation returned no change receipt.", nameof(mutation));
            await preparation.CompleteAsync(changed.Receipt, changed.ValuesFactory, CancellationToken.None).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return changed.Result;
        }
        catch (TenantChangeAuditWriteException) { throw; }
        catch (Exception failure) { throw new TenantChangeAuditWriteException(failure); }
    }
    public async ValueTask RecordAsync(TenantOperationContext context, TenantChangeReceipt receipt,
        Func<TenantChangeStates>? valuesFactory = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context); ArgumentNullException.ThrowIfNull(receipt);
        try
        {
            var record = BuildCheckedRecord(policy, validatedRegistry, clock, context, receipt, valuesFactory, cancellationToken);
            using var deadline = new CancellationTokenSource(timeout);
            await sink.AppendAsync(record, deadline.Token).ConfigureAwait(false);
            deadline.Token.ThrowIfCancellationRequested(); cancellationToken.ThrowIfCancellationRequested(); Demand(context, receipt);
        }
        catch (Exception error) { throw new TenantChangeAuditWriteException(error); }
    }
    internal static TenantChangeAuditRecord BuildCheckedRecord(TenantChangeAuditPolicy policy, TenantOperationRegistry? registry,
        TimeProvider clock, TenantOperationContext context, TenantChangeReceipt receipt,
        Func<TenantChangeStates>? valuesFactory, CancellationToken cancellationToken)
    {
        DemandReceipt(context, receipt, registry); cancellationToken.ThrowIfCancellationRequested();
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
        DemandReceipt(context, receipt, registry); cancellationToken.ThrowIfCancellationRequested();
        return record;
    }
    private void Demand(TenantOperationContext context, TenantChangeReceipt receipt)
        => DemandReceipt(context, receipt, validatedRegistry);
    internal static void DemandReceipt(TenantOperationContext context, TenantChangeReceipt receipt, TenantOperationRegistry? registry)
    {
        DemandCheckedContext(context, registry);
        context.DemandAccess(receipt.Tenant, receipt.ResourceKind, receipt.ResourceId, receipt.Action);
        if (!context.Identity.Principal.Equals(receipt.Principal) || !StringComparer.Ordinal.Equals(context.Identity.AuthenticationScheme, receipt.AuthenticationScheme) ||
            !StringComparer.Ordinal.Equals(context.OperationId, receipt.OperationId) || !StringComparer.Ordinal.Equals(context.Resource.Version, receipt.AuthorizationResourceVersion))
            throw new TenantAccessDeniedException();
    }
}
/// <summary>
/// Application-reported mutation result, receipt and optional lazy states for ExecuteAsync.
/// The receipt reports the application's claim; construction does not prove a database commit.
/// </summary>
public sealed class TenantChangeAuditMutation<TResult>
{
    public TenantChangeAuditMutation(TenantChangeReceipt receipt, TResult result,
        Func<TenantChangeStates>? valuesFactory = null)
    {
        Receipt = receipt ?? throw new ArgumentNullException(nameof(receipt));
        Result = result;
        ValuesFactory = valuesFactory;
    }
    public TenantChangeReceipt Receipt { get; }
    public TResult Result { get; }
    internal Func<TenantChangeStates>? ValuesFactory { get; }
}
/// <summary>
/// Opaque single-attempt recording preparation bound to its original recorder and checked context.
/// It is not a database reservation, mutation authorization, proof of commit or backend exactly-once guarantee.
/// </summary>
public sealed class TenantChangeAuditPreparation
{
    private readonly TenantChangeAuditRecorder owner;
    private readonly TenantOperationContext context;
    private int consumed;
    internal TenantChangeAuditPreparation(TenantChangeAuditRecorder owner, TenantOperationContext context)
        => (this.owner, this.context) = (owner, context);
    public async ValueTask CompleteAsync(TenantChangeReceipt receipt, Func<TenantChangeStates>? valuesFactory = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            if (Interlocked.CompareExchange(ref consumed, 1, 0) != 0)
                throw new InvalidOperationException("The audit preparation has already been consumed.");
            await owner.RecordAsync(context, receipt, valuesFactory, cancellationToken).ConfigureAwait(false);
        }
        catch (TenantChangeAuditWriteException) { throw; }
        catch (Exception failure) { throw new TenantChangeAuditWriteException(failure); }
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
