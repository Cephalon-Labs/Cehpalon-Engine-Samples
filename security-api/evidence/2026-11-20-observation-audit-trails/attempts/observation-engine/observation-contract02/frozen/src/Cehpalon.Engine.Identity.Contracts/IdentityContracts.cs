using System.Buffers;
using System.Collections.Frozen;
using System.Text;

namespace Cehpalon.Engine.Identity;

/// <summary>An exact issuer/subject key, not proof that either value was authenticated.</summary>
public sealed class PrincipalId : IEquatable<PrincipalId>
{
    public const int MaximumIssuerLength = 2048;
    public const int MaximumSubjectLength = 256;

    public PrincipalId(string issuer, string subject)
    {
        Issuer = IdentityText.Require(issuer, MaximumIssuerLength, nameof(issuer));
        Subject = IdentityText.Require(subject, MaximumSubjectLength, nameof(subject));
    }

    public string Issuer { get; }
    public string Subject { get; }
    public bool Equals(PrincipalId? other) => other is not null
        && StringComparer.Ordinal.Equals(Issuer, other.Issuer)
        && StringComparer.Ordinal.Equals(Subject, other.Subject);
    public override bool Equals(object? obj) => obj is PrincipalId other && Equals(other);
    public override int GetHashCode() => HashCode.Combine(
        StringComparer.Ordinal.GetHashCode(Issuer), StringComparer.Ordinal.GetHashCode(Subject));
}

/// <summary>
/// An immutable representation supplied by a configured trusted identity source.
/// Its constructor performs data validation, not JWT/OIDC/token authentication.
/// </summary>
public sealed class IdentitySnapshot
{
    public const int MaximumSchemeLength = 128;
    public const int MaximumSessionIdLength = 256;
    private const int MaximumObservationConstraints = 16;
    private static readonly ObservationConstraint[] NoObservations = [];
    private readonly ObservationConstraint[] observations = NoObservations;

    public IdentitySnapshot(PrincipalId principal, string authenticationScheme,
        DateTimeOffset notBeforeUtc, DateTimeOffset expiresAtUtc)
        : this(principal, authenticationScheme, notBeforeUtc, expiresAtUtc, null) { }

    public IdentitySnapshot(PrincipalId principal, string authenticationScheme,
        DateTimeOffset notBeforeUtc, DateTimeOffset expiresAtUtc, string? sessionId)
    {
        ArgumentNullException.ThrowIfNull(principal);
        if (expiresAtUtc <= notBeforeUtc)
            throw new ArgumentException("Identity validity must have a positive interval.", nameof(expiresAtUtc));
        Principal = principal;
        AuthenticationScheme = IdentityText.Require(authenticationScheme, MaximumSchemeLength, nameof(authenticationScheme));
        NotBeforeUtc = notBeforeUtc.ToUniversalTime();
        ExpiresAtUtc = expiresAtUtc.ToUniversalTime();
        SessionId = sessionId is null ? null : IdentityText.Require(sessionId, MaximumSessionIdLength, nameof(sessionId));
    }

    public PrincipalId Principal { get; }
    public string? SessionId { get; }
    public string AuthenticationScheme { get; }
    public DateTimeOffset NotBeforeUtc { get; }
    public DateTimeOffset ExpiresAtUtc { get; }

    /// <summary>
    /// Check only additional source observation constraints; true for plain representations.
    /// This is not authentication, issuer/scheme validation, ordinary UTC validity or a fresh session query.
    /// Clock faults invalidate the shared observation before propagating; later checks deny.
    /// </summary>
    public bool SatisfiesObservationConstraints()
    {
        foreach (var observation in observations)
            if (!observation.IsCurrent()) return false;
        return true;
    }

    /// <summary>Narrow UTC validity without changing bindings or restarting any original observation clock.</summary>
    public IdentitySnapshot WithValidity(DateTimeOffset notBeforeUtc, DateTimeOffset expiresAtUtc)
    {
        if (notBeforeUtc < NotBeforeUtc || expiresAtUtc > ExpiresAtUtc || expiresAtUtc <= notBeforeUtc)
            throw new ArgumentException("The validity interval must be a non-empty subset of the original interval.");
        return new(this, notBeforeUtc, expiresAtUtc, observations);
    }

    /// <summary>
    /// Intersect exact identity bindings, UTC validity and all original observations.
    /// Null means different bindings, disjoint validity or more than sixteen distinct constraints; none are truncated.
    /// </summary>
    public IdentitySnapshot? IntersectValidity(IdentitySnapshot other)
    {
        ArgumentNullException.ThrowIfNull(other);
        if (!Principal.Equals(other.Principal) || !StringComparer.Ordinal.Equals(AuthenticationScheme, other.AuthenticationScheme) ||
            !StringComparer.Ordinal.Equals(SessionId, other.SessionId)) return null;
        var before = NotBeforeUtc > other.NotBeforeUtc ? NotBeforeUtc : other.NotBeforeUtc;
        var expires = ExpiresAtUtc < other.ExpiresAtUtc ? ExpiresAtUtc : other.ExpiresAtUtc;
        if (expires <= before) return null;
        if (observations.Length == 0) return new(this, before, expires, other.observations);
        if (other.observations.Length == 0) return new(this, before, expires, observations);
        var combined = new List<ObservationConstraint>(observations);
        foreach (var candidate in other.observations)
        {
            // Private sealed constraints use reference equality and never expose their mutable clock state.
            if (combined.Contains(candidate)) continue;
            if (combined.Count == MaximumObservationConstraints) return null;
            combined.Add(candidate);
        }
        return new(this, before, expires, combined.ToArray());
    }

    private IdentitySnapshot(IdentitySnapshot original, DateTimeOffset before, DateTimeOffset expires, ObservationConstraint[] constraints)
        : this(original.Principal, original.AuthenticationScheme, before, expires, original.SessionId) => observations = constraints;

    internal IdentitySnapshot? AttachObservation(TimeProvider clock, long started, long completedTimestamp, long frequency,
        TimeSpan elapsedAtCompletion, TimeSpan maximumLifetime, DateTimeOffset completedUtc)
    {
        if (observations.Length == MaximumObservationConstraints) return null;
        var remaining = maximumLifetime - elapsedAtCompletion;
        var utcRemaining = ExpiresAtUtc - completedUtc;
        if (utcRemaining < remaining) remaining = utcRemaining;
        if (remaining <= TimeSpan.Zero) return null;
        var constraints = new ObservationConstraint[observations.Length + 1];
        observations.CopyTo(constraints, 0);
        constraints[^1] = new(clock, started, completedTimestamp, frequency, elapsedAtCompletion,
            elapsedAtCompletion + remaining, completedUtc, ExpiresAtUtc);
        var identity = new IdentitySnapshot(this, NotBeforeUtc, ExpiresAtUtc, constraints);
        return identity.SatisfiesObservationConstraints() ? identity : null;
    }

    private sealed class ObservationConstraint(TimeProvider clock, long started, long completedTimestamp, long frequency,
        TimeSpan completedElapsed, TimeSpan nativeCeiling, DateTimeOffset completedUtc, DateTimeOffset expiresUtc)
    {
        private readonly object gate = new();
        private bool active = true;
        private readonly DateTimeOffset lowerUtc = completedUtc;
        private DateTimeOffset lastUtc = completedUtc;
        private long lastTimestamp = completedTimestamp;
        private TimeSpan lastElapsed = completedElapsed;
        internal bool IsCurrent()
        {
            lock (gate)
            {
                if (!active) return false;
                try
                {
                    var now = clock.GetUtcNow(); var timestamp = clock.GetTimestamp();
                    if (clock.TimestampFrequency != frequency || frequency <= 0 || now < lastUtc || now < lowerUtc ||
                        now >= expiresUtc || timestamp < lastTimestamp) return active = false;
                    var elapsed = clock.GetElapsedTime(started, timestamp);
                    if (clock.TimestampFrequency != frequency || elapsed < lastElapsed || elapsed < TimeSpan.Zero || elapsed >= nativeCeiling)
                        return active = false;
                    lastUtc = now; lastTimestamp = timestamp; lastElapsed = elapsed;
                    return true;
                }
                catch { active = false; throw; }
            }
        }
    }
}

/// <summary>
/// Trusted adapter boundary. Resolve afresh per invocation; null means anonymous.
/// The adapter owns protocol authentication and must observe cancellation.
/// Caller metadata, a header or a constructed snapshot is not authentication.
/// </summary>
public interface IIdentitySource
{
    ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken cancellationToken);
}

/// <summary>Bounded session authority facts from a configured trusted source; construction is not authority.</summary>
public sealed class SessionStatusSnapshot
{
    public SessionStatusSnapshot(PrincipalId principal, string authenticationScheme, string sessionId, bool isActive,
        DateTimeOffset notBeforeUtc, DateTimeOffset expiresAtUtc)
    {
        Principal = principal ?? throw new ArgumentNullException(nameof(principal));
        AuthenticationScheme = IdentityText.Require(authenticationScheme, IdentitySnapshot.MaximumSchemeLength, nameof(authenticationScheme));
        SessionId = IdentityText.Require(sessionId, IdentitySnapshot.MaximumSessionIdLength, nameof(sessionId));
        if (expiresAtUtc <= notBeforeUtc) throw new ArgumentException("Session validity must have a positive interval.", nameof(expiresAtUtc));
        IsActive = isActive; NotBeforeUtc = notBeforeUtc.ToUniversalTime(); ExpiresAtUtc = expiresAtUtc.ToUniversalTime();
    }
    public PrincipalId Principal { get; }
    public string AuthenticationScheme { get; }
    public string SessionId { get; }
    public bool IsActive { get; }
    public DateTimeOffset NotBeforeUtc { get; }
    public DateTimeOffset ExpiresAtUtc { get; }
}

/// <summary>Trusted application session authority. Resolve afresh; null/inactive denies and faults/cancellation propagate.</summary>
public interface IIdentitySessionStatusSource
{
    ValueTask<SessionStatusSnapshot?> ResolveAsync(IdentitySnapshot identity, CancellationToken cancellationToken);
}

/// <summary>
/// Optional fresh session-status observation after established authentication, including cached host tickets.
/// This is not a live revocation subscription or atomic transaction with later admission/business execution.
/// </summary>
public sealed class SessionValidatingIdentitySource : IIdentitySource
{
    private readonly IIdentitySource inner;
    private readonly IIdentitySessionStatusSource sessions;
    private readonly TimeSpan maximumLifetime;
    private readonly TimeProvider clock;
    public SessionValidatingIdentitySource(IIdentitySource inner, IIdentitySessionStatusSource statusSource,
        TimeSpan maximumObservationLifetime, TimeProvider? timeProvider = null)
    {
        this.inner = inner ?? throw new ArgumentNullException(nameof(inner));
        sessions = statusSource ?? throw new ArgumentNullException(nameof(statusSource));
        if (maximumObservationLifetime <= TimeSpan.Zero || maximumObservationLifetime > TimeSpan.FromMinutes(5))
            throw new ArgumentOutOfRangeException(nameof(maximumObservationLifetime), "The observation lifetime must be positive and at most five minutes.");
        maximumLifetime = maximumObservationLifetime; clock = timeProvider ?? TimeProvider.System;
    }
    public async ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var before = clock.GetUtcNow(); var frequency = clock.TimestampFrequency; var started = clock.GetTimestamp();
        var identity = await inner.ResolveAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (identity is null || identity.SessionId is null || !identity.SatisfiesObservationConstraints()) return null;
        var authenticatedAt = clock.GetUtcNow(); var authenticatedTimestamp = clock.GetTimestamp();
        var authenticationElapsed = clock.GetElapsedTime(started, authenticatedTimestamp);
        if (frequency <= 0 || clock.TimestampFrequency != frequency || authenticatedAt < before || authenticatedTimestamp < started || authenticationElapsed < TimeSpan.Zero ||
            authenticationElapsed >= maximumLifetime || identity.NotBeforeUtc > authenticatedAt || authenticatedAt >= identity.ExpiresAtUtc) return null;
        var status = await sessions.ResolveAsync(identity, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var after = clock.GetUtcNow(); var ended = clock.GetTimestamp();
        var elapsed = clock.GetElapsedTime(started, ended);
        if (clock.TimestampFrequency != frequency || !identity.SatisfiesObservationConstraints() || after < authenticatedAt || ended < authenticatedTimestamp || elapsed < authenticationElapsed || elapsed >= maximumLifetime ||
            identity.NotBeforeUtc > after || after >= identity.ExpiresAtUtc || status is null || !status.IsActive ||
            !status.Principal.Equals(identity.Principal) || !StringComparer.Ordinal.Equals(status.AuthenticationScheme, identity.AuthenticationScheme) ||
            !StringComparer.Ordinal.Equals(status.SessionId, identity.SessionId) || status.NotBeforeUtc > after || after >= status.ExpiresAtUtc) return null;
        var notBefore = identity.NotBeforeUtc > status.NotBeforeUtc ? identity.NotBeforeUtc : status.NotBeforeUtc;
        if (after > notBefore) notBefore = after;
        var expires = identity.ExpiresAtUtc < status.ExpiresAtUtc ? identity.ExpiresAtUtc : status.ExpiresAtUtc;
        var utcCap = AddBounded(before, maximumLifetime); var remainingCap = AddBounded(after, maximumLifetime - elapsed);
        if (utcCap < expires) expires = utcCap;
        if (remainingCap < expires) expires = remainingCap;
        return expires > after && expires > notBefore
            ? identity.WithValidity(notBefore, expires).AttachObservation(clock, started, ended, frequency, elapsed, maximumLifetime, after) : null;
    }
    private static DateTimeOffset AddBounded(DateTimeOffset value, TimeSpan duration)
        => duration.Ticks > DateTimeOffset.MaxValue.UtcTicks - value.UtcTicks ? DateTimeOffset.MaxValue : value.Add(duration);
}

/// <summary>
/// Exact allowlist and snapshot-lifetime gate after upstream authentication.
/// Empty lists deny all. No token parsing, cryptographic validation, role mapping
/// or normalization is performed by this component.
/// </summary>
public sealed class IdentityTrustPolicy
{
    public const int MaximumEntries = 256;
    private readonly FrozenSet<string> issuers;
    private readonly FrozenSet<string> schemes;

    public IdentityTrustPolicy(IEnumerable<string> allowedIssuers, IEnumerable<string> allowedSchemes)
    {
        issuers = Snapshot(allowedIssuers, PrincipalId.MaximumIssuerLength, nameof(allowedIssuers));
        schemes = Snapshot(allowedSchemes, IdentitySnapshot.MaximumSchemeLength, nameof(allowedSchemes));
    }

    public IReadOnlySet<string> AllowedIssuers => issuers;
    public IReadOnlySet<string> AllowedSchemes => schemes;

    public bool IsAccepted(IdentitySnapshot? identity, DateTimeOffset now) => identity is not null
        && issuers.Contains(identity.Principal.Issuer)
        && schemes.Contains(identity.AuthenticationScheme)
        && identity.NotBeforeUtc <= now
        && now < identity.ExpiresAtUtc
        && identity.SatisfiesObservationConstraints();

    private static FrozenSet<string> Snapshot(IEnumerable<string> values, int maximumLength, string parameter)
    {
        ArgumentNullException.ThrowIfNull(values, parameter);
        // Limit total entries, not only distinct entries. A duplicate/infinite
        // enumerable cannot bypass the enumeration bound.
        var entries = values.Take(MaximumEntries + 1).ToArray();
        if (entries.Length > MaximumEntries)
            throw new ArgumentException($"At most {MaximumEntries} values are supported.", parameter);
        var copy = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in entries)
            if (!copy.Add(IdentityText.Require(value, maximumLength, parameter)))
                throw new ArgumentException("Duplicate trust values are not supported.", parameter);
        return copy.ToFrozenSet(StringComparer.Ordinal);
    }
}

internal static class IdentityText
{
    internal static string Require(string? value, int maximumLength, string parameter)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameter);
        if (value.Length > maximumLength)
            throw new ArgumentException($"Value exceeds the {maximumLength} UTF-16 code-unit limit.", parameter);
        var remaining = value.AsSpan();
        while (!remaining.IsEmpty)
        {
            if (Rune.DecodeFromUtf16(remaining, out var rune, out var consumed) != OperationStatus.Done
                || Rune.IsControl(rune))
                throw new ArgumentException("Control characters and malformed UTF-16 are not supported.", parameter);
            remaining = remaining[consumed..];
        }
        return value;
    }
}
