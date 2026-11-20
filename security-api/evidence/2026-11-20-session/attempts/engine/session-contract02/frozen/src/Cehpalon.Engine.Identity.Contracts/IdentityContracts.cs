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
        var before = clock.GetUtcNow(); var started = clock.GetTimestamp();
        var identity = await inner.ResolveAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (identity is null || identity.SessionId is null) return null;
        var authenticatedAt = clock.GetUtcNow(); var authenticatedTimestamp = clock.GetTimestamp();
        var authenticationElapsed = clock.GetElapsedTime(started, authenticatedTimestamp);
        if (authenticatedAt < before || authenticatedTimestamp < started || authenticationElapsed < TimeSpan.Zero ||
            authenticationElapsed >= maximumLifetime || identity.NotBeforeUtc > authenticatedAt || authenticatedAt >= identity.ExpiresAtUtc) return null;
        var status = await sessions.ResolveAsync(identity, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var after = clock.GetUtcNow(); var ended = clock.GetTimestamp();
        var elapsed = clock.GetElapsedTime(started, ended);
        if (after < authenticatedAt || ended < authenticatedTimestamp || elapsed < authenticationElapsed || elapsed >= maximumLifetime ||
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
            ? new(identity.Principal, identity.AuthenticationScheme, notBefore, expires, identity.SessionId) : null;
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
        && now < identity.ExpiresAtUtc;

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
