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

    public IdentitySnapshot(PrincipalId principal, string authenticationScheme,
        DateTimeOffset notBeforeUtc, DateTimeOffset expiresAtUtc)
    {
        ArgumentNullException.ThrowIfNull(principal);
        if (expiresAtUtc <= notBeforeUtc)
            throw new ArgumentException("Identity validity must have a positive interval.", nameof(expiresAtUtc));
        Principal = principal;
        AuthenticationScheme = IdentityText.Require(authenticationScheme, MaximumSchemeLength, nameof(authenticationScheme));
        NotBeforeUtc = notBeforeUtc.ToUniversalTime();
        ExpiresAtUtc = expiresAtUtc.ToUniversalTime();
    }

    public PrincipalId Principal { get; }
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
