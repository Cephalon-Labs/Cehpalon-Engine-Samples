using Microsoft.IdentityModel.Tokens;

namespace Cehpalon.Engine.Identity.JwtBearer;

/// <summary>
/// Consumer-owned bounded local key publication. The ring exposes metadata, not keys.
/// Publication/withdrawal are trusted management operations, never token-triggered refresh.
/// </summary>
public sealed class JwtKeyRing : IDisposable
{
    private readonly object gate = new();
    private readonly TimeProvider clock;
    private readonly TimeSpan maximumLifetime;
    private Snapshot? current;
    private long version;
    private bool closed;

    public JwtKeyRing(JwtAuthenticationProfile profile, TimeSpan? maximumSnapshotLifetime = null, TimeProvider? timeProvider = null)
    {
        Profile = profile ?? throw new ArgumentNullException(nameof(profile));
        if (profile.KeySource != JwtKeySource.RotatingKeyRing) throw new ArgumentException("Select the explicit rotating-key-ring source.", nameof(profile));
        maximumLifetime = maximumSnapshotLifetime ?? TimeSpan.FromMinutes(5);
        if (maximumLifetime <= TimeSpan.Zero || maximumLifetime > TimeSpan.FromHours(1))
            throw new ArgumentOutOfRangeException(nameof(maximumSnapshotLifetime), "Snapshot lifetime must be positive and at most one hour.");
        clock = timeProvider ?? TimeProvider.System;
    }
    public JwtAuthenticationProfile Profile { get; }
    public long Version { get { lock (gate) return version; } }

    /// <summary>Validate/copy a complete candidate, then atomically replace only the expected live version.</summary>
    public long Publish(long expectedVersion, IEnumerable<SecurityKey> signingKeys, IEnumerable<SecurityKey>? decryptionKeys,
        DateTimeOffset notBeforeUtc, DateTimeOffset expiresAtUtc)
    {
        lock (gate) DemandPublisher(expectedVersion);
        var signing = ProfileKeys.CopyProvided(signingKeys, Profile);
        SecurityKey[] decrypt;
        if (Profile.TokenProtection == JwtTokenProtection.EncryptedSigned)
            decrypt = JweKeys.Copy(decryptionKeys ?? throw new ArgumentException("Encrypted rings require separate decryption keys.", nameof(decryptionKeys)), Profile);
        else
        {
            if (decryptionKeys is not null) throw new ArgumentException("Signed rings cannot contain decryption keys.", nameof(decryptionKeys));
            decrypt = [];
        }
        foreach (var key in signing)
            if (!JweKeys.IsSeparate(key, decrypt)) throw new ArgumentException("Signing and decryption keys must use distinct IDs and material.");
        lock (gate)
        {
            DemandPublisher(expectedVersion);
            var now = clock.GetUtcNow();
            if (notBeforeUtc > now || expiresAtUtc <= now || expiresAtUtc - now > maximumLifetime || expiresAtUtc <= notBeforeUtc)
                throw new ArgumentException("Publish only currently valid keys with a bounded remaining lifetime.");
            var started = clock.GetTimestamp();
            var next = checked(version + 1);
            var candidate = new Snapshot(next, signing, decrypt, notBeforeUtc.ToUniversalTime(), expiresAtUtc.ToUniversalTime(), now, started);
            current = candidate; version = next;
            return next;
        }
    }

    /// <summary>Withdraw all future validations without falling back to an earlier snapshot.</summary>
    public long Withdraw(long expectedVersion)
    {
        lock (gate)
        {
            DemandPublisher(expectedVersion); var next = checked(version + 1);
            current = null; version = next; return next;
        }
    }
    private void DemandPublisher(long expectedVersion)
    {
        ObjectDisposedException.ThrowIf(closed, this);
        if (expectedVersion != version) throw new InvalidOperationException("The key publication version is stale.");
    }
    internal Snapshot? Capture()
    {
        lock (gate) return !closed && current is { } snapshot && IsLive(snapshot) ? snapshot : null;
    }
    internal bool IsCurrent(Snapshot snapshot)
    {
        lock (gate) return !closed && ReferenceEquals(current, snapshot) && snapshot.Version == version && IsLive(snapshot);
    }
    // Called only under gate; invalidity permanently latches for this version.
    private bool IsLive(Snapshot snapshot)
    {
        if (!snapshot.Active) return false;
        try
        {
            var now = clock.GetUtcNow(); var timestamp = clock.GetTimestamp();
            var elapsed = clock.GetElapsedTime(snapshot.Started, timestamp);
            if (now < snapshot.LastObservedUtc || now < snapshot.NotBeforeUtc || now >= snapshot.ExpiresAtUtc ||
                timestamp < snapshot.LastObservedTimestamp || elapsed < TimeSpan.Zero || elapsed >= snapshot.MaximumElapsed)
                return snapshot.Active = false;
            snapshot.LastObservedUtc = now; snapshot.LastObservedTimestamp = timestamp; return true;
        }
        catch { snapshot.Active = false; return false; }
    }
    public void Dispose()
    {
        lock (gate) { closed = true; current = null; }
    }
    internal sealed class Snapshot(long version, SecurityKey[] signing, SecurityKey[] decrypt,
        DateTimeOffset notBeforeUtc, DateTimeOffset expiresAtUtc, DateTimeOffset publishedUtc, long started)
    {
        internal readonly long Version = version, Started = started;
        internal readonly SecurityKey[] Signing = signing, Decrypt = decrypt;
        internal readonly DateTimeOffset NotBeforeUtc = notBeforeUtc, ExpiresAtUtc = expiresAtUtc;
        internal readonly TimeSpan MaximumElapsed = expiresAtUtc - publishedUtc;
        internal DateTimeOffset LastObservedUtc = publishedUtc;
        internal long LastObservedTimestamp = started;
        internal bool Active = true;
    }
}
