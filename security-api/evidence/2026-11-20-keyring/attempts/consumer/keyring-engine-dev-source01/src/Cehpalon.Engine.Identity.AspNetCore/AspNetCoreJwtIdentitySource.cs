using System.Globalization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Cehpalon.Engine.Identity.AspNetCore;

/// <summary>
/// Maps an explicit, host-validated JWT authentication ticket, never a caller-set User flag.
/// Configure the established JWT handler for signature/issuer/audience/algorithm/lifetime validation
/// and MapInboundClaims=false. This adapter requires unique iss/sub/nbf/exp claims.
/// </summary>
public sealed class AspNetCoreJwtIdentitySource : IIdentitySource
{
    private readonly IHttpContextAccessor accessor;
    private readonly string scheme;
    private readonly TimeProvider clock;
    public AspNetCoreJwtIdentitySource(IHttpContextAccessor accessor, string authenticationScheme, TimeProvider? timeProvider = null)
    {
        this.accessor = accessor ?? throw new ArgumentNullException(nameof(accessor));
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticationScheme);
        if (authenticationScheme.Length > IdentitySnapshot.MaximumSchemeLength || authenticationScheme.Any(char.IsControl))
            throw new ArgumentException("Invalid authentication scheme.", nameof(authenticationScheme));
        scheme = authenticationScheme; clock = timeProvider ?? TimeProvider.System;
    }
    public async ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var context = accessor.HttpContext;
        if (context is null) return null;
        var result = await context.AuthenticateAsync(scheme).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested(); context.RequestAborted.ThrowIfCancellationRequested();
        if (!result.Succeeded || result.Ticket is null || !StringComparer.Ordinal.Equals(result.Ticket.AuthenticationScheme, scheme)) return null;
        var identities = result.Ticket.Principal.Identities.Take(2).ToArray();
        if (identities.Length != 1 || !identities[0].IsAuthenticated) return null;
        var claims = identities[0].Claims.Take(257).ToArray();
        if (claims.Length > 256) return null;
        string? Single(string type)
        {
            var matching = claims.Where(c => StringComparer.Ordinal.Equals(c.Type, type)).Take(2).ToArray();
            return matching.Length == 1 ? matching[0].Value : null;
        }
        var issuer = Single("iss"); var subject = Single("sub"); var nbf = Single("nbf"); var exp = Single("exp");
        if (issuer is null || subject is null ||
            !long.TryParse(nbf, NumberStyles.None, CultureInfo.InvariantCulture, out var beforeSeconds) ||
            !long.TryParse(exp, NumberStyles.None, CultureInfo.InvariantCulture, out var afterSeconds)) return null;
        try
        {
            var before = DateTimeOffset.FromUnixTimeSeconds(beforeSeconds);
            var after = DateTimeOffset.FromUnixTimeSeconds(afterSeconds);
            var now = clock.GetUtcNow();
            if (before > now || now >= after) return null;
            return new(new(issuer, subject), scheme, before, after);
        }
        catch (ArgumentException) { return null; }
    }
}
