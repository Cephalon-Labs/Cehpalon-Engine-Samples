using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Cehpalon.Engine.Identity.AspNetCore;

/// <summary>Trusted pure protocol-specific mapping after the configured host handler authenticates a ticket.</summary>
public interface IAuthenticatedTicketIdentityMapper
{
    IdentitySnapshot? Map(AuthenticationTicket ticket, string authenticationScheme, DateTimeOffset observedAtUtc);
}

/// <summary>Optional bridge for established cookie/custom handlers. A User flag or a mapper alone never authenticates.</summary>
public sealed class AspNetCoreIdentitySource : IIdentitySource
{
    private readonly IHttpContextAccessor accessor;
    private readonly string scheme;
    private readonly IAuthenticatedTicketIdentityMapper mapper;
    private readonly TimeProvider clock;
    public AspNetCoreIdentitySource(IHttpContextAccessor accessor, string authenticationScheme,
        IAuthenticatedTicketIdentityMapper mapper, TimeProvider? timeProvider = null)
    {
        this.accessor = accessor ?? throw new ArgumentNullException(nameof(accessor));
        this.mapper = mapper ?? throw new ArgumentNullException(nameof(mapper)); clock = timeProvider ?? TimeProvider.System;
        scheme = new IdentitySnapshot(new("scheme-validation", "profile"), authenticationScheme,
            DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddSeconds(1)).AuthenticationScheme;
    }
    public async ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); var context = accessor.HttpContext;
        if (context is null) return null;
        var result = await context.AuthenticateAsync(scheme).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested(); context.RequestAborted.ThrowIfCancellationRequested();
        if (!result.Succeeded || result.Ticket is null || result.Ticket.AuthenticationScheme != scheme) return null;
        var identities = result.Ticket.Principal.Identities.Take(2).ToArray();
        if (identities.Length != 1 || !identities[0].IsAuthenticated) return null;
        var before = clock.GetUtcNow(); var identity = mapper.Map(result.Ticket, scheme, before);
        cancellationToken.ThrowIfCancellationRequested(); context.RequestAborted.ThrowIfCancellationRequested();
        var after = clock.GetUtcNow();
        return identity is not null && identity.AuthenticationScheme == scheme && after >= before &&
            identity.NotBeforeUtc <= after && after < identity.ExpiresAtUtc ? identity : null;
    }
}

/// <summary>Fixed application issuer, unique subject and established ticket validity (e.g. authenticated cookie ticket).</summary>
public sealed class TicketPropertyIdentityMapper : IAuthenticatedTicketIdentityMapper
{
    private readonly string issuer, subjectClaimType;
    public TicketPropertyIdentityMapper(string fixedIssuer, string subjectClaimType = ClaimTypes.NameIdentifier)
    {
        issuer = new PrincipalId(fixedIssuer, "mapping-validation").Issuer;
        this.subjectClaimType = new PrincipalId(subjectClaimType, "mapping-validation").Issuer;
    }
    public IdentitySnapshot? Map(AuthenticationTicket ticket, string authenticationScheme, DateTimeOffset observedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        var claims = ticket.Principal.Claims.Take(257).ToArray();
        if (claims.Length > 256) return null;
        var subject = claims.Where(c => c.Type == subjectClaimType).Take(2).ToArray();
        if (subject.Length != 1 || ticket.Properties.IssuedUtc is not { } issued || ticket.Properties.ExpiresUtc is not { } expires ||
            observedAtUtc < issued || observedAtUtc >= expires) return null;
        try { return new(new(issuer, subject[0].Value), authenticationScheme, issued, expires); }
        catch (ArgumentException) { return null; }
    }
}

/// <summary>Opt-in unique session claim mapping on the same established cookie/custom ticket mapped by the inner mapper.</summary>
public sealed class SessionBoundTicketIdentityMapper : IAuthenticatedTicketIdentityMapper
{
    private readonly IAuthenticatedTicketIdentityMapper inner;
    private readonly string claimType;
    public SessionBoundTicketIdentityMapper(IAuthenticatedTicketIdentityMapper innerMapper, string sessionClaimType = "sid")
    {
        inner = innerMapper ?? throw new ArgumentNullException(nameof(innerMapper));
        claimType = new PrincipalId(sessionClaimType, "session-mapping").Issuer;
    }
    public IdentitySnapshot? Map(AuthenticationTicket ticket, string authenticationScheme, DateTimeOffset observedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        var identity = inner.Map(ticket, authenticationScheme, observedAtUtc);
        if (identity is null) return null;
        var claims = ticket.Principal.Claims.Take(257).ToArray();
        if (claims.Length > 256) return null;
        var sessions = claims.Where(c => StringComparer.Ordinal.Equals(c.Type, claimType)).Take(2).ToArray();
        if (sessions.Length != 1 || (identity.SessionId is not null &&
            !StringComparer.Ordinal.Equals(identity.SessionId, sessions[0].Value))) return null;
        try { return new(identity.Principal, identity.AuthenticationScheme, identity.NotBeforeUtc, identity.ExpiresAtUtc, sessions[0].Value); }
        catch (ArgumentException) { return null; }
    }
}
