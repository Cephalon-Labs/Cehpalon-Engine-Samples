# Optional ASP.NET Core JWT authentication bridge

`AspNetCoreJwtIdentitySource` adapts `AuthenticateAsync(explicitScheme)` into portable `IIdentitySource`. It never authenticates an arbitrary `HttpContext.User` flag. One successful ticket for that exact scheme and one authenticated identity must contain one each of `iss`, `sub`, integral `nbf` and integral `exp`, with a valid current interval. Ambiguous/malformed/expired representations return anonymous; cancellation and infrastructure faults are preserved.

Configure the established host JWT handler with `MapInboundClaims=false`, fixed issuer/audience, signature/key validation, required signed tokens and expiry, explicit algorithms/types, appropriate clock skew and trusted key/metadata retrieval. The bridge does not parse a JWT or replace cryptographic validation. Add authentication before authorization in the ASP.NET middleware pipeline. A successful JWT is still subject to `IdentityTrustPolicy`, fresh tenant membership/resource checks and policy.

```csharp
var source = new AspNetCoreJwtIdentitySource(httpContextAccessor, "Bearer");
// Inject source into TenantSecurityServices for the protected dispatcher.
```

Other authentication protocols use their established host handlers and a trusted `IIdentitySource` adapter. This JWT bridge deliberately requires the stated JWT claim profile; it does not map cookie tickets, issue tokens, manage users/passwords, implement browser sign-in, MFA, refresh tokens or sessions. Token revocation/key rotation/issuer outage and session lifecycle must be configured and tested against the application's real IdP. Do not log bearer tokens or signing keys. Self-issued local fixture tokens only prove this bounded integration.

`AspNetCoreIdentitySource` now provides an explicit-scheme established-ticket bridge with `IAuthenticatedTicketIdentityMapper`. `TicketPropertyIdentityMapper` uses a fixed application issuer, unique subject claim and authenticated ticket IssuedUtc/ExpiresUtc, suitable for the declared cookie ticket profile. Mapping still follows actual AuthenticateAsync success; a caller-set User flag is ignored. Mapped scheme/lifetime, cancellation/request abort and clock rollback are rechecked after mapping. Use a DI-registered or request-owned accessor; constructing an ambient HttpContextAccessor and setting HttpContext inside parallel resolver code can clear shared request state.

Cookie/browser hosts own CSRF protection, cookie policy, secure persistent key management and account/session revocation. Samples uses a real encrypted cookie with an ephemeral provider solely for local integration; it does not establish a production login/session system. Configurable signed JWT/key profiles live in the separate Identity.JwtBearer module.

## Explicit session mapping and fresh application status

The original JWT bridge constructor keeps its sessionless behavior. Opt in with the four-argument overload; the explicit claim type must identify a unique authenticated session claim:

```csharp
var mapped = new AspNetCoreJwtIdentitySource(accessor, "Bearer", TimeProvider.System, "sid");
var guarded = new SessionValidatingIdentitySource(mapped, trustedSessionStatusSource,
    TimeSpan.FromSeconds(30));
// Supply guarded as TenantSecurityServices.IdentitySource.
```

Cookie/custom tickets use the same established-ticket bridge with SessionBoundTicketIdentityMapper(new TicketPropertyIdentityMapper(fixedIssuer), "sid"). The wrapper reads one bounded exact claim from that ticket after its inner mapper succeeds; a conflicting preexisting inner SessionId denies rather than being overwritten. Neither mapping authenticates a caller-set User flag. Missing/duplicate/malformed IDs deny only when the optional mapping is selected.

Cached AuthenticateAsync success does not cache the additional session-status observation. The portable decorator checks only calls routed through its IIdentitySource; it does not clear the host principal/ticket/cookie or change ordinary middleware/RequireAuthorization routes. Hosts must guard other entrypoints explicitly, own unique-per-login IDs and never reactivate/reuse revoked IDs while prior credentials may still work. Supply/link RequestAborted to the portable call for status-await cancellation. Returned lifetime bounds this observation, not all later admission awaits; revocation races and already admitted effects remain possible. The local port is not an OAuth logout endpoint, distributed revocation system or real IdP/session-store qualification. Audit of session management remains application-owned.
