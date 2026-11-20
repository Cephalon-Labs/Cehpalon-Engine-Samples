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
