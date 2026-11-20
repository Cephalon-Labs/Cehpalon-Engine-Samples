# Optional ASP.NET Core JWT authentication bridge

`AspNetCoreJwtIdentitySource` adapts `AuthenticateAsync(explicitScheme)` into portable `IIdentitySource`. It never authenticates an arbitrary `HttpContext.User` flag. One successful ticket for that exact scheme and one authenticated identity must contain one each of `iss`, `sub`, integral `nbf` and integral `exp`, with a valid current interval. Ambiguous/malformed/expired representations return anonymous; cancellation and infrastructure faults are preserved.

Configure the established host JWT handler with `MapInboundClaims=false`, fixed issuer/audience, signature/key validation, required signed tokens and expiry, explicit algorithms/types, appropriate clock skew and trusted key/metadata retrieval. The bridge does not parse a JWT or replace cryptographic validation. Add authentication before authorization in the ASP.NET middleware pipeline. A successful JWT is still subject to `IdentityTrustPolicy`, fresh tenant membership/resource checks and policy.

```csharp
var source = new AspNetCoreJwtIdentitySource(httpContextAccessor, "Bearer");
// Inject source into TenantSecurityServices for the protected dispatcher.
```

Other authentication protocols use their established host handlers and a trusted `IIdentitySource` adapter. This JWT bridge deliberately requires the stated JWT claim profile; it does not map cookie tickets, issue tokens, manage users/passwords, implement browser sign-in, MFA, refresh tokens or sessions. Token revocation/key rotation/issuer outage and session lifecycle must be configured and tested against the application's real IdP. Do not log bearer tokens or signing keys. Self-issued local fixture tokens only prove this bounded integration.
