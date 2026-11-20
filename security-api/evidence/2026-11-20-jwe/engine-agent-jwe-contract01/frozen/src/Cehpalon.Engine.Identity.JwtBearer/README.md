# Optional configurable JWT/JWS validation

Signed compact JWT carries claims; JWS protects the signature; JWK/JWKS describes keys; Algorithm selects a cryptographic algorithm. These are distinct settings. This helper configures the established ASP.NET Core JwtBearer implementation, not a new parser/crypto implementation.

```json
{
  "Authentication": {
    "Api": {
      "Scheme": "ApiBearer",
      "Issuer": "https://identity.example/realm",
      "Audience": "orders-api",
      "Algorithm": "PS256",
      "TokenType": "at+jwt",
      "KeySource": "AuthorityMetadata",
      "Authority": "https://identity.example/realm"
    }
  }
}
```

```csharp
var profile = JwtAuthenticationProfile.FromConfiguration(
    builder.Configuration.GetSection("Authentication:Api"));
// Inside the selected security module factory only:
builder.Services.AddAuthentication(profile.Scheme).AddCehpalonJwtBearer(profile);
```

`JwtProfileSettings` also supports typed binding and `new JwtAuthenticationProfile(settings)`. Profiles freeze their values. Unknown/nested configuration fields, unsigned/unknown algorithms, mismatched sources and invalid metadata URLs reject before key callbacks. Use one exact algorithm per scheme. Supported algorithm identifiers: RS256/384/512, PS256/384/512, ES256/384/512 and HS256/384/512. The representative RSA/PSS/P-256/HMAC integrations have actual signature tests; selecting another identifier does not itself establish external provider interoperability.

Key sources are explicit:

- `PublicJwks`: `AddCehpalonJwtBearer(profile, publicJwks: () => trustedPublicJwksJson)`. Configure the host's file/key-service location separately. Strict bounded public JWKS requires 1–16 unique bounded kids, matching kty/alg, use=sig and verify-only key_ops if present. Only n/e RSA or crv/x/y EC public fields are accepted; private/octet/unknown/remote-reference fields reject. RSA has canonical modulus/exponent checks and at least 2048 actual bits; EC curve/coordinate size must match. One profile may contain multiple verification keys for controlled local rollover; metadata lifecycle requires separate proof.
- `ProvidedKeys`: `AddCehpalonJwtBearer(profile, providedKeys: () => trustedKeyService.GetVerificationKeys())`. Return bounded identified RSA/EC or SymmetricSecurityKey objects. Inputs are snapshotted; public RSA/EC material only is retained. HMAC requires sufficient key bytes (256/384/512 bits), a secret-store callback and the matching family. Byte count cannot prove entropy/secrecy; the host must not reuse public bytes as a secret or reuse a key across algorithms/profiles.
- `AuthorityMetadata`: exact configured issuer/audience/type/algorithm and HTTPS Authority/optional MetadataAddress. The established configuration manager handles retrieval/cache/refresh; metadata cannot add accepted token issuers. Network location is trusted host configuration, never unverified token jku/x5u/issuer. Metadata configuration tests do not prove real IdP rotation/revocation/outage behavior. Provider-specific metadata extensions and X.509/JWE need their own supported adapter.

Local lookup requires the exact kid; it does not try arbitrary keys or URLs from a token. IncludeErrorDetails and SaveToken are false, clock skew is zero, and audience trailing-slash equivalence is disabled. Do not place signing keys, symmetric secrets or bearer tokens in appsettings, evidence or audit logs. Do not activate this module for a disabled security profile.

Use `AspNetCoreJwtIdentitySource` with the same explicit scheme to enter tenant dispatch. Cookie/custom established handlers can use `AspNetCoreIdentitySource` with `IAuthenticatedTicketIdentityMapper`; `TicketPropertyIdentityMapper` maps a fixed issuer, unique configured subject claim and ticket IssuedUtc/ExpiresUtc. It does not turn an arbitrary User flag into authority or implement account/login/session lifecycle. Other algorithms, protocols or key-provider semantics remain replaceable through established host handlers and IIdentitySource.
