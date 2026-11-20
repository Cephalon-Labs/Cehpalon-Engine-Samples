# Optional authentication, RBAC/ABAC and audit history consumer

Experimental local consumer of Core, Composition, CodeGeneration, the JWT identity bridge, Authorization and Tenancy. It starts only owned ephemeral localhost HTTPS endpoints and exits after its test matrix. Actual JwtBearer validates ephemeral RS256 fixture tokens with fixed issuer/audience/type/lifetime. No fixture key/token is persisted. The copied TLS/JWT fixture classes retain the preceding `small-api` fixture behavior; they do not implement a real IdP.

```powershell
python tools/verify_optional_security.py --dotnet D:/Cephalon/.tools/dotnet11/win-x64/dotnet.exe --engine-root D:/Cephalon/Cehpalon-Engine --output .local/optional-security-example01
```

Use a fresh output directory. Default verification restores locked dependencies, builds Release with warnings as errors, runs all checks, retains source hashes/output and verifies actual emitted typed registrations with no Roslyn/codegen runtime dependency. `--initialize-lock` is only for deliberate first lock creation; delivery verification uses locked mode.

The policy demonstrates RBAC-only, ABAC-only and combined rules from authoritative fixture data. Request `Tenant`/`ResourceId` are selectors; membership and resource ownership are checked before role/attribute policy. Signed token roles are not automatically trusted. Shared generated gateways route HTTP and GraphQL through the same tenant dispatcher. A fresh authority change denies an otherwise still-valid token. This is not an IdP token revocation/session/key rotation proof.

`Host.Start` demonstrates module switches for protected API, GraphQL, security, audit and a public health-only profile. Disabling security while selecting a protected transport rejects before factories. The public profile creates no security/audit/GraphQL services. Disabling audit skips the audit store and history endpoints; disabling GraphQL skips actual service registration and endpoint mapping. Runtime plan observations are separate from source/package presence.

`MemoryAuditStore` is bounded to 1,024 events and fixture-only. Required audit success precedes handler creation; terminal outcomes follow cleanup. Store outage prevents a mutation from starting. History has its own auditor role, checked tenant scope, bounded page and tenant-filtered store access. This records operation/outcome history, not automatically captured field-value changes. Framework sink/history contracts permit an application-selected durable store with its own transactions/outbox, idempotency, encryption, retention and protected query implementation. Do not deploy the fixture authority/store or ephemeral test token issuer.

Authentication middleware rejections occur before tenant dispatch and are covered by host security/access logging rather than this operation audit sink. Terminal audit failure after effects requires reconciliation; it cannot promise rollback or safe automatic mutation retry. No original benchmark workload or threshold changes, external provider qualification, package release or production claim. #3 remains Blocked.

## Consumer-selected authentication profiles

The expanded consumer binds `JwtProfileSettings` from an in-memory configuration section, freezes a `JwtAuthenticationProfile`, and registers `AddCehpalonJwtBearer` only inside the selected security module. Scheme, issuer, audience, token type, algorithm and key source are separate choices. A public configuration can contain settings such as:

```json
{
  "Authentication": {
    "Scheme": "Bearer",
    "Issuer": "https://issuer.example/realm",
    "Audience": "example-api",
    "Algorithm": "RS256",
    "TokenType": "at+jwt",
    "KeySource": "PublicJwks"
  }
}
```

The host supplies the public JWKS callback separately; a key/secret store supplies `providedKeys` when selected. No key secret belongs in this JSON. The fixture executes real RSA/RS256 with public JWKS, RSA-PSS/PS256, ECDSA/ES256 and HMAC/HS256 with provided keys. Every representative is tested over HTTPS HTTP and GraphQL, with wrong-key, unsigned and unknown-kid rejection before business factories. The default RSA profile also rejects an otherwise valid PSS token rather than expanding its algorithm choice. Disabled security executes zero key-provider callbacks.

The established cookie handler is also exercised with an encrypted authentication ticket, `AspNetCoreIdentitySource` and `TicketPropertyIdentityMapper`. Its data-protection provider is ephemeral/in-memory, no sign-in endpoint is exposed, no key ring is persisted, and ticket creation is controlled fixture setup. Tampered/expired cookies and an unrelated bearer credential do not authenticate the cookie profile. This is a bounded handler/mapping proof, not an account/password/MFA/session lifecycle implementation.

## Tenant switching and authorized read sets

`/tenant/select` and the GraphQL `selectTenant` mutation call the framework's destination selection operation. A successful A→B selection with the same login only returns B's checked selection; it does not change a singleton/current-user tenant or mint a universal credential. Each later data call validates its selected tenant again. The fixture proves revocation after selection and simultaneously held HTTP A/B requests and GraphQL sibling fields with independent checked contexts. The transport bridge uses a request-owned fixed accessor instead of mutating ASP.NET's ambient AsyncLocal holder.

`/document/read-all` and GraphQL `readSet` are separately registered read operations. A user with A and B membership still receives denial without a distinct trusted read-set grant. The authoritative grant fixes principal, operation, resource and a bounded exact tenant set; `Tenants: null` means every tenant in that grant. A limited grant to A yields only A; callers can request a contained subset, not add B, wildcard `*` or duplicates. Each tenant still passes normal membership/resource/RBAC/ABAC checks. The same tenant-scoped data port supplies the results.

The engine collects results privately. A later B membership denial discards the response even if an earlier authorized A read ran. This is not an atomic cross-tenant database snapshot or rollback guarantee, and the trusted registered read handler must avoid writes. With audit selected, a control-plane grant/terminal pair has no authorized-tenant stamp; per-tenant pairs link to it through `ParentInvocationId`. Ordinary tenant history cannot expose those control-plane records. The bounded consumer grant has two tenants; large catalogs, durable reporting and cross-provider snapshot guarantees require their own implementation and evidence.

## Optional nested signed JWE

The encrypted profile explicitly selects `TokenProtection: "EncryptedSigned"`, the inner signing `Algorithm`, outer `KeyManagementAlgorithm` and `ContentEncryptionAlgorithm`. This fixture uses the pinned library's proven authenticated `A256CBC-HS512` content mode with separately selected `RSA-OAEP` or `dir` key management. These are explicit configured profiles, not fallback from an unsupported GCM/OAEP-256 choice. Unsupported choices reject; broader algorithm/provider qualification remains separate.

```json
{
  "Authentication": {
    "Scheme": "Bearer",
    "Issuer": "https://issuer.example/realm",
    "Audience": "example-api",
    "Algorithm": "RS256",
    "TokenType": "at+jwt",
    "KeySource": "PublicJwks",
    "TokenProtection": "EncryptedSigned",
    "KeyManagementAlgorithm": "dir",
    "ContentEncryptionAlgorithm": "A256CBC-HS512"
  }
}
```

The application supplies the inner signature verification public JWKS and a distinct trusted `decryptionKeys` provider. Direct CBC-HMAC uses a 64-byte secret; RSA-OAEP uses a separate RSA decryption private key. No decryption secret/private key belongs in appsettings or the public signing JWKS. The fixture owns ephemeral separate keys and never saves the actual credential, plaintext or ciphertext to evidence.

HTTPS HTTP/GraphQL requests exercise standard-library decryption and inner signature/issuer/audience/lifetime checks before the same tenant dispatcher. The encrypted profile rejects plaintext downgrade, wrong decryption/signature keys, unknown kid, unapproved outer algorithm/content mode, tampered ciphertext/tag, unsigned or misbound inner tokens and disallowed header/compression shapes before business factories. Tenant selection, cross-tenant denial, explicit read-set grants and required audit remain unchanged after decryption. The signed-only default continues to use its existing tests; disabled JWE security runs no signing/decryption key callback. This is local encrypted-token interoperability evidence, not real KMS/HSM/IdP rotation, account lifecycle or production qualification.

The direct-encryption profile also requires the compact encrypted-key segment to be empty, including when ciphertext/tag would otherwise validate. Both HTTP and GraphQL reject a nonempty direct encrypted-key segment before business work. This is strict envelope-format validation; accepting the unused segment in an underlying implementation is not, by itself, evidence of a changed authenticated identity.

## Optional local key-ring rotation and withdrawal

The consumer can select `KeySource: "RotatingKeyRing"` with Signed or EncryptedSigned profiles. Inside the selected security module it registers `AddCehpalonJwtBearerKeyRing` with one trusted factory returning a consumer-owned `JwtKeyRing`. The ring starts without an active publication. The fixture publishes a complete signing/decryption set, then demonstrates an old/new overlap window, separate signing retirement and decryption retirement, explicit withdrawal, and a new trusted publication without restarting the WebApplication.

Publication is a trusted host control-plane operation, not a public authentication-management endpoint or a token-triggered key refresh. Each publication supplies the expected version and bounded validity; stale versions, invalid/duplicate/incompatible keys, and source enumeration failures cannot partially replace the current valid set. An expired, withdrawn or disposed publication cannot fall back to older keys. The fixture injects its own UTC/monotonic time controls rather than changing host time or waiting for favorable timing.

Fresh HTTPS HTTP and GraphQL requests are used after updates. Each authentication uses one coherent ring version for signature and decryption and the Engine checks that version/lifetime before accepting validation. Existing tenant/RBAC/ABAC checks, switching, explicit read-set grants and audit remain in force. A gated business request also demonstrates the boundary: withdrawal after authentication/admission does not roll back already permitted work or invalidate an authentication result that the host has already cached; a following request fails authentication. The Engine component corpus separately covers an update during cryptographic validation. This is not instantaneous distributed session revocation or transactional key-management/response delivery.

The actual fixtures cover Signed RS256 and nested JWE with RSA-OAEP/dir + A256CBC-HS512, using independent ephemeral keys in memory. No real KMS/HSM/IdP, external refresh service, account lifecycle, production retention or benchmark qualification is claimed. The caller owns ring/provider lifetime, key entropy, refresh/publication scheduling and reconciliation. Disabled security never calls the ring factory; no persistent key ring or actual token/key/ciphertext is written to evidence.


## Optional trusted session-status checks

`SessionValidatingIdentitySource` can wrap the authenticated source within the selected security module. The fixture opts in explicitly: JWT mapping reads one authenticated `sid` claim through the four-argument adapter constructor; cookie/custom ticket mapping uses `SessionBoundTicketIdentityMapper`. Legacy profiles do no session mapping or lookup. A bounded fresh status check runs per protected identity resolution, including each tenant child of an aggregate read even when the established handler caches its ticket within one HttpContext.

The application's trusted provider binds status to exact issuer/subject, authentication scheme and session ID. Missing, inactive, expired, future or misbound status denies; source faults/cancellation remain faults/cancellation, without cached fallback. This fixture uses a plain setup/control object and constructs its actual status-provider adapter only inside selected activation; disabled security has zero provider factory, constructor and lookup work. It is an ephemeral test source, without durable storage or a management endpoint.

The HTTPS corpus covers signed RS256 and existing RSA-OAEP/dir nested signed JWE, plus an encrypted real cookie ticket. One user's independent login remains valid when another is revoked; a new login receives a distinct ID, and revoked IDs cannot be reactivated by this fixture. Composite status keys isolate a reused opaque spelling under another principal. A valid session never grants another tenant: membership/resource/RBAC/ABAC and audit/history still run normally. Same-request read-set evidence compares one actual JwtBearer TokenValidated callback to three fresh session lookups (root, A, B); revoking after A denies B and withholds all response rows while preserving the earlier authorized execution/audit.

Session observation is bounded by the configured source lifetime and the identity/status validity, consuming lookup time against that budget. It is not an atomic status-to-business transaction or continuous revocation subscription. A gated already-admitted request may finish after withdrawal, while later protected invocations deny. Providers own unique login/generation IDs, tombstones, outage policy and distributed consistency; reactivating a revoked ID while old credentials still exist can revive those credentials. This is not an OAuth revocation/introspection server, account/password/MFA implementation, cross-node instant logout guarantee, durable provider qualification or performance claim. Operation audit records outcomes without raw session IDs, credentials or claims; trusted session-management auditing remains application/provider work.
