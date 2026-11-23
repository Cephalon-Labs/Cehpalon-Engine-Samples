# Optional authentication, RBAC/ABAC and audit history consumer

F5 with no arguments runs the existing local fixture suite and prints a fresh report path under Samples `.local/security-api-runs`. This uses ephemeral fixture credentials, not a configured external IdP. Explicit `--output=<new-report.json>` remains supported.

Experimental local consumer of Core, Composition, CodeGeneration, the JWT identity bridge, Authorization and Tenancy. It starts only owned ephemeral localhost HTTPS endpoints and exits after its test matrix. Actual JwtBearer validates ephemeral RS256 fixture tokens with fixed issuer/audience/type/lifetime. No fixture key/token is persisted. The copied TLS/JWT fixture classes retain the preceding `small-api` fixture behavior; they do not implement a real IdP.

```powershell
python tools/verify_optional_security.py --dotnet D:/Cephalon/.tools/dotnet11-ga/win-x64/dotnet.exe --engine-root D:/Cephalon/Cehpalon-Engine --output .local/optional-security-example01
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

The cap is checked after awaited authentication/status calls; it is not an I/O timeout and cannot cancel an uncooperative provider. The original monotonic start is not propagated through later membership/policy/audit awaits, which continue to use their existing time-lease checks. The guard does not clear the established host ticket or `HttpContext.User`, and ordinary `RequireAuthorization` can still see an authenticated caller. It protects only engine entrypoints wired to this decorated identity source; a revoked protected operation returns `403 access.denied` (or the GraphQL operation error), independently of host authentication success.


## Original session-observation validity through authorization

The optional ObservationFixture freezes its own UTC clock and advances only its declared monotonic counter; it does not alter host time, JWT/cookie cryptographic lifetime or existing benchmark controls. This proof injects that clock into session observation, tenant services and authority facts. Existing206 checks remain, then signed and both nested JWE profiles exercise membership/resource/policy/audit delays, shorter status lifetimes, original parent plus fresh child read-set constraints, handler/cleanup expiry, business-failure and cancellation precedence. Expired success can be withheld after actual effects/cleanup; no rollback is implied. Expiry during authorization persistence can leave an authorization record plus terminal denial with zero business factories. Authorization records alone are not proof of execution.

Original source clock constraints survive normal validity narrowing/intersection, nested session decorators, matching-ticket mapping and read-set propagation. They are synchronous validity checks, without extra status/network refresh calls. The observation cap remains a validity budget checked at boundaries, not an I/O timeout, continuous revocation subscription or atomic response transaction. Provider consistency, caller cancellation, tombstones and real distributed lifecycle remain application responsibilities. A fresh provider response cannot reset an older parent observation's monotonic origin.

## Optional domain audit HISTORY/TRAILS

AuditTrailFixture models separate projects selecting Disabled (default), MetadataOnly, ChangedFields or BeforeAfterSnapshots. Host.Start's final trailProfile argument drives a distinct configuration-selected trail module. Disabled projects construct no audit-trail sink/provider and expose no trail-history endpoint. Their explicitly selected domain mutation sample still performs normal tenant-checked business changes. MetadataOnly records no field images and never calls the deferred field-value factory. Field modes use a bounded explicit allowlist, typed scalar states, per-field redaction and unknown-field omission before the sink. ChangedFields retains only changed fields; snapshots also retain allowlisted unchanged values. Missing, explicit null, typed text/decimal/boolean and redacted values remain distinct.

The shared Core/Composition/CodeGeneration entity handlers mutate the controlled in-memory tenant entity first, then supply a principal/scheme/tenant/operation/action/entity/authorization-resource-version-bound provider/application receipt. Entity before/after versions are separate from the authorization resource version. This is explicit application reporting, not automatic request/result logging, change-data-capture, database-commit attestation, a transactional outbox or exactly-once persistence. Sink/projection/receipt failure after mutation returns the sample-specific audit_trail.write_failed_may_have_committed error while the actual state can remain changed. The sample deliberately handles the recorder exception as a business rejection (operation-audit Rejected); an unhandled SDK recorder exception is a fault. Neither outcome asserts rollback or unchanged data.

Trail history is a separate audit-trail/tenant/read capability with a dedicated role, distinct from operation-audit history. It has bounded pagination, tenant-isolated provider pages, current read-policy field filtering/redaction and CapturedMode provenance. Tightening policy hides old values; a later broader policy cannot recover fields never captured. Project policy and source remain host supplied. The actual HTTPS proofs cover signed/JWE and established cookie tickets, same entity ID in A/B, ordinary history permission denial, provider page leakage, modes/CRUD representations, before-sink masking, post-commit failure and observation expiry after mutation. No management endpoint, durable store, real provider/distributed/production or benchmark qualification is claimed.


## Optional validated audit preparation

The preparation profile caches the actual immutable `TenantOperationRegistry` before provider activation; request-local authentication and tenant security services remain fresh. `ActivateValidated` checks exact policy/catalog bindings and explicit required operation IDs before the sink factory. New-profile activation orders this validation ahead of credentials/listener/providers. `DescribeOperations` exposes informational sorted metadata without executing business factories. A registry rebuilt from identical metadata, including a second Build on the same builder, does not satisfy strict instance binding. Existing profiles retain their previous per-request registry construction and low-level recorder API.

A handler calls `Prepare(context, token)` before mutation. Missing rules, expired/wrong-origin scopes and cancellation fail before the fixture changes data. The resulting opaque preparation captures the original checked context and owner; `CompleteAsync` is consumed atomically before any receipt validation, field callback or append. Concurrent/replayed or failed-first completion cannot append again. This is one facade append attempt per preparation, not backend exactly-once, provider readiness, transaction reservation or proof of commit.

The HTTPS corpus preserves the prior455 cases and adds startup rejection, metadata/disabled laziness, signed/JWE/cookie prepared flows, strict registry clones, same-entity tenant isolation, held concurrent append, failed/null/cancelled first completion, retained scope and HTTP/GraphQL cancellation before prepare. Actual fixture mutation still precedes receipt completion. Post-mutation completion failures retain `MayHaveCommitted`; the sample explicitly maps them to `audit_trail.write_failed_may_have_committed` and operation-audit Rejected. Applications must not blindly retry or infer rollback. A deliberately deferred fixture demonstrates that preparations do not complete themselves or authorize background work after scope closure.

## Optional audited execution helper

The execution profile selects the same validated registry and existing generated entity gateways, but its project handler calls and awaits `TenantChangeAuditRecorder.ExecuteAsync<TResult>`. Preflight runs before the supplied mutation callback. The callback performs the domain change once and returns a trusted `TenantChangeAuditMutation<TResult>` containing its receipt, typed result and lazy state factory. The helper awaits required completion before returning that result. Disabled projects run their ordinary business path once, without constructing a recorder, receipt envelope, provider or field images. This integration is explicit: upgrading the Engine does not migrate other application handlers.

The caller token reaches the mutation callback. After a returned receipt, required completion uses its private write deadline and still checks the original live tenant scope. Caller cancellation does not cancel that private append token; it is checked again before publishing the typed result. A completed audit record can therefore exist while the result is withheld. Callback exceptions or cancellation after partial effects but before a receipt remain `MayHaveCommitted` with no fabricated audit row. Sink/receipt/projection failures likewise never trigger an automatic mutation retry or rollback. This helper is control-flow integration, without transaction/outbox/durable-provider/exactly-once guarantees.

The corpus retains all prior556 checks and adds actual HTTPS HTTP/GraphQL signed/RSA-OAEP/dir/cookie flows, all capture modes and redaction, separate trail-history authority, tenant denials, invalid catalog/missing rule/foreign registry controls, partial-effect callbacks, null/misbound receipts, failed values/sinks, held result publication and cancellation before receipt or during required append. These are local controlled consumer proofs; optional overhead and production/provider qualification remain open.
