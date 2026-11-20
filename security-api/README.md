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
