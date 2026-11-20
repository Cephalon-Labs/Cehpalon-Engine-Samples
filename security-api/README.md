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
