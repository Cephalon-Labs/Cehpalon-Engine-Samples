# Experimental tenant/identity consumer

This consumer exercises the portable tenant boundary through a **generated Core gateway**. One tenant-aware business handler serves A and B; both tenants deliberately have resource ID `shared`. Fixture identities, membership, resource ownership and policy are authoritative only within this in-process test. No tokens, real IdP, database, cache/retrieval provider, event/job transport or production isolation are qualified here.

The requested tenant is selection, not authority. Core correlation metadata containing tenant/admin/issuer/subject strings grants nothing. Fresh configured authority sources and fixed operation/action/resource-kind binding precede the business factory. The trusted snapshot callback copies mutable request fields before asynchronous lookups. The fixture data port checks `TenantOperationContext.DemandAccess` and its resource version before reading.

Denied pre-dispatch tenant/resource/policy checks create/read/write zero business objects. A stateless generated gateway can still be created to enter the security boundary. Later cancellation/expiry cleans up any handler already created; no claim of reversing prior business effects is made. Checked contexts are operation-bound capabilities, not a sandbox for arbitrary trusted C# or an atomic database authorization transaction.

`tools/verify_tenant_identity.py` requires the exact clean Engine revision in `engine-lock.json`, pinned SDK and a fresh result folder beneath ignored `.local`. It restores/builds locked graphs, runs the consumer and verifies that Roslyn/CodeGeneration remain build-time only. All results and emitted registry bytes are retained. First lock preparation is a separate maintainer operation.

```text
python tools/verify_tenant_identity.py --dotnet D:/Cephalon/.tools/dotnet11/win-x64/dotnet.exe --output .local/tenant-identity/new-windows-attempt
```

The consumer covers positive same-ID A/B reads, both cross-tenant directions, forged metadata, wrong resource ownership, default policy deny, next-call revocation, anonymous spoofing, retained contexts, actual overlapping calls and mutation while an identity lookup awaits. See the [contract ADR](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/adr/ADR-0007-tenant-identity-operation-boundary.md) for adapter and trust obligations.
