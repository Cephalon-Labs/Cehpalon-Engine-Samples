# Audit resource history transport requirements

Accepted2026-11-22; #18 with #7/#8 regressions. [ADR0053](../adr/ADR-0053-protected-audit-resource-history-transports.md), [protocol](../validation/audit-resource-history-transports.md).

- Select resource history independently on the existing HTTPS HTTP/GraphQL host, preserving old receipt APIs/defaults and shared source/lifetime.
- Validate tenant/resource/limit/cursor wire bounds and binding before querying. Cursor metadata never grants authority.
- Require validated request JWT, fresh membership/resource/RBAC-ABAC and a separate resource-history grant before source work.
- Reuse generated Core gateway and checked reader/budget, then project a primitive page/cursor response through the existing record mapper.
- Prove pagination, cross-tenant denial, same-ID isolation, concurrent GraphQL fields, current policy, corruption/error redaction, cancellation and joined mixed shutdown on actual indexed PostgreSQL.
- Keep original272/651 cases, registry bytes, packages and benchmark criteria. Synchronize GitHub/Docs/Project and push mains while #3 remains Blocked, #20 and all metadata/hours/M0 remain unchanged.
