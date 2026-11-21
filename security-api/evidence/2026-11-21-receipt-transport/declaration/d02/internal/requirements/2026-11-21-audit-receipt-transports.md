# Protected audit receipt lookup requirements

Accepted2026-11-21; #18 with #7/#8 regressions. [ADR0052](../adr/ADR-0052-protected-audit-receipt-transports.md), [protocol](../validation/audit-receipt-transports.md).

- Projects can select HTTP, GraphQL or neither for exact indexed audit receipt lookup without changing Engine contracts or existing hosts.
- Validate Composition before owned callbacks. Disabled selection performs no owned activation/I/O/listener work; invalid selected security dependencies reject before factories.
- Actual validated JWT identity and fresh tenant membership/resource/RBAC-ABAC checks precede provider lookup. Receipt/tenant metadata is not authority.
- Use the existing generated gateway and reader/budget, then one primitive response mapper with nullable absence and current-policy projection. Preserve registry bytes and error redaction.
- Client abort propagates to server/provider. Source lifetime is released only after all admitted server work joins, including stop failures and providers that ignore cancellation.
- Prove actual HTTPS HTTP/GraphQL against the owned indexed PostgreSQL fixture on both client hosts; retain prior cases, locks and dataset. Keep M0, original benchmarks, #3/#20 and all tracking metadata unchanged.
