# Optional audit read budget requirements

Accepted2026-11-21 for #18 with #7/#8 regressions. [ADR0051](../adr/ADR-0051-optional-audit-read-budget.md), [protocol](../validation/audit-read-budget.md).

- Each project can select an independent positive, at-most-one-minute cooperative budget for change-audit history, receipt lookup and resource-history reads.
- Existing constructors, Activate and null-budget behavior remain compatible; disabled selection performs no factory/timer/provider work.
- Budget cancellation reaches the actual provider. No successful record, null, empty page or projected result escapes after the configured completion veto.
- Original-caller cancellation takes precedence over the private budget when both are observed at primary selection; unrelated cancellation and non-cancellation faults preserve declared identities.
- Fresh checked tenant/identity scope, resource/cursor integrity and current read policy remain enforced. DTOs and cursors do not provide authority.
- Uncooperative provider work remains awaited and owned. No hard deadline, rollback, response delivery or provider callback quiescence is inferred.
- Preserve existing components, consumer cases, service declarations, packages and original benchmark gates. Prove new behavior on both client hosts with actual generated PostgreSQL consumers; keep M0 and all tracking metadata unchanged.
