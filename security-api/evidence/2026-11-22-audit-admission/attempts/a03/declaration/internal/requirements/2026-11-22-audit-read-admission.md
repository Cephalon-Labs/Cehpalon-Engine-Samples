# Optional audit-read concurrency requirements

Accepted2026-11-22 under #18 with #7/#8 regressions. [ADR0054](../adr/ADR-0054-audit-read-concurrency-admission.md).

- Projects may opt into one immutable total/per-tenant budget shared by receipt and resource history across HTTPS HTTP/GraphQL. Default behavior and positional APIs remain compatible.
- Validate selected configuration before owned callbacks; disabled profiles remain inert even with invalid unused limits.
- Fresh identity/membership/resource/RBAC-ABAC checks precede admission; capacity never reveals data or replaces tenant authority. Full tenant identifiers remain distinct, including same resource/receipt IDs.
- Saturation rejects promptly through existing generic errors without invoking a business handler/provider. A saturated tenant must not consume another tenant's available allowance below the total cap.
- Success, denial, provider failure, cancellation, cooperative timeout and shutdown preserve exact slot ownership and full joined source lifetime.
- Prove scope with actual transport/provider and cross-tenant tests, preserve original suites/registries/settings/benchmarks/#3 Blocked/#20/all metadata and synchronize GitHub/Docs/Project/main.
