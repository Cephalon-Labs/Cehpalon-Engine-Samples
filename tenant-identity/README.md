# Experimental tenant/identity consumer

This consumer exercises the portable tenant boundary through a **generated Core gateway**. One tenant-aware business handler serves A and B; both tenants deliberately have resource ID `shared`. Fixture identities, membership, resource ownership and policy are authoritative only within this in-process test. No tokens, real IdP, database, cache/retrieval provider, event/job transport or production isolation are qualified here.

The requested tenant is selection, not authority. Core correlation metadata containing tenant/admin/issuer/subject strings grants nothing. Fresh configured authority sources and fixed operation/action/resource-kind binding precede the business factory. The trusted snapshot callback copies mutable request fields before asynchronous lookups. The fixture data port checks `TenantOperationContext.DemandAccess` and its resource version before reading.

Denied pre-dispatch tenant/resource/policy checks create/read/write zero business objects. A stateless generated gateway can still be created to enter the security boundary. Later cancellation/expiry cleans up any handler already created; no claim of reversing prior business effects is made. Checked contexts are operation-bound capabilities, not a sandbox for arbitrary trusted C# or an atomic database authorization transaction.

`tools/verify_tenant_identity.py` requires the exact clean Engine revision in `engine-lock.json`, pinned SDK and a fresh result folder beneath ignored `.local`. It restores/builds locked graphs, runs the consumer and verifies that Roslyn/CodeGeneration remain build-time only. All results and emitted registry bytes are retained. First lock preparation is a separate maintainer operation.

```text
python tools/verify_tenant_identity.py --dotnet D:/Cephalon/.tools/dotnet11/win-x64/dotnet.exe --output .local/tenant-identity/new-windows-attempt
```

The consumer covers positive same-ID A/B reads, both cross-tenant directions, forged metadata, wrong resource ownership, default policy deny, next-call revocation, anonymous spoofing, retained contexts, actual overlapping calls and mutation while an identity lookup awaits. See the [contract ADR](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/adr/ADR-0007-tenant-identity-operation-boundary.md) for adapter and trust obligations.

Snapshot observer measurements are available for four controlled admission states. Each host retains all 80 intervals, a five-guardrail run of the original tenant benchmark, source hashes and analysis.

```text
python tools/analyze_budget_snapshot_observation.py --input <snapshot-observation.json> --output <new-analysis.json>
```

The [raw series and checksums](evidence/2026-11-19-snapshot-observation/SHA256SUMS.txt) record zero measured allocation on the reading thread. The [report](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/budget-snapshot-observation.md) includes cached-value comparisons, state order and interpretation limits.

The concurrent observer series adds four authorized producers and one dedicated observer thread. Both complete revisions are retained, including control lanes and all observer allocations.

```text
python tools/analyze_budget_contention.py --input <contention-observation.json> --output <new-analysis.json>
```

[Concurrent reports and hashes](evidence/2026-11-19-budget-contention/SHA256SUMS.txt) contain five alternating pairs per host and revision, operation checksums, exact authority/cleanup counts and the candidate's generated Small API regression. [Interpretation and tradeoff](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/budget-contention-observation.md)

Opt-in budget metrics can be observed through the standard MeterListener API. The periodic collection harness records all 20 collections at each of four controlled states, including the first collection and actual start times.

```text
python tools/analyze_budget_metrics.py --input <metrics-observation.json> --output <new-analysis.json>
```

[Metrics reports and hashes](evidence/2026-11-19-budget-metrics/SHA256SUMS.txt) include the final source and preparation revisions, original benchmark compatibility output and generated Small API proofs. [Metric names, ownership and results](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/budget-metrics.md)
