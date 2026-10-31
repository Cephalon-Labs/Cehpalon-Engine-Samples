# ADR0021 - Worker lineage and scheduler collection feasibility

Date: 2026-10-31. Status: accepted for bounded readiness study under Engine #20.

ADR0020 cannot separate exclusive causes: no task lineage, uncertified GC pairing and delayed scheduler credits. Before a new target/capture, inspect the exact runtime/provider contracts and read-only host tracing capabilities. No privileges, mounts, kernel settings, GC/concurrency changes, Engine patch or original benchmark rerun are authorized by this study. #3 remains Blocked.

Implement a reusable read-only readiness probe with synthetic guards. Presence of event formats, a perf binary, readable tracefs or permissive sysctl does not establish actual collection permissions, losslessness, clock joins or causal feasibility. Record inaccessible/missing/unknown distinctly; all gates must fail closed. No subprocess launches of perf record, workload, sudo or sysctl writes. Tests may use in-memory fixtures and temporary output only.

Review exact Task/TPL contracts separately from actual task lineage proof. GC runtime identity/source correspondence and installed binary attestation remain explicit gaps. A later capture needs a separate predeclared synthetic conformance target, target ownership/cleanup, complete event coverage, loss counters, clock mapping, observation overhead and immutable full-lane protocol. Do not combine separate runs into causal overlap.

Root is sole integrator/remote writer. Sync #20 body only through reviewed plan/readback; preserve #3 entire row and all gates/dependencies/estimates/null hours. Retain all failed probe/preparation attempts. No provider, supported-Windows, reference, release or production qualification follows.
