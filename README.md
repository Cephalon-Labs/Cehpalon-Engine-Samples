# Cehpalon Engine Samples

Private MIT-licensed consumer and end-to-end proof repository. Baseline: 2026-10-27.

All three lanes were selected by the user:

- [Small API](small-api/README.md): minimal API-only activation and shared-operation transport proof
- [Multitenant business](multitenant-business/README.md): API, Worker, SQL, event recovery and tenant isolation
- [AI / Agent / Retrieval](ai-retrieval/README.md): model/provider portability, scoped retrieval, tool authorization and bounded evaluations

Small API now has a bounded experimental protected HTTP/GraphQL consumer and a separate public measurement fixture. The business and AI folders remain scenario plans; none establishes certified providers or full production acceptance. Consume Engine at an explicit revision/package version when implementing; do not test against an unrecorded sibling checkout.

The separate [portable Core consumer](portable-core/README.md) exercises generated typed operation registrations, appsettings module selection and shared business logic entirely in process. Its module recorders establish a bounded W1 integration proof and do not implement the three transport/provider sample lanes.

The [CLI-generated portable consumer proof](tooling/README.md) exercises a fresh console scaffold with actual Core/Composition and generated registrations. This experimental `portable-request-reply` profile is separate from transport/provider sample qualification.

The [tenant/identity consumer](tenant-identity/README.md) adds fresh authoritative fixture checks and a checked data port through a generated Core gateway, including cross-tenant denials. It does not establish real IdP/provider/transport qualification.

[Owned provider qualification fixtures](qualification/README.md) now have component probe and cleanup evidence for five immutable images. These checks are separate from the three consumer scenarios. See the [current SDK/artifact/tracking qualification report](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/w0-qualification-and-sync.md) for the supported-Windows and hosted-CI blocker.

W0 provider/workload selection is recorded in the [decision package](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/w0-decisions.md). Each lane below points to its ADR and predeclared acceptance protocol. All runtime profiles remain M0 until qualification and execution evidence exists.

See the [program plan](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/2026-10-27-program-plan.md), [Project](https://github.com/orgs/Cephalon-Labs/projects/4) and [AGENTS.md](AGENTS.md).

The [protected Small API consumer](small-api/README.md) reuses generated Core gateways and guarded tenant handlers through HTTP/GraphQL with actual localhost HTTPS/JWT fixture checks. It is a separate experimental protected profile; the separate [public Small API comparison](small-api-benchmark/README.md) now has complete observational conformance/startup/idle/load/diagnostic results. The [startup/variance continuation](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/w2-small-api-tuning.md) passes the unchanged numerical startup/idle/main/CV gates; diagnostics have11timed runs plus one failed2000/s collector preflight. Reference qualification and #3 remain Blocked.
