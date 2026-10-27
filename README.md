# Cehpalon Engine Samples

Private MIT-licensed consumer and end-to-end proof repository. Baseline: 2026-10-27.

All three lanes were selected by the user:

- [Small API](small-api/README.md): minimal API-only activation and shared-operation transport proof
- [Multitenant business](multitenant-business/README.md): API, Worker, SQL, event recovery and tenant isolation
- [AI / Agent / Retrieval](ai-retrieval/README.md): model/provider portability, scoped retrieval, tool authorization and bounded evaluations

These three folders remain scenario plans with no real-transport consumer E2E passes or certified providers. Consume Engine at an explicit revision/package version when implementing; do not test against an unrecorded sibling checkout.

The separate [portable Core consumer](portable-core/README.md) exercises generated typed operation registrations, appsettings module selection and shared business logic entirely in process. Its module recorders establish a bounded W1 integration proof and do not implement the three transport/provider sample lanes.

[Owned provider qualification fixtures](qualification/README.md) now have component probe and cleanup evidence for five immutable images. These checks are separate from the three consumer scenarios. See the [current SDK/artifact/tracking qualification report](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/w0-qualification-and-sync.md) for the supported-Windows and hosted-CI blocker.

W0 provider/workload selection is recorded in the [decision package](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/w0-decisions.md). Each lane below points to its ADR and predeclared acceptance protocol. All runtime profiles remain M0 until qualification and execution evidence exists.

See the [program plan](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/2026-10-27-program-plan.md), [Project](https://github.com/orgs/Cephalon-Labs/projects/4) and [AGENTS.md](AGENTS.md).
