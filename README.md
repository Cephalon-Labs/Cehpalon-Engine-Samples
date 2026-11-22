# Cehpalon Engine Samples

For local Visual Studio builds, open [Cehpalon.Samples.slnx](Cehpalon.Samples.slnx).
It includes all six source consumers and their ten Engine dependencies, so Build
can build referenced projects as well. NuGet automatic restore is enabled in this
repository. If a consumer's default `obj` directory is removed while the IDE is
open, `Directory.Build.targets` provides locked restore before the real build.
It skips IntelliSense/design-time builds, CLI builds and existing assets. Set
`CehpalonRestoreMissingAssets=false` to disable this fallback. Custom intermediate
layouts require explicit restore with the same output properties. This is scoped
to these checked-in consumers and their current package graphs; generated CLI
consumers remain separate and use their documented `dotnet build` workflow.
Build does not run the fixtures. Several executables require a fresh report path;
the audit/outbox fixture additionally requires its separately configured provider.

Reproduce build/restore checks in an isolated Samples checkout with a clean Engine:

```powershell
python tools/verify_visual_studio_restore.py --engine-root <clean-engine> --msbuild <VS-MSBuild.exe> --output .local/build-restore/new-attempt --run-consumers
```

MIT-licensed consumer and end-to-end proof repository. Baseline: 2026-10-27.

The current root SDK is stable .NET11.0.100. The active protected Small API, optional security and PostgreSQL audit-outbox consumers use the current GA package graph. Historical consumer locks, benchmark results and nested trace SDK pins retain their original revisions: replay them from those exact Samples/Engine sources with the retained matching RC SDK. Running an old collector under the current GA root does not establish matching runtime offsets or renewed benchmark qualification.

All three lanes were selected by the user:

- [Small API](small-api/README.md): minimal API-only activation and shared-operation transport proof
- [Multitenant business](multitenant-business/README.md): API, Worker, SQL, event recovery and tenant isolation
- [AI / Agent / Retrieval](ai-retrieval/README.md): model/provider portability, scoped retrieval, tool authorization and bounded evaluations

The optional [security API consumer](security-api/README.md) demonstrates actual signed-token HTTPS authentication, RBAC/ABAC, generated HTTP/GraphQL gateways and tenant-scoped operation audit/history. Security and audit are independently selected; the authority and memory history store are controlled fixtures rather than certified external providers.

Small API now has a bounded experimental protected HTTP/GraphQL consumer and a separate public measurement fixture. The business and AI folders remain scenario plans; none establishes certified providers or full production acceptance. Consume Engine at an explicit revision or package version. The Engine loopback suite verifies HTTP and GraphQL overload responses with a shared in-process budget. The Small API profile still uses its original defaults. [Operation capacity evidence](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/operation-capacity-transports.md)

The separate [portable Core consumer](portable-core/README.md) exercises generated typed operation registrations, appsettings module selection and shared business logic entirely in process. Its module recorders establish a bounded W1 integration proof and do not implement the three transport/provider sample lanes.

The [CLI-generated portable consumer proof](tooling/README.md) exercises a fresh console scaffold with actual Core/Composition and generated registrations. This experimental `portable-request-reply` profile is separate from transport/provider sample qualification.

The [CLI-generated Small API proof](tooling-small-api/README.md) builds the new protected HTTPS scaffold, exercises cross-tenant denial and disabled modules, then probes caller-configured serving with strict TLS/JWT and graceful shutdown. Its in-memory identity/membership/data fixtures remain separate from real IdP/provider or full lane qualification.

The [offline transport contract proof](tooling-contracts/README.md) exports selected HTTP OpenAPI/JSON shapes and actual GraphQL SDL, compares them with real runtime schemas/HTTPS behavior and checks disabled artifact/service work. Structural schema acceptance remains separate from business validation and tenant authority.

The [tooling observational benchmark](tooling-benchmark/README.md) measures actual generator/emit and fresh CLI processes with fixed correctness checks, retained raw rows and descriptive variability. [Baseline results](tooling-benchmark/results.md) and [variance follow-up](tooling-benchmark/variance-results.md), including negative final outcomes, remain separate from full performance/platform/provider qualification.

The [tenant/identity consumer](tenant-identity/README.md) adds fresh authoritative fixture checks and a checked data port through a generated Core gateway, including cross-tenant denials. It does not establish real IdP/provider/transport qualification.

[Owned provider qualification fixtures](qualification/README.md) now have component probe and cleanup evidence for five immutable images. These checks are separate from the three consumer scenarios. See the [current SDK/artifact/tracking qualification report](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/w0-qualification-and-sync.md) for the supported-Windows and hosted-CI blocker.

W0 provider/workload selection is recorded in the [decision package](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/w0-decisions.md). Each lane below points to its ADR and predeclared acceptance protocol. All runtime profiles remain M0 until qualification and execution evidence exists.

See the [program plan](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/2026-10-27-program-plan.md), [Project](https://github.com/orgs/Cephalon-Labs/projects/4) and [AGENTS.md](AGENTS.md).

The [protected Small API consumer](small-api/README.md) reuses generated Core gateways and guarded tenant handlers through HTTP/GraphQL with actual localhost HTTPS/JWT fixture checks. It is a separate experimental protected profile; the separate [public Small API comparison](small-api-benchmark/README.md) now has complete observational conformance/startup/idle/load/diagnostic results. The [startup/variance continuation](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/w2-small-api-tuning.md) passes the unchanged numerical startup/idle/main/CV gates; diagnostics have11timed runs plus one failed2000/s collector preflight. Reference qualification and #3 remain Blocked.

- [Process-scoped tooling diagnostics and retained traces](tooling-traces/README.md): separate JIT/GC/thread/syscall evidence, collector conformance and full untraced original benchmark. Diagnostic timing is perturbed; #3 remains Blocked and no qualification is inferred.
