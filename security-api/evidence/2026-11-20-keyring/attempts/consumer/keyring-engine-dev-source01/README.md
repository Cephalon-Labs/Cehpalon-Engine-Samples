# Cehpalon Engine

MIT-licensed .NET engine program. Baseline: 2026-10-27.

Goal: a small host-agnostic core with optional modules, reusable business handlers and configuration-selected supported transports, topology and capability profiles.

**Status: experimental Core, Composition and operation code generation are implemented; full features remain M0 while their acceptance/dependency gates are outstanding. Scoped local component proof is separate from supported-platform, transport/provider, performance or production qualification.**

The [W1 solution](Cehpalon.Engine.slnx) contains a BCL-only typed dispatcher, strict immutable appsettings composition and an opt-in incremental generator for lazy typed operation registrations. Run [component verification](Tests/README.md) with the pinned SDK. See the [experimental portable consumer](https://github.com/Cephalon-Labs/Cehpalon-Engine-Samples/tree/main/portable-core) and [W1 decision](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/adr/ADR-0005-w1-portable-core-composition.md). #3 remains Blocked until supported-Windows evidence exists.

The experimental [source-checkout CLI](src/Cehpalon.Engine.Tooling/README.md) scaffolds `portable-request-reply` console and `small-api` protected HTTPS profiles with profile-specific Composition validation. Both use existing Core/Composition and build-time generation; Small API wires fresh tenant dispatch and optional GraphQL. See the [portable proof](https://github.com/Cephalon-Labs/Cehpalon-Engine-Samples/tree/main/tooling) and [generated Small API proof](https://github.com/Cephalon-Labs/Cehpalon-Engine-Samples/tree/main/tooling-small-api). Full #20 transport-schema, tooling benchmark and distribution gates remain outstanding.

The generated Small API also supports offline `--export-contracts`: selected HTTP operations produce serializer-derived OpenAPI3.1 shapes and selected GraphQL produces actual vendor SDL. Export opens no listener or credential files; GraphQL schema compilation is reported and disposed separately from runtime activation. See the [contract export proof](https://github.com/Cephalon-Labs/Cehpalon-Engine-Samples/tree/main/tooling-contracts). Structural schemas do not replace validators or tenant authority.

[Identity contracts](src/Cehpalon.Engine.Identity.Contracts/README.md) and [Tenancy](src/Cehpalon.Engine.Tenancy/README.md) add a separate default-deny protected operation boundary over Core. Fresh configured identity/membership/resource/policy checks precede business handlers; checked contexts are bounded, revocable in-process capabilities. Plain Core and generated registrations do not authenticate callers automatically. See [ADR-0007](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/adr/ADR-0007-tenant-identity-operation-boundary.md); real IdP/provider qualification remains separate.

[PlatformQualification](Tests/PlatformQualification/README.md) now pins the private-tested .NET11 RC3 SDK and a locked driver graph. The bounded HTTPS/JWT/GraphQL and owned PostgreSQL/RabbitMQ smoke has explicit proof limits and retained failures. Local Windows26H2 is observational compatibility because that version is not in the checked support table; Linux qualification uses listed Ubuntu22.04.5 under WSL. See the qualification evidence and CI results for the exact host/revision tested.

W0 has [selected sample profiles and predeclared proof contracts](docs/w0-profiles.md). Provider selection and bounded qualification tooling are in place; Protected HTTP/GraphQL adapters and a Small API consumer now have bounded experimental proofs; full lane conformance remains separate. All Engine runtime features remain M0.

- [Project](https://github.com/orgs/Cephalon-Labs/projects/4)
- [Engine issues](https://github.com/Cephalon-Labs/Cehpalon-Engine/issues)
- [Plan and documentation](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs)
- [Three sample lanes](https://github.com/Cephalon-Labs/Cehpalon-Engine-Samples)
- [Shared AI rules](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/skills/cehpalon-engine/SKILL.md)

## Layout

- `src/`: experimental Core, Composition and build-time CodeGeneration; Identity/Tenancy and opt-in HTTP/GraphQL adapters; provider adapters remain future work
- `Tests/`: independently runnable component contracts, compiler consumer and separate platform qualification
- `Benchmarks/`: bounded component regression runner with a predeclared protocol; three lane workloads remain unmeasured
- `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`: entry points to canonical program guidance

.NET11 SDK `11.0.100-rc.3.26522.148` is pinned in `global.json` with roll-forward disabled. Use a matching private SDK or CI setup; unrelated system SDKs were not replaced. Direct driver versions and the qualification lock graph are explicit. .NET12 remains a separate research track. Package distribution/license review is required before release; the complete third-party graph must not be described as MIT-only.

For Qwen, DeepSeek or another tool that does not discover these entry files, explicitly supply AGENTS.md and the linked shared skill/memory. Automatic support for a vendor tool is not claimed without a tested integration.

[HTTP](src/Cehpalon.Engine.Transports.Http/README.md) and [GraphQL](src/Cehpalon.Engine.Transports.GraphQL/README.md) use explicit typed operation bindings. The host owns validated authentication and tenant dispatch wiring. HTTP has no GraphQL dependency; opt-in GraphQL is POST-only with bounded inputs/schema exposure. See the [protected Small API consumer](https://github.com/Cephalon-Labs/Cehpalon-Engine-Samples/tree/main/small-api) and [ADR0008](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/adr/ADR-0008-protected-http-graphql-adapters.md). Full W0 performance and supported-Windows gates remain outstanding.
