# ADR-0055: Offline audit-read transport contract export

**Status:** Accepted bounded continuation. **Date:** 2026-11-22.
**Tracking:** #18 with #7/#8 identity and tenant regressions. #3/#20 unchanged.

## Decision

The indexed audit host supports protected receipt/resource reads but has no consumer contract export. Choose Samples-only offline OpenAPI3.1 and GraphQL SDL export over protected bookmarks or response-byte limits. Existing Engine serializer-schema and GraphQL executor APIs suffice; introduce no Engine API/source, dependency, operation attribute, SQL or storage schema change.

Extract one immutable typed selection catalog used by runtime HTTP mapping, runtime GraphQL registration and export. Preserve existing binding objects, paths, field names, primitive DTOs, explicit generated gateway bridges, four-position options/Activate API, authority, capacity and full joined lifetime. Extract/reuse pure Composition-plan compilation and selected read-setting validation without changing runtime construction/callback order. Offline validation creates no host, source, budget, timer, TLS/key/credential or authority work. Unselected invalid read settings remain ignored. This is not validation of trusted host/security/source factories.

Generate request/response JSON Schema using OperationHttpAdapter.ExportJsonSchema<T>(), and errors with ExportErrorJsonSchema(). Requests separately enforce the actual object-only envelope; retain nullable successful roots. Give each embedded schema a distinct $id resource so local references retain their root. Include generic bearer authentication and actual adapter statuses including503, without inventing JWT algorithms, issuer/audience or grants. The two selected wire operation IDs must be a subset of the existing SIX generated registrations; collect metadata with a forbidden handler factory and prove zero factory calls. Do not equate internal generated gateway contracts with wire DTOs.

Selected GraphQL export builds/disposes one offline service provider and emits the actual executor schema. Record that positive work, including disposal on failure; disabled GraphQL registers/builds nothing. No WebApplication, network introspection/schema endpoint or transport dispatcher execution. All-off exports a manifest only. Artifact metadata includes selected IDs/transport descriptions and SHA256/byte lengths; deterministic UTF8/LF without timestamps or private configuration. Returned metadata/artifacts must be detached from shared catalog/serializer state.

Expose a CLI branch before legacy connection-file parsing; export requires no database/TLS/authentication secrets. Publish to a new directory with an existing trusted plain parent, create-new files/staging and no-overwrite final promotion. Reject existing/file destinations and malformed options without modifying prior output. Preserve failed/partial publication evidence; observed paths are not a hostile filesystem race sandbox.

## Evidence

Declare16 new checks per host: eight offline groups and four actual HTTPS/JWT/PostgreSQL wire cases per HTTP/GraphQL, detailed in the protocol. Build each host once from committed/frozen clean source. Execute Windows and WSL offline checks while the owned DB fixture is stopped, then start that exact retained fixture/helper set and execute each host's wire checks against the SAME verified binaries/source. Preserve all attempts/corrections and cross-host artifact/source maps. No unchanged passing-suite reruns.

Reuse prior332-provider/651-security and Engine1523Windows/1520WSL/four hosted jobs as explicit baseline only. Preserve original old-suite source, generated e3/service and0534/security registry bytes and normal runner behavior; new targeted results do not constitute a fresh348-provider total or new full-suite/hosted execution. Changed runtime mapping is covered by actual selected/disabled/parity/cross-tenant/fresh-authority/capacity controls. If review exposes another changed behavior, declare the necessary affected regression before execution.

Structural documents cannot fully express custom validators, CLR ranges, Unicode/duplicate/body/depth restrictions, current read policy or tenant authority. Keep unsigned bookmark, cooperative read/capacity intervals and M0 limitations. No performance/production/native Windows DB/external IdP/all-provider qualification; original benchmarks/settings remain unchanged.

Root is sole remote writer. Only #7/#8/#18 bodies update, with no Engine journal entry if Engine unchanged. Keep current body results concise; preserve old summaries with exact bytes in Docs. Review exact plan/dry/apply/readback23/direct Project253, preserve other20 rows/task bytes/all metadata/milestones/null hours, #3 Blocked and #20 entire row/dependencies/gates/original benchmark. Push mains, remove only owned merged refs, preserve eight user files/worktrees/raw/objects, stop exact owned fixture/helpers while retaining data/image/volume. Usage/billing blocks defer only the affected GitHub step.

[Requirements](../requirements/2026-11-22-audit-contract-export.md) · [Protocol](../validation/audit-contract-export.md)
