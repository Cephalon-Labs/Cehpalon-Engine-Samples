# GraphQL adapter contracts

Run with the repository's locked private .NET 11 RC3 SDK. This executable uses real loopback Kestrel HTTP and a finite server-owned authenticated-principal fixture. It deliberately does not implement or prove JWT/OIDC authentication, TLS or tenant authority; the external Small API consumer exercises those separately.

Restore `GraphQL.ContractTests.csproj` in locked mode with the repository `NuGet.Config`, build Release with warnings as errors and a fresh artifacts directory, then run its DLL with `--output=<fresh-results.json>`. The executable returns nonzero on any failed check and writes every result; retain failed attempts. No test packages or host-global settings are required.

The 45 checks cover catalog preflight/immutability, explicit typed query/mutation bindings, shared validator ordering, anonymous rejection, generic tenant denial, intentional domain codes, unexpected faults including host `GraphQLException` and unrelated cancellation, strict JSON/body/media limits including unknown-length uploads and malformed Unicode, disabled GET/schema/IDE/WebSocket exposure, introspection behavior, input coercion/unknown fields, aliases/fragments cost, recursive depth rejection, explicit multioperation selection, unsupported incremental directives and actual client cancellation. These adapter checks are not a claim that the fixture's denial stands in for real tenant-source checks.

Windows 26H2 results remain observations and do not unblock #3. WSL results are Linux-in-WSL observations rather than native deployment or hosted CI proof. No benchmark or load thresholds are asserted here.
