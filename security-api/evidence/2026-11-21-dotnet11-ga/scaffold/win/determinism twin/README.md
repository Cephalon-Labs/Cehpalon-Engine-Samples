# SmallApiProof - experimental protected Small API

This generated source-checkout consumer uses existing Core, Composition, Identity,
Tenancy, HTTP/GraphQL adapters and actual typed/lazy generated Core gateways.
It is a bounded HTTPS/JWT fixture-backed profile, not production scaffolding,
a real IdP/provider, database/RLS proof or an installable distribution.
Assembly PortableConsumer.SmallApiProof and fixed namespace PortableConsumers.Generated
avoid framework/Engine naming collisions.

The CLI only writes these fourteen files; no build, download, installation or service
is executed by generation. With the exact SDK pinned by global.json installed:

```text
dotnet build Consumer.csproj -c Release
dotnet run --project Consumer.csproj -c Release --no-build -- --self-test --output <new-report.json>
dotnet run --project Consumer.csproj -c Release --no-build -- --export-contracts --config appsettings.graphql.json --output <new-contract-directory>
dotnet run --project Consumer.csproj -c Release --no-build -- --serve --config appsettings.json --certificate <user.pfx> --public-key <RS256-public.pem> --ready <new-ready.json>
```

Only explicit --self-test creates ephemeral private JWT/TLS fixture keys. Its tests
read the four emitted configurations beside the executable and exercise actual
HTTPS requests, authentication, both cross-tenant denial directions, revocation,
owner/default-policy rejection, typed generated dispatch, disabled endpoints/modules,
invalid startup, in-flight cancellation and owned shutdown. This is correctness
evidence; timings are not performance/production qualification. Raw keys/tokens are
never written to output. A fresh report path is mandatory.

Normal --serve requires caller-provided TLS PFX (password via CEHPALON_TLS_PASSWORD)
and an RSA public PEM of at least2048bits. No host trust or credentials are invented.
It binds HTTPS HTTP/1.1 on IPv4 loopback at an ephemeral port and atomically publishes
a new readiness JSON with address/counters only; existing readiness is refused.
JWT issuer is urn:cehpalon:small-api-fixture, audience cehpalon-small-api-fixture,
algorithm RS256 and type at+jwt; validated subject alice has tenant-a membership,
bob has tenant-b. Both tenants share IDs in the bounded synthetic memory store.
Membership/resource/policy are fresh fixture authority, not real provider integration.
Caller tenant/role/subject headers and Core correlation metadata grant no authority.
Optional --max-concurrent-operations <positive-int> on --serve sets one in-process
business-handler limit shared by the enabled HTTP and GraphQL entrypoints. Admission
follows tenant authorization and capacity is held through handler cleanup. Full
capacity returns operation.capacity_exceeded. Run --self-test-capacity --output
<new-report.json> for the bounded protected HTTPS fixture. Optional
--max-concurrent-operations-per-tenant <positive-int> requires a host limit at least
as large. Both limits count admitted business operations. The partition key is the
authorized tenant. Run --self-test-tenant-capacity --output <new-report.json>
to verify that another tenant can use spare host capacity. The host closes both
kinds of budget at shutdown and waits for admitted work within the shutdown
timeout. Readiness and the post-cleanup stopped report include aggregate capacity
snapshots when a budget is configured. Tenant snapshots contain counts only.
Run --self-test-drain --output <new-report.json> for that lifecycle check.
The generated host offers CreateBudgetMetrics with a host-selected meter name.
Its caller owns collection and disposal. Run --self-test-live-metrics --output
<new-report.json> for protected HTTP/GraphQL traffic with periodic collection and
an admitted write held across shutdown.

Type `stop` followed by Enter, or Ctrl+C, for awaited listener/handler cleanup and
a stopped JSON report. Redirected stdin EOF alone keeps the host alive without
polling; an explicit stop command or Ctrl+C remains necessary.

After building, --export-contracts --config <json> --output <new-directory> writes
offline transport artifacts without WebApplication, TLS/key reads, handlers or
tenant authority calls. It first validates the same Composition/capability plan.
manifest.json is always present; enabled API adds openapi.json and enabled GraphQL
adds schema.graphql from the actual pinned vendor schema. All-off adds neither.
The same typed catalog drives runtime mapping and export; generated operation IDs
are checked with a throwing handler factory that must remain uncalled. Enabled
GraphQL export explicitly constructs/disposes its offline schema service provider
and reports those counters; disabled GraphQL performs no such registration.

HTTP schemas use the adapter's serializer policy and its actual problem envelope.
The object-only request root is explicit; inline schema $id resources preserve
local $ref resolution. These are structural shapes, not complete acceptance rules:
custom validators, CLR numeric bounds, duplicate JSON names, Unicode/byte limits,
tenant policy and business constraints remain enforced by actual runtime checks.
Nullable success roots remain possible as Core allows. No credential or host
readiness is required to export, and HTTP introspection/schema endpoints stay off.
Output is new-only staged publication; artifacts contain no timestamps/output paths.

appsettings.json enables API only, appsettings.graphql.json enables API+GraphQL,
appsettings.graphql-only.json enables GraphQL only, appsettings.off.json disables
all entrypoints. Off configuration imports no TLS/JWT files and constructs no store,
WebApplication or services. GraphQL-disabled skips vendor service registration and mapping;
package/source presence is not activation. /health is anonymous readiness only.
Business routes /api/catalog/get,list,set and optional POST-only /graphql require
valid JWT and TenantOperationDispatcher checks. GraphQL IDE/schema/introspection,
WebSockets/batching/multipart/incremental execution remain disabled by the adapter.
Worker/database/cache/broker/AI/retrieval are unsupported sentinel capabilities;
enabling them fails before any host/module factory. The sole supported tuple is
Modular / SingleProcess / RequestReply.

engine-source.json records observed selected editable source bytes, not immutable
Git/build attestation or a complete source inventory. Source paths and inherited
SDK/MSBuild parent policy must be trusted. Revalidate actual source and package
locks before reusing evidence. GraphQL/JWT versions are pinned to the observed Engine
package policy, not claimed latest. Compiler-only CodeGeneration/Roslyn must not
appear in the runtime dependency graph. Full #20 tooling benchmark, arbitrary transport schema
generation, packaging/global-tool, AOT/trimming, #3 and production gates remain open.
