# SmallApiProof - experimental protected Small API

This generated source-checkout consumer uses existing Core, Composition, Identity,
Tenancy, HTTP/GraphQL adapters and actual typed/lazy generated Core gateways.
It is a bounded HTTPS/JWT fixture-backed profile, not production scaffolding,
a real IdP/provider, database/RLS proof or an installable distribution.
Assembly PortableConsumer.SmallApiProof and fixed namespace PortableConsumers.Generated
avoid framework/Engine naming collisions.

The CLI only writes these thirteen files; no build, download, installation or service
is executed by generation. With the exact SDK pinned by global.json installed:

```text
dotnet build Consumer.csproj -c Release
dotnet run --project Consumer.csproj -c Release --no-build -- --self-test --output <new-report.json>
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
Type `stop` followed by Enter, or Ctrl+C, for awaited listener/handler cleanup and
a stopped JSON report. Redirected stdin EOF alone keeps the host alive without
polling; an explicit stop command or Ctrl+C remains necessary.

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
appear in the runtime dependency graph. Full #20 tooling benchmark, transport schema
generation, packaging/global-tool, AOT/trimming, #3 and production gates remain open.
