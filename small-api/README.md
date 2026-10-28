# Experimental protected Small API consumer

This external project consumes the exact clean Engine revision in `engine-lock.json`. Three generated Core gateways reuse the same tenant-aware catalog handler over typed HTTP POST and optional HotChocolate16.7.1 GraphQL. Pinned JwtBearer11 RC3 validates process-local RSA fixture tokens before fresh tenant identity/membership/resource/policy checks. No real IdP, database, broker, cache or AI service is required.

Run from the Samples root with the pinned SDK:

```powershell
python tools/verify_small_api.py --dotnet D:/Cephalon/.tools/dotnet11/win-x64/dotnet.exe --output .local/small-api/new-attempt
```

The Engine checkout must be clean at the locked full SHA. The verifier restores locked dependencies, builds Release, runs actual loopback HTTPS requests with a custom fixture CA, preserves source/package/output hashes, and verifies generated registrations compile without Roslyn in the runtime graph. Output directories must be new. Keys/tokens stay in process; no trust root is installed. Failed attempts are retained.

`FixtureHost.Config(api, graphql)` constructs schema1 configuration. Composition validates before host creation. API-only omits GraphQL registration/mapping, GraphQL-only leaves API off, all-off creates no WebApplication/listener, and unsupported worker/provider selections fail before activation. Unimplemented modules have throwing factory traps. The combined consumer carries GraphQL assemblies, which does not imply activation. API-only checks zero registration branch/HotChocolate DI descriptors and forbidden factory calls through10,000 requests and shutdown; these counters do not separately instrument vendor schema/executor constructors.

| Operation | HTTP POST | GraphQL field |
| --- | --- | --- |
| GetItem | `/api/catalog/get` | query `catalogItem(input: GetItemInput!)` |
| ListItems | `/api/catalog/list` | query `catalogPage(input: ListItemsInput!)` |
| SetLabel | `/api/catalog/set` | mutation `setLabel(input: SetLabelInput!)` |

Fixture alice belongs to tenant-a, bob to tenant-b; identical item IDs exist independently. Authority checks the tenant-owned catalog, then guarded data ports apply item/pagination/update semantics. Metadata grants no membership. Immutable inputs have bounded labels/pages and optimistic revision updates. Intentional semantic error codes match, while REST statuses/problem details and GraphQL field-error envelopes differ. Parsing/coercion errors remain transport-specific.

GraphQL is authenticated POST JSON only,16KiB, depth8/cost1000, with no introspection/schema download/IDE/WS/batching/multipart/incremental execution. DTO field changes are schema changes. Runtime business contracts contain no HttpContext/vendor objects. Host authentication and dispatcher wiring are mandatory; calling an adapter alone does not establish tenant authority.

The functional suite checks TLS trust/hostname, invalid JWT signature/issuer/audience/time/type/ambiguous or malformed subject, cross-tenant rejection before business work, same-ID isolation, metadata spoofing, fresh membership revocation, wrong owner/default policy, validation/not-found/pagination/update/conflict, abort/no delayed write, malformed/oversized bodies, disabled exposure and owned cleanup. Startup timings are diagnostics only.

This protected fixture has10,000 records per tenant (20,000 total), so it is **separate from the unchanged public W0 benchmark**. Full1,000-case ordered corpus,100 timed cancellations/profile,30 restarts, startup/RSS/latency/throughput pairs remain Not run. Windows26H2 observations do not clear #3; WSL evidence does not prove native deployment or production. Full features remain M0.

See [ADR0008](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/adr/ADR-0008-protected-http-graphql-adapters.md), [functional protocol](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/validation/transport-small-api-functional-protocol.md) and unchanged [W0 gates](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/validation/small-api-workload.md).

Current2026-10-28 [complete conformance and measurement report](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/w2-small-api-conformance-benchmark.md) and [retained raw evidence](../small-api-benchmark/evidence/2026-10-28/retention-manifest.json): functional corpus passes on both observational hosts; all planned measurements exist, but startup absolute budget fails and Engine GraphQL CV12.3681% invalidates the main performance series. Shared WSL reference qualification and #3 remain Blocked. Same-binary/native-direct baseline shares fixture scaffolding, including unused pure module-registration metadata; it does not compile/activate Composition or invoke Core dispatch. These are activation/path observations, not stripped-distribution footprint or production proof.
