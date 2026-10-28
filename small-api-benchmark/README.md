# Small API public fixture and direct-handler comparison

Experimental W0-shaped synthetic catalog for Engine #9/#11. It is separate from the protected20,000-record tenant consumer. This project has exactly10,000 records, IDs1..10000, initial `item-{id:D5}` labels, revision0 and integer amount `id*17`. GetItem, ListItems and SetLabel use the same store, typed validators, handler implementations and per-invocation owned disposal in both variants. Pages contain20 ascending records. SetLabel applies an optimistic revision under the store lock, without inserting keys.

`--variant=baseline` maps native ASP.NET Core Minimal API endpoints and native HotChocolate16.7.1 typed field resolvers to direct owned handlers. It does not invoke Core dispatch, generated registrations, Composition compilation or plan activation. `--variant=engine` uses generated typed Core registrations, immutable Composition activation and Engine HTTP/GraphQL adapters. Both variants share portable Core result/context/interface representation types; this does not mean the baseline invokes Core runtime dispatch. Both are compiled into the same executable and carry the same package graph, so footprint comparisons measure activation/path differences, not separately stripped package-distribution sizes.

Native baseline transport parsing is independent of Engine adapter execution. The same declared media/JSON limits, validation, intentional business error messages/codes, cancellation and handler cleanup apply; the functional corpus verifies their mapping. Native GraphQL uses the same vendor/version, inferred DTO schema,16KiB/depth8/cost1000 limits, no batching/incremental/multipart/GET/schema download/introspection/IDE/WebSocket. Engine's actual adapter remains the Engine path. Protocol coercion errors may differ from semantic errors in both profiles.

The profile has no external authentication or tenant authority. A fixed server-owned `public-fixture` principal permits only synthetic public fixture operations through protected adapter prerequisites. It is never derived from caller headers and is **not identity/tenant/security certification**. The separate protected sample supplies those bounded negative tests. All fixture controls are loopback-only synthetic tooling, not an application management API.

Build with the pinned SDK, official isolated NuGet source, locked restore and explicit EngineRoot pointing to the exact clean Engine revision in `engine-lock.json`. No package publication is required. Example from Samples:

```powershell
dotnet restore small-api-benchmark/SmallApi.Benchmark.csproj --locked-mode --configfile NuGet.Config
dotnet build small-api-benchmark/SmallApi.Benchmark.csproj -c Release --no-restore
dotnet small-api-benchmark/bin/Release/net11.0/SmallApi.Benchmark.dll --mode=self-test --variant=engine --transport=graphql
```

Use the private pinned `dotnet` executable, not an unrelated installed SDK. `--transport=http` is API-only; `graphql` enables API plus GraphQL HTTP at `/graphql`. HTTP POST routes are `/api/catalog/get`, `/api/catalog/list`, `/api/catalog/set`; fields are `catalogItem`, `catalogPage`, `setLabel`, all with typed `input` arguments. The first verified request must inspect actual expected business data, not only readiness.

For process timing, pre-generate one fresh shared fixture **outside measurement**:

```text
--create-fixture=<new ignored private directory>
--mode=serve --variant=baseline|engine --transport=http|graphql --fixture-dir=<same directory> --ready-file=<new file> --state-file=<new file>
```

The fixture contains public `root-ca.der` and private `server.pfx`; never track/copy the PFX into evidence. Linux permissions are0700/0600. Both variants load the identical48-hour leaf/49-hour CA; RSA key generation is outside fresh-process timing. TLS1.3 is enforced server and C# client, with custom-root trust and normal hostname validation. No trust store is changed. The ready JSON exposes only public DER, address, variant/transport/process/dataset/hash. Send `STOP` on stdin for bounded owned shutdown. Final state is written only to a new output file.

Controls: POST `/__fixture/reset` requires all handlers disposed, reseeds outside the measured interval, then returns dataset hash; POST `/__fixture/delay?enabled=true` enables the cancellable5s SetLabel fixture. GET `/__fixture/metrics` reads cheap allocation/CPU/GC/work counters; GET `/__fixture/state` additionally serializes all10,000 records and final hash. Use metrics at measurement boundaries and full state **after** load only, since full-state serialization would pollute allocation deltas. Metrics collection itself has small matching instrumentation overhead and is not a per-request allocation tracer.

Probes record host/API/GraphQL registration factories, HotChocolate DI descriptors and forbidden-module factory traps. A real vendor diagnostic callback counts executor initialization; `GraphQLSchemasReady` counts schemas observed ready via that executor, not an independent schema constructor hook. API-only must keep all GraphQL probes zero through requests and disposal. The public host's static preflight rejects malformed plans; actual all-off host suppression remains independently covered by the protected consumer. Unimplemented provider traps do not qualify providers.

`--mode=conformance --output=<freshdirectory>` is supplied by `Conformance.cs`; `--mode=load-client` or `--load-client` is supplied by `Driver.cs`. The main integrator owns orchestration, source hashes, retained attempts, request/dataset manifest generation, paired order, dedicated-resource preflight and analysis. Do not run performance measurements while agents/builds/collectors compete. Follow the unchanged W0 protocol:30 fresh starts per variant, idle120s+60samples,60s warmup+180s open-loop1,000req/s, max128 outstanding, five alternating pairs per transport. Record drops/timeouts/failed requests and all outliers; do not lower budgets or cherry-pick reruns. Shared WSL affinity observations do not establish dedicated2CPU/2GiB reference qualification, native deployment or supported-Windows proof. #3 remains Blocked; full features remain M0 until their actual gates are met.
