# Small API public fixture and direct-handler comparison

An empty-argument IDE launch now executes one finite HTTP correctness smoke test and exits. It does not run a benchmark. Existing explicit modes and nonempty serve invocations keep their measurement protocol and all original acceptance criteria.

Experimental W0-shaped synthetic catalog for Engine #9/#11. It is separate from the protected20,000-record tenant consumer. This project has exactly10,000 records, IDs1..10000, initial `item-{id:D5}` labels, revision0 and integer amount `id*17`. GetItem, ListItems and SetLabel use the same store, typed validators, handler implementations and per-invocation owned disposal in both variants. Pages contain20 ascending records. SetLabel applies an optimistic revision under the store lock, without inserting keys.

`--variant=baseline` maps native ASP.NET Core Minimal API endpoints and native HotChocolate16.7.1 typed field resolvers to direct owned handlers. It does not invoke Core dispatch, generated registrations, Composition compilation or plan activation. `--variant=engine` uses generated typed Core registrations, immutable Composition activation and Engine HTTP/GraphQL adapters. Both variants share portable Core result/context/interface representation types; this does not mean the baseline invokes Core runtime dispatch. Both are compiled into the same executable and carry the same package graph, so footprint comparisons measure activation/path differences, not separately stripped package-distribution sizes.

Native baseline transport parsing is independent of Engine adapter execution. The same declared media/JSON limits, validation, intentional business error messages/codes, cancellation and handler cleanup apply; the functional corpus verifies their mapping. Native GraphQL uses the same vendor/version, inferred DTO schema,16KiB/depth8/cost1000 limits, no batching/incremental/multipart/GET/schema download/introspection/IDE/WebSocket. Engine's actual adapter remains the Engine path. Protocol coercion errors may differ from semantic errors in both profiles.

The profile has no external authentication or tenant authority. A fixed server-owned `public-fixture` principal permits only synthetic public fixture operations through protected adapter prerequisites. It is never derived from caller headers and is **not identity/tenant/security certification**. The separate protected sample supplies those bounded negative tests. All fixture controls are loopback-only synthetic tooling, not an application management API.

The active benchmark build uses .NET SDK `11.0.100` and runtime `11.0.0`.
Use a clean Engine checkout at the revision in `engine-lock.json`. The
build verifier and measurement orchestrator read that benchmark lock.
Historical evidence retains its original Engine, SDK, protocol and results.
Run a locked Release build without starting a benchmark from Samples:

```text
python tools/verify_small_api_benchmark.py --dotnet <absolute-sdk-host> --engine-root <clean-engine-checkout> --output .local/small-api-benchmark/<new-attempt> --require-clean --build-only
```

Omit `--build-only` for the ordered conformance matrix. `--transport=http` is API-only; `graphql` enables API plus GraphQL HTTP at `/graphql`. HTTP POST routes are `/api/catalog/get`, `/api/catalog/list`, `/api/catalog/set`; fields are `catalogItem`, `catalogPage`, `setLabel`, all with typed `input` arguments. The first verified request must inspect actual expected business data, not only readiness.

## Two-host reference execution

Run the controller on the approved Linux x64 app machine. Use a
separate approved Linux x64 driver machine on a private network. The
controller checks an existing isolated cgroup v2 app leaf with exactly
two exclusive CPUs and `memory.max=2147483648`, complete ancestor
limits, and disjoint controller affinity. Run the controller with
delegation to move its own child into that leaf. The runner does not
provision resources. Inspect both machines' upstream reservations
and use a quiet driver allocation for the attempt.

Build on the app host with the locked verifier shown above. Stage the
identical directory containing the emitted assembly and all dependencies
on the driver. Stage both `tools/small_api_remote_driver.py` and
`tools/small_api_reference_resources.py` beside one another at an
absolute path on the driver. Install the pinned .NET SDK 11.0.100 with
.NET and ASP.NET Core runtime 11.0.0 on each machine. Give the driver
account an existing private job directory with mode 0700. Configure a
scoped SSH key and an independently verified server host key.

Create a private configuration under the ignored `.local` directory.
The following values are illustrative.

```json
{
  "app": {
    "listen_ip": "10.40.0.10",
    "driver_ip": "10.40.0.20",
    "resources": {
      "cgroup": "/sys/fs/cgroup/benchmark/app",
      "controller_cpus": [4, 5]
    }
  },
  "driver": {
    "host": "10.40.0.20",
    "user": "benchmark",
    "port": 22,
    "known_hosts": "/private/benchmark/known_hosts",
    "identity_file": "/private/benchmark/id_ed25519",
    "remote_helper": "/opt/benchmark/tools/small_api_remote_driver.py",
    "remote_dotnet": "/opt/dotnet/dotnet",
    "remote_publish_dir": "/opt/benchmark/application",
    "remote_job_root": "/home/benchmark/.local/jobs",
    "app_host": "10.40.0.10"
  },
  "build_manifest": "/private/benchmark/build/manifest.json"
}
```

The app listens on a dynamic port at the declared private IPv4 address.
Allow the controller at that address and the direct driver address to
reach that listener on your private network. The certificate uses the
private IPv4 SAN and the socket admits only the controller and driver
source addresses. SSH verifies the staged driver and transfers the
fixture CA certificate. The private server key stays on the app host.

Use the same configuration for a dedicated preflight or a full W0
attempt. Use a new output directory for each attempt.

```text
python3 tools/benchmark_small_api.py --dotnet <GA-dotnet> --assembly <Release-assembly> --engine-root <clean-engine> --remote-config .local/remote-config.json --output .local/reference/<attempt> --preflight-only
```

The remote preflight performs the original collector preparation and a
two-second offered-work probe on each of the four baseline/Engine and
HTTP/GraphQL lanes. It writes raw results per lane and a summary. For
the full attempt, omit `--preflight-only` after confirming the two real
allocations. The runner repeats the admission and collector preflight
before entering all four original phase families and checks the timed
acceptance rows before publishing a reference verdict.

The laboratory switch `--remote-preflight-lab --preflight-only` uses
only the `app.listen_ip` and `app.driver_ip` and the same `driver`
configuration. It exercises SSH and TLS across isolated test endpoints.
Its summary cannot mark the reference environment qualified and it
cannot start timing.

## Manual fixture and existing loopback protocol

For process timing, pre-generate one fresh shared fixture **outside measurement**:

```text
--create-fixture=<new ignored private directory>
--mode=serve --variant=baseline|engine --transport=http|graphql --fixture-dir=<same directory> --ready-file=<new file> --state-file=<new file>
```

The fixture contains public `root-ca.der` and private `server.pfx`; never track/copy the PFX into evidence. Linux permissions are0700/0600. Both variants load the identical48-hour leaf/49-hour CA; RSA key generation is outside fresh-process timing. TLS1.3 is enforced server and C# client, with custom-root trust and normal hostname validation. No trust store is changed. The ready JSON exposes only public DER, address, variant/transport/process/dataset/hash. Send `STOP` on stdin for bounded owned shutdown. Final state is written only to a new output file.

Controls: POST `/__fixture/reset` requires all handlers disposed, reseeds outside the measured interval, then returns dataset hash; POST `/__fixture/delay?enabled=true` enables the cancellable5s SetLabel fixture. GET `/__fixture/metrics` reads cheap allocation/CPU/GC/work counters; GET `/__fixture/state` additionally serializes all10,000 records and final hash. Use metrics at measurement boundaries and full state **after** load only, since full-state serialization would pollute allocation deltas. Metrics collection itself has small matching instrumentation overhead and is not a per-request allocation tracer.

Probes record host/API/GraphQL registration factories, HotChocolate DI descriptors and forbidden-module factory traps. A real vendor diagnostic callback counts executor initialization; `GraphQLSchemasReady` counts schemas observed ready via that executor, not an independent schema constructor hook. API-only must keep all GraphQL probes zero through requests and disposal. The public host's static preflight rejects malformed plans; actual all-off host suppression remains independently covered by the protected consumer. Unimplemented provider traps do not qualify providers.

`--mode=conformance --output=<freshdirectory>` is supplied by `Conformance.cs`; `--mode=load-client` or `--load-client` is supplied by `Driver.cs`. The main integrator owns orchestration, source hashes, retained attempts, request/dataset manifest generation, paired order, dedicated-resource preflight and analysis. Do not run performance measurements while agents/builds/collectors compete. Follow the unchanged W0 protocol:30 fresh starts per variant, idle120s+60samples,60s warmup+180s open-loop1,000req/s, max128 outstanding, five alternating pairs per transport. Record drops/timeouts/failed requests and all outliers; do not lower budgets or cherry-pick reruns. Shared WSL affinity observations do not establish dedicated2CPU/2GiB reference qualification, native deployment or supported-Windows proof. #3 remains Blocked; full features remain M0 until their actual gates are met.

The orchestrator verifies private fixture modes in task-owned Linux-home `.local/share/cehpalon-benchmark-fixtures`; Windows-mounted files may not enforce chmod and are not used for canonical private fixtures. The load collector retains130 read-only connection preparations and a2s fixed-rate capacity preflight before resetting into the unchanged warmup/measurement. A failed preflight stops the whole attempt. Actual TLS1.3/cipher observations return the original authenticated stream, with no certificate-validation override. Native buffering matches the Engine strategy (HTTP16KiB backing buffer, GraphQL4KiB streaming) to avoid an artificial codec-allocation penalty.

Previous attempt02 [conformance and measurement report](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/w2-small-api-conformance-benchmark.md) and [retained raw evidence](../small-api-benchmark/evidence/2026-10-28/retention-manifest.json): functional corpus passes on both observational hosts; all planned measurements exist, but startup absolute budget fails and Engine GraphQL CV12.3681% invalidates the main performance series. Shared WSL reference qualification and #3 remain Blocked. Same-binary/native-direct baseline shares fixture scaffolding, including unused pure module-registration metadata; it does not compile/activate Composition or invoke Core dispatch. These are activation/path observations, not stripped-distribution footprint or production proof.

Startup/variance continuation uses the same pinned runtime and original budgets, with Linux-native SDK/shared runtime/app/cwd/output for both variants. Web SDK build output now excludes evidence/** while repository raw evidence remains retained. Ready files publish only after complete serialization/flush/disposal via no-overwrite rename; transient stat/read absence is retried within the original counted startup/deadline. Optional --startup-trace=FILE is diagnostic only and must be absent in canonical runs.

The collector buffers every indexed observation and writes the identical raw schema after joining all requests. Request schedules, payloads, deadlines,128cap and correctness checks are unchanged. Final server metrics are captured immediately after measured requests, before persistence; this explicitly corrects the prior flush-inclusive bracket. Additional phase client CPU/GC/thread-pool and TLS timestamps aid interpretation. Managed failures preserve partial rows; abrupt process/host loss can lose an in-memory phase and invalidates the attempt. This reduces instrumentation contention without proving the cause of the prior GraphQL variance. Follow ADR0010 and the full unchanged protocol, never substitute diagnostics for acceptance.

Previous [startup and variance report](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/w2-small-api-tuning.md) and [complete retained execution](../small-api-benchmark/evidence/2026-10-28-tuning/execution-retention-manifest.json): Engine startup p95 HTTP438.697ms/GraphQL902.391ms; GraphQL Engine CV3.2616% under the unchanged10% rule. All startup/idle/main numerical gates pass in the declared native-storage WSL profile. All12diagnostic attempts are accounted for;11timed, one EngineHTTP2000/s preflight has37drops/4000 and no warmup/measurement. It is not a successful2000/s qualification. Keep reference/#3 Blocked and overallM0. Native deployment placement and collector changes are not an Engine-code-only speedup; all-five mean p95 observations are higher than prior values. Raw failures and the old invalid series remain preserved.

The [collector connection continuation](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/w2-small-api-collector-readiness.md) follows ADR0011. A separate control pool serves fixture controls and two verified warm reads. A fresh load pool must hold128 distinct TLS1.3/HTTP1.1 responses unread at one barrier, then validate all bodies before the fixed-rate preflight. A shared30s preparation deadline cancels and joins failed holds. This proves observed readiness at that barrier, not continued socket health or capacity. Every entered phase retains connection/client snapshots and raw accounting; a managed preflight rejection emits a structured failure and returns nonzero before warmup/measurement. Missing metadata invalidates the controller attempt. `--preflight-only=true` is for the separately declared diagnostic: preserve full180s/60s manifest preconditioning, execute only the2s preflight, and label planned versus executed counts explicitly. It never substitutes for the complete benchmark. Source and failure robustness tests,12fresh probes and the complete canonical04 attempt have finished; exact observations and limits are recorded in the continuation report.

Canonical04 is now complete: all120startup,20idle,20main and12actually timed diagnostics retained in [execution evidence](evidence/2026-10-28-collector/execution-retention-manifest.json). All original numerical gates pass in the declared shared-WSL profile;5,472,000measured requests correct/zeroerrors or drops. Engine startup p95HTTP417.955ms/GraphQL863.722ms; GraphQL Engine CV4.769352% passes10% but is higher than03's3.261601%. No universal variance or Engine-code-only improvement claim. All12connection probes separately pass48000actualoffers/128heldloadTLS each;4.32Mplanned manifest entries are not executed-request counts. Windows01's single failed in-flight-cancellation case remains; one frozen complete sequential02 repeat passes bothhosts without changed criteria. Reference/#3 and full9/11 remainBlocked/M0. Full response/provenance/fixture limits and unchanged Engine revision are in the continuation report; no production or supported-platform qualification follows.
