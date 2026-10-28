# Startup diagnosis and integration review

Read-only analysis of the complete predeclared ADR0010 diagnostic02:64 fresh processes,4 repetitions x4 layout cells x baseline/Engine x HTTP/GraphQL. No timings rerun or outliers removed. Diagnostic01's40 completed starts remain an aborted attempt after a DrvFs readiness-read ENODATA race; they are not merged into diagnostic02. All64 diagnostic02 startup traces have1GHz monotonic ticks, ordered marks, valid first business responses and passed owned shutdowns. These are descriptive small-sample observations, not acceptance scoring.

## What changed and what is supported by the evidence

The largest observed factor is SDK/runtime filesystem placement. Moving only SDK/runtime from DrvFs to Linux-native storage (A->B) reduces median startup by roughly680-782ms across the four lanes; moving app output plus cwd/content root alone (A->C) reduces it by roughly85-173ms. Moving both uniformly (A->D) reduces medians by roughly763-902ms. All cells use identical traced application bits and equivalent verified runtime bits; the app factor explicitly includes cwd/content root. Controls and trace output stay on fixed DrvFs. Placement is the intervention; stage timings do not prove which individual file read or runtime implementation instruction accounts for the difference.

| Lane | A SDK/app DrvFs median ms | B native SDK median ms | C native app/cwd median ms | D all-native median ms |
| --- | ---: | ---: | ---: | ---: |
| baseline http | 1193.959 | 489.462 | 1088.240 | 402.186 |
| engine http | 1178.541 | 498.041 | 1093.142 | 415.449 |
| baseline graphql | 1717.244 | 998.892 | 1575.145 | 852.712 |
| engine graphql | 1786.061 | 1003.712 | 1613.097 | 884.406 |

The external process start to first application timestamp is about253-286ms in SDK-DrvFs cells A/C, versus17-32ms in native-SDK cells B/D. This span includes runtime/assembly loading and entry-method JIT before our first timestamp; it is not a direct measurement of CLR startup alone. Builder, app-build, route, host-start and pre-builder/JIT spans also shrink with native SDK/app placement. Remaining all-native GraphQL host-start is about408-415ms and first business execution about171ms; HTTP host-start is about115-123ms and first business execution about19-20ms. Those vendor/schema/protocol initialization costs remain inside startup and must not be moved outside the timer.

PKCS12 import is about29-36ms in A and12-13ms in D. It is not the dominant startup cost and its cryptographic work has not been weakened. Readiness's full10,000-record dataset hash remains inside startup: about16ms baseline and7-8ms Engine in D. The Engine path earlier serializes its configuration, so framework/JIT initialization can be paid in different segments. Segment medians do not add up to the median total, and per-stage comparisons are not independent causal micro-profiles. Do not delete hash work or claim a special faster Engine hasher.

## Source and packaging review

Three files ready for integration from D:/Cephalon/.worktrees/w2-startup-tuning:

- BenchmarkHost.cs: opt-in startup marks and first-business ingress/egress hook. No hooks/middleware installed when trace is absent; no business/validation/TLS changes. Traces write once after shutdown and are disabled for canonical measurements.
- Program.cs: optional trace argument; readiness now serializes/flushes/disposes a fresh sibling `.writing`, then publishes through File.Move(overwrite:false). All this work remains inside startup. Partial/failed attempts are retained; final-path overwrite is prohibited. This corrects the observed publish/read race without hiding startup wait time.
- SmallApi.Benchmark.csproj: exclude `evidence/**` from default build items. Prior WebSDK output accidentally copied2135 raw evidence files:2202files/380,306,562bytes. The cleaned output has67files/23,265,909bytes, no evidence. All raw source evidence and build01/02 artifacts remain retained. deps.json and runtimeconfig.json are byte-identical before/after; package/runtime graphs did not change.

The packaging correction was applied uniformly before diagnostic02. Its independent startup effect was not isolated; the factorial diagnosis supports placement, not a quantified packaging-speed claim. Trace build03 DLL SHA256:2e4f664fc442f024fc91b61af35b8bdf63c42a401222fcba823b9698ad7031f1. All64 layout cells use that same binary. Source changes do not touch Engine6804271, domain/handler/codec semantics, TLS1.3/trust/KDF, dataset, limits, cancellation, offered-rate protocol or budgets.

## Candidate and proof boundaries

Uniform Linux-native SDK/app/cwd deployment is supported as the next candidate by the complete factorial diagnosis and standard WSL filesystem behavior, with no R2R/new packages/runtime knobs. Keep raw outputs on native storage too in the next explicitly declared execution profile to avoid collector DrvFs interference; that collector placement is separately declared and is not measured by these server-only64 starts. Preserve old startup failures/CV invalidity. No code-only speculative optimization is justified as critical after these observations; remaining GraphQL work must be tested by the entire unchanged30-start/idle/load matrix.

Four starts per cell do not establish p95, confidence intervals, dedicated resources or stable variance. Diagnostic instrumentation adds overhead. The complete canonical rerun, with traces disabled, remains required. Shared WSL/affinity/no2GiBcap is still nonqualifying, and #3 remains Blocked regardless numeric results. Same-binary/package-graph baseline and the public synthetic fixture retain their existing scope limitations.

Machine-readable stage intervals for every run: .local/startup-stage-analysis.json. Packaging proof: startup worktree .local/startup-packaging-verification.json (build02); build03 retains the same67-file graph with atomic-publish code.
