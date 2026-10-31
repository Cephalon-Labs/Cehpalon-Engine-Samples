# Process-scoped tooling diagnostics

Diagnostic-only investigation of #20, governed by Docs ADR-0018. These tools do not modify the Engine benchmark driver, original tooling harness, runtime flags, primers or acceptance criteria. Trace overhead, startup coordination, rundown and OS polling perturb all diagnostic timings. Original untraced results remain authoritative for the observational benchmark.

`tools/prepare_tooling_trace_driver.py` prepares a separate instrumented copy of the exact clean Engine55 driver. Build it with the pinned private SDK. `TraceAnalysis/` is a standalone locked managed reader; `Conformance/` is a synthetic collector fixture with explicit forced GC **only for collector verification**. The production workload and benchmark never force GC.

`tools/trace_tooling.py` orchestrates `conformance`, `runtime`, `native-conformance` and `native` modes into a fresh output directory. Runtime capture needs the pinned dotnet-trace DLL, analyzer DLL and owned target. Native mode needs strace on Linux. Run conformance before full fixed lanes. The target has one suspended reverse diagnostic port; its verified OS observer starts first, then the collector starts EventPipe and resumes through that same port. Child environments isolate inherited diagnostic-port aliases without changing global settings or overriding disabled IPC policy. Missing tool binaries must spawn zero children.

The fixed runtime/native lane is one complete diagnostic generator matrix plus three rotated/reversed rounds of all eight CLI scenarios (25 targets). CLI fixtures are prepared using the original harness `--prepare-only`, retaining actual emitted registry, dependency graph, config and output hashes. No credentials, network serving or provider calls are required. Every case keeps raw logs, semantic checks, clock/provenance data and owned-process cleanup.

Windows current token supplies process CPU/I/O and initial owned-thread CPU only: no kernel scheduling/context-switch/physical-disk attribution, and later-created threads are outside its cached-thread dimension. Linux proc sampling retains identity, runtime/runqueue/context-switch/fault counters and coverage gaps; proc I/O is unavailable on this host. Separate native strace observations are syscall intervals, not physical disk latency. EventPipe and native lanes are separate executions and cannot be fused as exact causal overlap.

Keep all failures, partial observations and quality flags. Raw nettrace/native/proc files are authoritative and retained with deterministic compression and hashes. ETLX is a derived local conversion. Build outputs, private fixtures, clone objects and credentials are excluded from evidence. See the evidence manifest and Docs report for actual source/host/tool versions, full-lane completion, limits and unchanged-source untraced benchmark results.


## Same-process managed/native waits (ADR0019)

Linux experimental modes `combined-conformance` and `combined` capture EventPipe plus strace wait/IO and proc sampling from one verified managed PID. Pin the private SDK/tools/analyzer, use absolute executable paths and a fresh output directory. The pinned SDK host path must be ASCII without strace C escapes; unsupported renderings fail before a target lease. Prepare a fresh copied driver with `tools/prepare_tooling_wait_driver.py`; only its post-body UTC/Stopwatch anchor support differs from the original diagnostic driver. Build the separate `WaitConformance` project with its committed SDK/NuGet/lock. Keep synthetic forcedGC out of real workloads.

Run `combined-conformance` with `--conformance-target <WaitConformance.dll>`, then `tools/analyze_tooling_waits.py --folder <capture>/known-target --output <new-analysis-dir> --conformance`. Require semantic/positive-managed/native/known4096IO/clock/owned-cleanup gates before a fixed lane. `combined` takes the original prepare-only `--fixture`, fresh `--driver`, exact clean `--engine-root`, pinned `--dotnet`, `--trace-tool`, `--analyzer` and a new `--output`. It collects one complete generator matrix and24CLI cases. After all capture finishes, run the offline wait analyzer for each case into a new output directory. It never executes targets.

The collector observes strace startup children as diagnostics only; only a successful exact-host raw execve joined to stable live birth/parent/group/session and executable establishes the target lease. After lease, identity cannot change. Source bytes and loaded function inventory/code fingerprints plus binary hashes are frozen before/after; globals/defaults/imported bindings remain outside attestation. Header-only waiting permits tracer0 after resume while waiting boundedly for the collector header; other readiness remains strict.

WaitHandle pairs use PID/CLR/nativeTID. Malformed/nested/orphan/reused identities cannot form favorable later pairs. Native WAIT success/timeout, EAGAIN, interruption/restarts, WAKE and unknown are separate; elapsed syscall intervals include ptrace/scheduling overhead. Post-body target UTC brackets calibrate generator/synthetic intervals conditionally, retaining precision and strict-model failure. CLI has no such markers: lifetime counts only, never an exact cross-stream startup join.

Caller-only overlap fields are separate from process-wide background/idle thread unions. In particular `same_tid_managed_wait_native_observed_overlap` matches each pair and native intervals on its TID across the whole process; it is not caller-only or proof of a particular managed lock/futex owner. Never add overlapping managed/native/GC dimensions to infer exclusive CPU/blocked time. GC pairing and native loss remain explicitly partial/unknown even with integrity passes.

[Retained ADR0019 evidence](evidence/2026-10-30-waits) includes failed full01, corrected whole02, both synthetic captures, negative/mocked checks, all source/clock/ownership data, independent audit and offline PE/EE studies. The original untraced benchmark is unchanged and was not repeated for a collector-only correction; Engine55 remains unchanged and #3 remains Blocked.


## 2026-10-31 Emit worker analysis (ADR0020)

Offline replay of the complete retained combined-linux02 generator; Engine unchanged.
`tools/analyze_tooling_emit_workers.py --folder INPUT_GENERATOR --output NEW_CONTEXT`
classifies exact compiler/ThreadPool point witnesses and retains legacy GC observations separately from uncertified supplementary hypotheses. `--self-test` runs 20 guards.
`tools/analyze_tooling_worker_scheduler.py --capture INPUT_GENERATOR --context NEW_CONTEXT --output NEW_SCHEDULER --expected-context-source-sha256 4738c34d631b637af6f31bcb1eba4c0b73f7ce9bced8d38d0bc25f1c074506cc`
reports adjacent stored-counter increments only. The old wait analyzer must retain its pinned source hash. Rehydrate original bytes from the previous retention manifests; analysis output directories must be new.

Compiler frames occur in 242/270 measured Emit rows; point observations do not identify caller-task ownership or runnable state. Two of the legacy 23 GC envelopes have cross-initiator disputed ends; neither the legacy nor supplementary pairing is certified pause truth. Stored scheduler credits can include activity before the query, even when both read windows are inside it. Never interpret them as phase CPU/runqueue duration, lower bounds or exclusive GC/scheduler shares.

[Retained attempts, fixtures and reviews](evidence/2026-10-31-emit-workers/retention.json) preserve superseded sources/results, the original declaration, 20 classifier fixtures, 30 scheduler fixtures on Windows and WSL, 19 independent credit fixtures, 294,835 point checks and 1,078,247 independent endpoint checks. The first independent endpoint audit had a Python indentation error; its source/log remain, and the corrected copy is retained separately. No new target, build, capture or original benchmark ran; no Engine optimization is justified.
