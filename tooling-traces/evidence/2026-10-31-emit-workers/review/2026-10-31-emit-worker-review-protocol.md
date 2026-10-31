# Independent Emit worker review protocol

Scope: offline analysis of the retained combined Linux02 generator execution at Engine55. No new target, build, benchmark, Engine change, tracking write or remote write by this reviewer. Root remains sole integrator/remote writer. Preserve #3 Blocked, #20 metadata and every original criterion.

## Statements the retained channels can support

- Exact row/input/marker identity, source hashes and same-process ownership can be replayed independently.
- A uniquely paired caller WaitHandle interval is an observed runtime elapsed interval. A caller stack point containing the exact vendor WaitForWorkers context locates residency at that sampled point.
- A noncaller stack point containing the declared vendor MethodCompiler/CompileNamedTypeAsync lambda and ThreadPool frames is an observed compiler-context point. It does not make that ThreadPool thread a permanently owned Roslyn task.
- Original GC intervals remain immutable **previous-analyzer outputs**, not certified pause truth. A later same-initiator hypothesis study disputes two of their end boundaries; neither pairing choice is approved without the exact runtime contract. Incomplete/ambiguous EE records remain unresolved. No GC total upper bound or absence claim follows from either interval set.
- Proc records contain stored cumulative counter values read during bounded windows. Same-birth adjacent endpoint differences selected inside a query are counter changes **observed between those reads**. They are not an exclusive CPU/runqueue/GC time budget for that query.

The matching-name public WSL source reads stored sum_exec_runtime, run_delay and pcount directly. Its scheduler credits completed queued intervals when arriving/dequeuing. Counter publication can therefore include time preceding the query. Even a 100ms jump between two samples inside a 10ms query must remain a valid stored-counter observation; it cannot become a guaranteed 100ms in-query delay or be filtered as an impossible outlier. Public source naming is context, not installed-binary attestation.

Sources: [WSL proc reader](https://raw.githubusercontent.com/microsoft/WSL2-Linux-Kernel/linux-msft-wsl-6.18.54.1/fs/proc/base.c), [WSL scheduler accounting](https://raw.githubusercontent.com/microsoft/WSL2-Linux-Kernel/linux-msft-wsl-6.18.54.1/kernel/sched/stats.h).

## Required pairing and clock conditions

Keep PID/CLR/nativeTID pairing, observed TID-birth reuse exclusions, malformed identity wildcard poisoning, actual source/input hashes and original row order. Unknown identity is not repaired from a favorable neighboring event.

Keep EventPipe-to-target marker-write bounds separate from target UTC mapping and Python perf-counter sample windows. A declared clock link and its uncertainty are required. Equal units or similar numeric timestamps do not prove equal domains. Unsupported clock models yield unassigned observations; no smoothing, widening, interpolation or prorating.

Use complete proc endpoint windows inside a guaranteed query core, adjacent samples only, same native birth, and no matching read race/reset/missing field. This selects observation geometry; it does not establish when credited CPU/runqueue time accrued. The gap between endpoint windows is not a guaranteed counter-accrual interval.

## Independent fixture requirements

1. Compiler-context point predicate rejects caller, foreign vendor, ForceComplete-only and missing ThreadPool frames; preserve exact raw frame witnesses.
2. Unknown/reused TID, missing birth, foreign PID, malformed wait records, partial clock intersection and boundary-only residency remain explicit.
3. Missing endpoints/fields, races, counter decreases and gaps cannot become zeros or bridged values.
4. A pre-query queued interval credited inside the query retains its full raw jump with in-query elapsed attribution unknown.
5. Multiple adjacent deltas telescope without duplicate counting; parallel thread sums may exceed wall time and are not forcibly capped into a one-thread budget.
6. Original GC ambiguity and the two disputed boundaries are retained; previous-analyzer overlap zero is not a no-GC statement. Hypothesis-only per-TID reconstruction cannot replace original intervals or certify them by agreement.
7. Worker/caller sample counts are points, not interpolated durations or on-CPU percentages. GC, managed waits and native intervals remain overlapping dimensions.

## Product decision rule

These channels can strengthen observed context and expose unsupported causal claims. They cannot independently isolate worker starvation, exact runnable/blocked state, a managed lock owner, physical IO, total GC delay or an avoidable Engine operation. A safe product optimization needs a concrete Engine-owned action shown to be unnecessary while preserving original behavior, authority/module guards, compiler concurrency, schema work and durable publication. Existing evidence does not yet justify such a patch. No unchanged-source benchmark rerun is authorized merely to seek lower variance.
