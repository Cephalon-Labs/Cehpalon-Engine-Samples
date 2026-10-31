# ADR0020 — Emit worker GC and scheduler evidence

Date: 2026-10-31 (Asia/Bangkok). Status: accepted for bounded offline diagnosis under the user's continuation. Tracking: Engine #20; #3 remains Blocked.

## Question and fixed scope

The previous same-process lane observed caller WaitHandle residency in PE Emit, frequently with `MethodCompiler.WaitForWorkers`. This does not identify a lock owner or show whether worker progress was limited by GC, runqueue delay, useful compilation, tracing overhead or another cause. Reanalyse the retained complete `tooling-wait-combined-linux02/generator` execution first; retain both prior completed and failed attempts. Do not merge different executions.

Engine stays at `55c630fc5d4c47258a1a2b0da4a16ce8bc42b9f7`. This wave authorizes offline diagnostic tools and synthetic fixtures, source review and evidence/Docs/tracking synchronization. It does not change runtime, compiler flags, concurrency, GC, primers, workloads, thresholds or the original benchmark. No fresh workload target or capture is predeclared in this wave. A justified product patch would require a separate declared change and the complete unchanged original benchmark; unchanged-source reruns are not evidence of an improvement.

## Analysis declared before replay

1. Identify caller waits by the existing PID/CLR/native-TID pairing and stage markers. Identify worker-context observations by actual managed stacks containing Roslyn compilation-worker frames, preserving the original sample time and thread identity. A matching thread is a context observation, not proof it owns or satisfies the caller's particular task. Do not classify all background threads as Emit workers.
2. Compare only per-TID scheduler observations with stable identity/lifetime, monotonic counters and the full read brackets inside a supported same-execution time mapping. Retain requested versus actual sample gaps, races, missing fields, resets and uncovered edges. Do not prorate a counter across a boundary or convert missing observations to zero. Report on-CPU and runqueue counters independently; neither sampled residency nor native syscall elapsed time is CPU time.
3. Preserve the previous conservative GC envelopes and every pairing error. A GC start/end lifetime is not an execution-engine suspension. If a supplementary pairing is studied, keep it separately named and reject malformed/ambiguous/cross-identity transitions. Public documentation and exact source availability must be recorded; current upstream code cannot stand in for the installed runtime revision. Incomplete GC channels prevent an exclusive GC-versus-scheduler percentage or a conclusion that an uncovered interval was GC-free.
4. Do not add overlapping dimensions or subtract them from wall time to manufacture exclusive causes. Do not infer scheduling delay from cumulative counters without accounting for when the kernel credits them. Explicitly inspect whether the retained sampling brackets can support the intended attribution; fail closed if not.
5. Test boundary containment, TID reuse, counter resets, missing observations, malformed/ambiguous GC episodes, cumulative-credit ambiguity and overlap accounting with synthetic fixtures. Independently review source and replay invariants. Hash consumed source evidence and outputs; retain failed analysis attempts.

## Delivery boundary

Publish a reproducible bounded report and machine-readable evidence, including negative or insufficient-evidence outcomes. Root is the sole remote writer. Engine #20 body may record the result through the reviewed two-way sync; preserve its full metadata/dependencies, Planned test/benchmark gates, P2/M0 and null actual/remaining hours. Preserve #3's entire row. Docs/Samples commits are technical provenance, while task commit journals contain Engine SHAs only. No provider, supported-Windows, dedicated reference, production or release acceptance follows from this diagnosis.

## References

- [ADR0019](ADR-0019-tooling-same-process-wait-traces.md) and [previous report](../planning/tooling-waits.md).
- Linux kernel [scheduler statistics](https://www.kernel.org/doc/html/latest/scheduler/sched-stats.html): cumulative counters require deltas; per-task fields describe running time, runqueue waiting and timeslices.
- Microsoft [.NET GC event contract](https://learn.microsoft.com/en-us/dotnet/fundamentals/diagnostics/runtime-garbage-collection-events): collection and execution-engine suspension/restart events are separate.
