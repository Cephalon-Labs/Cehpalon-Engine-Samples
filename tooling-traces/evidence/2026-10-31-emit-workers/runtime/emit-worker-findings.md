# Emit worker and GC evidence from the retained execution

ADR0020 scope, 2026-10-31: reanalyse only the complete combined-linux02 generator. Engine55 is unchanged; no target, build, capture, compiler/GC setting change or original benchmark ran in this wave. The result identifies compiler-context observations and a material GC-model limitation. It does not determine an exclusive GC-versus-scheduler cause or justify an Engine patch.

## Direct compiler-context observations

The reusable tool is `tools/analyze_tooling_emit_workers.py`, final SHA256 `4738c34d631b637af6f31bcb1eba4c0b73f7ce9bced8d38d0bc25f1c074506cc`. Final output is `emit-worker-context03`. It streams all505,810 raw EventPipe records and107,929 managed stack records, validates all2,956 ordered marker/sidecar identities, and retains all306 Emit rows:36 primers and270 measurements.

The frozen worker predicate requires a noncaller native TID with both the exact `Microsoft.CodeAnalysis.CSharp.MethodCompiler+...<CompileNamedTypeAsync>b__...` frame and a ThreadPool frame. It finds8,195 compiler-context points on22 native TIDs over the whole execution. Completion-only context is separate (851 points); caller WaitForWorkers context is separate (2,540 points). These whole-execution totals include preflight/seed/postflight work and are not measured-row counts.

The NuGet4.14.0 pin identifies Roslyn commit8edf7bcd4f1594c3d68a6a567469f41dbd33dd1b. Its [MethodCompiler source](https://github.com/dotnet/roslyn/blob/8edf7bcd4f1594c3d68a6a567469f41dbd33dd1b/src/Compilers/CSharp/Portable/Compiler/MethodCompiler.cs#L296) shows WaitForWorkers awaiting popped tasks and CompileNamedTypeAsync scheduling Task.Run work. Retained content SHA256 is7364b87146219a8b63a8916f58feee1ba6a3ea1943f52e22614268407e6f1a8a. This supports the frame predicate. No captured TaskID establishes which sampled worker satisfies a particular awaited task.

| Measured query scope | Queries | With strict compiler point witness | Without witness: unknown | Distinct compiler points |
|---|---:|---:|---:|---:|
| Emit |270|242|28|3,219|
| Caller wait with a WaitForWorkers point inside Emit |67|53|14|1,993|

The67 selected waits belong to63 distinct measured Emit spans. All80 measured completed caller-wait/Emit intersections remain retained;13 lack a caller WaitForWorkers point and keep unknown context. The full output has306 Emit plus73 selected wait queries including primers. Across these379 queries,5,390 point-query associations reference only3,357 distinct points;2,033 associations repeat points across scopes.

Each query admits a TID only through a whole point-uncertainty interval inside its guaranteed core, with observed unique proc birth/owned lifecycle and no observed TID reuse. All matching raw stack record indices and deduplicated frames remain. A witness is a point/window observation, not permanent ownership of a ThreadPool thread, CPU time, runnable state, task lineage or starvation. Absence of a sample is not absence of worker activity. Scheduler counter interpretation is a separate tool and must retain kernel cumulative-credit limits.

## GC model limitation is substantive

The legacy analyzer's23 GC-labelled envelopes and1,637 EE errors remain immutable. Raw phase counts are12,147 each for SuspendStart, SuspendStop, RestartStart and RestartStop. SuspendStart reason counts:12,024 Other,73 GC,10 GCPrep and40 AppDomain-shutdown labels. These are suspension episodes, not83 distinct collections.

Legacy EE errors comprise308 repeated starts,303 ambiguous episodes not promoted,325 suspend stops without unique starts,331 restart starts without unique suspensions,62 incomplete inner-phase envelopes and308 restart stops without starts. The separate unfinished JIT start is not counted in1,637. Sixty-two unique GC-labelled starts appear in these errors; the problem affects GC specifically.

Strict same-PID/CLR/initiator-header-TID four-phase sequencing yields83 GC-labelled hypotheses. Twenty-one agree with every legacy phase timestamp. Sixty starts are absent from the legacy23 set, and two legacy envelopes disagree at RestartStart/end. All62 nonmatching candidates have another initiator start within their envelope. This is co-observation, not a proven explanation of runtime behavior. The17 GC initiator TIDs have observed unique birth/lifecycle coverage, but that does not establish the runtime pairing contract or identify the workers paused.

The installed runtime reports commit5254d8bcf59917edc1e1abc33bdf2442b77b1c70. Its exact official threadsuspend.cpp URL still returns404; that result and official source provenance are retained. [Public GC event documentation](https://learn.microsoft.com/en-us/dotnet/fundamentals/diagnostics/runtime-garbage-collection-events) distinguishes collection and EE suspension phases, but does not establish a version-specific same-initiator pairing contract. Neither the legacy nor supplementary model is certified pause truth.

The disputed records are precise:

- GCPrep: start8182/TID811 at7797.357258ms; SuspendStop8185/TID811 at7798.818823ms. Legacy end8186/TID779 is7799.737490ms with missing RestartStart. Same-initiator hypothesis has RestartStart8188/TID811 at7800.265230ms and end8190/TID811 at7809.088924ms,9.351434ms later. This precedes all306 retained main rows.
- GC: start287711/TID754 at142352.541406ms; SuspendStop287712/TID754 at142353.570106ms. Legacy end287714/TID779 is142355.716060ms with missing RestartStart. Same-initiator hypothesis has RestartStart287763/TID754 at142371.142912ms and end287765/TID754 at142374.773140ms,19.057080ms later. It intersects size32/fresh/manual pair11: legacy envelope3.174654ms versus hypothesis22.231734ms. Neither endpoint choice is certified.

Measured compiler-wall overlap, with unions physically capped and all270 rows retained:

| Interval model, all uncertified | Envelope overlap ms | Inner four-phase interval ms | Positive measured rows |
|---|---:|---:|---:|
| Legacy23 previous-analyzer model |321.309097|—|13|
| Legacy21 with all four phases agreeing |318.134443|277.024083|12|
| Two disputed legacy envelopes |3.174654|unknown|1|
| All83 same-initiator hypotheses |2,387.723305|1,326.603070|50|

During80 measured caller-wait/Emit intersections, legacy/21 envelope overlap is18.600719ms (inner14.849256ms) in one intersection. The83-hypothesis envelope overlap is391.252653ms (inner157.233763ms) in seven. These numbers are separate model observations, not interchangeable pause measurements or total GC. Incomplete channels and disputed boundaries prevent subtracting either model from wall/wait time to infer a GC-free remainder or scheduler percentage.

## Validation and retained attempts

Final tool20 focused synthetic guards passed: exact vendor predicate negatives, duplicate/orphan/out-of-order/incomplete EE sequences, cross-identity refusal, physical overlap caps/overlapping unions, ordered clock mapping, wholly-inside versus boundary witnesses and invalid intersections. Independent final raw recount passed294,835 checks and confirmed point/query payloads and21all-phase agreements. No reported EventPipe loss is distinct from this incomplete attribution.

Context01 (source8128449...) remains retained. Context02/03 add physical caps, exact sidecar sequence gates, explicit UTF8/LF output and disputed legacy-GC qualification. Replays are offline preparation corrections, not new workload attempts or favorable timing selection. Selftest01–04 logs and each context's exact source snapshot remain.

Artifact index under this worktree's `.local`:

- `emit-worker-context03/`: final source snapshot, input/output hashes, frame catalogue, raw point references, all306 rows,379 scheduler queries, caller intersections and nonauthoritative EE candidates/rejections. Context01/02 remain separately.
- `emit-worker-selftest01.log` through `emit-worker-selftest04.log`:12 initial then20 final guards; no SDK build.
- `emit-worker-context-aggregate04.json` and `aggregate_emit_worker_context.py`: distinct-point versus repeated-association summaries.
- `emit-gc-gaps04/`: legacy error distribution/raw frame indices, every four-phase comparison, both disputed boundaries and separate overlaps for all queries. Gaps01–03 and their source snapshots remain.
- `emit-worker-research-sources01/`: pinned Roslyn source/nuspec, public GC documentation and exact-runtime404 provenance with hashes.
- `emit-worker-bound-manifest01.json`: complete consumed-input and final-output hashes, added to bind the supplementary study without changing its reports.
- `emit-worker-delivery-results01.json`: concise machine-readable handoff for Docs.

No safe avoidable Engine work was isolated. Stronger causal evidence would require a separately declared same-execution task-to-worker link, an exact runtime suspension contract, and scheduler events with known credit/loss semantics. Those are future evidence needs; none was captured in this wave. Keep Engine55, #3 Blocked and Observed/not_qualified status. Do not change concurrency, GC, publication or the original benchmark to manufacture a result.
