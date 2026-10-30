# Same-execution wait diagnostic interpretation

Scope: final complete `tooling-wait-combined-linux02` only, Engine55 unchanged. This report does not combine clocks/events from the earlier separate runtime/native executions. The failed partial combined01 remains separate. No live target, build, collector, benchmark or product edit was performed by this interpretation.

The new offline interpretation succeeded on its first execution and retains all306 compiler rows, all18 size/state/variant groups and all24 CLI cases (eight scenarios in each of three rounds). The source and every derived JSON remain in this directory. Descriptive traced CVs and launch-to-exit durations are not accepted as the original benchmark or a performance comparison.

## Caller observations

Generator capture:466 WaitHandle starts,465 stops,465 accepted complete pairs and one unfinished background-TID851 start. Target/caller TID754 is distinct. No observed reused native TID was promoted. EventPipe/ETLX loss and payload read errors are zero. GC pairing remains highly incomplete:1,637 EE pairing errors and23 paired GC-related envelopes. All306 rows have conditionally supported strict UTC models; that still assumes no hidden wall-clock excursion between retained anchors. Kernel event loss remains unknown.

Across270 measured compiler rows (36 primers retained separately), summed compiler wall is93,019.972ms. This is a heavily instrumented diagnostic duration. Bounds below are summed across these non-overlapping rows, with physically capped unions within each row:

| Observed dimension | Positive measured rows | Summed overlap ms | Fraction of summed measured wall |
|---|---:|---:|---:|
| Caller managed WaitHandle pairs |76|19,400.635–19,400.635|20.856%–20.856%|
| Caller eligible native syscall intervals |270|30,984.475–30,999.991|33.309%–33.326%|
| Paired GC suspension envelopes |13|321.309–321.309|0.345%–0.345%|

These dimensions overlap. Do not add them or subtract them from wall time to derive CPU, exclusive blocked time or causes. In particular, incomplete GC pairing prevents interpreting zero paired overlap as no GC.

All19,400.635ms of observed measured caller managed waits fall within PE Emit stages. There is zero paired caller managed-wait overlap in the135 measured RunGenerators stages. Aggregate stage durations are1,743.339ms RunGenerators and91,276.236ms Emit. During observed completed caller waits within measured stages,288 caller managed residency samples contain Compilation.Emit, Task.InternalWait, ManualResetEventSlim.Wait and WaitHandle.WaitOneNoCheck;283 contain MethodCompiler.WaitForWorkers. These locate observed wait context in Roslyn Emit. They do not identify a physical lock owner, worker starvation cause, OS on-CPU activity or an avoidable Engine action.

For example, size32/edit/manual pair3 has3,528.855ms wall,2,762.945ms caller managed wait and2,851.971–2,852.079ms caller native interval overlap. Size32/noop/manual pair5 has3,483.642ms wall,2,541.239ms caller managed wait and2,548.086–2,548.128ms native overlap. Size32/edit/generator pair12 has2,344.868ms wall,1,896.235ms managed wait and1,899.344ms native lower bound. These are illustrative rows; all270 measurements and36 primers remain included.

Native per-row associations comprise2,586 same-caller-TID and15,328 other-TID possible call overlaps across measured rows; counts can repeat an event crossing row boundaries and are not unique-event totals. All are also positive-core associations under outward-rounded saved offset bounds in this dataset. Background/idle thread activity cannot establish caller stall.

The existing field `same_tid_managed_wait_native_observed_overlap` matches each managed pair with native intervals on that pair's TID across the whole process. Its88.36% aggregate overlap is NOT caller-only. Report it as process-wide matched-TID co-observation, never as88% caller wait or a proven correspondence between a particular managed wait and futex.

## All CLI scenarios and rounds

All24 CLI traces completed offline interpretation. Eighteen have zero observed managed WaitHandle pairs and no wait pairing errors. Each of six enabled GraphQL exports has one complete main-TID pair,9–10 other-TID pairs and one unfinished background start. All24 report zero EventPipe loss. The six enabled cases retain partial dimensions; their GC pairing errors are5 each except one case7. The other18 have no such wait errors. CLI has lifetime observations only: there are no precise marker-based cross-stream startup joins, and launch coordination is not benchmark startup.

Independent managed-stack/JIT inspection of the same new24 CLI traces finds3,744 HotChocolate JIT intervals and166 schema/executor-name-category intervals in each enabled GraphQL export. Observed HotChocolate residency samples range1,433–1,470. None was observed in the other18 traces. API-only/both exports show the expected two JSON-schema-name JIT intervals. This agrees with source guards and selected offline schema construction, rather than identifying disabled module work. Counts/samples are not CPU cost and absence of a sampled/JIT event is not a universal absence guarantee.

## Product decision

No safe, avoidable Engine work was isolated. The same-execution evidence strengthens the location of observed caller waits in Roslyn Emit and distinguishes background activity, while remaining perturbed and incomplete. It does not justify disabling compiler concurrency, tiering or GC; removing selected schema work; weakening durable publication; or changing canonical clocks, primers or workload. Keep Engine55 unchanged, #3 Blocked and performance Observed/not_qualified. No additional unchanged-source benchmark is implied by this diagnostic interpretation.

## Artifact index

- `interpret_combined_waits.py`: full25case interpretation source; syntax check passed before execution.
- `combined-linux02-interpretation01.json`: all306rows,18groups,24CLI summaries and quality flags.
- `interpret_wait_stage_context.py` / `combined-linux02-wait-stage-context01.json`: complete measured Emit/RunGenerators stage context and caller residency samples.
- `analyze_cli_residency.py` / `combined-linux02-cli-runtime-context01.json`: all24 same-execution CLI JIT/stack evidence.
- Matching `.log` files retain original tool output. Earlier PE metadata/EE hypothesis files are separate and not used to promote new GC pairings.
