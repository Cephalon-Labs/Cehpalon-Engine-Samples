# Retained runtime diagnostic observations

Scope: Engine55c630fc5d4c47258a1a2b0da4a16ce8bc42b9f7; completed Windows runtime02 and Linux runtime01. No product code changed. The traces are perturbed diagnostics, not canonical benchmark acceptance. No launch-to-exit timing is used because startup suspension/coordination is included.

## Generator and compiler

Both traces contain all 2,956 spans and all 306 main compiler rows (36 primers and 270 measurements). Marker mapping is bounded/consistent; loss and payload errors are zero. Windows has 40,916 paired JIT intervals and 87 paired GC-related suspension envelopes; Linux has 41,532 and 77. Pairing is deliberately incomplete: Windows 9 EE errors plus one unfinished Roslyn JIT start; Linux 105 EE errors. These are not perfect absence proofs.

The main measured compiler rows spend an aggregate 631.438 ms / 449.090 ms in RunGenerators and 7,189.789 ms / 6,226.028 ms in PE Emit (Windows/Linux). These aggregate sums describe this traced matrix, not standalone generator or user startup costs. They include both manual and generated emit rows, with RunGenerators only in the generated half. The cold seed/cache preflight is excluded from these sums.

Windows diagnostic group CVs above 15%: size1 fresh generator 32.778%, size1 fresh manual 38.948%, size32 edit manual 15.508%, size32 fresh manual 19.222%, size32 noop generator 18.623%. Linux: size32 edit manual 20.889%, size32 fresh generator 17.045%, size32 fresh manual 19.398%. All values and rows are retained. These are traced descriptive CVs, not the original acceptance series.

Representative slow rows:

| Host / size / state / variant / pair | Compiler wall ms | RunGenerators / Emit ms | Narrow fully-suspended GC overlap ms |
|---|---:|---:|---:|
| Windows / 1 / fresh / generator / 14 | 40.946 | 4.242 / 36.703 | 0 paired |
| Windows / 1 / fresh / manual / 14 | 39.421 | — / 39.420 | 0 paired |
| Windows / 32 / fresh / manual / 3 | 96.725 | — / 96.725 | 33.367 |
| Windows / 32 / noop / generator / 6 | 54.740 | 0.267 / 54.472 | 20.615 |
| Linux / 32 / fresh / generator / 6 | 66.994 | 11.525 / 55.469 | 23.522 |
| Linux / 32 / fresh / manual / 3 | 53.650 | — / 53.650 | 16.907 |

The Windows size1 fresh slow rows include no paired GC or same-caller JIT interval. Some have background JIT overlap and others do not. Thus neither GC nor JIT explains every slow row. Size32 rows show substantial actual narrow GC-suspended overlap in both manual and generated variants. Background JIT commonly overlaps almost the whole compiler wall, but that measures elapsed background compilation and does not establish a caller stall.

Windows' two ambiguous EE episodes involve reasons0/0 and0/2, outside all measured compiler rows. Linux has21 ambiguous episodes, ten involving GC/GCPrep;13 measured rows intersect an ambiguous episode window. The latter windows only flag uncertainty; they are not promoted to pause durations. Paired-GC zero in a Linux row cannot establish absence of GC there.

Managed samples on the compiler caller contain Compilation.Emit (633/690 Windows,4692/5065 Linux sampled observations associated with measured compiler rows) and MethodCompiler.WaitForWorkers / task waits. These are inclusive managed thread residency observations, including waiting, not CPU hotspot percentages. Native scheduling/IO evidence is separate. The data locates much observed variance in Roslyn Emit/wait/GC work shared by manual and generated paths; it does not isolate an avoidable Engine operation.

## All CLI scenarios and rounds

Inspected all24 CLI traces per host: eight scenarios in each of three rounds. All48 have zero event loss and payload errors; all sampled-stack extractions completed. Total lane EE errors39 Windows /135 Linux include generator errors above. Each of the six enabled GraphQL CLI exports per host has five EE ambiguity records involving a GC start plus another suspension, so its zero paired GC envelope count is not a zero-pause claim.

In every enabled export-both/export-graphql trace,3,744 paired JIT intervals identify HotChocolate methods, including166 in the explicit schema/executor-name category. Observed stacks include RequestExecutorManager.GetExecutorAsync, CreateRequestExecutorAsync, CreateSchemaServicesAsync, CreateSchemaAsync, and SchemaBuilder.Create. HotChocolate stack observations are205–210 (Windows) and400–424 (Linux), with differing sampler/host coverage, not comparable CPU costs.

Across the36 other scenario traces (new, validate, API-only export and export-off), no HotChocolate JIT interval or managed sampled stack was observed. API-only/both exports each show two JsonSchemaExporter/ExportJsonSchema-name JIT intervals; GraphQL-only/off do not. This agrees with source branch guards: ContractExport.cs.txt lines82–84 invoke GraphQLSchema only when enabled; lines106–121 explicitly register/dispose the offline schema provider and resolve the executor. It is expected contract-export work, not evidence of disabled GraphQL activation.

## Product decision

No justified Engine optimization patch was isolated. Removing schema construction, changing Roslyn concurrency, suppressing GC/JIT, or altering the fixed workload would change behavior/protocol without causal evidence. Keep Engine55 unchanged and run the full original untraced Windows→Linux benchmark. Retain diagnostic imperfections and report observed/not-qualified status independently from correctness checks. #3 remains Blocked.

## Retained analysis artifacts

- Source: analyze_runtime_stages.py, enrich_runtime_attribution.py, analyze_cli_residency.py in this directory. They perform offline reads only and never execute targets or collect traces.
- Full stage JSON: runtime-win02-stage-analysis.json and runtime-linux01-stage-analysis.json.
- Enriched row/stage/uncertainty JSON: runtime-win02-stage-attribution.json and runtime-linux01-stage-attribution.json.
- All48 CLI case evidence: runtime-win02-cli-analysis.json and runtime-linux01-cli-analysis.json.
- Parser replay build: trace-analysis-replay01 (locked Release zero warnings/errors), successful frozen conformance03 replay02. Final parser worktree Program SHA2959bc5a121493f4879aa5415e5e62de1df96826e291e1d0def2904e67d4962f. Primary differs intentionally for the parent's corrected default-port ACK label.

Limitations: source string/UTF8 preparation, logger bookkeeping and final persistence remain unassigned gaps; hash spans measure SHA/hex bodies only. GC envelopes include rendezvous/restart; the narrower interval is separately reported. JIT start-to-load is elapsed, not CPU work; sample profiler is not native scheduler evidence. No traced timing is used for canonical acceptance.
