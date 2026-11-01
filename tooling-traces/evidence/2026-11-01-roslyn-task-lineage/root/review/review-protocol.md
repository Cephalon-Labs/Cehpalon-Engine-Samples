# Independent Roslyn task-lineage review protocol

Read-only source/fixture/raw replay; no builds, targets/captures, host settings or remote writes. Root is sole integrator. Respect shared skill and the predeclared ADR0023 when available.

Proof levels remain separate: TPL caller wait identity; task execution event lifetime and native TID; exact compiler-worker stack point co-observation; caller WaitForWorkers stack point co-observation; row/stage timing containment conditional on same-capture clock intersection. No exclusive task ownership, blocked/CPU/runqueue duration, GC share, starvation or production inference from overlap alone.

Adverse cases: all raw loss/read/source-capture identity/target completion gates; complete marker/sidecar identity and clock-bracket intersection; integer/native TIDs distinct from PID/process generation; source TaskID destination vs ambient scheduler contexts; zero/alias/duplicate/reused/malformed/out-of-order/unfinished tasks and waits; only synchronous caller waits; wait and worker point uncertainty fully inside supported guaranteed query cores; no boundary prorating or missing=>zero. Keep noncaller waits separate.

Overlapping/nested caller TPL wait brackets can all contain a WaitForWorkers ancestor frame. Overlapping/nested execution event lifetimes on one native TID can all contain a compiler frame. Preserve candidate counts and ambiguous contexts; do not equate every containing lifetime with unique direct owner. A complete event lifecycle is not logical completion with attached child tasks. Complete-before-wait and canceled-before-start paths can have absent events.

Independent raw replay should audit the full declared lane/row/span counts, exact marker parity and conditional clock geometry, every selected caller wait/task identity, compiler and WaitForWorkers point frame predicates, unique sample indices vs query associations, nested candidate identities and all unknown/rejection counts. Reference full input/source hashes and preserve failed audit attempts.
