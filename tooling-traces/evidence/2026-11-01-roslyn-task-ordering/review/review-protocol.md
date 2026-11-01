# Independent literal TPL ordering review protocol

ADR0024 bounded offline analysis of the full same ADR0023 execution. No target/build/capture/benchmark/remote writes or primary edits by reviewer. Root sole integrator. Read canonical shared skill, current memory and ADR0024 once declared.

Primary proof is literal event timestamp relation: strictly before, strictly after, equal timestamp unknown ordering. Never use raw file-record index to invent chronology for equal timestamps, especially across native threads. Preserve raw record references only as identities. Missing/malformed/reused/poisoned/lossy references remain rejected/unknown.

Schedule destination scheduler differs from ambient execution/wait contexts. TaskCompleted marks execution-exit telemetry, not unconditional logical task completion or the instant a waiter becomes runnable. TaskStart may occur before/inside/after a caller wait event bracket; none implies CPU, blocked time, runqueue delay, GC cause or overhead. Schedule-to-start is event spacing, not scheduler latency. No exclusive partition of wall time.

Review precise process/task/native identity, actual metadata/version and immutable raw-reference bindings, type/alias/negative/foreign-PID/duplicate/reuse/missing/out-of-order gates. Preserve every306row and all2177 row-wait associations from prior same-execution lineage; no favorable subset or stitching. Check each row/wait/task identity and all output class/group counts against independently read raw events.

Portable fixtures should test before/after/equal-time relations, equal-time distinct record ordering, impossible timestamp histories, incomplete states, wrong task/PID/TID/reference indices/versions, numeric aliases, foreign/reused/poisoned identities, nested and partial-row observations without causal promotion. Independent raw audit must consume the complete chosen input and compare identity sets and literal classes, not only aggregate counts.
