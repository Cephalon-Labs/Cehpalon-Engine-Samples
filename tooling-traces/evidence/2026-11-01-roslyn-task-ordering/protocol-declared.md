# ADR0024 - Literal Roslyn task event ordering

Date: 2026-11-01. Status: accepted bounded offline analysis under Engine #20; #3 remains Blocked.

## Fixed scope before replay

Reanalyse the complete retained ADR0023 execution only, with its frozen full306row/2956span lineage output,19527executioneventhistories and2372pairedwaits. No builds, target launches, captures, benchmark, Engine changes, permissions or host configuration. Retain all prior raw and analysis attempts, including unknown/partial/malformed records. No filtering toward favorable outcomes.

Bind every task schedule/start/completion and wait begin/end model reference to the exact raw event at its zero-based index with strict type/identity/payload equality. Verify pinned assembler/lineage source hashes, all consumed input/output hashes and same-process capture identity. Hash and retain source/evidence; do not duplicate the prior full raw capsule unnecessarily.

## Analysis declared before counts

For every retained paired wait classify literal recorded timestamp relations: schedule vs waitbegin, execution-start event vs waitbegin, execution-completion event vs waitbegin, and execution-completion event vs waitend. Use exact decimal-derived rational values from retained EventPipe milliseconds. Before/after/equal timestamp are separate categories. Equal timestamps remain order-unresolved; raw record index or TID is not a timing tie-break. Reject malformed identities/nonfinite/negative clocks and retain incomplete/poisoned/missing execution context as unknown.

Keep all2372waits including nonmain/outside-selected-Emit observations; report all306Emit rows and all2177rowwaitassociations. Preserve prior boundary/nested/native-lifetime/callsite unknowns and candidate sets. Separate measured270rows and36primers; provide allwait totals and clearly named nested method-context subsets rather than select only good witnesses. Distinct waits/rows and repeated associations must be explicit.

These are telemetry event-order categories, not task-state, queue residence, blocked time, firstCPU, runnable/runqueue delay, work progress or GCpause attribution. Completion-event-before-WaitBegin and WaitEnd-before-completion-event are legal under source races/emission semantics; do not reject them merely for that ordering. Already-completed tasks may emit no wait, so observed waits do not describe all joins. No exclusive GC/scheduler share, speedup, qualification or Engine patch follows.

Validate with adversarial portable fixtures (including ties, latercompletion, inline, missing/ambiguous execution, type/identity/reference/hash drift, duplicate/reused IDs) plus an independent full raw-event/reference/order audit. Predeclare corrections before any new complete analysis interpretation; never overwrite attempts. Root is sole remote writer. Sync #20 body only through reviewedplan/readback; preserve #3 entire row, all metadata/dependencies/estimates/Plannedgates/nullhours.
