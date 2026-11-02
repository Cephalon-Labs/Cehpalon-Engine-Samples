# Independent scheduler evidence boundary and next conformance gates

2026-11-02. Read-only review of the current handoff, ADR0026 and retained ordinary/root inventory; no new host command, target, build or capture by reviewer. Root owns integration and remote writes.

## What the existing evidence can and cannot decide

ADR0023-25 provide exact task/header lifetimes, literal event-order relations and sampled method contexts. The latest strict global query scope has samples in681/2372 waits, while1691 have no strict sample. Measured row scope has points in547/1913 associations and1366 unknown. These are separate denominators and labels overlap. Neither a compiler frame nor absence of a wait frame establishes useful progress, CPU, physical blocking, runqueue delay or GC cause. Recounting these points cannot supply scheduler transitions.

A sched_switch/wakeup stream would add guest scheduling-state observations, but still would not prove physical CPU work or an exclusive GC cause. A thread switched out runnable can remain eligible without a new wakeup; a nonrunnable switch-out requires a later successful wakeup/state edge before assigning a runnable interval. Waking is not interchangeable with wakeup. State R+ is a preemption form, not simply nonzero=blocked. Use the exact live field/print contract and source correspondence, not generic integer heuristics. Switch-in/out delimit recorded guest scheduling observations, not first instruction, useful work, host-vCPU scheduling or native progress.

Existing GC events identify process coordination phases and emitter TIDs, not the paused-worker identity or a physical scheduling cause. Same-execution source-qualified GC/task/kernel streams and bounded clock/identity joins would allow nonexclusive overlap observations. They do not justify subtracting one dimension from another to manufacture an exclusive GC/scheduler percentage.

## Reviewed host readiness

The retained inventory records40 commands. Ordinary UID1000 has no effective/permitted/ambient capabilities and cannot read the eight requested event formats. Existing one-shot WSL root invocation reads all eight formats successfully, while leaving settings untouched. Current root readability is a candidate for a separately declared collector; it is not perf_event_open/filter/event-delivery/loss/clock conformance. Root collector identity must remain separate from the ordinary target identity.

Existing tracefs clock is local. Do not assume that supports cross-CPU chronology or change global trace_clock as a shortcut. A candidate per-session perf collector should request and verify CLOCK_MONOTONIC on every event FD/CPU, retaining actual attributes and independent target anchors. Every denied/missing/unavailable channel remains a failed or unknown gate, including where tool help or readable formats exist.

## Minimal bounded collector proposal

Start with a declared static setS of positive native TIDs in one owned ordinary-user synthetic process, not the production/generator workload. Bind each TID to observed process/image/starttime/boot scope at a start barrier; do not make an unobserved birth or reuse claim. Root opens only the scoped collector; target credentials/capabilities and source remain ordinary and are checked independently. No chmod, mount, sysctl, persistent capabilities, tracefs global enable/filter/clock or unrestricted host recording is part of this proposal.

Payload filters must retain both sides of switch (prev_pid or next_pid), target pid for waking/wakeup/new/migrate/exit/free, and either parent_pid or child_pid for fork. common_pid identifies emission context, which can be an unowned waker or previous task; it cannot substitute for payload filtering. A per-target thread/perf -t session alone cannot establish complete switch-in or external-wakeup coverage. Evaluate the exact filter truth table against owned/unowned/counterparty fixtures before collection.

Capture all relevant CPUs with per-event payload filters forS. Unknown/unlisted child TIDs remain out of scope; fork notification does not automatically expand eligibility because other filters would omit that child. Unexpected eligible growth, reuse, filter/ABI drift or partial CPU coverage rejects the fixed lane. Record only requested scheduler/lifecycle fields; disclose unavoidable counterparty PID/comm/priority and emitter metadata in retained matching events. Do not assign counterparty ownership or causality. Default synthetic mmap/comm/build-ID/process inventory needs separate suppression/verification; event filters alone do not constrain every sideband record.

## Fail-closed gates before a later workload

1. Freeze versions, exact format bytes/eventIDs/fields/offsets/sizes, filter expressions, static population/leases, buffer/non-overwrite mode, clocks, active deadline, source and cleanup. Planning-only compiler output must always say capture_ready=false.
2. Actually open every required eventFD, apply/read back its filter and clock attributes, arm all CPUs, then acknowledge readiness before releasing an owned target barrier. File readability and a live perf process are insufficient.
3. Use a separately declared synthetic sequence covering positive running/preempt-runnable-out, sleep/nonrunnable wakeup, migration and lifecycle cases. Keep all cases and failures even if a requested positive event is absent. No successful native state inference from managed marker entry alone.
4. Preserve per-CPU raw records, timestamps, sample IDs, loss/lost-sample records, overrun metadata, errors and drain/stop counts. Unknown loss accounting is not zero; overwrite mode is unsuitable. Zero reported loss still needs positive case/coverage checks.
5. Validate stable native generations, CPU transitions, wakeup/switch state interpretation and complete event adjacency. Prefix/suffix unknown states, duplicate/reordered/tied cross-CPU times, missing wakeup, migration gaps, unexpected child/reuse and lost records reject phase attribution; no boundary prorating.
6. Map native CLOCK_MONOTONIC and EventPipe/Stopwatch using explicit bracketed same-execution anchors and drift bounds. Do not fuse separate runs or assume Python/managed/perf clocks identical.
7. Join every owned target/thread/collector at a fixed stop deadline and verify only owned cleanup. Keep collector privilege and output ownership auditable. A future fixed workload lane is a separate declaration after this conformance, with unchanged original benchmark/GC/compiler settings.

## Decision

GO for a planning-only filter/ABI compiler and portable adverse fixtures. NO current active capture or causal/performance qualification follows. Concrete missing gates are actual scoped event delivery, filter application, static lease/state coverage, losses, clock joins, cleanup and perturbation. GC applicability/build/binary evidence remains separate. #3 stays Blocked and original benchmark gates remain unchanged.

Primary sources reviewed: matching-name WSL [scheduler event source](https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.18.54.1/include/trace/events/sched.h), [perf security](https://docs.kernel.org/admin-guide/perf-security.html), [event formats/filters](https://www.kernel.org/doc/html/latest/trace/events.html). Tag/release correspondence is not installed-binary attestation.
