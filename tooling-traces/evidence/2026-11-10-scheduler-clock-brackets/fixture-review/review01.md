# Bounded gettid clock-bracket fixture review

Read-only design review, 2026-11-10. Shared skill and latest Nov10 handoff read. No actor, kernel attachment, build, global change, remote mutation or shared source edit performed by this reviewer.

## Minimal practical lane

Use the existing raw sys_enter allowlist and a single program filtered to x86-64 gettid syscall186. Reuse Program.current_storage, typed current-task storage and fresh pidfd seeding for one still-live ordinary UID/GID1000 single-threaded actor. An exact cookie read before any emitted row authenticates the owned task; no raw task-pointer read or process-wide scheduler subscription is needed. Label early and late timestamps as post-ownership callback-body begin/end, not syscall exit or physical switch. A sys_exit hook is unnecessary for this smallest lane and would require an explicit allowlist extension plus active-syscall state to avoid pairing exits of clock reference syscalls.

The actor explicitly invokes libc.syscall(SYS_clock_gettime=228,CLOCK_MONOTONIC=1, timespec) before gettid and again after. Do not call libc.clock_gettime or Python time.clock_gettime_ns for the reference, since those may use a vDSO. Validate every raw return and timespec nanosecond range; retain each exact integer reference, returned local TID, phase CPU and syscall ordinal. Pin affinity before brackets. Raw gettid return must match the held actor PID. Python orchestration overhead widens the bracket, which is honest and makes no latency microbenchmark claim.

One BPF invocation may obtain helper5 begin, helper8 begin CPU, reserve a unique slot, publish metadata, then helper8 end CPU and helper5 end before storing the final timestamp. Record the exact order in frozen bytecode. The begin timestamp intentionally excludes ownership lookup when sampled after that guard. If it is instead sampled before ownership, label the broader interval and keep nonmember output suppressed. There is no need for a new kernel kfunc or typed context-switch probe merely to observe these bracketing controls.

## Fixed ordered matrix

Freeze one capacity-negative case and one fresh positive case, with no adaptive repetition. Suggested negative: capacity1, exactly2 owned gettid brackets on CPU0, require attempted2/retained1/lost1/faults0. Suggested positive: capacity128, exactly64 brackets,32 on CPU0 followed by32 on CPU1, require64 unique records and no reported loss/fault/misses. This is a two-CPU execution-scope observation, not proof of simultaneous cross-CPU time consistency. If the intended claim needs controlled cross-CPU handoffs, declare that separately rather than inferring it from sequential phase migration.

In each fresh case attach while the held task is unseeded: an owned unseeded gettid, root nonmember gettid and owned wrong-syscall getpid must leave attempted/lost/fault counters zero. Then seed the owner via its live pidfd, confirm through independently opened alias, perform the declared exact pairs, and keep the same live owner lease until detach. A row emitted after seeding is the hook acknowledgement. No child or replacement TID is admitted.

Resource proposal: one BTF FD, one task-storage map, one counters map, one fixed record array, one program, one raw link and three pidfds(owner,alias,collector nonmember)=9 native FDs per case, with actor pipes tracked separately. Map sizes/capacity, verifier-log cap,64pair count, CPUs0/1, per-command5s, case30s and outer90s can be frozen before load. Do not change kernel permissions, sysctl, global affinity or install tools. Verify pinned kernel/BTF and existing actor Python bytes.

## Gates and interpretation

After the complete declared positive run, detach first; require stable terminal counters, full ledger and repeated detached hash/count read, zero unused slots, unique contiguous ordinals, exact target return and control counts, expected CPU snapshots, zero recursion misses and all9 native descriptors closed. Delete/read task storage only while lease is verified; after actor reap require map absence where the existing API permits it. Kill/reap only the exact owned actor on failure and preserve raw source, failure and partial records.

Reference brackets must have before<=after and fully formed syscall results. For each recorded fast timestamp F and surrounding references L/U, report numeric containment and the conditional error interval[F-U,F-L]. The actual callback point lies somewhere within the reference call boundaries under the verified source/identity order. A finite observed hull of these intervals is descriptive for this execution. It is not a transferable upper bound for fast-clock error or universal monotonicity. Even zero overshoots or begin/end reversals in64cases cannot certify Roslyn's historical event timestamps.

Keep all pairs if one timing containment check fails, provided ownership/resources remain sound; evaluate the fixed complete artifact rather than selecting passing rows. Structural ownership/loss failures stop dependent claims. Do not use the maximum observed overshoot as a new acceptance threshold. Do not subtract callback-body span from scheduler durations or promote a sys_enter sample to physical dispatch/off-CPU time.

## Meaningful offline tests

Reject wrong syscall, nonmember/unseeded emission, reused lease, duplicate/missing/reordered ordinal, noninteger fields, bad timespec, wrong local return, impossible CPU phase, capacity overrun, nonzero unused slots, counter/hash mismatch, recursion misses and cleanup failure. Include negative timestamps or reversed L/U references, fast timestamps below/above bracket and reversed body timestamps as retained negative timing outcomes. Preserve the exact error-interval calculation with integer nanoseconds and no float rounding. Test source/template relocation only at declared live FDs.

## Limits for current Roslyn evidence

Current capture02 remains unqualified for physical CPU/blocked/runqueue duration and exclusive GC cause even if this fixture passes. Its existing fast timestamps lack these per-event independent brackets and its trace_sched_switch callbacks precede context_switch. A separate synthetic execution cannot retrospectively repair either limit. The new fixture can establish only that this owned gettid collector recorded its finite body/reference/CPU/sequence observations and cleanup correctly. A later switch-boundary protocol still needs independently justified reference/error semantics and a clearly stated target event boundary.
