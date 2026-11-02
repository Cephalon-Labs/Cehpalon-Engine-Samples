# ADR0029 fixed static conformance protocol

Pre-execution declaration,2026-11-02. Final sources/imports/Python/privateatomic/ABI/argv and this protocol must be hash-frozen before any target/perf FD. Root sole operator. Engine/original benchmark/#3 unchanged.

## Sessions, actors and bounds

Two ordered cases, overflow-negative then positive, with complete disable/drain/close/unmap/target-join between them. Stop on failed/inconclusive negative; never adapt pressure or automatically repeat. New ordinaryUID/GID1000 controller process and four precreated worker threads per case: handoffA, handoffB, migrator, sacrificial (five TIDs total). Empty supplementary groups and effective/permitted/ambient/inheritable capabilities; one explicit ready/barrier protocol. Each live nativeTID gets its own task-attached syscall-specific mapping before scheduler filters. No cached IDs/cross-boot leases or automatic new-child admission. All lease/environment reads/rechecks must be retained individually, including errors. Fixed source/actor/import/Python/libatomic hashes and exact8formats+gettid format. Linuxx86_64/4096pages, entire declared online topology max32CPUs; at least two permitted CPUs for positive migration. Existing verified private Ubuntu library only, no installation/configuration/namespace changes.

Per case up to256schedulerFDs, each pid=-1/cpu=oneonlineCPU/group=-1,128-byte disabled+CLOEXEC/CLOCK_MONOTONIC sample1158/read23 attrs, noinherit/sideband/callchain/overwrite. Negative1data page/FD, positive64data pages/FD (positive max65MiB includingmetadata). Each ring uses actual lockfree8/acquire2/release3. Mapping FDs/rings are task-scoped and closed before scheduler arm. Retained data cap256MiB/case; never silently truncate. Deadline ready/mapping/setup bounded in final source, eachphase<=5s, negative pressure<=5s, positive active<=30s including2sRCUtail, completecase<=60s includingcleanup; outer process150s with2sforced-kill grace forbothcases. Cleanup must get its own bounded budget. No competing owned builds/audits during active case.

## Arming and filtering

Record global/local TID maps and live proc UID/GID/capabilities/image/starttime/taskset/PID+time+user namespaces, boot, permitted/onlineCPU topology and zero time offsets. Open every FD disabled; set exact global-S payload filters on every CPU/event; retain each ioctl ACK and private-filter readback unavailable status. Validate mappings/resources/leases. Only after ALL filters/mappings are installed may any FD enable. Retain each enable bracket. Release controller/workers only after final enable. Numeric filters do not encode immutable lifetime; counterparty/header/comm and possible post-end reused-ID metadata are declared bounded raw scope, not owned attribution.

## Negative pressure

handoffA/B pinned first permitted CPU perform exactly10,000 condition handoff rounds. The consumer does not drain during fixed250ms after release; pressure has5s deadline. Afterwards drain while finishing the fixed work, stop at final actor barrier, disableall and terminaldrain/read every FD. Require nonzero terminal PERF_FORMAT_LOST on at least one scheduler FD, all raw/delivery/filter/ownership/cleanup accounting retained. No-final-LOST is allowed; emitted LOST is not added to the independent counter. No loss means INCONCLUSIVE, no positive case/retry. A head-tail overrun is an invariant error, never this expected pressure rejection. Close/join all before fresh positive.

## Positive fixed phases

1.100 complete handoffA/B condition rounds (park/wake evidence).
2.1000sched_yield calls eachA/B.
3.10000integer arithmetic iterations eachA/B; retain deterministic checksum/count.
4.migrator8affinity alternations across firsttwo actual permittedCPUs, sched_yield aftereach; preserve phase/iteration monotonic markers and actual affinity readbacks.
5.controller creates one separately tracked nonmember child, child immediately _exit(0), controller waitpid joins it. Retain localchildID/status and fork command brackets. Child is never S. Parent-side fork may be observed; child-side newwake must remain excluded. No owner expansion.
6.preleased sacrificial exits and controller joins while collection remains armed. Retain end/join snapshots; fixed2s RCU observation tail, remainingactors/controller at finalbarrier. No wait-until-success extension.
The RCU deadline is tail-start+2,000,000,000ns. Retain actual observer return/overshoot, but a free record after that declared deadline cannot pass merely because the observer resumed late. Python join and native death remain separate observations.
7.recheck live actor set, environment/ABI/images, disableALL, stable terminaldrain/counters, close/unmap before finalrelease/join of survivors/controller. Record all ownFD/pidfd/pipe/child closure results, with independent failures kept.

## Analysis and gates

Strictly decode exact ABI including fixedcomm and __data_loc string ranges/terminators/recordpadding; keep malformed/unknown/error raw bytes. Preserve every SAMPLE/LOST/throttle/otherrecord and stable perFD read-format23 tuple/ID. Positive requires all rawsample payload predicates match S, zero terminalLOST/throttle/decoder errors, complete terminalheadtail and conservative perFDcount==parsedSAMPLE. This is a fixed observed conformance gate, not a universal kernel count equation or proof against upstream dropped trace events.

Pre-first-execution accounting addition: every positive CPU-wide scheduler FD must also show0<time_running==time_enabled. Keep legitimate inactive/setup/hotplug rejection separate from loss/code failure; equality is perf-context accounting only, not hostCPU/wall/upstream-delivery proof. MappingFDs are task-scoped and do not receive this equality gate. Resource/mapping-capacity preflight for BOTH cases must complete before any actor; no limits are raised.

Validate controlled actor/phase counts, marker/session clocks and perCPU ordering. Across CPU equal/uncertain timestamps are not resolved by concatenation/index. Decode switch prev_state exactkernelmask: RUNNING0 or preempt markerTASK_REPORT_MAX/runnable; nonrunning labels do not identify cause. Seek complete switch-out/wakeup/switch-in chains within known actor lifetime/controlled phase, retain missing/initial/final/ambiguous transitions asunknown. Record migration/lifecycle/fork tests per observed window rather than claimingpositivewholeABI fromFDsuccess.

Static actors cannot positively exercise ownedwakeup_new/capturedinitialbirth afterarm. Ownedwakeup_new remains UNEXERCISED/UNKNOWN; negativechildnewwake should be absent throughpayloadfilter. No all8positive delivery or dynamicRoslyn capture readiness. DeadIDs canrecycle despitepidfd; newfork/newwake matchingclosednumericgeneration poisons it, allpostendmatchesunassigned except declared candidate lifecycle evaluation, no automaticadmission. RCUfree missing bydeadline unknown/failure. No observedreuse is not universal absence.

Retain collector CPU/resource/cadence/rawbytes per stage as perturbation observations, not Engine speedup/CPUduration/GCpause or hostvCPU availability. Preserve every failed/source/fixture/partial/raw attempt. Any correction needs a stated new immutable attempt, no favorable same-source rerun, thresholds/GC/concurrency changes or original benchmark repeat. #20 body-only tracking readback must leave #3 entire row Blocked/allothermetadata/Plannedgates/nullhours identical.
