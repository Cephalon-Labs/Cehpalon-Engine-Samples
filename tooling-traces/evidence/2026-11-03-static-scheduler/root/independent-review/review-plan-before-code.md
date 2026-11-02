# Independent ADR0029 review plan — pre-code

Scope: offline source, portable mocked/byte fixtures, then independent retained-artifact audit. Reviewer launches no actor, perf FD, native library, target, build or host configuration change. Root is sole active operator and remote writer. Current positive ADR0028 mapping belongs to an exited task and cannot seed this execution.

## Freeze and bounded resources

Require declared ADR0029 and exact protocol before active execution: phases, actor roles/count (<=16 total owned tasks including controllers/sacrificial/nonmember roles), allowed CPUs, per-event/per-CPU FD count, buffer bytes, perf/FD/mlock limits, total/phase deadlines, negative generation cap, free deadline, drain cadence, output bytes, ordinary actor UID/GID and cleanup ownership. Exact source/import/Python/private atomic library/ABI/input hashes and full launch bytes must match freeze. Retain every failed preparation and attempt. No fallback, ignored CPU, auto-expanded membership, hidden retry, or positive from an invalid negative.

## Identity / scope

Each actor's own task-attached gettid bootstrap must bind local PID/TID, stable proc starttime/image/UID/GID/capabilities/namespaces and unique same-execution global common_pid before scheduler S is constructed. No duplicate global/local IDs or bool-as-int identities. Retain all individual pre/post observations and compare them, including controller and sacrificial lifetimes. No post-exit proc reconstruction. Root is collector only, ordinary actors have zero effective/permitted/inheritable/ambient caps. A known unleased child is negative-only, never silently enrolled.

## Arm and filter

Every online CPU x eight scheduler event FD opens disabled with exact tracepoint config, CLOCK_MONOTONIC, no inherit/sidebands, CLOEXEC and bounded forward ring. All filters use payload fields (switch prev_pid|next_pid, fork parent_pid|child_pid, others pid), all filter acknowledgments precede any enable, and final enable precedes release barrier. Prefix and per-FD enable skew remain outside assigned state. Failed/partial opens/filter/enable/constructor states close owned resources and keep actors held/terminated. CPU set and leases rechecked before and after. No unsupported filter readback claim; delivery positive/negative proof is separate.

## Ring/records/counters

Retain raw metadata and complete data pages or exact consumed slices with monotonic head/tail snapshots, per-FD raw reads twice after disable, requested attrs and actual event IDs. Use acquire head/release tail through pinned lockfree atomics; validate ABI offsets/sizes/ordering and constructor cleanup. Decode every record with strict bounds, exact RAW format and padding, record type/loss/throttle/unknown behavior and header CPU namespace semantics. Bind every sample to its FD CPU/config/record offset and payload-membership result; comm/counterparty/emitter privacy scope disclosed. No absence-of-LOST inference. Independent audit reconstructs ordered bytes across wrap and all terminal drain/counter accounting. Keep ties/cross-CPU ordering unknown. Counting value vs emitted samples/loss relationship requires exact source rationale and sample_period=1; never assume value=delivered without checking all suppression/loss states.

## Fixed negative then positive

Overflow negative is first and separate: deliberately prevent/limit drain for a fixed generation budget and deadline; require explicit expected rejection based on overrun/independent lost/accounting evidence (not merely a missing transition). Retain the complete invalid dataset. Close/join its entire session before opening fresh positive FDs/rings/actor mappings. Positive cannot reuse negative identity, counts, ring or state. No extra generation until overflow is observed unless that exact bounded generation schedule was frozen. No favorable rerun.

## Positive phase coverage

Validate phase marker transcripts and monotonic brackets, ordinary known CPU-running/yield plus pipe/futex park/wake, intentional cross-CPU migration when >=2 permitted CPUs, remote emitter-vs-target wake filter proof, fork/exit and fixed bounded free observation from predeclared sacrificial tasks while armed. Require exact lifecycle boundaries and stable identity; delayed/missing free is unknown/fail, never infer it. A complete observed switch-out/wake/switch-in chain is needed for any synthetic chain gate; preserve initial/final unknown states and ambiguous preemption/ties. Controller I/O, phase ACKs and scheduler timestamps are not CPU-duration proof.

## Cleanup / audit outcome

Audit all FDs opened/disabled/closed, mappings closed, all child identities/pidfds and pipes, waitpid join/reaped state before any later kill path; unexpected failures preserve original plus cleanup errors. No numeric-PID kill after reaping. Retain all final proc/environment/hash/readback records and terminal clocks, raw stdout/stderr/exit status. No orphan/perf resource or ownership uncertainty can be a pass.

Pass scope is a bounded static synthetic collector only. Dynamic Roslyn ThreadPool admission/lifetime coverage, GC/scheduler cause, runnable/CPU/blocked durations for original traces, speedup, benchmark gates, provider/Windows/reference/production/release remain unqualified. #3 remains Blocked; #20 original metadata/dependencies/Planned gates and null actual hours unchanged.
