# Same-execution Roslyn scheduler correlation

Date 2026-11-07. Scope ADR0031 and Engine #20. No Engine source or original benchmark setting changes. Retain every preparation and capture attempt.

## Fixed preparation and scope

Use pinned WSL kernel 6.18.54.1 and raw BTF, the native .NET 11 RC3 SDK/runtime and prebuilt TraceDriver SHA `21d061db61ac77608f470f168b431cb5a631a099bfb1b07ed64cd5be04d53b5c`. Reuse the established collector and parser binaries, full 306 Emit rows, 36 primers, 270 measured rows, 2,956 stage markers and complete original generator ordering and semantics. EventPipe uses the previously declared Runtime, diagnostic stage and TPL provider masks, sampled-thread-time profile, 256 MiB drop buffer and original deadlines. Freeze all source and binary bytes before launch and compare afterwards.

First run a separate controlled CLR ThreadPool actor with the enlarged profile, demonstrating initial main enrollment and a new callback generation through process-teardown free. After it passes, launch one full Roslyn target suspended on its private reverse port. Target and EventPipe collector run at UID/GID 1000. Root binds at most 16 stable pre-arm tasks through their live thread pidfds, exact TID/start-time/namespace/credentials and task storage. Lifecycle hooks attach before the initial syscall enrollment hook. Native diagnostic activity before managed resume may create valid initial records. Keep the arm snapshot and unknown initial state.

Bound total initial and born generations to 64, private hash entries to 64 and the ledger to 262,144 fixed 40-byte slots. Counter layout records attempts, publication losses, faults, completed frees, total admissions and initial admissions. No drain or adaptive resize. Reject any lost publication, fault, recurrence miss or missing lifecycle. Terminal free uses a two-second post-reap tail. Retain complete first ledger, second count snapshot and hash, named link receipts and exact close accounting. Selected initial task enrollment is left-censored. Unregistered pre-arm threads and births from unbound parents remain outside coverage claims.

The EventPipe collector must start and resume its own reverse endpoint after scheduler arm. Check the actual loaded CLR host/library paths and zero-offset shared time namespace. Keep the established proc observer, which adds a further perturbation channel. Limit complete native/managed diagnostic artifacts to 2 GiB. Any data beyond a gate remain retained but do not establish complete attribution.

## Analysis

Require complete managed corpus, marker parity, native ledger reconciliation, source/binary parity and zero reported managed payload/loss errors. Decode per-generation identities and conservative scheduler states. Initial state, missing or tied transitions and the waking-to-wakeup interval remain unknown. Join each EventPipe point through its exact marker-derived MONOTONIC interval. Boundary-touch or multiple candidate lifetimes remain unassigned.

For caller waits in measured Emit cores, report bounded observed running, runnable, off-CPU sleep-state and unknown intervals where identity and clocks permit. Retain the awaited task and sampled compiler context as explicit TPL and stack observations. Preserve every GC suspend/restart event and raw metadata. Overlap does not establish a GC pause, exclusive cause or safe optimization. The result can remain incomplete if evidence cannot distinguish those causes. Audit all observations and sync only #20 body through exact reviewed plan and readback.

## Preparation note

The first passive freeze stopped at Git's ownership check before any target or BPF operation. Run the exact Engine revision and cleanliness reads as the ordinary repository owner. Keep the rejection receipt and leave host Git configuration untouched.
