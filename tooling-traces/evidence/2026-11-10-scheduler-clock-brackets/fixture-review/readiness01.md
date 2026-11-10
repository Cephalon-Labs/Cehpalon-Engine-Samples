# Owned clock fixture source readiness review

Read-only review of five new Samples tools, 2026-11-10. Source hashes are observations at review time in readiness-source-hashes01.json. No native load/attach, actor, build, shared source edit, remote write or configuration change by reviewer.

No blocking BPF/control/loss/cleanup defect found. Typed-current task-storage ACK and syscall186 comparison precede counters/output. The attempted counter fetch-add returns the zero-based record index, stores it at stack-4 and passes it unchanged to the records array lookup. Count/record map pointers in r9/r7 are callee-saved across helpers. Bounded overflow routes to lost counter. The fixed array guarantees record indices below capacity<=128; unused bytes are checked by analysis.

Actual snapshot order is CPU_begin,fast_begin,reservation/record writes,fast_end,CPU_end. The interval is an inner post-ownership callback-body observation. It excludes prior ownership lookup and later CPU/end-field store. It is not syscall entry/exit, hook total time, physical switch time or a transfer envelope for historical events.

Unseeded owned gettid, root nonmember gettid and seeded wrong-syscall controls precede fixed pairs and must leave all counters zero. Each fresh case has owner/alias/nonmember pidfds plus BTF/storage/counts/records/program/link, totaling9 native FDs. Detach precedes double ledger/count read. Actor lease is checked live before detach; explicit finish/reap precedes task-storage absence check. Failure ExitStack closes links before resources, closes actor stdin and reaps/kills only the known actor. No process replacement or extra owned generation is accepted.

Actor initial source used -B without -I/-S, unlike the existing held-owner preflight. Optional prefreeze isolation hardening was sent to integrator: -I/-S prevents unrecorded site/PYTHONPATH startup extension code. This is not a binary-attestation claim or a found runtime failure. Any integration correction must remain explicit in the freeze/source receipts.

Native readiness is conditional on root freezing current source/binaries/BTF and running only the declared negative then positive matrix. All timing containment/backward-point anomalies must remain reported outcomes. A finite successful fixture will not qualify Roslyn or physical scheduler durations. Independent raw-result audit remains pending actual root output.
