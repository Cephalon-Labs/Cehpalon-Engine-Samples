# Boundary pairing model handoff

The two uncommitted source files are isolated on features/scheduler-boundary-analysis. Sixteen meaningful adversarial tests pass on Windows, with no failed model test attempt. No native actor, attachment, build or remote mutation occurred.

The model imports only standard-library code. It independently validates the complete 512-slot one-worker legacy lifecycle, identity consistency, endpoint reservation order and terminal switch, without requiring monotonic fast timestamps. It decodes the separate 1024-slot boundary ledger, reconciles exact loss/padding/ordinal and strict bool/identity fields, and avoids classifying intentionally lost negative rows.

Positive invocation pairing follows each generation's reservation order. Prefix exits remain explicit, with leader left-censoring distinct from owned newborn true exits and unknown worker false prefixes. Pending leader entry at detach remains open; a closed worker's pending tail requires observed retirement. Retired entries/exits may still pair during cleanup. A trailing unreturned retired entry is a conditional closed-lifetime observation and does not assert a direct do_task_dead callsite.

Complete pairs retain exact entry ordinal, exit ordinal, bools, CPUs and retirement flags. CPU migration and timestamp reversals do not alter pairing. Nested entries, noninitial orphan exits, bad identity/generation/bool/ordinal/counters, contradictory retirement, missing worker coverage and unexplained live worker tails reject classification. Every retained row is conserved as paired edge, prefix or open tail. No physical duration, GC cause, historical Roslyn or general capture readiness is established.

Root should add program structural tests against its own new builder. These tests do not import the mutable main-checkout builder. The root integrator may copy the two source files and rerun both-host checks before its frozen native attempt. Source paths/hashes and the test log are retained beside this review.
