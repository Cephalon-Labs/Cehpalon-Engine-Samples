# Independent task assembler review protocol

Read-only root source review and pure in-memory adversarial fixtures. No builds, owned-target captures, remote writes or primary edits. Review shared skill and ADR0022 fixed protocol. Synthetic tests do not establish actual provider delivery or scheduler tracing readiness.

Exact reviewed Task.cs/TplEventSource.cs contract: TaskID with validated process generation forms task lifecycle; schedule scheduler is destination but start/stop scheduler may be ambient origin; preserve contexts separately. WaitBegin/End origin scheduler belongs waiter, not awaited task. Tasks may execute inline within synchronous wait brackets; interval is not blocked time. Nested inline tasks on same TID require stack-compatible or nonexclusive representation.

Adverse tests: exact IDs/versions/opcodes/type; bool-as-int identities; missing/negative/zero/oversize/string identities; finite timestamps/order; duplicate/reuse/malformed permanent compatible-key poisoning; missing start/stop; mismatched execution native TID; ambiguous nested/repeated waits on same key; async wait unsupported; cross-process/cross-scheduler origin handling; equal-time ordering; completed-before-wait absence; schedule-before-bound race; exception/cancellation distinction. Root selftests remain separate evidence.

Real trace audit: verify every raw TPL occurrence and sidecar marker, all expected IDs/versions and native IDs; compare independently counted lifecycle/wait histories including unknown/error groups. Preserve all failed fixture/audit attempts. Source hash and hashes of consumed raw/parsed artifacts bind results. No GC/runtime/Engine causal claim.
