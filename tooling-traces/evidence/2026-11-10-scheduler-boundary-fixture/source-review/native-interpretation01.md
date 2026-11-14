# Native boundary interpretation audit

2026-11-10. Read-only audit of the completed fixed native01 attempt against the exact source contract. No program builder, production decoder or analyzer was imported; raw ledgers were unpacked independently. No actor, BPF load/attach or remote operation was performed by this reviewer. The first interpretation audit passes 553 checks and retains its script, JSON report and logs.

## Observed attachment and scope

Both native case reports contain exactly one `sched_entry_tp` and one `sched_exit_tp` named attachment receipt, with zero cookies, alongside the declared lifecycle hooks. These are retained actual-open/fdinfo receipts and captured event evidence, rather than a new live inspection after the links have closed. The negative case contains intentional capacity loss and correctly declines complete pairing classification.

The positive ledger hash matches its report and contains 182 owned rows, with zero unused bytes. Strict event/header identity, ordinal, kind, bool and retirement values reconcile. Independent generation-local pending-invocation reconstruction yields 89 complete pairs: 25 exit(true) switch pairs and 64 exit(false) no-switch pairs. Nine pairs have different entry/exit emitter-CPU endpoints. This endpoint observation does not count every intervening migration or measure physical switch latency. All observed complete-pair entry mode flags are false; native preempt-mode-true entry coverage remains unobserved.

## Prefixes and open tails

The seeded leader's first exit(true) has no captured entry and remains a left-censored prefix, with no newborn assertion. The admitted child's first boundary is exit(true); its separate owned lifecycle has birth, first wake, selected-in, retirement, terminal switch and free with stable local/global/generation identity. This supports the separately labelled owned-newborn exit prefix under the source [schedule_tail](https://github.com/microsoft/WSL2-Linux-Kernel/blob/d504d40ab83839cb61942a812a99d183c42227b9/kernel/sched/core.c#L5258) contract.

Two entries remain open. The leader is held in the reported stdin read at detach. The child's final entry(false) has retired=1 and is numerically between the lifecycle retirement and terminal TASK_DEAD switch, before free. `unreturned_retired_lifetime_entry` is an appropriate evidence label. It does not identify a direct do_task_dead callsite, even though that [source path](https://github.com/microsoft/WSL2-Linux-Kernel/blob/d504d40ab83839cb61942a812a99d183c42227b9/kernel/sched/core.c#L6953) explains why a terminal invocation can validly fail to return. All 182 rows are accounted by the 89 pairs, two prefixes and two open tails.

## No-switch observations and numerical links

All 64 raw exit(false) pairs have exactly one containing offered raw-clock yield bracket for both callback bodies, and the 64 bracket IDs are distinct. This is an observed numerical association under the retained fast/reference clock assumptions; it is not a physical scheduler-duration bound. The [source branch](https://github.com/microsoft/WSL2-Linux-Kernel/blob/d504d40ab83839cb61942a812a99d183c42227b9/kernel/sched/core.c#L6903) makes false the oracle for prev==next in that invocation. It does not establish an uninterrupted physical CPU interval or turn every future yield on a shared host into a no-switch guarantee.

The reported decoder limitations remain false for physical scheduler duration, historical Roslyn qualification, general capture readiness and GC cause. No actionable interpretive overclaim is found in those classifications. Preserve the explicit entry-mode-true coverage gap, prefix/newborn distinction, endpoint-only CPU wording and absence of direct terminal callsite proof in final reporting.
