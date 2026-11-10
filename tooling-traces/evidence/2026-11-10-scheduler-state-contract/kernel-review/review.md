# Exact raw scheduler-state source review

2026-11-10. Read-only source and retained-ledger review, with no actor, BPF attachment, build, configuration change or remote mutation. The named Microsoft release tag resolves to immutable commit `d504d40ab83839cb61942a812a99d183c42227b9`; the tag API receipt is retained. Six primary source files were fetched by that commit, with exact bytes and SHA-256 in `provenance.json`. The cached matching-tag scheduler headers are byte-identical to the immutable-commit copies. The web tool's tag API failure and successful `gh api` fallback are recorded; all six file acquisitions succeeded.

## Raw callback contract

The [scheduler trace declaration](https://github.com/microsoft/WSL2-Linux-Kernel/blob/d504d40ab83839cb61942a812a99d183c42227b9/include/trace/events/sched.h#L222) declares arguments `(preempt, prev, next, prev_state)`. The [BPF bridge](https://github.com/microsoft/WSL2-Linux-Kernel/blob/d504d40ab83839cb61942a812a99d183c42227b9/include/trace/bpf_probe.h#L45) forwards those original arguments as u64 slots. The formatted trace record separately computes a transformed state at sched.h line243; its encoding must not be applied to the raw argument.

The actual captured `switch_out` program SHA-256 is `6f9b68198beea2331c58c2648543aa148dd585c84064278cf5ab8a233213503c`. Independent byte inspection matches the five-instruction source sequence at index23: raw context offset24 supplies the state, raw context offset0 supplies preempt, then private bit31 is ORed when preempt is true before a u32 stack store. It does not reread task_struct.__state. The parent builder is Samples/tools/scheduler_dynamic_multi_program.py lines123-129, reused by scheduler_roslyn_program.py lines97-98.

## Exact additions

[State definitions](https://github.com/microsoft/WSL2-Linux-Kernel/blob/d504d40ab83839cb61942a812a99d183c42227b9/include/linux/sched.h#L103) give 8193/0x2001 as interruptible plus freezable, and 258/0x102 as uninterruptible plus wake-kill, the TASK_KILLABLE convenience value. Freezable permits freezing; it does not assert that freezing occurred. Killable describes signal wake conditions and identifies no wait cause. The wait header at lines368-369 explicitly uses the first combined mask in its freezable wait macro, but this does not identify the callsite in the Roslyn capture.

An explicit pinned raw-argument profile may extend the existing conditional `off_cpu_sleep_state` label with exactly those two values. Leave all other combined values and unknown bits outside the new whitelist. Keep the legacy default, private preemption behavior, raw rows, and existing ambiguity masks unchanged. Do not reinterpret raw258 as a formatted preemption flag: the formatted report's preemption sentinel is 0x100, while this collector's private marker is 0x80000000.

## Callsite and interpretation limits

The [core scheduler source](https://github.com/microsoft/WSL2-Linux-Kernel/blob/d504d40ab83839cb61942a812a99d183c42227b9/kernel/sched/core.c#L6546) clears both task state and the passed state pointer on pending-signal cancellation at lines6552-6556. The caller samples __state at6867, passes &prev_state to try_to_block_task at6881, then calls the raw switch trace at6941. Thus the argument includes that correction. A separate proxy-execution path can retain mutex-blocked tasks on the runqueue when should_block is false. These source semantics do not certify physical blocked/runqueue time or a causal GC share. Recorded BPF callback timestamps still require their existing ordering/latency qualifications.

The retained native ledger's full raw-state histogram is 8193:57408,258:2393,1:538,2:74,0:660,private-preempt:5,terminal128:39. Main818 counts are 7262,2303,138,11,139,4,1 respectively. These are point counts, not durations. They were counted independently from the raw binary and reconciled with its SHA-256.

The recorded kernel release, BTF hash/layout and actual callback byte contract support this bounded interpretation. Tag-name correspondence and BTF do not attest an exact reproducible installed kernel binary. The review deliberately retains this limit. The source-contract replay passes21 checks; raw-state-source-audit.json preserves the exact program/source/counter evidence.
