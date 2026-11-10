# Bounded timestamp/order contract review

2026-11-10. Read-only review for Engine #20 and ADR0031. No native attach, workload, build, global configuration, Engine source, tracking or remote mutation was performed. Only this isolated evidence directory was created.

## Observed retained data

Independent byte-ledger replay verifies SHA-256 f7476d81a17240fa018cb01483fabb8eba48a7bd705ec57c402510a6d8220cf3, 243,270 used rows and zero unused bytes. It reproduces 740 global adjacent timestamp reversals and 50 ties, and 13 per-generation reversals. Every reversal pair has different emitter CPUs. Per-CPU reservation-order subsequences have zero reversals and zero ties. This pattern does not identify why the clocks and reservation order disagree.

The five original main-generation masks intersect the union of all 1,909 selected measured caller-wait cores by exactly zero nanoseconds. The core union remains 5,304,379,677 ns. Consequently the measured caller partition's large unknown share is not from these five visible-order masks, and an independently validated switch-state decode can be evaluated while retaining identical masks.

## Loaded callback contract

Samples tools/scheduler_roslyn_program.py:5-7 imports publish and target from scheduler_dynamic_multi_program.py. That builder reserves a slot through atomic fetch-add at line153, writes record metadata, then calls helper8 at164 and helper5 at166. Actual capture02 program_hex independently confirms one helper5 after the reservation and CPU helper for each of nine emitting probes, and no clock call for exec. This proves placement in retained BPF bytecode, not immutable executing JIT or host attestation.

Exact published Microsoft kernel helper source kernel/bpf/helpers.c:177-181 calls ktime_get_mono_fast_ns(). Its proto is mapped at183-188 and selected by bpf_base_func_proto at1967-1968. kernel/trace/bpf_trace.c:1670-1683 delegates the raw-tracepoint helper to bpf_tracing_func_proto, which selects bpf_base_func_proto at1265. There is no architecture or CONFIG_TIME_NS alternative in these selected source branches. Newly fetched helpers.c and bpf_trace.c exactly match the previously retained SHA-256 hashes. The public tag/source match, captured kernel release and BTF checks remain version/provenance observations; they do not establish immutable running-image correspondence.

The exact source kernel/time/timekeeping.c:425-455 documents that the fast monotonic accessor can return backwards values around a timekeeper update, including cross-CPU observation; local NMI contexts have a related exception. This source supplies an additional possible ordering mechanism, without establishing that any specific inversion here came from a timekeeper update. Callback slot reservation before clock sampling is another possible mechanism. The prior report should state both as limits and avoid attributing all reversals to publication placement.

Finally kernel/sched/core.c:6941-6944 emits trace_sched_switch before context_switch. Both recorded in/out are callback points around switch selection. Their helper timestamps do not mark exact physical CPU dispatch or withdrawal. The same published source has wake paths concurrent across emitter and target CPU, so cross-CPU recorded order requires conservative interpretation.

## Recommendation

The present slice can remain offline: retain all original counts, unknown prefixes, clocks and masks; refine only state labels justified by the exact raw-state source contract, keeping the default legacy decoder and full old results. Do not turn recorded-label partitions into exact CPU, blocked, runnable delay or exclusive GC cause. Current masks cover visible recorded-order conflicts only, not all timestamp error.

A new bounded native fixture is unnecessary merely to reproduce deterministic label decoding. Any subsequent demand for physical scheduler-duration accuracy needs a separately frozen timestamp/clock-error and switch-boundary protocol, with entry/exit/sequence/CPU observations and an independently justified error envelope. A favorable synthetic result or finite zero-reversal fixture alone cannot certify the fast clock's universal monotonicity or Roslyn causality. Repeating unchanged Roslyn capture does not resolve this source-level limitation.

Artifacts: independent-timing-audit.json and audit_timing.py reproduce the data check; helper-source-audit.json binds loaded instructions and source paths; acquisition.json records the newly fetched timekeeping source. All raw input capture files are unchanged.

## Immutable source follow-up

The kernel reviewer resolved the release tag to commit `d504d40ab83839cb61942a812a99d183c42227b9`. Fresh reads of helpers.c, timekeeping.c and bpf_trace.c by that immutable commit match all three frozen source hashes exactly. `immutable-source-acquisition01.json` retains the per-file URL, retrieval time, size and paired hashes. This strengthens source revision provenance; it does not establish immutable running-kernel/JIT correspondence.
