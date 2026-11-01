# ADR0025 - Awaited execution stack-context observations

Date: 2026-11-01. Status: accepted bounded offline diagnosis under Engine #20; #3 remains Blocked.

## Fixed scope before replay

Use only the complete retained ADR0023 raw capture and pinned ADR0023 lineage / ADR0024 ordering outputs. No target, build, capture, original benchmark, Engine code or host permission/settings change. Root is sole integrator and remote writer; agents isolate new code or perform read-only review. Preserve all attempts and original gates/dependencies/estimates/Planned statuses/null hours.

Keep all2372globalwait queries and all306Emit rows/2177rowwaitassociations, with measured270/primer36 phases separate. Global query scope is intersection of a caller TPLwait bracket and the awaited task's observed execution-event lifetime on its execution header nativeTID. Row scope additionally requires the point inside the guaranteed Emit core from the existing conditional marker-clock map. These scopes have separate denominators; do not mix them with whole-execution-lifetime samples. Missing execution, no sample, boundary/clock uncertainty and malformed references remain unknown/unassigned; no sample is never zero work/wait.

Verify pinned source/input/output hashes and all copied raw references. Verify complete raw SampleProfiler versus ETLX stack PID/TID/time multiset parity before joining. Retain every containing execution candidate ID, nested/overlapping contexts and partial native-generation scope. Do not choose an innermost task as ownership proof. Count distinct raw stack indices separately from query/row associations; retain repeated associations explicitly.

## Predeclared multi-label dictionary

Labels match ANY recorded managed frame and retain rule ID, exact full frame, catalog reference and serialized frame depth; depth is not native/on-CPU/top-frame state. Nonexclusive labels:

- roslyn_method_compiler_frame: exact Microsoft.CodeAnalysis.CSharp.MethodCompiler dot/nested-type family.
- other_codeanalysis_frame: Microsoft.CodeAnalysis namespace frames outside that family.
- managed_wait_entry_frame: exact named methods from Task InternalWait/InternalWaitCore/SpinThenBlockingWait/SpinWait, TaskAwaiter GetResult/HandleNonSuccess/ValidateEnd, WaitHandle Wait methods, ManualResetEventSlim.Wait, Monitor Wait/Enter/TryEnter, SemaphoreSlim Wait/WaitAsync, ReaderWriterLockSlim Enter/TryEnter methods, Thread Join/Sleep methods. Such entrypoints can complete without blocking.
- runtime_preparation_entry_frame: named RuntimeHelpers PrepareMethod/PrepareDelegate/RunClassConstructor/InitializeArray and Assembly/AssemblyLoadContext loading or ReflectionEmit DefineDynamicAssembly entrypoints. Not JIT CPU/progress proof.
- explicit_gc_request_entry_frame: System.GC Collect/WaitForPendingFinalizers entrypoints only; not GC suspension attribution.
- other_frame_context: nonempty stack with no recognized rule; unresolved_context for empty/unavailable stack.

The exact finite method-token dictionary must be snapshotted before replay; avoid substring matches/naive namespace aliases. Multiple labels may coexist (e.g. compiler ancestor and wait entry). Never turn points/counts into duration, useful work, CPU, runnable/runqueue, physical blocking or GCpause. Missing categories are not proven absence.

Retain all27nonmain TPLwaits as a separate same-execution event-header co-observation channel. Any nested worker-wait relation requires matching recorded nativeTID and intersecting outer wait / execution windows, retaining all candidates and boundaries; it is not permanent ownership, causal dependency or blocked duration.

## Verification and delivery

Portable adverse fixtures plus independent full raw/context/dedup/row/candidate audit cover overlapping labels, frame spoof prefixes, method tokens, nested execution/wait scopes, empty/partial stacks, boundary points, sample/hash/reference drift and no-sample queries. Preserve rejected/preparation/source versions. No directcallsite/native-lifetime/GC/scheduler causality or provider/supported-Windows/reference/production/release qualification follows. Sync #20 body only via reviewed plan and readback; preserve #3 entire row and all other metadata.
