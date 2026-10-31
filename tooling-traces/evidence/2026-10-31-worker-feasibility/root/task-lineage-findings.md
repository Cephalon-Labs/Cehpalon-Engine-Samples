# Exact-revision TPL/task and GC source feasibility

Read-only source/installed-version review, 2026-10-31; no Engine edits, builds, targets, captures or remote writes.

## Material source-lookup correction

The installed WSL host and SDK report version11.0.0-rc.3.26522.148/11.0.100-rc.3.26522.148 and commit5254d8bcf5. The full recorded revision5254d8bcf59917edc1e1abc33bdf2442b77b1c70 is accessible in the official **dotnet/dotnet** repository under src/runtime, rather than dotnet/runtime. The earlier HTTP404 from dotnet/runtime does not establish source unavailability. All seven exact-revision source URLs/status/content hashes are in source-contracts/provenance.json. This is repository revision/source availability; it is not a complete installed-binary/source attestation or a certified event-pairing result.

## Task lineage feasibility

Pinned TplEventSource.cs defines provider System.Threading.Tasks.TplEventSource, GUID2e5dba47-a3d2-4d16-8ee0-6671ffdcd7b5. Candidate minimal task lifecycle/wait subscription is 0x43 at Verbose5: TaskTransfer1+Tasks2+TaskStops0x40. It avoids activity-flow/set-activity/debug/async-instrumentation keywords. Nevertheless enabling the source invokes AsyncInstrumentation.UpdateTplFlags with defaults (source line38), causes task ID access/allocation and emits extra events. It is perturbing instrumentation, not a behavior-free observation.

Required templates: ID7 TaskScheduled v1 (OriginatingTaskSchedulerID,OriginatingTaskID,TaskID,CreatingTaskID,TaskCreationOptions,appDomain); ID8 TaskStarted (scheduler,origin,TaskID); ID9 TaskCompleted v1 (scheduler,origin,TaskID,IsExceptional); ID10 TaskWaitBegin v3 (scheduler,origin,TaskID,Behavior,ContinueWithTaskID); ID11 TaskWaitEnd (scheduler,origin,TaskID). Verify actual emitted ID/version/template/payload and all loss channels before accepting a join. TaskID0 as origin/continuation denotes unknown/context absence, not a missing task to manufacture. Retain lifecycle generations/wrap/duplicate/unknown handling, scheduler identity, provider/PID and caller native TID.

Exact TaskAwaiter.cs104-106 calls InternalWait for an incomplete task in GetResult; already completed tasks need not emit waits. Exact Task.cs3123-3180 emits synchronous TaskWaitBegin/End with awaited TaskID. Inside that bracket, code may execute the task inline (3153-55) or spin/block. Therefore TaskWait duration is not blocked duration, scheduler delay or CPU. Task.cs2466-2528 emits TaskStarted/Completed on the executing thread; combine IDs with native event headers only inside a validated task lifetime, not sampled ThreadPool permanence. It can be the caller thread during inline execution.

Pinned Roslyn4.14.0 MethodCompiler.WaitForWorkers waits via GetAwaiter().GetResult, while CompileNamedTypeAsync schedules Task.Run. These paths make a same-execution TaskID linkage plausible, but no experiment has yet established which of its events appear under the installed runtime or whether every relevant Emit wait can be linked. Do not assume every TPL event is Roslyn work. Require schedule/context/row evidence or keep task identity with unknown work kind.

## Existing parser gaps

Current Samples tools/trace_tooling.py and tooling_wait_capture.py never subscribe the TPL provider; the retained traces do not retrospectively gain this channel. TraceAnalysis/Program.cs71-90 registers Dynamic.All and AllEvents and writes all payloads, PID/nativeTID/time, ID/opcode/version/templateType. It has no task-lifecycle assembler or TPL quality gates. Frame259-260 does not retain ActivityID/RelatedActivityID, keywords, raw binary payload or assembly-load context. A minimal TaskID proof need not depend on activity IDs, but any later activity-chain claim requires preserving them and validating its contract. No parser/capture changes were made in this review.

## GC source contract limits

threadsuspend.cpp5531 emits GCSuspendEEBegin before ThreadStore lock acquisition around5547; multiple initiation events can coexist before serialized suspension. Successful GCSuspendEEEnd is5706. RestartEE emits its own begin5385/end5485 on its caller. GC-to-EE contract comments5492-5507 are explicitly asymmetric. gcenv.ee.cpp38-64 separately delegates SuspendEE and RestartEE. These functions alone do not prove the same native initiator must call both, so a per-TID four-phase model remains a hypothesis pending full caller-path review. Debugger failed-suspension retry invokes RestartEE(false) at5685 then jumps back to retry5541 without another top-level begin event. Production applicability of debug branches must be checked against actual build configuration.

The exact implementation shows why accepting only one process/CLR pending start can reject or mispair observable episodes. It does not by itself certify all83 supplementary episodes, the two disputed ends, native event header generation, task pause duration, GC-free residual or exclusive GC/scheduler shares. GC event generation/manifest and platform-specific header path still need review; collect binary provenance separately. Preserve old outputs and qualify them rather than overwrite.

## Bounded next experiment proposal

Declare a separate synthetic owned-task conformance capture before any generator target: scheduledTask.Run plus completed-before-wait, synchronous wait, forced block, inline execution, nesting, exception and cancellation cases. Use positive fixture markers/task IDs, validate actual ID/version/headers, missing/duplicate/out-of-order/wrap behavior and all trace loss channels. Freeze source/provider configuration and record overhead; do not change compiler concurrency/GC flags or original benchmark gates. A fresh full generator lane can be justified only after conformance passes and separate scheduler-transition feasibility/clock joins are established; otherwise report partial task evidence and keep unknowns. No original benchmark rerun or Engine patch is justified by this source review.
