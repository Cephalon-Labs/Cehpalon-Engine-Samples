# ADR0023 - Roslyn task lineage diagnostic lane

Date: 2026-11-01 (Asia/Bangkok). Status: accepted bounded diagnosis under Engine #20; #3 remains Blocked.

## Protocol fixed before capture

One complete WSL generator-only diagnostic execution, reusing the byte-identical prebuilt wait driver and original Engine55 source/support preparation. No rebuild or Engine patch. Preserve270measurements+36primers+12seeds+3preflight+18postflight and2956stage spans, originalcaseorder/compilerconcurrency/GC/options/primers/flags. No CLI/plaincomparison/originalbenchmark series.

Use existing owned suspended reverse-port EventPipe capture/cleanup and proc10ms observer. Providers: Microsoft-Windows-DotNETRuntime:0x411C14FCCBD:5, Cehpalon-Tooling-Diagnostic:0x1:4, System.Threading.Tasks.TplEventSource:0x43:5; original sample profile,256MB/Drop collection. No native syscall or kernel scheduler-transition channel and no permission/configuration changes. This perturbed trace cannot quantify overhead, speedup, CV or exclusive GC/scheduler causes.

Freeze loaded runner/helper code and source before target launch, including exact declared provider extension. Retain original prepared source/build provenance, byte hashes of actual driver plus adjacent app binaries/deps/runtimeconfig, loaded SDKhost/shared runtime/collector/analyzer pins and all inputs. These are observational checks, not immutable execution or binary equivalence attestation. Retain every preparation/capture/analysis attempt. A correction requires declaration before a complete repeat; no subset selection or stitching.

## Fixed analysis and gates

Verify complete original generator corpus/order/semantics and all2956markers/spans. Require zero reported EventPipe/ETLX loss and payload errors, successful full stack extraction, no provider errors, complete marker parity and a common markerclock intersection. Use exact integer metadata and source-pinned TPL assembler validated by ADR0022. Retain malformed/duplicate/reused/unfinished histories and every missing observation as rejected/unknown.

For all306Emitrows, compare caller-only TPLwait brackets with WaitForWorkers point witnesses and awaited TaskID execution-event lifetimes in this SAMEexecution. Native header TIDs are emitter/executing observations. Distinguish schedule destination vs ambient origin scheduler. Validate row identity/PID/caller identity/conditional clock windows. Compiler-plus-ThreadPool samples within task execution are point co-observations, not permanent thread ownership or CPU/runnable state.

Nested/inlined waits or executions can contain a WaitForWorkers ancestor or compilerframe. Retain all candidates, overlapping/nested scopes and ambiguous ownership. A unique contained sample alone does not prove the exact directly awaited Roslyn task/callsite; label supported eventTaskID-to-executionheader linkage separately from method-context co-observation. Do not label TaskWait duration blocked time, logical task completion, schedulerdelay or GCpause. No pause model becomes accepted by this wave.

Focused adversarial fixtures and independent source/raw review must cover loss/types/clockedges/stageboundary/missingpoint/nestedambiguous/inline/crossprocess/reuse/partiallifetime cases. Hash inputs/outputs. Root is sole remote writer; sync #20 body only with reviewedplan/readback, retain #3 entire row and all metadata/dependencies/estimates/Plannedgates/nullhours. No provider, supported-Windows, reference, release or production qualification.
