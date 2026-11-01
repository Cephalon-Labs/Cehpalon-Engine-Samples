# Independent awaited-task worker-stack context review

Read-only ADR0025 source/fixture/raw audit over the exact full ADR0023 execution, with frozen lineage and ordering evidence. No builds, workload targets, captures, host changes or remote writes. Root sole integrator. Wait for declared scopes/taxonomy and code API before replay.

Every managed stack frame label is nonexclusive. A compiler/ForceComplete/WaitForWorkers ancestor can coexist with task wait, monitor, WaitHandle, spin or other context. Record all declared label matches and actual frame witnesses. A label is a sampled managed-stack observation, not CPU, progress, blocked/runnable/runqueue duration or exclusive GC/scheduler cause. Empty/unknown/unmatched/truncated stacks never become productive execution or zero waiting.

TPL awaited TaskID links native execution emitter headers, not exact direct WaitForWorkers callsite or permanent worker identity. Preserve every containing/nested execution lifetime candidate at each point; no favorable innermost selection. Sampled proc birth observations are partial context and never native lifetime proof.

Keep all2372 paired waits and all306rows/2177rowwaitassociations, including nonmain and outside-Emit waits, missing/unaccepted execution, no samples and boundary uncertainty. Declare separately whole execution lifetime, caller-wait intersection and guaranteed row Emit core scopes. Do not silently stitch/prorate boundaries. Repeated point/wait/row associations differ from unique raw sample indices; multilabel totals may overlap.

Adverse fixtures: exact timestamps/identities and typed raw-reference/hash binding; equal-time/partial/no-core/foreignPID/missing/truncated/duplicate sample input; malformed/poisoned/reused/incomplete task histories; nonmain/inline/nested execution and waits; labels coexisting on ancestor stacks; all negative gates preserveunknown or reject, never false zero/progress.

Independent audit: full raw SampleProfiler/ETLX PID-TID-time multiset parity and point index/frame witness binding, all source input/output manifests, exact candidate sets per scope, complete wait/row membership, strict row core geometry, every declared label counter plus distinct-point/association fingerprints and no direct ownership/native-lifetime/duration claims. Preserve all superseded fixtures/audits.

## Fixed scope after reading ADR0025

The accepted global scope is execution-event lifetime intersect caller TPLwait only; whole-execution samples are outside this analysis. Row scopes add guaranteed Emit core. Root strict-boundary clarification before replay requires strict inequalities for point promotion and preservation of equal-edge/unassigned candidates; prior ADR0023 closed observations stay unchanged. No taxonomy counts reviewed before the finite dictionary snapshot.
