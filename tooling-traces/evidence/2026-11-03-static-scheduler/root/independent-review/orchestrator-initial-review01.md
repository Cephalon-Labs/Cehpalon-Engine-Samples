# Orchestrator initial source review — active freeze blocked

Source is in development; initial bytes retained separately. Pure core152tests passed on both platforms but that does not qualify orchestrator/actor behavior.

Before active freeze resolve:

1. Retain every individual environment/proc/ABI/source read, including failed or changed observations. Current observe/actor_leases require equality/validity before saving observations, losing mandatory failure evidence. Final source/ABI/import/environment readback needs retained data, not only success boolean.
2. Retain original opened FD number separately from nullable live handle, plus exact filter/enable/disable/close ACK/deadline/cleanup identity. Current close clears fd before manifest serialization.
3. Enforce absolute complete-case60s, phase5s and active30s deadlines across setup/open/filter/enable/drain/decode/gates, and separate bounded cleanup time. Outer150s is final containment, not a case timeout. Constructor and partial failures must leave all resources owned/known.
4. Apply256MiB/case cap to all files, including plan/chunks/manifest JSON and terminal pages; binary-only write counter is incomplete. Check sufficient unchanged existing FD/mlock limits for BOTH fixed cases before launching negative; no host limit writes or adaptive fallback.
5. Implement retained state/preempt/park-wakeup-switchin analysis with exact controlled handoff/lifetime windows and unknown/tie/missing buckets. gates currently checks only event existence in whole common window; raw state values are not decoded into declared state observations.
6. Migration needs perstep requestedCPU/orig-dest/marker joins, rather than any migrator event. Nonmember fork needs its unique controlled bracket and no child admission. Lifecycle needs retirement/end/RCU bounds, duplicate and reuse-birth poisoning, explicit post-end unassigned records; any matching numeric ID anywhere is insufficient.
7. Worker/step markers must be typed, ordered and inside phase bounds. Retain perFD temporal order and uncertainty, not index-based crossCPU ordering. Positive FD running/enabled counters need explicit coverage gate; zero/gapped running cannot become a quiet lossless FD.
8. Collector imports resource at top-level, blocking portable Windows mocked orchestrator imports. Native-only modules should be deferred/guarded for portable test coverage.

The above was sent to root and code agent before any active attempt. Reviewer performed no actor/perf/native operations. This is an interim defect list, not the final state of later source revisions.
