# ADR-0051: Optional cooperative audit read budget

**Status:** Accepted bounded continuation. **Date:** 2026-11-21.
**Deciders:** Program integrator with independent design review.
**Tracking:** #18 resource budgets; #7/#8 tenant and identity regressions. #3/#20 unchanged.

## Context

The existing change-audit history, exact receipt lookup and exact resource-history readers recheck checked tenant authority and apply a captured immutable read policy. Caller cancellation already reaches their sources, but a project cannot select a separate read budget. ADR0050's optional indexed source does not add that Engine behavior. This continuation adds a portable, optional budget to the three existing readers, with real generated PostgreSQL consumer proof.

## Decision

Preserve all existing public constructors and `Activate` CLR signatures. Add `ActivateWithBudget(policy, TimeSpan? readTimeout, sourceFactory = null)` to each reader. A disabled policy returns null before timeout/factory validation and performs no factory, timer or I/O work. For enabled policies, a non-null timeout must be positive and at most one minute before invoking the factory. Null retains the complete legacy path, original provider token, faults and guard order, including the legacy history reader's scope-only final check.

Use built-in system timers; no new public TimeProvider option or package. For a configured read, allocate a private timer and linked token only after existing input, original-caller, live scope and cursor preconditions pass, immediately before provider work. Demand original caller, then private budget before source invocation. Keep the budget alive across the awaited provider call, page/record integrity checks, policy projection and final successful-result publication checks. Check original caller then budget both before and after the final live-scope guard. Empty pages and null lookup results have the same success veto. Current scope, query, cursor, tenant and policy checks remain required.

Classify only configured cancellation at primary error selection, before timer/link disposal: when the original caller is requested, return an OperationCanceledException bound to the original caller and retaining the caught OCE; otherwise, when the private budget is requested, return a generic TimeoutException retaining that OCE; otherwise rethrow the exact original OCE. Preserve non-OCE provider, integrity and projection failures even if cancellation becomes requested later. Do not traverse foreign exception trees or reclassify after cleanup. A final completion checkpoint can reject a returned result without identifying the physical cause of provider delay.

Await the entire provider operation, including a provider that ignores cancellation. Do not use WaitAsync/WhenAny to abandon work or release checked context lifetime early. The reader owns only its timer/link, not the provider lifetime or arbitrary provider callbacks. Dispose the link before the private timer source. Provider callbacks must be nonblocking/nonthrowing and own any additional asynchronous work; CTS disposal is not a join of undisclosed callbacks. This is cooperative cancellation, not a hard deadline, rollback, global admission budget or atomic network delivery deadline.

The [official CTS constructor contract](https://learn.microsoft.com/en-us/dotnet/api/system.threading.cancellationtokensource.-ctor) documents a countdown beginning during construction. It is design rationale, not a bound on host scheduling, callback completion or database execution.

## Options considered

| Option | Benefit | Cost and decision |
| --- | --- | --- |
| Caller cancellation only | Existing compatible behavior | Retained for old/null paths; no independent project budget |
| Optional linked system timer | Existing portable contracts and minimal API | Selected; cooperative and scheduler-dependent |
| Public custom TimeProvider | Deterministic timer injection | Deferred; extra callback, disposal and API surface is unnecessary for this slice |
| Forced timeout or provider-specific SQL deadline | Earlier caller return | Would abandon ownership or change provider semantics; not selected |

## Validation and compatibility

Predeclare 48 new component cases, 16 per reader, preserving prior Trail200, complete Engine1475Windows/1472WSL and fixed17/32 scaffold inventories. Use gated source/token observations and independent watchdog/finally force-unblock/join controls, without elapsed-time performance assertions. Preserve failed preparations and attempts.

Add 24 PostgreSQL consumer cases, retaining prior220 and security651: five actual port/profile combinations are legacy history/lookup/resource and indexed lookup/resource. Indexed storage does not implement tenant-wide history. Add one local typed generated history gateway; preserve the original five service declarations and all existing operations. The service registry digest intentionally changes by that declared addition; security registry0534 remains. Reuse fresh checked dispatch, not caller DTO authority. No new HTTP endpoint or transport contract is introduced.

Execute complete components plus security and provider consumers serially on Windows and WSL from committed source. Pin SDK11.0.100/runtime11.0.0 and existing provider/packages; preserve original220 provider prefix,4096-row default-planner fixture, Pooling=false and all original benchmark criteria. Real SQL Lock waits must be observed before configured expiry, followed by cancellation, caller-owned join, backend quiescence and reuse. Synthetic timeout classification is separate from actual SQL evidence. Hosted CI is exact Engine revision evidence, not a new hosted PostgreSQL profile claim. If usage/billing blocks a step, retain its exact pending action without billing changes or unchanged rejected reruns.

Only #7/#8/#18 bodies and Engine commit journals are in scope. Review a bounded plan, dry run, apply the exact hash, read back23 mirrors and253 Project fields, and preserve all other20 rows/task bytes and all metadata, milestones, null hours and M0 gates. Keep #3 Blocked and #20 unchanged. Publish reviewed suitable source/raw evidence, push all three mains, delete only owned merged refs and retain user files, worktrees and raw data.
