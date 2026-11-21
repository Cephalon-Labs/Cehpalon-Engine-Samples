# ADR-0047: Optional cooperative budget across an outbox drain

**Status:** Accepted bounded continuation, 2026-11-21.
**Tracking:** #18; #7/#8 regressions. #3 Blocked and #20 unchanged.

## Context

ADR0046 bounds batch and acknowledgement counts. ADR0045's relay timeout restarts for each batch. A host can need one cooperative work budget spanning the complete manual drain.

## Decision

Add `DrainWithBudgetAsync(context, TimeSpan? drainTimeout, maximumBatches=16, maximumRecords=2048, maximumPerBatch=128, cancellationToken=default)`. Preserve the existing DrainAsync signature, forwarding through the same private core with null total policy. Null creates no additional cancellation sources and preserves legacy token and exception references. Non-null must be positive and at most one minute; validate before provider work. Start the system timer after initial argument/caller/scope admission, before the first batch; retain it through all child cleanup and final guards. Each batch still has its configured relay timeout. Release retains its independent five-second token. Await uncooperative work and cleanup: this is no forced completion deadline.

A private cancellation context carries original caller and total-budget signals into RelayCore. Classify an observed OperationCanceledException at primary-error selection, before cleanup, using caller then total then per-batch precedence. Preserve unrelated failures and an already selected failure if another signal arrives during cleanup. Never reinterpret a foreign RelayException from Claim, borrow its counters, or classify a release-only error as a work timeout. Existing DrainException.PrimaryFailure/InnerException remains the exact child failure; no new public error property. Outer guards check caller, total then scope; before any batch starts rejection remains raw, afterwards preserve structured progress. Count successful acknowledgements before post-await guards even if a timer expires during cleanup.

## Options and consequences

Keep per-batch-only budgets: compatible but leaves total work uncontrolled. Add the distinct optional API: selected, preserves binary signatures and opt-in behavior. Race/abandon tasks: rejected because unknown publishing and cleanup would outlive the operation. No retry, renewal, parallelism, background work, schema/provider interface change, new authority or per-batch identity refresh. Keep runtime in Audit.cs and generated typed/lazy consumer dispatch. Counters describe acknowledgements, never unique delivery, rollback or global backlog emptiness.

## Validation and follow-up

Follow [protocol](../validation/total-drain-budget.md). Prove early classification with unrelated cancellation followed by late timer expiry during release, caller token identity, both signals, per-batch selection, release-only faults, current invocation provenance, late acknowledgements and external fixture watchdog/finally joins. Retain every attempt and all prior suites. No benchmark gate, flags, GC or concurrency changes; no performance or production qualification.

If expiry during child cleanup withholds the child's return, its acknowledged records remain interrupted-batch progress; CompletedBatches advances only after a successful child return. The [official .NET cancellation model](https://learn.microsoft.com/en-us/dotnet/standard/threading/cancellation-in-managed-threads) requires listener cooperation and permits linked tokens. It supports this design rationale, not runtime or timing proof.
