# ADR-0048: Optional tenant-scoped audit receipt lookup

**Status:** Accepted bounded continuation. **Date:** 2026-11-21.
**Deciders:** Program integrator with independent scoped design review.
**Tracking:** #18 audit history retrieval, #7/#8 regressions; #3/#20 unchanged.

## Context

Field audit history currently exposes bounded pages only. The PostgreSQL sample orders random receipt IDs using OFFSET. A known receipt can require scanning, and concurrent inserts can shift pages. Its existing sink primary key is already tenant plus receipt. An exact read is useful without changing pagination, storage or delivery semantics.

## Decision

Add `ITenantChangeAuditLookupSource.FindAsync(TenantId authorizedTenant, Guid receiptId, CancellationToken)` returning a nullable TenantChangeAuditRecord. Add a separate optional `TenantChangeAuditLookupReader` with constructor(source, policy), Activate(policy, sourceFactory) and FindAsync(context, receiptId, cancellationToken=default). Preserve all existing history/relay/source signatures. A Disabled policy skips the source factory; direct construction rejects Disabled. Validate non-null context/nonempty receipt, cancellation and the live audit-trail/tenant/read scope before I/O. Propagate the original caller token and original provider failure object. No new timer or cancellation classification is installed. Await all work, including a source ignoring cancellation.

After awaiting either record or null, check caller and live scope again. A returned record must match both requested tenant and receipt exactly before current-policy projection. Project into a fresh immutable record using existing policy.Project; check caller and scope before returning. A null is only this provider's absence observation, including undelivered or retained-away data, not delivery/health/global-existence proof. A receipt ID and returned DTO are not authority. Reader captures the configured immutable policy; projects activate/configure a reader with the current read policy rather than assume automatic policy reload.

Use existing history read scope, not relay/inspect/operation-metadata history permission. Generated consumer adds an explicit sample operation grant and lazy typed gateway through Core/Composition. No implicit global or all-tenant lookup, cursor authority, transport endpoint, background work, retry, retention deletion or uniqueness claim. Raw provider exceptions remain trusted-host-only; public transports still require redaction. Disabled-factory-zero and denied-query-zero are distinct assertions unless composition actually defers construction until authorized dispatch.

## Options considered

| Option | Benefit | Cost and decision |
| --- | --- | --- |
| Scan current pages | No interface change | Shifting OFFSET and repeated reads; retain legacy API but add exact option |
| Exact optional lookup | Existing tenant/receipt key, bounded identity checks | Selected; consumers implement a new optional port |
| General filtering/keyset snapshot | Rich browsing | Requires cursor/query/order/snapshot contracts; separate work |
| Poison quarantine/restore | Manual recovery | Changes eligibility/status/storage/fencing and operator history; separate profile |

## Consequences and actions

Keep runtime in Audit.cs so fixed17/32 scaffold inputs remain. Use an additive sample PostgreSQL lookup adapter with parameterized tenant/receipt WHERE and validated owned schema; preserve existing PostgresStore/Integration SQL and all prior cases. Existing sink storage means pending outbox records remain absent until published. Duplicate receipt IDs in tenants A/B remain valid isolated keys. Generated service registry intentionally adds the new gateway; security registry stays unchanged.

Follow [protocol](../validation/audit-receipt-lookup.md), implement component and actual provider proofs, independent review, reviewed body-only7/8/18 sync and readback23/Project253, public suitable evidence and main pushes. M0, null actual hours, #3 Blocked, entire #20 row and original benchmark criteria remain unchanged. No production, full supported-host/provider, snapshot or performance qualification follows.
