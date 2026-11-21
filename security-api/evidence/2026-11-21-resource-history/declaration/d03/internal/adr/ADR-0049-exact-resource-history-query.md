# ADR-0049: Optional exact resource history with typed continuation

**Status:** Accepted bounded continuation. **Date:** 2026-11-21.
**Deciders:** Program integrator with independent scoped design review.
**Tracking:** #18 audit history retrieval; #7/#8 regressions. #3/#20 unchanged.

## Context

Receipt lookup finds one known change. Consumers also need bounded history for one resource kind/id. Existing tenant-wide OFFSET pages remain available. Add a separate optional contract with explicit ordering/binding rather than change their behavior or imply a chronological snapshot.

## Decision

Add immutable TenantChangeAuditResourceCursor(tenant, resourceKind, resourceId, afterReceiptId), TenantChangeAuditResourceQuery(resourceKind, resourceId, limit=50, continuation=null), TenantChangeAuditResourcePage(entries, nextCursor=null), ITenantChangeAuditResourceHistorySource.ReadAsync(authorizedTenant, query, cancellationToken), and optional TenantChangeAuditResourceHistoryReader constructor(source, policy)/Activate(policy, sourceFactory)/ReadAsync(context, query, cancellationToken=default). Keep runtime in Audit.cs/fixed17/32 scaffold inputs, all existing history/lookup/source APIs unchanged.

Kinds use existing OperationId validation; resource IDs use existing bounded Opaque512 validation. Limits1..200, non-null tenant/query/entries and nonempty cursor receipt. Page constructor freezes at most200 non-null records. Public cursors are untrusted selection metadata. A cursor binds tenant, exact ordinal kind/id and last receipt; page size may change. The contract's ordering is ascending lowercase Guid-N ordinal, defined by receiptId.ToString("N") and StringComparer.Ordinal, version1 of this typed contract. It describes receipt-key order. RecordedAtUtc/commit order and chronology are separate concerns.

The reader checks caller/live audit-trail/tenant/read scope and input cursor tenant/filter binding before source I/O. Pass the original token and preserve provider failure references; add no timer/retry/background work. After await check caller/scope, reject null page/oversized page or any row outside exact tenant/kind/id. Require each returned receipt strictly greater than input continuation and previous row in canonical order, rejecting duplicate/nonadvancing/nonascending rows. If NextCursor exists, require nonempty page, exact tenant/filter binding and AfterReceiptId equal to its last returned receipt. Nonempty underfilled pages may carry a valid continuation; a cursor is provider continuation information, not proof of a global backlog. Project all records with existing captured immutable read policy into a new bounded page and check caller/scope again, including an empty page. Disabled activation skips its factory; direct construction rejects Disabled.

Pre-SDK error-shape refinement: after the live scope check, input cursor tenant/filter mismatch is ArgumentException for invalid caller selection metadata, with no provider query. Semantic scope denial remains TenantAccessDeniedException (protected dispatch maps it to access.denied). Returned source-page identity/order/continuation/null/count faults are InvalidOperationException. Preserve the original provider exception object; do not relabel it based on later signals.

Selection filters do not grant entity read/write authority or widen history permission. Use a fresh protected service dispatch for each request. No all-tenant selector, wildcard/predicate DSL, field-value filters, time ranges, signed/encrypted cursor or cursor authenticity claim. A caller can construct another allowed position without gaining broader tenant/filter access. New reader selection is required for changed project read policy; no automatic policy reload.

## Provider profile and limits

Add an independent PostgreSQL adapter over existing audit_sink. Validate owned schema and parameterize physical tenant/after. Select physical tenant/receipt and existing TEXT payload in native uuid keyset order, using C equality for tenant. Decode each streamed bounded payload with the established PayloadCodec, validate decoded tenant/receipt against physical keys, then apply exact Ordinal kind/id selection in managed code. Retain at most limit+1 matching records plus the current decoded bounded row, stopping after lookahead; return up to limit and a cursor from the last returned record only when lookahead finds another match. Keep old PostgresStore/SQL/schema/indexes/packages and all156 prior cases unchanged. Verify actual PostgreSQL ordering agrees with canonical Guid-N across adversarial keys and all page sizes. The [PostgreSQL18 source](https://github.com/postgres/postgres/blob/REL_18_STABLE/src/backend/utils/adt/uuid.c) compares uuid bytes; this is source rationale, separate from actual18.7 fixture proof.

Pre-SDK provider refinement03 preserves the existing scalar wire profile. TenantChangeValue.Text permits well-formed UTF16 controls including NUL; PayloadCodec escapes these into stored TEXT. [PostgreSQL18 JSON documentation](https://www.postgresql.org/docs/18/datatype-json.html) states jsonb rejects the NUL escape and JSON processing may reject it even for json. Therefore the original unexecuted JSON/JSONB filter proposal is retained as preparation evidence and replaced before SDK. No regex JSON extraction or storage migration is selected. Valid NUL-bearing matching and unrelated resources must round-trip via old AppendOnce/lookup and new query. Malformed scanned payload/physical identity is a provider-integrity fault even on an unrelated resource; do not skip corruption silently.

Page size bounds retained matching records, not total rows scanned, decoding work, elapsed time or all driver/network buffering. Scan cost, connection occupancy and reader disposal/drain are unmeasured; caller cancellation is cooperative. A future indexed metadata/storage profile needs separate schema/migration and performance evidence. This functional profile makes no database-side entity-filter or universal memory/IO bound claim.

The sample returns NextCursor only after lookahead sees another matching row. Inserts at/before a returned position can be missed; later keys may appear; retention/deletion can remove rows, including the bookmark row. No stable snapshot, complete timeline, delivery-health, global-empty, uniqueness-of-business-change or chronological guarantee. A nullable continuation does not attest permanent completeness. Provider ports must implement the declared canonical ordering rather than assume every database's native GUID ordering matches.

Generated sample adds a fifth lazy typed Core gateway with explicit operation grant and fresh checked history boundary. Existing mutation fixtures retain their Composition host. Registration is not activation/authority, and no separately activated Composition query module or new HTTP/GraphQL endpoint is claimed.

## Options and consequences

| Option | Benefit | Cost/decision |
| --- | --- | --- |
| Scan legacy tenant pages | No new port | Shifting OFFSET/repeated reads; retain but add exact option |
| Exact resource + typed receipt continuation | Bounded selection, explicit cross-provider order and validation | Selected; new optional provider implementation |
| Recorded-time keyset/snapshot | Chronological exploration | Timestamp precision, tie-breaks and snapshot lifetime require another profile |
| Cryptographic history/cursors | Different integrity/confidentiality properties | Separate key custody/provenance contract; not implied by DTO binding |

## Actions

Follow [protocol](../validation/resource-history-query.md), component/adversarial/provider proofs and independent review. Reviewed only7/8/18 body/Engine SHA journals, readback23/Project253, preserve #3 Blocked/#20/original benchmark/all metadata/nullhours/M0. Public suitable source/raw, checksums/index/SDK exclusions, main3 pushes and owned merged branch cleanup. No production, full supported-host/provider or performance qualification.
