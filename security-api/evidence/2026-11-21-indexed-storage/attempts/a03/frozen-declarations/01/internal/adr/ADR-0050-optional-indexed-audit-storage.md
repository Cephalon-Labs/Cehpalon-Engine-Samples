# ADR-0050: Optional PostgreSQL indexed audit storage profile

**Status:** Accepted bounded provider continuation. **Date:** 2026-11-21.
**Deciders:** Program integrator with independent scoped design review.
**Tracking:** #18 audit history; #7/#8 regressions. #3/#20 unchanged.

## Context

ADR0049's compatible TEXT source can scan unrelated tenant records. Existing Engine sink/lookup/resource-history ports already permit another project-selected storage implementation. Add an explicit sample profile with physical resource metadata and a composite index; keep Engine code/API and legacy storage unchanged. No new Engine commit or commit journal is manufactured for provider-only work.

## Decision

Add sample PostgreSQL indexed storage implementing existing ITenantChangeAuditIdempotentSink, ITenantChangeAuditLookupSource and ITenantChangeAuditResourceHistorySource. New versioned table `audit_sink_indexed_v1` has C-collated non-null tenant/resource_kind/resource_id/TEXT payload and UUID receipt, PK(tenant,receipt), plus composite B-tree index(tenant,resource_kind,resource_id,receipt). Exclude payload from index. Derive metadata and encoded payload from the same immutable record; append them in one atomic conditional INSERT/ON CONFLICT statement. Exact replay requires identical payload and all metadata under C equality; any difference faults with no overwrite. Concurrent same-data replay produces one physical row, conflicting writes one winner/one conflict. Sink dedup is not new authority, exactly-once delivery or a replacement for old outbox lease fencing.

The established bounded TEXT codec preserves NUL-bearing fields; no SQL JSON conversion. Resource query uses parameterized tenant/kind/id/after and SQL ORDER BY receipt LIMIT limit+1; exact lookup uses tenant/receipt. Validate all selected physical metadata against decoded receipt before returning typed pages, then existing Engine readers enforce scope, cursor/order and current policy. Validate lookahead too. Column equality is exact C/ordinal; canonical UUID ordering remains ADR0049. Unrelated indexed rows are not decoded/validated by a selective query; metadata corruption can hide rows, and this profile does not continuously attest integrity or run repair scans. Lookup/replay can detect touched inconsistent records.

## Actual Composition selection and lifecycle

Add a real optional Support module selected by configuration. Compile/validate immutable ActivationPlan before calling the module factory, reading its credential factory or performing SQL. PlanActivator owns the returned newly constructed module through ActivationLease. Disabled/invalid configuration has zero module factory/credential/connection/DDL/query work. Shared fixture/domain dependencies are counted separately. Reuse generated RelayGateway/LookupGateway/ResourceHistoryGateway under existing fresh grants; registry stays4695 and security0534. No new endpoint or Engine source/template/package change.

Separate explicit CreateNew and OpenExisting modes. CreateNew uses a new owned profile table/index in a DDL transaction with no IF NOT EXISTS or legacy migration/backfill. OpenExisting does read-only exact version/table/column/type/nullability/C-collation/PK/index-key inventory checks and fails closed on missing/incompatible structure; it never creates/repairs. Repeat CreateNew on an existing table faults. Constructor/plan compilation performs no I/O. Partial factory failures dispose owned client resources; an unknown commit may leave initialized storage, so cleanup does not claim rollback/delete of committed DDL. Module disposal rejects new work; in-flight operations remain awaited/owned by callers and are not forced-abandoned. Add no process-global pool clearing or host setting changes.

Pre-SDK refinement02: inspect ordinary persistent table shape in one coherent catalog snapshot. Require exact five non-null columns/types (text or uuid, not domains), C collations for four text columns, no defaults/identity/generated fields, exact PK(tenant,receipt) and valid/ready B-tree search index with four key attrs in declared order, no INCLUDE/expression/predicate, expected operator classes/collations and ascending options. Reject unexpected RLS/policies, user triggers/rules, inheritance/partitioning or extra schema behavior. Validation is point-in-time under trusted schema administration; later DDL is not continuously attested. Latch module inactive on disposal before cleanup so retained references reject new work without connections. Equal conditional UPSERT can create PostgreSQL MVCC versions even when logical content is unchanged: dedup means one visible history key/record, not zero duplicate-write/index/vacuum cost.

Old/new sinks are distinct histories. Selecting new sink for old outbox publishes pending receipts there, but already acknowledged receipts/legacy history are not silently copied or replayed. Outbox Delivered is not a destination-history attestation. No dualwrite, automatic switch, import/backfill, retention/delete or migration API. Restarts use explicit verified OpenExisting. Current-policy projection and coarse history/read permission remain independent of entity read/write permission; DTOs/IDs/cursors/metadata columns are not authority.

## Options and consequences

| Option | Benefit | Cost/decision |
| --- | --- | --- |
| Legacy streaming profile | Existing schema and full scalar compatibility | Retained; scan cost unmeasured |
| Explicit indexed metadata+TEXT profile | Database-side exact selection/keyset and atomic metadata | Selected; new versioned storage and index-write cost |
| Alter/backfill old sink automatically | One history location | Migration/cutover/retention semantics undefined; deferred |
| Add Engine-specific PostgreSQL API | Convenient vendor hooks | Existing ports suffice; keep vendor objects outside Engine |

The [PostgreSQL18 INSERT contract](https://www.postgresql.org/docs/18/sql-insert.html) supports conditional conflict handling; [multicolumn B-tree guidance](https://www.postgresql.org/docs/18/indexes-multicolumn.html) motivates equality-prefix/range-last keys. These are design rationale, separate from actual18.7 tests. Index existence does not guarantee index use or speedup.

## Validation and measurement boundary

Follow [protocol](../validation/indexed-audit-storage.md): actual Composition zero-work/ordering/disposal, schema/open/restart, atomic/concurrent replay/conflict, exact tenant/resource/cursor/policy/NUL bounds, real outbox→selected sink/ack uncertainty/replay/fencing, actual lock cancellation/quiescence and index inventory/query plans. Functional correctness plus selective SQL/EXPLAIN observations only; no timed benchmark or new latency gate. Freeze4096-row deterministic plan fixture and actual default planner settings, permit SeqScan and retain plans without coercion. Index write/storage/scan/performance remain unqualified.

Engine d0d49c7 remains unchanged with existing1475/1472 component/CI evidence. Execute changed consumer full provider+existing651security Windows/WSL; repeated unchanged full components are not a new indexed-profile proof. Hosted Engine CI baseline is labeled reused, not new indexed-profile hosted qualification. Body-only7/8/18 sync with no new Engine journal entry, readback23/Project253/other20row guards, public evidence and main synchronization. All M0/nullhours/#3 Blocked/#20/original benchmark criteria remain.
