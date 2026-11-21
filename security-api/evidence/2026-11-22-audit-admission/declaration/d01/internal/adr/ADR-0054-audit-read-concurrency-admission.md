# ADR-0054: Optional shared audit-read concurrency admission

**Status:** Accepted bounded continuation. **Date:** 2026-11-22.
**Tracking:** #18 with #7/#8 tenant and identity regressions. #3 and #20 unchanged.

## Decision and observed gap

ADR0053 exposes indexed receipt and resource history on HTTPS HTTP/GraphQL. Each request currently constructs an unbudgeted tenant dispatcher. Page limits and cooperative read timeouts do not bound simultaneous protected provider operations, particularly with the retained Pooling=false profile.

Select optional shared total/per-tenant audit-read concurrency admission as the next consumer slice independent of #3. Reuse Engine TenantOperationConcurrencyBudget and WithTenantConcurrencyBudget; add no Engine API/source, operation attribute, dependency, schema or SQL change. Alternatives considered were offline transport contract export and protected bookmarks. Both remain separate work; unsigned bookmarks currently grant no authority.

Add a nonpositional init-only optional configuration property on AuditReceiptTransportOptions containing immutable total/per-tenant integer limits. Null retains the original unlimited dispatch path and the exact four-position constructor/Deconstruct/Activate signatures. Validate selected limits before any caller callbacks or source work: both positive, per-tenant no greater than total. Inert profiles skip unused limit validation and all owned work. Capture one host-owned budget, created once for a selected configured profile and shared across receipt/resource, HTTP/GraphQL and every request-owned dispatcher. Expose aggregate immutable snapshot observations only; no tenant-tagged diagnostics, meter, background task or new listener.

The existing Engine budget admits only after fresh ticket identity, membership, resource and RBAC/ABAC checks, using the authorized resource tenant. Capacity rejection is the existing generic operation.capacity_exceeded result (HTTP503 and GraphQL error), before a business handler/source call. DTO tenants, cursors and operation grants never bypass authorization. Separate hosts do not share budget state. No waiting queue, fairness, rate limit or distributed capacity claim.

## Lifetime

Keep the existing outer host Admission as owner of the entire bridge, including result mapping. Budget occupancy covers protected dispatch and owned-handler completion; authentication, DTO mapping, serialization and wire flush remain outside the capacity interval. Reader timeout and caller cancellation remain cooperative: an admitted slot cannot be released merely because the client stopped waiting.

Synchronously close outer admission and initiate permanent budget drain before asynchronous shutdown. Stop the app before awaiting drain; join both outer work and budget work before the one source disposal, including stop faults and held empty/populated results. Retain all in-flight ownership and token-only probes. Do not use WaitAsync/WhenAny to abandon provider work. Unselected/null budget does no budget construction or snapshot work.

## Evidence and delivery

Preserve all existing308 provider and651 security cases and generated service/security registry bytes. Add24 declared cases (four shared controls and ten per HTTP/GraphQL), with actual HTTPS/JWT, scheduled simultaneous work and indexed PostgreSQL, for332 total provider cases per host including three restart cases. The exact matrix is in the linked protocol. First development attempt and all failures/corrections are retained; source/declaration freeze precedes SDK execution. Final changed-consumer lanes run serially from committed source on Windows and WSL. Unchanged Engine component/hosted CI evidence is explicitly reused, not rerun/new host CI. No timed benchmark, threshold, corpus4096, Pooling=false, package, schema, SQL or host configuration change.

Root is sole remote writer. Body-only #7/#8/#18 tracking updates, no Engine journal addition if Engine unchanged; reviewed exact plan/dry/apply/readback23/direct Project253 and preservation of all metadata/milestones/unknown hours/other20 complete task bytes. #3 stays Blocked; #20 entire row and original benchmark remain unchanged. Publish suitable source/raw/hash evidence, sync/push all mains, remove only owned merged refs, retain worktrees/raw/objects/eight user files and stop exact owned fixtures/helpers. M0 remains; local tests do not qualify throughput, capacity, native Windows DB, external IdP or production readiness.

[Requirements](../requirements/2026-11-22-audit-read-admission.md) · [Protocol](../validation/audit-read-admission.md)
