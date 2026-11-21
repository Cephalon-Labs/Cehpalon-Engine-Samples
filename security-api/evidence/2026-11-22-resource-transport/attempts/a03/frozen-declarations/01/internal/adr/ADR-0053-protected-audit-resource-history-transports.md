# ADR-0053: Protected audit resource history over HTTPS HTTP and GraphQL

**Status:** Accepted bounded continuation. **Date:** 2026-11-22.
**Deciders:** Program integrator with independent design review.
**Tracking:** #18 with #7/#8 isolation and identity regressions. #3/#20 unchanged.

## Context

The user requests resource history through actual HTTPS HTTP/GraphQL, cross-tenant tests and synchronized mains. ADR0052 provides the indexed receipt host and request-owned transport bridge. The existing Core ResourceHistoryGateway, query/cursor contract, checked reader and cooperative budget already support resource selection. Extend that host rather than duplicate its authentication, source ownership or drain logic. Engine source and APIs remain unchanged.

## Decision

Add two init-only selector properties to AuditReceiptTransportOptions: ReceiptLookupEnabled defaults true and ResourceHistoryEnabled defaults false. Preserve its exact four positional constructor parameters, Deconstruct and existing ActivateAsync signature; old default receipt behavior and counters stay compatible. Effective selection is (HTTP or GraphQL) and (lookup or resource). Both reads off, or both transports off, yields an inert host with zero owned callbacks/source/listener work, ignoring unused invalid timeout values. Resource-only and combined selections share one indexed source/OpenExisting, security configuration, admission latch and full drain. Map each operation only when selected; resource-only has no receipt route or GraphQL receipt field.

Add HTTPS POST `/audit/resources/history` and GraphQL `trailResourceHistory`. Use primitive sample-owned request/cursor/page DTOs. Request contains Tenant, ResourceKind, ResourceId, Limit (default50), and nullable Continuation. Cursor contains Tenant, ResourceKind, ResourceId and nonempty Guid AfterReceiptId. Response contains Tenant, projected AuditReceiptView entries and nullable NextCursor. Reuse the existing projected record mapper, including resource kind and capture provenance.

Pure binding validation enforces existing tenant/kind/id bounds, limit1..200, nonempty cursor Guid and Ordinal equality of cursor tenant/kind/id with the request, before Core query construction/dispatch/provider work. Malformed or cross-bound input is validation.failed, without a query. The explicit request-owned wire bridge maps to the unchanged ResourceHistoryRequest/ResourceHistoryResult signatures, then invokes existing generated ResourceHistoryGateway. Add no Operation attribute, duplicate operation ID, package, Engine source/API or registry change. Core checked reader still validates the actual authorized tenant, identities/order/cursor and policy before mapping.

Authentication remains the actual established ASP.NET JWT ticket and explicit scheme/issuer trust, followed by fresh project membership/resource/RBAC-ABAC checks on each request/GraphQL field. Require the distinct `trail.resource-history` operation grant and audit-trail/tenant/read scope. Lookup, ordinary history and entity permissions alone do not authorize this operation. Resource selection does not imply permission to read the original entity. DTOs/cursors and supplied tenant values are not authority. Never use the local ResourceHistoryHost fixture identity for serving.

## Pagination and evidence boundaries

Preserve ascending lowercase Guid-N receipt-key order and SQL keyset/limit lookahead. Pages can be empty or terminal-underfilled, and page size can change between requests. A caller-created bound cursor whose bookmark row is absent remains valid selection data. Insertion/deletion can alter later pages; cursors are unsigned bookmarks, without chronology, stable snapshot or authenticity claims. Do not claim that the concrete indexed source emitted an underfilled nonterminal page: Core permits that separately, while this source uses limit+1 lookahead.

Current immutable read policy projects every returned record; selected physical metadata and decoded identities remain checked by the source and reader. This query does not scan/attest unrelated corrupted rows. Reader budget is independent per invocation and excludes page DTO mapping/serialization/network flush; entry count is not a response-byte or latency limit. Preserve generic error redaction/status semantics.

## Lifecycle and compatibility

Compile the immutable Composition plan before owned factories/configuration/credentials; validate selected configuration before source construction. Source factory returns a new uninitialized PostgresIndexedAuditStorage and the host uses OpenExisting only. Fixture provisioning remains separate. Startup catalog SQL is distinguished from per-request lookup/resource query counters. Preserve old lookup probe semantics and add distinct resource gateway/handler/source/result counters, dispatch/work tokens and token-only hooks; no raw page/record diagnostic hook.

All operations share atomic close/admit and full joined shutdown. Mixed receipt/resource calls must finish before the single source is disposed, even if stop fails or a client aborts. No WaitAsync/WhenAny abandonment. Client completion is not server completion; observe server tokens, await admitted work and verify exact backend quiescence/reuse. SQL cancellation witnesses run one controlled source query or bind an exact active backend/tag without treating a concurrent mutable LastBackendPid as authority. Undelivered factory resources and undisclosed provider work retain their existing ownership rules.

## Alternatives

| Option | Decision |
| --- | --- |
| Duplicate resource-only host | Rejected; would duplicate security and lifetime behavior |
| Extend existing host with nonpositional selectors | Selected; compatible defaults and project-level independent selection |
| New wire gateway/operation or Engine API | Existing generated signature plus explicit bridge suffices |
| Signed cursors, encryption, metrics, new admission limits | Separate work; not required by this transport continuation |

## Verification and delivery

Add36 provider cases: four shared selection/ABI/mixed-lifetime controls plus16 per HTTP/GraphQL. Preserve old272 provider cases (269main+3restart), security651, servicee3a87d/security0534 registries,4096-row corpus, Pooling=false, SQL/schema/locks/packages and all benchmark criteria. New total308 per host. Exercise actual wire pagination/cursor validation, fresh grants/cross-tenant same IDs/parallel siblings, projection/NUL fields, corruption redaction, SQL budget/client cancellation and held empty/nonempty results with joined shutdown.

Execute four changed-consumer final lanes serially: Windows security651/provider308, WSL security651/provider308, from committed/frozen source with matching maps. Engine5184517 components1523Windows/1520WSL and four hosted jobs44903430462/44903430522 are reused baseline only, not new resource-host hosted proof. Keep M0; local indexed PostgreSQL/token fixtures do not establish native Windows DB, external IdP, all-provider, performance or production qualification.

Root owns remote writes. Update only #7/#8/#18 bodies with no new Engine journal entry; reviewed plan/dry/exact apply/readback23/directProject253 and strict other20row/taskbyte/allmetadata/milestone/nullhour preservation. Keep #3 Blocked and #20/original benchmark unchanged. Publish suitable source/raw/failed attempts with SHA256SUMS/index equality, push mains, remove only owned merged refs, preserve eight user files/worktrees/objects and stop exact owned fixture/helpers/native listener while retaining data/image/volume. Usage/billing blocks defer only the affected GitHub action without billing changes or unchanged rejected reruns.
