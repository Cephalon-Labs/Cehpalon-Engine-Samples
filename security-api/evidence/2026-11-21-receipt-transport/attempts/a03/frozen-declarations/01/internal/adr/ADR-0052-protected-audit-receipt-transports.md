# ADR-0052: Optional protected audit receipt lookup transports

**Status:** Accepted bounded continuation. **Date:** 2026-11-21.
**Deciders:** Program integrator with independent design review.
**Tracking:** #18 with #7/#8 regressions; #3/#20 unchanged.

## Context

ADR0048/0050/0051 already provide tenant-scoped exact lookup, an optional indexed PostgreSQL source and cooperative read budgets. The PostgreSQL lookup proof uses a local generated gateway with fixture-service authority. SecurityApi already has tenant-wide history HTTP/GraphQL wiring, and its PostgreSQL integration explicitly tests HTTP history; that wiring alone does not establish provider GraphQL-history execution. The next missing proof selected here is exact receipt lookup over actual authenticated HTTP and GraphQL.

## Decision

Add a small opt-in HTTPS host in Samples audit-outbox, retaining the current outbox→aliased security-api project reference. No reverse project reference, new package, Engine source/API, new endpoint in existing hosts, or new generated operation is required. Reuse LookupGateway and its exact LookupRequest/LookupResult Core signatures. A request-owned typed ITransportOperationDispatcher explicitly maps sample wire DTOs to those types, invokes the generated gateway and maps only the checked, policy-projected result to a shared primitive/nullable response. Include resource kind, receipt ID and captured/current modes. Preserve legitimate null lookup results and absence semantics for the selected store.

Expose only HTTPS POST `/audit/receipts/lookup` and optional GraphQL `trailReceipt`. Exact resource-history transports, general API packaging, encryption, admission options and metrics are deferred. The host source is specifically PostgresIndexedAuditStorage, opened through explicit read-only OpenExisting. Fixture creation/seeding is separate. No automatic table creation, migration, legacy HTTP lookup or all-provider claim.

Compile an immutable Composition plan from transport/security selection before host, security, source, credential, key or configuration callbacks. Both transports off yields an inert host and zero module-owned callback/source/listener/service/endpoint work; skip unused invalid budget values. A selected transport requires security and lookup modules. Enabled read budgets retain ADR0051 positive≤one-minute/null semantics and are validated before source construction. Invalid returned security/read-policy configuration can fail after its selected factory but before source activation; do not conflate this with plan rejection. Startup OpenExisting catalog work is distinct from per-request lookup SQL.

The trusted host configuration supplies actual TLS and an established JWT authentication handler, issuer/audience/algorithm/key trust and explicit scheme. Authenticate before authorization. Each request or GraphQL field uses a request-owned fixed HttpContext accessor and AspNetCoreJwtIdentitySource over a validated ticket, plus fresh injected membership/resource/RBAC-ABAC services. Do not use LookupHost.Run, its invented fixed service identity, a constructed DTO, a principal flag or tenant metadata as authority. Require the existing audit-trail/tenant/read checked scope and an explicit project lookup operation grant; ordinary entity/history permissions alone are insufficient.

The wire bridge performs no duplicate reader authorization logic. Let TenantOperationDispatcher and TenantChangeAuditLookupReader.ActivateWithBudget enforce current checked context, tenant/receipt identity and captured immutable read policy. Map data only after success. Existing generic unexpected-error redaction and transport status semantics remain; no new timeout status. Reader budget ends at reader completion and excludes DTO serialization/network flush, so no end-to-end response deadline is claimed. Local signed-token fixtures are not real IdP/session/provider qualification.

## Ownership and shutdown

The selected source factory returns a newly constructed, uninitialized storage instance. Once delivered, ActivationLease owns its OpenExisting/lifetime; undelivered partial resources remain factory-owned. Host activation follows source activation so reverse disposal stops the host before storage. Host shutdown closes admission synchronously and joins every admitted bridge/dispatch task before storage disposal, even if Kestrel StopAsync fails or aborts an HTTP request. Stop/dispose failures must not skip the join; retain primary and cleanup failures. Do not use WaitAsync/WhenAny to abandon work.

A trusted optional sample probe can observe request tokens/completion, await a post-SQL hook within the reader source budget and force a known stop failure. Default execution has no hook. It is test instrumentation without payload/credential logging, not a new portable observation API. Client cancellation/completion does not establish server or backend completion. Observe RequestAborted/resolver cancellation at the server, then actual task/backend quiescence; held uncooperative work stays owned until explicitly released/joined. Provider callback obligations remain ADR0051's.

## Options considered

| Option | Benefit | Cost and decision |
| --- | --- | --- |
| Extend existing SecurityApi mutation/history host | Reuse fixture setup | Broader changes and coupling; leave original651 cases/host unchanged |
| Dedicated indexed lookup host with typed wire bridge | Bounded transport/authority/provider proof, unchanged generated registry | Selected; project-owned composition/handlers and explicit shutdown ownership |
| Expose local LookupHost directly | Minimal code | Rejected: invents service identity and bypasses request authentication |
| New wire operation/gateway IDs | Direct wire registration | Unnecessary dispatch duplication; use explicit bridge to existing signature |

[Middleware ordering](https://learn.microsoft.com/aspnet/core/fundamentals/middleware) and [RequestAborted](https://learn.microsoft.com/dotnet/api/microsoft.aspnetcore.http.httpcontext.requestaborted) are design references. Actual token propagation and server completion require the declared wire tests.

## Evidence and delivery

Add28 consumer cases: four shared Composition/lifecycle controls and twelve per transport, including actual indexed PostgreSQL lookup, authenticated/fresh denial, same-Guid A/B isolation, absence/invalid input, policy projection, redacted provider corruption, observed SQL Lock cancellation and joined reuse. Include GraphQL sibling isolation/fresh revocation as subcontrols and positive held server ownership/client abort plus stop-failure drain controls. Preserve original244 provider cases/651 security cases and their source, existing4096-row corpus, Pooling=false, packages and benchmark gates. Expected provider272 per host; security651 remains. Both service e3a87d and security0534 generated registries remain byte-identical.

No Engine commit or duplicate journal entry is manufactured. Engine5184517 component1523Windows/1520WSL and four hosted jobs44903430462/44903430522 are explicitly reused baseline, not new host execution. Execute changed-consumer security/provider final lanes serially on Windows and WSL from committed source. Four new local consumer lanes do not establish hosted PostgreSQL/native Windows DB, reserved resources, performance or production acceptance. Keep M0.

Review/execute only #7/#8/#18 body updates, read back23 mirrors and253 native Project fields, preserve other20 whole rows/task bytes and every metadata/milestone/null-hour value including #3 Blocked/#20. Publish reviewed suitable evidence and SHA256SUMS, push three mains with Engine unchanged, remove only owned merged refs, retain source/raw/user files, stop exact owned fixture/helpers/native listener with data/image/volume retained. Billing/usage blocks defer only the exact affected GitHub action without billing changes or unchanged rejected reruns.
