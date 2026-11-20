# Experimental tenant operation boundary

This BCL-only assembly references Core and Identity.Contracts. It is an in-process
request/reply boundary, not a JWT/OIDC validator, provider sandbox, RLS implementation,
distributed revocation service or real transport certification. Full #7/#8 acceptance
and #3 supported-Windows qualification remain open; umbrella maturity remains M0.

`TenantOperationRegistryBuilder.Register<TRequest,TResponse>` binds an operation ID,
action and resource kind in trusted startup code. A required pure `freezeRequest`
callback must create a **deep defensive snapshot** of the request; `selectTarget`
derives the untrusted tenant/resource selection from that same frozen request.
The engine cannot infer deep immutability of arbitrary application payloads. Callers
must not retain mutable aliases to the frozen snapshot; handlers must use the checked
context for provider access rather than treating payload/metadata as authority.

`TenantOperationDispatcher` resolves a fresh configured identity, validates its
explicit issuer/scheme trust and time interval, resolves membership bound to the
exact issuer+subject and selected tenant, resolves resource ownership, and finally
checks the configured policy. Missing policy denies. Requested tenant is supplied
to resource lookup because resource IDs can be tenant-local; the returned actual
tenant/kind/ID must still match. Semantic denials return the same `access.denied`
error and do not create a business handler. Core correlation metadata supplies no
identity, tenant, role or policy authority.

After authorization the boundary mints an internal operation-bound lease, then
bridges into Core through a private invocation type/registry. Handler factories
execute only after lease and cancellation guards and transfer a **new owned handler**.
Core disposes the bridge and its handler on success/failure/cancellation; execution
and cleanup errors are both retained. A cleanup-thrown access-denied exception is
wrapped as an unexpected cleanup fault with the original cause, so it cannot be
mistaken for a new semantic authorization denial after business work. Cancellation is cooperative, not forced
interruption of application code. Unexpected authority/policy faults propagate
without business work; real transports must map/sanitize those failures themselves.

`TenantOperationContext` has no public minting constructor. Its immutable identity,
membership, resource, operation/action and correlation are bound to one invocation.
`DemandAccess(tenant,kind,id,action)` rejects a different tuple, an expired lease or
a context retained after completion. Validity is bounded by the identity/member
expiry and an explicit maximum lease lifetime. Clock rollback before lease creation
time also rejects access. Monotonic elapsed time additionally caps the effective
lease lifetime, so a smaller UTC rollback cannot extend it. Negative elapsed time,
observed expiry/invalidity or a clock fault permanently revokes the lease; clock
recovery cannot resurrect it. This is an in-process capability for trusted application
code, not protection against reflection, malicious handlers or code that bypasses
the checked provider boundary.

Authoritative sources and policies are trusted configured adapters. Constructing
public snapshot DTOs does not authenticate anyone. A protocol adapter must use an
established implementation to validate signature, issuer, audience, token type,
lifetime and subject before emitting identity. No tokens or claim bags are stored
in these contracts. The library refreshes sources per invocation but has no atomic
transaction with provider data or external revocation: a membership/resource can
change after the check. Provider adapters must enforce scoped keys, conditional
versions/transactions/RLS and cleanup appropriate to their own semantics.

No `AsyncLocal` or ambient principal/tenant is used. Registration builders are for
single-writer startup; their built registries are snapshots safe for concurrent
reads. Auth source implementations themselves must support the application's
concurrency/lifetime model. API/Worker/cache/retrieval/event entrypoints must use
this boundary explicitly; the existence of these contracts does not certify those
paths or automatically secure an ordinary unguarded Core registry.
## Optional audit and history

Pass `audit: new TenantAuditServices(yourSink)` to `TenantSecurityServices` to enable required structured operation history. Without it there is no audit envelope or sink call. Persist authorization success before business factories, then a terminal record after owned cleanup. Early tenant/policy denial or infrastructure fault has a terminal record without an authorized tenant. Unknown operations/contract mismatches and HTTP authentication middleware rejections occur outside this tenant invocation boundary; hosts should configure separate protocol/access security logging for those events.

`ITenantAuditSink.AppendAsync` is awaited with an independent bounded cancellation token (default five seconds, maximum one minute). Implementations must honor cancellation and supply the required durability. A pre-business write failure prevents execution. A terminal failure throws `TenantAuditWriteException` with conservative `OperationMayHaveExecuted=true`; do not blindly retry mutations. If both operation and persistence fail, an aggregate preserves both causes. A process crash can leave an authorization record without a terminal event; transactional outbox/idempotent effects require a provider-specific implementation. No fire-and-forget writes, implicit retries or best-effort downgrade.

Events contain invocation ID, stage, timestamp, fixed outcome, operation/action/kind and verified principal/tenant/resource identifiers. No token, raw claim bag, body, response or exception text is recorded. Identifiers may still be personal/sensitive data; consumers own access control, minimization, retention, encryption, archival and deletion. This is operation/security history, not automatic before/after field-value versioning or tamper-proof storage.

Use `TenantAuditHistoryReader` over your `ITenantAuditHistorySource` inside a tenant handler authorized for `audit-history` kind, `tenant` resource and `read` action. It demands the active scope before and after the asynchronous call, caps pages at 200 and rejects foreign/unverified tenant records. Your source must scope queries and pagination to the provided checked tenant. Do not expose the raw sink/history source as a public endpoint. The source/sink lifetime remains consumer-owned.

## Tenant selection and read sets

`builder.RegisterTenantSelection()` adds `tenant.select` with action `select`, kind `tenant` and destination-tenant ID as resource ID. Use normal `TenantSecurityServices` and destination membership/resource/policy. A successful `TenantSelectionRequest` only returns the selected ID; it does not mutate a global current tenant, change login identity, issue an authority token or bypass the next data request's checks. Keep a selected tenant in client/tab/request state and send it as an untrusted selector. Parallel requests retain their own checked context; A work cannot acquire B authority because another tab switched.

For explicit cross-tenant reads, register a separate `TenantReadSetOperation<TQuery,TResponse>` and supply an `ITenantReadSetSource` to `TenantReadSetDispatcher`. The source must freshly grant an exact principal/operation/resource-bound tenant set. `requestedTenants: null` means the tenants in that grant; a nonempty caller subset must be contained in it. Grants and subsets are bounded to 64 exact unique IDs. Empty, duplicate, over-limit, wildcard or ungranted selection cannot promote access. Large global reporting/catalog pagination needs a separately designed provider capability; this implementation rejects over-limit input instead of silently truncating it.

```csharp
var operation = new TenantReadSetOperation<ReportQuery, ReportRows>(
    "report.read", "report", query => query.Copy(), query => query.ReportId,
    () => new ScopedReadHandler(dataPort));
var dispatcher = new TenantReadSetDispatcher(securityServices, trustedReadGrantSource);
var result = await dispatcher.DispatchAsync(operation, query, correlation,
    requestedTenants: null, cancellationToken: token);
```

Read-set handlers are registered by trusted application code and always receive action `read` with a normal checked tenant context. The framework cannot prove arbitrary C# handlers have no writes. Data/query/cache ports must demand and apply the checked tenant, not caller payload tenant fields. The query snapshot callback must deep-copy mutable graphs; the dispatcher freezes the query and caller subset before authority awaits, then supplies a separate frozen query per child. Response values and application code remain trusted; the framework cannot inspect arbitrary row types for semantic tenant ownership.

The dispatcher pins principal **and authentication scheme**, but resolves the original source afresh for every tenant. Each child runs fresh membership/resource/policy checks and can share a supplied tenant concurrency budget. The batch lease is bounded by its grant, initial identity and configured maximum; child identity validity is capped by that same lease. It checks the batch after each child and after the final required audit write before returning results. No partial result is returned on denial, cancellation or fault. Earlier authorized reads may already have run before a later failure; this is not an atomic cross-provider snapshot, rollback, instantaneous distributed revocation, a universal administrator grant or a write fanout API.

When audit is selected, a required control-plane authorization event precedes child handlers, each normal tenant event carries `ParentInvocationId`, and a control-plane terminal event follows processing. Control-plane records have `AuthorizedTenant=null` and are excluded from tenant history. `ResourceId` on the root is the grant version, not a caller-supplied tenant assertion or a token. A terminal record describes processing at its observation point: audit persistence and transport delivery cannot be atomic. If the grant expires or caller cancels during the final write, the terminal processing event can be `Succeeded` while the final lease/cancellation gate still withholds all response rows. Applications must distinguish processing history from delivered responses.
