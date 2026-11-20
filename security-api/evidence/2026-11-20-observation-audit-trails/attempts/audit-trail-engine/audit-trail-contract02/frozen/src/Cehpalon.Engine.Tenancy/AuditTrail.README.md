# Optional audit history and change trails

The engine supports project-selected Disabled, MetadataOnly, ChangedFields and BeforeAfterSnapshots modes. Automatic TenantAuditServices remains operation metadata. These new APIs record explicit domain/entity change receipts reported by trusted application/provider code, including before/after values only where configured. They do not infer a database commit or diff an arbitrary request/response.

```csharp
var policy = new TenantChangeAuditPolicy(TenantChangeAuditMode.ChangedFields,
    [new TenantChangeAuditRule("document.update", "write", "document",
        [new("title"), new("classification"), new("sensitiveNote", redact: true)])]);
var recorder = TenantChangeAuditRecorder.Activate(policy, () => trustedStore);
// Inside a checked tenant handler, after the application's mutation/commit receipt:
await recorder!.RecordAsync(context, providerReportedReceipt,
    () => new TenantChangeStates(beforeState, afterState), cancellationToken);
```

Leave the feature unselected or set Disabled to skip sink/history-source factory and constructor work; Disabled activation needs no provider delegate. MetadataOnly and empty matching field allowlists never call the state factory. Default mode is MetadataOnly; empty/unmatched operation/action/resource-kind rules deny recording. Settings are portable immutable objects: hosts can bind their own project configuration without adding vendor configuration to business contracts.

Receipts bind exact principal/issuer, authentication scheme, tenant, operation/action, entity kind/ID and authorization-resource version to the active checked context. Separate before/after entity versions are provider metadata: an ACL/resource-scope version is not necessarily the database row version. Create/delete receipts support reserved pre-authorized entity scopes; the host must establish that scope. Receipt IDs can serve as provider idempotency keys; there is no fabricated verified link to the automatic operation InvocationId or caller correlation. ReportedAtUtc is provider-supplied and optional; RecordedAtUtc is observed by this recorder.

Payloads are closed Missing/Null/Text/Boolean/Decimal/Redacted scalars. Names are bounded to128 UTF16 units, text to4096, at most64 fields per state/record, aggregate32768 text units per state and65536 per record. Inputs are defensively frozen with finite enumeration. Missing and Null differ for create/delete and field removal. Unknown fields are omitted. ChangedFields compares original typed values before redaction; a WasChanged flag preserves that fact even when both projected values are redacted. Snapshots include permitted unchanged fields. Projection happens before the persistence boundary, without retaining raw state objects in the record. This is not a managed-memory zeroization or trusted-host sandbox guarantee.

TenantChangeAuditHistoryReader requires a separate active audit-trail/tenant/read scope. Ordinary audit-history metadata permission does not grant field history. It validates bounds/tenant before returning and rechecks the context after persistence and projection. Current project policy omits/redacts older persisted fields again. Effective Mode never upgrades an older metadata/diff record into invented full snapshots; CapturedMode preserves original capture provenance. A provider can tighten retention/field access independently.

Recording is required persistence after a provider-reported change. Scope/receipt/payload/clock/cancellation/sink failures are wrapped in TenantChangeAuditWriteException with MayHaveCommitted=true, because the application change may already exist. The wrapper retains the original cause. An unhandled wrapper is an operation fault; applications may explicitly map it to a business rejection that still states possible committed effects. It is not ordinary business cancellation or rollback. A bounded independent write deadline (default5seconds, positive<=1minute) is passed to the sink, and timeout/caller cancellation/scope are rechecked after await. A started write can finish after caller abort. An uncooperative sink is not forcibly terminated; hosts own provider I/O deadlines/cooperation.

Supply durable append/history providers and application transaction/outbox/CDC integration as required by each project. The framework adds no database, automatic retry, exactly-once persistence, tamper-evidence, distributed transaction, universal field authorization, global session logout or production/benchmark qualification. Applications must never put secrets in metadata/version identifiers or allowlisted values inadvertently. No payload is captured by default.
