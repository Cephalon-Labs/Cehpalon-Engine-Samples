# Audit trail contracts

Run with pinned SDK11.0.100-rc.3.26522.148 and a fresh retained output. The executable covers project modes/activation, explicit provider-reported receipts and exact checked-context binding, closed scalar representations, bounded immutable snapshots, allowlist/redaction before sink, original change metadata, current-policy history filtering and capture provenance.

Tests use actual portable TenantOperationDispatcher contexts and a controlled in-memory sink/history provider. A fixture mutation precedes failing append/cancellation/expiry to assert MayHaveCommitted and the required-operation audit fault boundary. No database/outbox/CDC/durable provider, rollback/exactly-once, supported-host, performance or production qualification is established. Raw output contains check names/counts and sanitized error types, no actual credentials or payload values.
