# Tenant selection and read-set contracts

Pinned net11.0 Release executable, fresh `--output=<result.json>` required. Covers request-local destination selection, parallel A/B contexts, fresh normal membership/resource/policy, explicit max64 grant/subset binding, input snapshots, principal/scheme pinning, late revocation/fault/cancellation without partial results, grant/identity/monotonic lifetime, checked child scope expiry, audit opt-out/parent lineage/failures and final audit-versus-delivery races. Exact raw attempts and source copies belong under ignored `.local`, never overwritten.

These are portable fixture proofs. Trusted read handlers/data ports remain responsible for read-only behavior and real query/cache tenant filtering. Prior permitted reads can occur before a later failure. No real IdP/durable provider, atomic multi-database snapshot, instant distributed revocation, performance or production qualification follows.
