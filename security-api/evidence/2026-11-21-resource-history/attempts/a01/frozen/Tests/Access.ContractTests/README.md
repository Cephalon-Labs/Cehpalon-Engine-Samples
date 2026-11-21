# Optional access and audit contracts

Run via `tools/verify_w1.py` on the pinned SDK for a locked Release build plus every existing suite. A fresh output directory retains failures. Covers exact RBAC/ABAC rules, fresh/expiring principal-tenant-version authority, UTC rollback, cancellation, defensive configuration copies, required audit ordering/failures, cleanup, checked history tenant/lease rejection and explicit ASP.NET authentication ticket mapping. Actual signed-token HTTPS/HTTP/GraphQL composition and generated gateway proof lives in Samples `security-api`.

No external IdP, durable audit database, supported-host or benchmark claim follows from these controlled contracts.
