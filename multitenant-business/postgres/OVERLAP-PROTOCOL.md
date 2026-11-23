# Concurrent order proof protocol

Declared 2026-11-24 for Engine #7 and #12. Preserve the existing exact
Engine 6fe7254404cf6b148370bd95befe8331e8932354 reference, .NET SDK 11.0.100,
runtime 11.0.0, locked Release restore, and pinned disposable PostgreSQL
18.6 Linux/amd64 image with Npgsql 10.0.3. Run the original migration,
single-connection, and lease controls first. Keep migration and fixture
initialization in the runner.

Use READ COMMITTED transactions and fixed seeds at revision zero. Open
at most two application leases in a separate pool, and use a third,
unpooled connection for runtime-role observation of only the participants'
own backends. A gate after a returned UPDATE row holds the transaction
open. The waiter signals immediately before submitting UPDATE. Ordering
is determined by those gates and PostgreSQL state receipts.

1. Overlap A and B using order ID 2 in their own scopes. Both updates
   arrive at the post-UPDATE gates on distinct backend PIDs. PostgreSQL
   must observe both idle in an open transaction. Release B, verify it
   commits while A remains held, then release A and verify both tenant
   rows changed exactly once. Check B's returned backend is unscoped.
2. Compete for tenant A's order 3 with two updates at expected revision
   zero. While the first is held after UPDATE, PostgreSQL must observe
   the second active on an UPDATE waiting for a lock with the first PID
   as its only blocker. Release the first to commit. The second completes
   with zero rows and the final row has revision one. The terminal status
   guard and revision check can both exclude the second update. The
   retained single-operation wrong revision case tests the revision check
   with the row still eligible.
3. Repeat the real lock-wait observation on tenant A's order 4. Cancel
   the waiter before releasing the holder. Require the original caller
   token, PostgreSQL query-canceled status and one acknowledged rollback.
   While the holder still owns the other lease, reuse the waiter's exact
   backend and verify absence of tenant scope and rows. Release the
   holder, verify the single committed row and check one checkout and
   one order UPDATE attempt per dispatch.

After releasing gates, await both dispatches in every case. Provider
observation has a five-second cooperative deadline. Retain any failed
execution before corrections. The runner verifies owned container,
volume, and loopback cleanup and records pinned inputs and results.
Report boolean outcomes and counts without raw query or credential data.
This protocol covers one local PostgreSQL profile and these conditional
operations. It supplies no throughput, production, external IdP, or
commit-acknowledgment-fault evidence.
