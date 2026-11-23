# Scoped PostgreSQL order proof

This optional executable exercises a typed order store through the Engine tenant
dispatcher. Two synthetic principals read order 1 in their own tenants. The
store validates the checked operation, action and resource before acquiring a
connection. It derives the tenant from the checked context, binds it locally
to the owned transaction, and uses explicit tenant and order parameters with
forced row-level security. The runtime account has SELECT and column-limited
UPDATE permissions for the order table. The proof uses a runtime-only connection
string. Its startup does not apply a migration.

The runner provisions an owned PostgreSQL 18.6 container and creates separate
migrator and runtime logins. It applies the fixed SQL file explicitly with psql
as the migrator. The SQL file is intended for a single-transaction apply to a new
schema. The runner first verifies that a failure after the SQL body leaves no
schema, then applies the file successfully and verifies that a second apply is
refused. A fixture administrator seeds the two synthetic rows separately.

Use Bash with Docker, a clean Engine checkout at
`6fe7254404cf6b148370bd95befe8331e8932354` and a path to the Samples-pinned
.NET Linux SDK. Both repositories must be usable by Git inside the shell.
Use a new evidence directory inside the Samples checkout's `.local/` tree.

```bash
bash multitenant-business/postgres/run-proof.sh \
    "$dotnet" "$engine_root" "$PWD/.local/postgres-app/<new-attempt>"
```

The runtime login connects through a one-connection pool. The assertions check
the same order ID under both tenants, zero store work for mismatched resource or action and denied,
stale or pre-canceled calls, committed revision and the effects of canceling
after an update but before commit. The proof opens a new logical connection
on the same backend after each commit or rollback under test and expects to
see neither tenant scope nor rows. The runner confirms removal of the owned container,
its volume and the loopback listener.

The concurrent checks use two application connections plus a read-only
fixture observer. They verify separate tenant writes, contention on one
eligible row, and cancellation while PostgreSQL reports the blocked
UPDATE. See [the concurrent protocol](OVERLAP-PROTOCOL.md) for ordering
receipts and boundaries.

Application authorization comes from the Engine tenant dispatcher with synthetic
authority sources. The fixture covers a bounded PostgreSQL transaction and
migration. Real identity, additional migration versions, broader order or stock
semantics, performance qualification, HTTPS, events and the Business workload
require their corresponding proof.
