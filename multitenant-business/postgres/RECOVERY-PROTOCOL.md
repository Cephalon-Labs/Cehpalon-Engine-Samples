# PostgreSQL order crash recovery protocol

Declared 2026-11-24 for Engine #7 and #12. Use the existing pinned
Linux/amd64 PostgreSQL 18.6 image, Engine revision 6fe7254, .NET SDK
11.0.100, runtime 11.0.0 and locked Npgsql 10.0.3 Release build. Provision
one new loopback-only container with separate owner and runtime logins.
Run the existing normal proof first. Keep its committed, migration and
overlap cases. For recovery, check that fsync, synchronous_commit and
full_page_writes are on. Record the container and image, owned volume,
database system identifier and postmaster start time for readback.

In a separate application process, complete tenant A's order 5 at
revision zero and require the acknowledged result at revision one.
Then start tenant B's order 5 update at revision zero. Hold after UPDATE
returns a row and before commit. Check through a distinct runtime-role
backend that PostgreSQL observes this exact actor idle in an open UPDATE
transaction. Only that receipt releases the runner to send SIGKILL to
the verified, newly owned PostgreSQL container. Require exit 137 and
a stopped container. The runner then signals the stage process to
cancel its gate and joins it. The stage gate cannot enter commit.

Restart the same container with the same image and volume, without
rerunning SQL initialization. Wait for TCP readiness and verify the
original database system identifier, a new postmaster start time and
fresh PostgreSQL automatic-recovery and completed redo log markers.
Check that recovery has ended and the three durability settings are
still on. The runner compares identities privately and records only
the sanitized outcomes in its transcript.

Launch a fresh application process and connection pool. Verify tenant A
sees its committed revision one and tenant B sees the original row at
revision zero. For both scoped reads, open the same returned backend and
check that tenant context and unscoped rows are absent. Check that an
A-to-B read performs no runtime store checkout or SQL command. Clean up
and verify removal of the owned container, volume and loopback binding.

The test exercises PostgreSQL crash recovery after one acknowledged
commit and one pre-commit interruption. It does not model a lost commit
acknowledgment, host/disk loss, managed failover, point-in-time restore
or backup verification. Retain preparation and failed results
separately. The public record contains assertions and hashes without
credentials, raw backend details or data values.
