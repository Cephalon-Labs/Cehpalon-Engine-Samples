# Durable order replay proof

Run this correctness matrix on Linux amd64 using the local Docker context.
Use the pinned PostgreSQL 18.6 and RabbitMQ 4.4.0 fixture images, the
current locked Samples project, SDK 11.0.100, runtime 11.0.0, and clean
Engine `6fe7254404cf6b148370bd95befe8331e8932354`. PostgreSQL and
RabbitMQ use distinct owned volumes and loopback listener ports on an
isolated bridge. The fixture applies the checked-in schema as its
separate migration owner and executes the consumer under a restricted
runtime role. The controller checks the table ownership, forced row
security and exact durable rows independently.

| Phase | Required provider observations |
| --- | --- |
| Bootstrap and create | Tenant B's sentinel exists under the same order ID. A's order and unpublished outbox event appear together. |
| Publisher exits with code 76 | Publisher received a tracked confirm, the outbox remains unpublished, and the quorum queue has one ready record. |
| First broker restart and publisher retry | The same broker volume retains one ready record. The retry confirms another copy of the same event and marks the single outbox row. The queue has two ready records. |
| Worker exits with code 77 | The Worker commits before its application acknowledgement. Stock decreases from 10 to 8, the order becomes reserved at revision 1, and one inbox row appears. The broker requeues the unacknowledged delivery on client exit. |
| Second broker restart and new Worker | The retained queue presents two copies. The Worker checks the known event and reports one redelivery and one initial delivery, with no second business mutation. Both copies are manually acknowledged after the SQL transaction. |
| Third broker restart and new verifier | The queue remains empty and the exact tenant A and B ledgers match the worker-commit checkpoint. |

At every SQL checkpoint, compare all rows of the four fixture tables to
the expected snapshot, including the unchanged tenant B stock and order
and its empty outbox and inbox. Validate broker counters independently
of application receipts. Each application phase runs in a separate
managed process. The two intentional exits are controlled process returns.
Each broker stop is graceful and preserves its volume. The proof covers
two duplicate-delivery windows in the single-node fixture. Application
crashes, TLS, multi-node failover, poison handling and broader Business
acceptance require separate evidence.

Use a new ignored output directory and retain failures:

```text
python3 multitenant-business/order-replay-proof/run-proof.py --dotnet /path/to/dotnet --engine-root /path/to/clean/Engine --samples-revision <full-samples-sha> --output .local/order-replay/<attempt>
```

On success, review `report.json` for publication. Build logs, provider
stdout/stderr and fixture values stay private. At teardown the controller
verifies that the exact owned containers, volumes and bridge are absent
and loopback listeners are closed.
