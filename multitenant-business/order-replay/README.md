# Multitenant order replay proof

Declared 2026-11-24 for the bounded Business recovery slice. The sample
uses separate invocations for the checked command, publisher and Worker.
It uses the same pinned local PostgreSQL 18.6 and RabbitMQ 4.4.0 profiles
with Npgsql 10.0.3, RabbitMQ.Client 7.2.2 and .NET 11.0.0. Restore the
project in locked mode with the Samples-pinned SDK and a clean Engine
checkout at `6fe7254404cf6b148370bd95befe8331e8932354`. Pass its absolute
path as `-p:EngineRoot`.

The disposable runner applies [schema.sql](schema.sql) transactionally
as its separate migration owner. It gives the runtime login only the
grants in the schema and supplies the owned PostgreSQL and AMQP
connections through `CEPHALON_ORDER_REPLAY_POSTGRES` and
`CEPHALON_ORDER_REPLAY_AMQP`. Both connect over loopback to the
runner's fixture. Keep connection settings and provider logs private.
The issuer and membership sources are synthetic in-process fixtures.

## Phase order and receipts

| Phase | Exit | Required state |
| --- | ---: | --- |
| `create` | 0 | Commit a pending tenant-A order at revision 0 and its unpublished event together. |
| `publish-confirm-only` | 76 | A single-node durable quorum queue confirms the mandatory persistent event. Exit before updating its outbox flag. |
| `publish` | 0 | Read the unchanged event, confirm an identical publish and mark the outbox row. |
| `worker-exit-after-commit` | 77 | Begin from an initial delivery with manual acknowledgments. Commit the inbox marker, order transition and stock decrement together. Exit before issuing a broker acknowledgment. |
| `worker-replay` | 0 | In a fresh process, see the redelivered original and the initial delivery of the separately confirmed copy. Both find the committed inbox key. Acknowledge each only after PostgreSQL returns, then check the queue is empty. |
| `verify` | 0 | Confirm persisted A/B state, check unscoped pool reuse, verify engine denial before cross-tenant store work, and inspect the queue in a new session. |

The runner independently checks that the outbox remains unmarked after the
first publisher exits and that the Worker effect is committed while its
delivery remains unacknowledged by the application. The runner owns any
broker stop and restart. The expected state after recovery is tenant A
stock 8, reserved order revision 1, one marked outbox event and one inbox
marker. Tenant B retains stock 20 and its pending revision-zero sentinel
for the same order ID, with zero outbox and inbox rows. The application
repeats these ledger checks.

The publisher serializes its authorized persisted event. The Worker
checks the delivery route, durability metadata, message identifier and
bounded exact JSON encoding before accepting its typed fields. It then
checks those fields against the authorized persisted outbox record in
the same transaction as the inbox decision. Each store checkout uses
an Engine-checked operation, exact order resource and transaction-local
tenant setting. Queries and keys explicitly carry tenant scope, with
forced row-level security alongside them. The envelope-guard controls
exercise altered fields and AMQP metadata in process.

The two exit phases intentionally terminate these disposable clients.
They preserve the boundary between a broker confirm and an outbox mark,
and between a database commit and a broker acknowledgment. This is a
bounded at-least-once replay proof for one logical event. It leaves
multi-publisher claims, external authorization, derived events,
dead-letter policy, broker HA and the full Business workload outside
the verified scope.
