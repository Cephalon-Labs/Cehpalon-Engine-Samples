# RabbitMQ single-node restart fixture

This correctness fixture exercises broker persistence for #14 with the
Business profile's RabbitMQ 4.4.0 Linux amd64 image, Erlang/OTP 29.1.2,
RabbitMQ.Client 7.2.2 and .NET 11.0.0. It uses a dedicated Docker bridge
and a loopback AMQP port. The project restore is locked.

1. Confirm three mandatory persistent publishes to a durable quorum
   queue with an initial group size of one. Give each record a distinct
   synthetic ID and payload.
2. Consume and acknowledge the first record. Wait for its channel-close
   reply. On a separate channel consume the second without acknowledging
   it, and keep that channel open. Require one ready and one
   unacknowledged record in the broker's counters.
3. Gracefully stop the exact owned broker container. Require exit zero,
   a closed listener and shutdown observed by the first client. Start the
   same container with the same volume and unchanged node name. Verify
   a new process start, broker readiness and two ready records.
4. Open a new AMQP session with automatic recovery disabled. Consume the
   former pending and unacknowledged IDs once each and verify each payload
   and persistent property. Require the unacknowledged record to arrive
   with the redelivery flag. Acknowledge both and confirm an empty queue
   from an independent channel after the acknowledgement channel closes.
5. Repeat the graceful restart on the same volume and verify the queue
   still exists and is empty in a new session. Remove the fixture
   container, volume and network and verify loopback closure.

Run on WSL Ubuntu or a compatible Linux amd64 host with the local default
Docker context. Run on a clean Samples checkout with a fresh ignored
output directory:

```text
python3 multitenant-business/recovery-broker/run-proof.py --dotnet /path/to/dotnet --samples-revision <full-samples-sha> --output .local/recovery-broker/<attempt>
```

Keep failed attempts, build logs and provider output in the selected
`.local` folder. Review `report.json` before publication. The proof
covers graceful broker restarts on the retained local volume. Abrupt
termination, host or storage loss, multi-node failover, application
idempotency, SQL outbox/inbox and TLS require their own evidence.
[RabbitMQ quorum queues](https://www.rabbitmq.com/docs/quorum-queues) · [Publisher confirms](https://www.rabbitmq.com/tutorials/tutorial-seven-dotnet)
