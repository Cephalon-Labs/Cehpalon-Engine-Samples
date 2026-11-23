# Dispatch completion correlation on the generated Small API

Exercise Engine issue #18 via the actual CLI-generated protected Small API
on local Windows and WSL Ubuntu using SDK 11.0.100 and runtime 11.0.0.
Run on each host against the same clean Engine revision. This is a
functional test of the selected outer Core gateway.

The harness builds the existing CLI, generates all fourteen Small API
files, checks the observed Engine source inventory, freezes the generated
package graph and builds with locked dependencies. A proof overlay adds
one middleware at the beginning of the generated endpoint pipeline and
selects the completion observer only at the outer dispatcher construction.
The test host retains the generated HTTPS startup, authentication, tenant
policy, transport bindings and owned handlers. The regular scaffold files
require no changes. The report excludes tokens, request headers, IDs, trace
state, baggage and inspected payloads. Copy only the reviewed
`trace-results.json` for publication. Build and attempt files stay under
`.local`.

For each transport, run owner, authenticated tenant denial and anonymous
requests with distinct valid trace parents. Also run owner requests with an
absent and a malformed parent header. The middleware independently reads
ASP.NET Core's native request Activity from `IHttpActivityFeature` and
confirms that it is the ambient server Activity. Compare its detached W3C
IDs to the completion record, and expect absent IDs for a non-W3C native
Activity. For valid parents, independently verify native parent linkage.
Check the host's structured event field allowlist using private fixture
values, then write only the comparison result.

Hold four real catalog reads before releasing them in both of these cases.
The overlapping HTTPS case submits two HTTP and two GraphQL requests with
distinct native traces. The GraphQL alias case submits a single request
with four distinct parallel fields under one native trace. Before release,
all four handlers must have entered the barrier, with no cleanup or
completion. After release validate each response and exact observation
counts. Validate the existing 2/1/0 histogram layers for owner, authenticated
tenant denial and anonymous calls and verify that the histogram retains
only its outcome tag.

Run two more owner controls with the observer disabled and assert that
the all-off composition never creates a host. Both enabled hosts must close
their loopback HTTPS ports and dispose owned handlers once. Expect 17 wire
cases, 16 dispatch completion records and 34 histogram observations per
host. The scope is in-memory protected HTTPS. Provider, exporter, and
performance qualification call for their own tests.

From a clean Samples checkout, substitute the SDK host and a clean Engine
checkout, and use a fresh ignored output path:

```text
python tooling-small-api/dispatch-correlation/verify.py --dotnet <dotnet> --engine-root <engine-checkout> --engine-revision <full-engine-sha> --output .local/dispatch-correlation/<attempt>
```

## Graceful drain and fresh activation

The drain matrix uses the same exact generated consumer and an opt-in
proof overlay. Run `verify.py` with `--drain` added to the command above.
A successful attempt writes `drain-results.json` to the new local output
folder. Use Engine `5e92ac1c7fa1e150e7e97de6d68e94b31ffba053` on both
hosts, and retain complete failed attempts under the ignored output root.
Any complete rerun follows a stated preparation or fixture correction.

Run two isolated lanes. In the total-budget lane hold a GraphQL mutation
before it writes, then hold its owned handler during cleanup. In the
tenant-budget lane hold an HTTP mutation and its owned cleanup, which
disposes the handler before raising a synthetic cleanup fault. The total
limit is two in each lane and the tenant lane also sets a per-tenant limit
of two, leaving one spare slot before admission closes. The overlay calls
the public budget drain API while the generated listener is still online,
and extends owned cleanup with a deterministic test barrier. It keeps the
generated host disposal and permission checks on their normal paths.

In each lane:

1. Wait for the admitted handler to enter, then close admissions. Confirm
   one active permit before and after close, and cancel only a second
   wait while the original drain remains pending.
2. For each transport check an authorized overload, an authenticated
   tenant denial and an anonymous denial. Compare the sanitized public
   envelopes and outer dispatch completion to the native request Activity.
   Confirm those requests add no new handler, mutation or cleanup.
3. Release the mutation and wait for cleanup to reach the barrier.
   Verify the write has happened, the permit is still held, and the
   admitted request has not emitted its completion or histogram.
   Start generated host shutdown and verify it waits for cleanup.
4. Release cleanup and join the admitted response, drain and shutdown.
   Match the success or fault outcome, confirm observation after actual
   disposal, verify closed and empty capacity, and check that the old
   HTTPS port refuses a fresh connection.
5. Start a new generated host with the same budget mode. Verify open,
   empty capacity before requests, successful authorized HTTP and GraphQL
   reads under new request traces, and closure after disposal. The new
   in-memory catalog starts at the fixture's initial revision.

Each host must produce 18 wire controls, 14 completion records and 20
histogram observations across the two lanes. Treat the result as controlled
local graceful drain and fresh activation. Admission close is observed
while the listener is intentionally still online, before generated host
shutdown begins. Wait cancellation concerns one drain waiter. The
synthetic cleanup fault concerns an admitted handler. The result establishes
neither crash durability nor exporter recovery.
