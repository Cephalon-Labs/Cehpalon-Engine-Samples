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
