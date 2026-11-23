# Dispatch and module lifecycle metrics on a generated Small API

Run the existing [generated Small API verifier](../README.md) successfully
against the exact clean Engine revision first. Then run the separate observer
probe against the generated source it verified.

```powershell
python tooling-small-api/dispatch-lifecycle-metrics/verify.py --dotnet <pinned-sdk> --verified-attempt .local/histograms/windows --out .local/histograms/windows-observer
```

The probe verifies the generated source and lock hashes, then builds a copy
with its own entry point. The original generated executable and its
configuration stay available in the first attempt. The new entry point drives
the same generated host, HTTPS transport bindings, JWT fixture and tenant
dispatcher. The listener consumes only two Engine histograms and retains their
bounded outcome and lifecycle tags.

The three fresh processes exercise normal observation, an observer throwing
during first publication, and an observer throwing on each measurement.
The all-off plan must publish neither instrument. A combined API/GraphQL host
must report three successful activations and three successful disposals.
For each transport, an owner read must yield two Core invocations, a
cross-tenant denial one, and an anonymous denial zero. In the publication
failure case the requests and cleanup keep working, including a second host
after the listener is removed. Both failed instruments stay unavailable for
the rest of that process. Repeated lease disposal produces no extra records.

This is a loopback correctness fixture with process-local credentials and an
in-memory store. The reports contain status codes, bounded tags and observation
counts. They provide no transport latency, remote provider or exporter
evidence.
