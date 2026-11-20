# Tenant/identity component regression smoke

Read the [predeclared protocol](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/validation/tenant-identity-component-protocol.md) before measurement. Run the locked Release executable only after the entire correctness/collector workload has finished, using a new result file. Every paired repetition is retained.

This measures synchronous in-memory authority fixtures and checked Core delegation, not token validation, security assurance, a database query, network latency or production performance. Authorized calls resolve all authorities and own one business handler; cross-tenant denial must create/read/write zero business objects. A shared-host observation is not a resource-limited workload qualification.

Use the explicit observer mode to record Core and tenant snapshot cost across four controlled admission states.

```text
dotnet Tenancy.Components.dll --observe-budget-snapshots --output=<new-json-path>
```

The recorded loops include typed delegate calls and checksum calculations. The cached-value lanes run the same loop with detached snapshots. The report retains all five repetitions. Read the [protocol](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/validation/budget-snapshot-observation.md) before measuring.

Use `--observe-budget-contention --output=<new-json-path>` for the separately declared concurrent observer series. Four dedicated producer threads run fixture-authorized tenant operations while a fifth thread either waits or continuously reads aggregate snapshots. Both modes retain exact operation and cleanup counts. [Concurrent protocol](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/validation/budget-contention-observation.md)

Use `--observe-budget-metrics --output=<new-json-path>` for 20 periodic MeterListener collections in each of four controlled budget states. The report records the first collection, each actual timestamp, callback count and caller-thread allocations. [Metrics protocol](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/validation/budget-metrics.md)
