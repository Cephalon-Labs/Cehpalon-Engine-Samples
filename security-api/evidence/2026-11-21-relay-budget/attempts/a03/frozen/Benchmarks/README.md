# Engine benchmarks

Before measurement, declare workload, runtime/provider/host versions, baseline, machine resources, warmup, sample count, thresholds and analysis. Retain all raw/failed/invalid attempts.

[W1.Components](W1.Components/README.md) implements the bounded warm Core/Composition regression protocol. Its local WSL results belong to the Docs W1 evidence report and do not qualify production workloads, generator speed or transport/provider performance.

[Tenancy.Components](Tenancy.Components/README.md) measures synchronous authorized/denied fixture paths with fresh authority checks and business-work counters. It excludes token cryptography, real provider/transport work and full security/production qualification.

W0 has selected the first [three workload protocols](../docs/w0-profiles.md). Their budgets remain unmeasured; exact hardware/artifacts/dataset hashes and baseline parity must be frozen before the first run.
