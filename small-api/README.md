# Small API sample plan

Implement a minimal API-only consumer, then expose the same supported business operation through an optional second transport by configuration. Prove validation, policy, cancellation and zero activation of disabled GraphQL/Worker/AI modules. Measure startup and idle footprint against a declared baseline. Status: M0, not executable.

W0 selects Kestrel + Minimal API with a bounded BCL catalog fixture; no external database/cache/broker/AI/IdP. Hot Chocolate 16.7.1 is opt-in and still requires RC3 qualification. Workload: 10,000 records, 1,000 req/s, five baseline/Engine pairs; warm p95/p99 budgets 20/50 ms. These are design budgets, not results.

- [ADR-0002](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/adr/ADR-0002-small-api-profile.md)
- [Full protocol and gates](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/validation/small-api-workload.md)
- Engine task: [#11](https://github.com/Cephalon-Labs/Cehpalon-Engine/issues/11)
