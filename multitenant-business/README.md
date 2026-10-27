# Multitenant business sample plan

Implement a tenant-aware business workflow through API, SQL, events/outbox and Worker. Prove identity/policy/tenant boundaries, duplicate/crash/retry recovery and selected local/distributed profiles using shared handlers. Provider/version/workload choices require an ADR. Status: M0, not executable.

W0 selects PostgreSQL 18.6/Npgsql 10.0.3, RabbitMQ 4.4.0/Client 7.2.2 and Keycloak 26.8.1; cache stays off. Order/reservation workload: 100 tenants, 100,000 stock rows + 100,000 initial orders, 100 req/s; warm HTTP p95/p99 budgets 100/250 ms and no tenant leaks/lost acknowledged effects/duplicate reservation effects. Single-node broker proof is separate from HA. No provider execution has occurred.

- [ADR-0003](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/adr/ADR-0003-multitenant-business-profile.md)
- [Full protocol and gates](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/validation/business-workload.md)
- Engine task: [#15](https://github.com/Cephalon-Labs/Cehpalon-Engine/issues/15)
