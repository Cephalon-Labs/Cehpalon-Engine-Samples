# W0 sample profiles and proof contracts

Decision date: 2026-10-27. Status: selected for W0 planning; runtime qualification pending, M0.

The canonical decisions live in Docs. This Engine index links contracts used by upcoming Core/composition/adapter work; it does not duplicate executable configuration or claim adapters exist.

| Lane | Initial provider family | Canonical decision and acceptance protocol |
| --- | --- | --- |
| Small API | Kestrel/Minimal API + bounded fixture state; optional Hot Chocolate GraphQL | [ADR-0002](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/adr/ADR-0002-small-api-profile.md), [protocol](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/validation/small-api-workload.md) |
| Multitenant business | PostgreSQL/Npgsql, RabbitMQ, Keycloak; cache off by default | [ADR-0003](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/adr/ADR-0003-multitenant-business-profile.md), [protocol](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/validation/business-workload.md) |
| AI/Agent/Retrieval | Ollama + pinned Qwen GGUF + Qdrant; Keycloak for real-provider tiers; llama.cpp portability | [ADR-0004](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/adr/ADR-0004-ai-retrieval-profile.md), [protocol](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/validation/ai-retrieval-workload.md) |

[ADR-0001](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/adr/ADR-0001-w0-profile-and-proof-boundaries.md) defines common boundaries: immutable validated startup composition, shared business contracts within declared semantics, no disabled-module activation, trusted tenant/policy context, and restart/redeploy for profile changes.

Correctness, isolation/security cases, failure/recovery and performance are separate gates. Numbers in the protocols are predeclared engineering budgets on specified resource tiers, not measurements or production promises. Baselines must preserve policy, schema and durability semantics. Failed/invalid runs remain evidence; do not tune thresholds after seeing results to claim a pass.

Issue #3 owns exact SDK/provider/artifact qualification. The repository now has [SDK pins and bounded platform/driver qualification](../Tests/PlatformQualification/README.md); raw outcomes, unsupported-host observations and package-license limits are explicit. W0 design/qualification completion does not complete Engine adapters or sample tasks. Current artifact/model/CI boundaries remain recorded in Docs.
