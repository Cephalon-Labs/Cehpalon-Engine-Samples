# AI, Agent and Retrieval sample plan

Implement provider-specific adapters behind portable model/retrieval/tool contracts. Prove tenant-scoped retrieval, tool permissions, cancellation, quotas, failure and cost/token budgets. Separate deterministic fixtures from real-provider E2E and adversarial evaluations. Do not provision paid services or credentials as part of planning. Status: M0, not executable.

W0 selects Ollama 0.40.11 + pinned official Qwen3 generation/embedding GGUF + Qdrant 1.20.0, Keycloak 26.8.1 for real-provider identity, and llama.cpp 0.7.0 as a second inference adapter. Workload: 10 tenants, 2,000 chunks, 200 bilingual gold cases +100 negative cases; semantic Hit@5/mean Recall@5 budgets 95%/90%, grounded-answer budget 90%, unauthorized tool effects and tenant leaks zero. Fixture, retrieval and real-model proof tiers stay separate; model node resource target is 8 vCPU/16 GiB. No model weights were downloaded or executed.

- [ADR-0004 and publisher artifact identities](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/adr/ADR-0004-ai-retrieval-profile.md)
- [Full protocol and gates](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/validation/ai-retrieval-workload.md)
- Engine task: [#17](https://github.com/Cephalon-Labs/Cehpalon-Engine/issues/17)
