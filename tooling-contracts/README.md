# Experimental transport contract export proof

This proof invokes the actual source-only CLI, builds its generated Small API consumer, then invokes explicit offline contract export. HTTP JSON schemas derive from the adapter's actual serializer policy; GraphQL SDL derives from the pinned vendor's actual executor schema. Disabled module artifacts and construction stay absent. Export is not a tenant authority or substitute for runtime validation.

From Samples with a clean Engine revision matching [engine-lock.json](engine-lock.json):

```text
python tools/verify_tooling_contracts.py --dotnet <pinned-dotnet> --output .local/tooling-contracts/<fresh-attempt>
```

The harness retains every command/failure, verifies deterministic profile-specific exports and safe no-overwrite/path refusal, then builds a separate C# differential helper against the emitted consumer. That helper compares exported SDL with a live enabled schema, checks actual HTTP route metadata, validates actual request/response bodies against the bounded JSON-schema keyword set used by these DTOs, and sends real localhost HTTPS tenant/disabled/exposure requests. Shape-valid payloads can still fail custom validators or tenant authorization; those are deliberately separate contracts.

Final evidence must use the exact clean pinned Engine revision and complete sequential Windows/Linux runs. `--integration` is preliminary only. Private keys/PFX/tokens, compiled artifacts and clone object databases are excluded from committed raw evidence. Full #20 tooling benchmark/schema/distribution/provider qualification and #3 remain outstanding; no performance or production claim follows.

Engine `972522eb455d0b1b6415cf4e88398c14baa82fbe` passed the complete clean sequential Windows→Linux matrix: **160 export checks +25 actual runtime differential checks per host**. Core/component suites passed505Windows/502Linux (HTTP51; Tooling151/148), while complete Small API133+39 and portable70regressions also passed per host. Three Windows-only path aliases explain the count difference. Enabled GraphQL export observes28service descriptors, one registration/schema/provider and one awaited disposal; all host/TLS/handler/dispatch/authority counters stay0. Disabled GraphQL has no service/schema/provider work.

[Retained raw evidence](evidence/2026-10-29/retention-manifest.json) includes emitted artifacts, generated/helper source, exact manifests and preliminary attempts. The [delivery report](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/tooling-contract-export.md) distinguishes these local passes from current CI, whose four jobs were rejected before any steps for account payment/spending-limit reasons. No historical CI pass is promoted to this revision.
