# Experimental transport contract export proof

This proof invokes the actual source-only CLI, builds its generated Small API consumer, then invokes explicit offline contract export. HTTP JSON schemas derive from the adapter's actual serializer policy; GraphQL SDL derives from the pinned vendor's actual executor schema. Disabled module artifacts and construction stay absent. Export is not a tenant authority or substitute for runtime validation.

From Samples, use a clean Engine checkout matching [engine-lock.json](engine-lock.json)
and the absolute path to the .NET 11.0.100 executable on the current host.

```text
python tools/verify_tooling_contracts.py --dotnet <absolute-pinned-dotnet> --engine-root <clean-engine-checkout> --output .local/tooling-contracts/<fresh-attempt>
```

The harness retains every command/failure, verifies deterministic profile-specific exports and safe no-overwrite/path refusal, then builds a separate C# differential helper against the emitted consumer. That helper compares exported SDL with a live enabled schema, checks actual HTTP route metadata, validates actual request/response bodies against the bounded JSON-schema keyword set used by these DTOs, and sends real localhost HTTPS tenant/disabled/exposure requests. Shape-valid payloads can still fail custom validators or tenant authorization; those are deliberately separate contracts.

Final evidence must use the exact clean pinned Engine revision and complete sequential Windows/Linux runs. `--integration` is preliminary only. Private keys/PFX/tokens, compiled artifacts and clone object databases are excluded from committed raw evidence. Full #20 tooling benchmark, schema, distribution and provider qualification remain outstanding.

The earlier GA lock at Engine `c18757f` passed **160 export checks and 25
HTTPS/runtime differential checks per host** on Windows build 26300 and WSL
Ubuntu 22.04.5. Paired exports matched byte for byte within each host. SDL also
matched across hosts. OpenAPI matched across hosts after LF normalization
because the indented JSON used the platform's line endings.

The current GA lock at Engine `6fe7254` passed the same 160 export checks and
25 HTTPS/runtime differential checks on each host. All eight published files
across the four profiles, including OpenAPI, SDL and export manifests, matched
byte for byte between Windows and WSL and matched the prior WSL exports.
Generated source provenance keeps its observed checkout path.

Engine `972522eb455d0b1b6415cf4e88398c14baa82fbe` passed the complete clean sequential Windows→Linux matrix: **160 export checks +25 actual runtime differential checks per host**. Core/component suites passed505Windows/502Linux (HTTP51; Tooling151/148), while complete Small API133+39 and portable70regressions also passed per host. Three Windows-only path aliases explain the count difference. Enabled GraphQL export observes28service descriptors, one registration/schema/provider and one awaited disposal; all host/TLS/handler/dispatch/authority counters stay0. Disabled GraphQL has no service/schema/provider work.

[Retained raw evidence](evidence/2026-10-29/retention-manifest.json) includes emitted artifacts, generated/helper source, exact manifests and preliminary attempts. The [delivery report](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/tooling-contract-export.md) distinguishes these local passes from current CI, whose four jobs were rejected before any steps for account payment/spending-limit reasons. No historical CI pass is promoted to this revision.
