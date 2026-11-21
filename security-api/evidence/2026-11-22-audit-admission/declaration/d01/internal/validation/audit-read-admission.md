# Audit-read admission validation protocol

Declared2026-11-22 before implementation/SDK. [ADR0054](../adr/ADR-0054-audit-read-concurrency-admission.md).

## Fixed scope and matrix

Samples-only extension of the indexed audit transport host; unchanged Engine5184517 baseline. Preserve old308 provider/651 security cases exactly, existing4096 corpus, Pooling=false, default planner, packages/SQL/schema and original benchmark criteria. Do not run a timed benchmark or claim a performance improvement. M0 remains.

Four shared controls:

1. Positional ABI/default/null configuration and inert profiles, including invalid unused limits and zero budget/callback/source/listener activation.
2. Invalid selected limits rejected before factories/configure/credentials/source work.
3. Independent selected hosts own distinct budgets; aggregate snapshot contains counts only and both clean up.
4. Mixed receipt/resource shutdown closes both admissions permanently, joins held empty/populated work and disposes one source even if Stop fails.

Ten cases for each actual HTTPS HTTP/GraphQL:

1. Default/null budget preserves overlapping independently scheduled reads.
2. Per-tenant saturation rejects same-tenant resource/receipt while another authorized tenant with identical resource/receipt IDs succeeds below total cap.
3. Total saturation by A+B rejects further authorized work without handler/source invocation.
4. Invalid JWT, forged tenant, missing grant and revoked authority deny before capacity/provider and do not consume slots.
5. Provider/corruption failure releases its slot and permits subsequent valid work without leaking raw errors.
6. Caller abort does not release a held server slot; replacement is rejected until the joined server work finishes, then succeeds.
7. Cooperative read timeout cancels the work token while a held provider completion retains capacity; release/join restores capacity.
8. Receipt/resource and HTTP/GraphQL share the same selected host budget; GraphQL siblings each use fresh authority.
9. Eight synchronized scheduled workers over A/B respect exact total/per-tenant limits, with positive held overlap, denials and complete unconditional joins.
10. Fresh membership/resource/policy revocation is checked during saturation and after release; authorized replacement preserves tenant isolation.

Expected new24/provider332 per Windows/WSL (329 main plus3 restart). Preserve old prefixes and observation arrays; record24 new observations with actual counts/tokens/aggregate snapshots, never credentials or payloads. Budget excludes authentication and response mapping/wire; no queue/fairness/hard timeout/distributed capacity claim. Engine owned-handler cleanup semantics are reused baseline, not a new injectable cleanup-fault proof in the sample.

## Execution and retention

Freeze source/locks/scripts/declarations before each declared development attempt. Retain every failed preparation/build/runtime attempt and exact corrections. Only root schedules SDK lanes, serially without competing owned builds. After source commit run Windows security651/provider332 then WSL security651/provider332; verify frozen/current/committed/cross-host maps and unchanged generated registries. Independent source/raw review checks ownership, actual overlap, denied-query deltas and old-case preservation. Clean Engine worktree only; preserve primary four dirty Engine files and four untracked Samples files.

Use retained owned PostgreSQL18.7/Npgsql10.0.3 container/volume only after verifying its identity. Windows client uses owned loopback/stdio proxy; WSL client connects directly; neither proves native Windows DB. Retain failed/raw/source evidence, publish reviewed suitable copies with SHA256SUMS and index-byte checks. Stop only exact owned fixtures/helpers and verify native listener closure, retaining data/image/volume. Sync body-only7/8/18, readback23/direct Project253, metadata/task-byte guards and push mains. Usage/billing blocks defer exact GitHub step without changing billing or rerunning unchanged payment-rejected jobs.
