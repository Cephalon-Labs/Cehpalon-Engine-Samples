# Experimental CLI-generated Small API proof

This verifier invokes the real Engine CLI with `--profile small-api`, builds its freshly generated Web consumer and exercises real protected localhost HTTPS requests. The consumer uses existing Core/Composition, actual generated typed gateways and the fresh tenant dispatcher. Synthetic JWT identities and in-memory tenant data establish a fixture boundary; they do not establish a real IdP, database/broker provider, deployment or production qualification.

The CLI writes source only. The separate verifier explicitly restores, locks, builds and runs the generated consumer. It checks deterministic fourteen-file output (including offline contract export), all four configuration selections, unsupported/invalid combinations, the actual emitted three-operation registry, and runtime dependencies without Roslyn/CodeGeneration/Tooling. GraphQL packages may be present in the runtime graph while API-only observations prove its factory/services/endpoints stay disabled.

The generated consumer's explicit self-test covers HTTPS/JWT/tenant/transport/lifecycle checks. The verifier additionally invokes normal serving mode: all-off and invalid configurations with nonexistent credential paths, existing readiness preservation, and a real externally driven HTTPS listener with supplied TLS certificate and RSA public key. Owner calls for the same resource ID remain tenant-isolated, both cross-tenant directions deny despite spoofed headers, anonymous/untrusted-token requests deny, and disabled GraphQL remains absent. The documented `stop` console command must await cleanup and close the owned listener.

From Samples with a clean Engine checkout matching [engine-lock.json](engine-lock.json), use the pinned SDK and a fresh ignored attempt directory:

```powershell
python tools/verify_tooling_small_api.py --dotnet D:/Cephalon/.tools/dotnet11/win-x64/dotnet.exe --output .local/tooling-small-api/windows-01
```

Use the same verifier with the pinned Linux SDK for the complete sequential Linux matrix. `--integration` records preliminary uncommitted proof and cannot substitute for final locked-revision results. Final verification creates an actual clean Engine clone in a source path containing Unicode, spaces and `&`, then generates consumers into another such path.

A BCL-only fixture helper creates ephemeral TLS/JWT material in restricted ignored Windows `.local/.private-fixtures` or a native Unix temporary directory. It verifies Windows current-user-only protected DACL or Unix0700directory/0600files; Unix material uses native temporary storage because a mounted Windows filesystem may not enforce Unix mode bits. It changes DACL access rules without changing filesystem ownership. The helper source hash and permission observation are recorded. Private keys/PFX/passwords/tokens are excluded from retained raw evidence and never printed or included in command arguments. Preserve public command logs/results/source/hash manifests and failed attempts; do not copy private fixture directories, compiled artifacts or clone object databases into evidence.

This is a bounded experimental subset of #20. Full tooling profiles/transport schemas, benchmark, packaging, AOT/trimming and platform qualification remain outstanding; #3 remains Blocked. No performance or production claim follows from these checks.

Original profile delivery Engine `535e6be86428a135da1b4abd8399ab9bd299a8bf` passed the complete sequential Windows→Linux matrix: **133 harness checks and39 actual HTTPS self-test cases per host**, plus70checks per host for the existing console profile. Engine component suites passed496Windows/493Linux, including149/146Tooling contracts (three Windows-only alias cases). External serving observed owner200/200, cross-tenant403/403, anonymous/untrusted-key401/401 and disabled GraphQL404, then graceful listener cleanup. A late readiness failure reports one activated/one disposed host rather than false zero counters.

[Retained raw evidence](evidence/2026-10-29/retention-manifest.json) includes preliminary attempts, the failed pre-key-write helper privilege trial, emitted source/registrations, exact manifests and public serve observations. The [delivery report](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/small-api-cli-profile.md) distinguishes these local passes from current hosted CI, which was rejected before all four jobs started for account payment/spending-limit reasons. Prior revision CI passes do not certify the current revision.

The current Engine lock advances for the [offline contract export continuation](../tooling-contracts/README.md), which repeats this complete Small API matrix and the original console regression. Historical profile results above are retained separately from current-revision evidence and CI status.

The optional Small API capacity validation uses the existing 39-case run and a separate shared-budget self-test. Select a clean Engine revision explicitly for this continuation.

```powershell
python tools/verify_tooling_small_api.py --dotnet <pinned-sdk> --engine-root <checkout> --engine-revision 688efec571627ad5f9235934beccb578400ca782 --capacity --output .local/small-api-capacity
```

[Capacity evidence and hashes](evidence/2026-11-17-shared-host-capacity/SHA256SUMS.txt) cover actual generated protected saturation, cross-tenant denial, active serving with the flag and all-off behavior.

To verify the optional per-tenant cap, pass `--tenant-capacity` with the exact clean Engine revision. This also runs the original and shared-host capacity checks.

```powershell
python tools/verify_tooling_small_api.py --dotnet <pinned-sdk> --engine-root <checkout> --engine-revision baaabf1af720b1c8f021b124663323e5b4c959d0 --tenant-capacity --output .local/tenant-capacity
```

[Evidence and hashes](evidence/2026-11-18-tenant-capacity/SHA256SUMS.txt) cover simultaneous tenant isolation, all-off behavior, and active serve with both limits.

The shutdown continuation exercises active writes with both budget modes when the host stops.

```powershell
python tools/verify_tooling_small_api.py --dotnet <pinned-sdk> --engine-root <checkout> --engine-revision cb9088cc9b02f3855107444e28bb1af592a13ad4 --drain --output .local/budget-drain
```

[Drain reports and hashes](evidence/2026-11-18-budget-drain/SHA256SUMS.txt) include the fixed dispatch observations before and after the change.

The snapshot continuation observes aggregate budget state at readiness, during held-write drain and after cleanup.

```powershell
python tools/verify_tooling_small_api.py --dotnet <pinned-sdk> --engine-root <checkout> --engine-revision 46d07c9b9da9d38adbfc7f083ba1b3297d8ff82e --snapshots --output .local/budget-snapshots
```

[Snapshot reports and hashes](evidence/2026-11-19-budget-snapshots/SHA256SUMS.txt) contain aggregate counts and the recorded limits. Private fixture keys and tokens remain local.

The live metrics continuation collects caller-owned gauges during real fixture HTTPS traffic through both transports and tenants, including controlled overlap of five admitted operations and shutdown. Generate with Engine revision `5f8f252e901e85c50d7fc6f4b760e457965ce3bb` and run:

```text
python tools/verify_tooling_small_api.py --dotnet <pinned-sdk> --engine-root <checkout> --engine-revision 5f8f252e901e85c50d7fc6f4b760e457965ce3bb --live-metrics --output .local/live-metrics-new
```

The option includes the earlier capacity, tenant-capacity and drain checks. [Preserved initial and extended attempts](evidence/2026-11-20-live-metrics/README.md) retain each collection and actual cadence. These are bounded functional and collection-cost observations; the canonical performance gates remain open.
