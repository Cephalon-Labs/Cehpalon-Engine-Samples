# Code-generation component contracts

Two complementary checks exercise the actual generator:

1. `CodeGeneration.ContractTests.csproj` runs a Roslyn 4.14.0 in-process driver.
   It compiles emitted code against the real Core project; checks diagnostics,
   partial/alias/inheritance/accessibility/ID rules, deterministic output and
   retained incremental-driver caching/edit invalidation; rejects same-display-name
   file-local/normal pairs in both declaration orders, split-partial duplicate
   attributes and reserved namespace collisions; then emits and invokes
   a generated fixture to prove lazy typed registration, Core dispatch and disposal.
2. `CompilerFixture/CompilerFixture.csproj` uses an actual analyzer ProjectReference
   with `ReferenceOutputAssembly=false`, proving the pinned .NET 11 SDK compiler
   can load this netstandard2.0 generator. It dispatches a dependency-injected
   business operation and verifies cancellation before factory activation.

From the repository root with the private pinned SDK:

```text
dotnet restore Tests/CodeGeneration.ContractTests/CodeGeneration.ContractTests.csproj --locked-mode --configfile Tests/CodeGeneration.ContractTests/NuGet.Config
dotnet run --project Tests/CodeGeneration.ContractTests/CodeGeneration.ContractTests.csproj -c Release --no-restore -- --output=.local/codegen-tests.json
dotnet restore Tests/CodeGeneration.ContractTests/CompilerFixture/CompilerFixture.csproj --locked-mode --configfile Tests/CodeGeneration.ContractTests/NuGet.Config
dotnet run --project Tests/CodeGeneration.ContractTests/CompilerFixture/CompilerFixture.csproj -c Release --no-restore
python Tests/CodeGeneration.ContractTests/collect-package-evidence.py --output .local/codegen-package-inventory.json
```

Use the same private package cache for restore and build if passing `--packages`.
An optional `-p:CoreProject=ABSOLUTE_CSPROJ` permits the isolated agent proof against
the peer Core worktree; integrated evidence must rerun against the actual committed
Engine source. Normal default references point at this repository's Core project.

The driver harness uses reflection only to invoke an emitted test assembly. The
generated runtime registry and Core dispatch do not depend on that test machinery
or on Roslyn. Inspect the consumer `*.deps.json` to confirm no Roslyn/analyzer runtime
entry. Source maps and release-tracked diagnostic IDs remain in the analyzer project.

Retain failed/warning attempts, exact graph/content hashes and raw nupkg hashes as
distinct observations. The package collector reads cached archives and license
metadata; it does not validate publisher signatures, audit code, or approve
redistribution. Local Windows26H2 results are observational, not listed-supported
Windows, hosted CI, real transport, tenancy, benchmark, AOT or production proof.
