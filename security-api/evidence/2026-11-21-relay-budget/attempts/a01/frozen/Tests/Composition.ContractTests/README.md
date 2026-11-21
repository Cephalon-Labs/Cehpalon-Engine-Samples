# Composition contract checks

Standalone BCL executable; no external test framework or provider is required.
Restore with a reviewed single-source NuGet configuration, build Release, then
run the resulting assembly with the pinned private .NET11 SDK/runtime:

```text
dotnet restore Tests/Composition.ContractTests/Composition.ContractTests.csproj --configfile Tests/PlatformQualification/NuGet.Config --locked-mode
dotnet build Tests/Composition.ContractTests/Composition.ContractTests.csproj -c Release --no-restore
dotnet Tests/Composition.ContractTests/bin/Release/net11.0/Composition.ContractTests.dll --output=.local/composition-results.json
```

The process exits nonzero on any failed case and records every case and error in
JSON. Tests cover schema/graph/profile/immutability/bounds, explicit-disabled zero
work, full registration preflight, cancellation, reverse rollback, aggregate
failures, and concurrent/idempotent lease cleanup. The three named profiles use
recorders counting factory/constructor/connection/endpoint/background calls, not
real hosts. These checks are not benchmarks, provider/tenant/E2E or CI evidence.
