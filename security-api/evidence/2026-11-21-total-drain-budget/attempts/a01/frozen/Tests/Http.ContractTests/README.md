# HTTP adapter contracts

Executable tests use DefaultHttpContext with a fixture authenticated principal and probe dispatcher. They exercise typed contracts, protected direct invocation, lazy mapping/authorization metadata, strict and bounded streamed JSON, generic error mapping, infrastructure faults and cancellation propagation before/during dispatch. These are adapter tests, not JWT or tenant-provider qualification. Small API consumer tests own real authenticated network invocation and cross-tenant business effects.

Run with the repository's pinned SDK:

```powershell
dotnet restore tests/Http.ContractTests/Http.ContractTests.csproj --locked-mode
dotnet build tests/Http.ContractTests/Http.ContractTests.csproj -c Release --no-restore
dotnet tests/Http.ContractTests/bin/Release/net11.0/Http.ContractTests.dll --output result.json
```

The JSON report and process exit code retain each check and any failure.
