# Core component contract checks

Run with the repository's pinned .NET SDK. These executable checks require no test
framework package, network listener, provider, Docker service or credentials.

```text
dotnet restore Tests/Core.ContractTests/Core.ContractTests.csproj --configfile Tests/PlatformQualification/NuGet.Config --locked-mode
dotnet build Tests/Core.ContractTests/Core.ContractTests.csproj -c Release --no-restore
dotnet Tests/Core.ContractTests/bin/Release/net11.0/Core.ContractTests.dll --output=.local/core-results.json
```

32 checks cover canonical IDs; result/context snapshots and guards; lazy immutable
registration; unknown/type-mismatched calls doing zero factory work; cancellation
before dispatch, during factory and during handler; correct owned synchronous and
asynchronous disposal; preserved execution/cleanup failures; overlapping concurrent
dispatches; shared business contracts; and the BCL-only Core assembly boundary.

These are local component proofs. Windows26H2 is an observational host, not the
listed supported Windows evidence required by #3. They do not establish tenant or
identity enforcement, transport/provider integration, hosted CI, benchmarks, HA or
production maturity. The independent callers in this harness are in-process calls,
not HTTP/GraphQL/Worker transports. Raw initial restore/build failures and prior
results are retained by the integrator alongside the final source-bound evidence.
