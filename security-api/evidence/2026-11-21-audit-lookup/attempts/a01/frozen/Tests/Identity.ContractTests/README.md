# Identity contract checks

Use the SDK pinned by Engine global.json and the repository NuGet.Config:

```text
dotnet restore Tests/Identity.ContractTests/Identity.ContractTests.csproj --locked-mode --configfile NuGet.Config
dotnet build Tests/Identity.ContractTests/Identity.ContractTests.csproj -c Release --no-restore
dotnet Tests/Identity.ContractTests/bin/Release/net11.0/Identity.ContractTests.dll --output=.local/identity-new-result.json
```

The executable rejects an existing result file and retains all check failures.
It tests exact principal/trust identities, defensive snapshots, malformed text,
inclusive/exclusive validity boundaries and a cancellation-observing fixture
source. A fixture source is not an authenticated protocol implementation.
No live IdP, JWT/JWKS, token/session lifecycle, provider, transport, supportedWindows,
hostedCI or benchmark result is established by this suite.
