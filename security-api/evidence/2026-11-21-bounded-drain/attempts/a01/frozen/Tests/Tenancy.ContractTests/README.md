# Tenant contract executable

Run with the repository-pinned private .NET11 RC3 SDK:

```text
dotnet restore Tests/Tenancy.ContractTests/Tenancy.ContractTests.csproj --locked-mode --configfile NuGet.Config
dotnet build Tests/Tenancy.ContractTests/Tenancy.ContractTests.csproj -c Release --no-restore
dotnet Tests/Tenancy.ContractTests/bin/Release/net11.0/Tenancy.ContractTests.dll --output=.local/tenant-new-attempt.json
```

The standalone BCL fixture covers exact issuer/subject/tenant/resource bindings,
same resource ID in two authorized tenants, anonymous/untrusted/expired identity,
inactive/misbound membership, generic denial, default deny, role/tenant metadata
spoofing, fresh revocation on a reused dispatcher, deep request snapshot during
await, parallel tenants, private minting surface, retained/expired contexts,
cancellation and fault/cleanup semantics. Zero business factory/read counters are
checked on rejected paths. Source lookup counters are distinct from business reads.

Fixture identity/membership/resource/policy sources are configured in-process
authority simulators; they do not validate tokens or prove real IdP/store security.
No database, cache, worker, event, retrieval, network, hosted CI, supported-Windows,
performance or production proof is claimed. Windows26H2 runs are observational;
WSL22.04.5 remains a listed-distribution local component tier.

The initial 61/63 run is retained under the agent worktree's ignored
`.local/tenant-tests`: two assertions incorrectly required cumulative business reads
to be zero after an earlier successful invocation. They were corrected to preserve
the prior read count, strengthened to reuse the same dispatcher, and two additional
clock/policy-expiry guards were added. No runtime denial condition was weakened.

The later 65/69 run intentionally reproduced four monotonic/clock-resurrection
defects before their fix. Fixed leases enforce UTC plus monotonic effective lifetime
and permanently latch invalidity. Independent peers replayed the original public API
cases. The 69/70 run then retained a cleanup-only-denial classification defect:
cleanup failures must propagate rather than become an expected access-denied result.
The corrected wrapper retains the original cleanup cause and 70/70 checks pass.
