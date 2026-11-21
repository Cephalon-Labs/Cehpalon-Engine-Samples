# Engine tests

Engine suites are split by component/provider/profile for targeted execution. Record exact Engine revision, dependencies, commands and proof scope. [PlatformQualification](PlatformQualification/README.md) is a separate bounded SDK/platform/third-party smoke executable with pinned packages and explicit Not run cases. Its passes do not establish Engine runtime feature maturity.

```text
python tools/verify_w1.py --dotnet D:/Cephalon/.tools/dotnet11/win-x64/dotnet.exe --output .local/w1/new-attempt
```

The W1 verifier requires a fresh ignored attempt directory, restores the locked solution with the repository's isolated official source, builds Release with warnings as errors and runs [Core](Core.ContractTests/README.md), [Composition](Composition.ContractTests/README.md), [CodeGeneration](CodeGeneration.ContractTests/README.md), [Identity](Identity.ContractTests/README.md) and [Tenancy](Tenancy.ContractTests/README.md), plus the actual compiler-analyzer consumer. Every result/log and source hash is retained. It does not run benchmarks or claim hosted CI/supported-Windows acceptance. For a committed proof, use a clean exact Engine checkout.

The same verifier also runs [HTTP](Http.ContractTests/README.md) and [GraphQL](GraphQL.ContractTests/README.md) adapter contracts. GraphQL tests own a localhost HTTP listener with a synthetic trusted-principal fixture; actual pinned JWT/HTTPS/tenant/storage checks live in the separate Small API consumer. HTTP has no GraphQL runtime dependency. These bounded tests do not execute the original W0 benchmark protocol.

It also runs [Tooling](Tooling.ContractTests/README.md) filesystem/configuration contracts. The [Samples tooling verifier](https://github.com/Cephalon-Labs/Cehpalon-Engine-Samples/tree/main/tooling) separately invokes the actual CLI and restore/build/runs a newly generated console consumer. Full tooling profiles, transport schemas, performance and distribution qualification remain outstanding.

The [generated Small API verifier](https://github.com/Cephalon-Labs/Cehpalon-Engine-Samples/tree/main/tooling-small-api) separately invokes `new --profile small-api`, builds the actual HTTPS consumer and checks cross-tenant denial, disabled modules and caller-configured serving/cleanup. This fixture-backed profile does not certify a real IdP/provider or production hosting.

W0 correctness, tenant/policy, zero-activation and failure/recovery contracts are indexed in [sample profiles](../docs/w0-profiles.md). Implement each supported provider/profile suite from its canonical protocol; fixture passes cannot substitute for real-provider E2E.
