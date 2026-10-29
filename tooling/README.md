# Experimental CLI-generated portable consumer

This proof invokes the Engine CLI to create a fresh `portable-request-reply` console application, builds it with the pinned SDK and exercises the actual generated Core operation registration through Composition. It is a separate portable integration fixture; it does not implement any of the three transport/provider sample lanes.

The CLI writes source only. The verifier explicitly performs restore/build/run, retains every attempt and checks app-on, optional-off, all-off, invalid configuration, owned cleanup and runtime dependencies. The generated operation is public and unprotected. Tenant/identity authority requires separate explicit wiring through the protected boundary.

The verifier also compiles and runs eight names that overlap framework/compiler/Engine identifiers. Generated code uses the fixed namespace `PortableConsumers.Generated` and assembly prefix `PortableConsumer.<Name>`. Final proof uses a real clean local Engine clone whose source path contains Unicode, spaces and `&`; this exercises actual source-reference escaping.

From Samples, with a clean Engine checkout matching [engine-lock.json](engine-lock.json):

```powershell
python tools/verify_tooling.py --dotnet D:/Cephalon/.tools/dotnet11/win-x64/dotnet.exe --output .local/tooling/windows-01
```

Use a fresh output directory every time. Linux uses the same verifier and locked revision with the pinned Linux SDK. The verifier creates output beneath ignored `.local`, including a consumer path containing spaces, Unicode and `&`. Generated source references the observed Engine checkout by absolute path; it is a source-checkout experiment, not an installable distribution. The CLI's source hashes describe bytes observed during generation and do not freeze or authenticate that mutable checkout.

The original delivery at Engine `39ae0cc6ae56045a9d3d24f94eb564efa5941254` passed70checks per host in complete sequential final02 runs. The main consumer exercised enabled/off/invalid config and eight additional consumers compiled/dispatched collision names. Runtime dependencies contain only the consumer, Core and Composition; the actual generated registry is retained. [Original raw evidence and earlier attempts](evidence/2026-10-29/retention-manifest.json) preserve the failed System assembly attempt and exact final logs/sources. Original Engine component suites passed462checks on Windows and459on Linux; historical hosted CI also passed those counts. The current [engine lock](engine-lock.json) advances for the [Small API profile's full portable regression](../tooling-small-api/README.md); its current CI state is reported separately. Three extra checks apply only to Windows path aliases.

See [ADR0012](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/adr/ADR-0012-portable-cli-scaffolding.md), the [predeclared correctness protocol](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/validation/portable-cli-scaffolding-protocol.md) and [delivery report](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/portable-cli-scaffolding.md). Full #20 profiles/transport schemas, tooling benchmark, packaging, listed-supported Windows and #3 remain outstanding. No throughput/startup or production claim follows from this proof.
