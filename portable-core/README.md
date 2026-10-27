# Experimental portable Core consumer

This is an executable in-process integration proof for W1 Core/Composition and operation code generation. It is separate from the Small API, business and AI sample lanes. The API/GraphQL/Worker names select **module recorders**; this consumer starts no HTTP/GraphQL server or background worker and makes no tenant/identity/provider/production claim.

One `[Operation("calculator.add")]` business handler is registered by the Engine incremental generator. Generated registration calls are lazy and typed. `appsettings` profile JSON selects a validated immutable module plan before any owned resources are created. Disabled module recorder factory/constructor/connection/endpoint/background counters remain zero. Handlers are new owned instances per call and are disposed on success/business error; the module lease cleans up once.

Use `tools/verify_portable_core.py` with the pinned private SDK. It verifies the exact Engine commit in `engine-lock.json` and a clean Engine checkout **before restoring/building/running**; an unrecorded sibling checkout is rejected. Result directories are new and retained rather than overwritten. The sample project consumes Core/Composition normally and CodeGeneration through `OutputItemType="Analyzer" ReferenceOutputAssembly="false"`; Roslyn stays out of its runtime dependency graph.

```text
python tools/verify_portable_core.py --dotnet D:/Cephalon/.tools/dotnet11/win-x64/dotnet.exe --output .local/portable-core/windows-run01
```

The wrapper passes `--locked-mode`; first maintainer lock generation is a separate explicit preparation step. No NuGet package has been published. Core context is correlation metadata, not tenant authority. Changing topology/provider/transport semantics or adding trusted identity requires the corresponding Engine capabilities and real conformance tests.
