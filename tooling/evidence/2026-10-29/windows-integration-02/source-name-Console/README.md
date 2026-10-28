# Console — experimental portable request/reply consumer

This generated console application uses the existing Engine Core, Composition and
operation-registration generator through explicit local source project references.
It is not an HTTP, GraphQL, Worker, provider, tenant-protected or production template.
The only supported tuple is Modular / SingleProcess / RequestReply. Startup config
selects the app; changing config does not require changing the business handler.

From this directory, with the exact private SDK selected by global.json installed:

```text
dotnet build Consumer.csproj -c Release
dotnet run --project Consumer.csproj -c Release --no-build
dotnet run --project Consumer.csproj -c Release --no-build -- appsettings.off.json
```

The CLI itself does not invoke these commands or install anything. Building may
restore the pinned compiler-only dependency graph from official nuget.org. Roslyn
and CodeGeneration must not be consumer runtime dependencies. The consumer reads
one config path (default: copied appsettings.json beside the executable), compiles
it before activation, and reports JSON only after owned cleanup. Enabled app uses
one generated lazy registration and dispatches sample.echo once. All-off config
constructs no module or handler and dispatches nothing. Optional is a negative
fixture whose factory throws if explicitly enabled; it is not an implemented feature.

Plain Core is unprotected: correlation metadata and generated registrations provide
no tenant, identity or authorization authority. Add the documented trusted tenant
boundary before using protected business data. This fixture has no network services,
credentials or external business side effects.

engine-source.json is an observed byte/hash manifest of selected Engine inputs at
scaffolding time, not an immutable git revision, full source attestation or protection
against future source edits. It omits unrelated repository inputs. Source project
references remain editable; revalidate source bytes and locked build inputs before
reusing old proof. Outputs are deterministic for the same name, explicit source root
and observed input bytes. SDK/feed policy bytes are copied from the verified inputs.
The generated project inherits ordinary SDK/MSBuild parent build policy; use trusted
source and output parents. It does not isolate arbitrary inherited build customizations.
No public package, supported-Windows, trimming/AOT or CI claim follows from generation.
