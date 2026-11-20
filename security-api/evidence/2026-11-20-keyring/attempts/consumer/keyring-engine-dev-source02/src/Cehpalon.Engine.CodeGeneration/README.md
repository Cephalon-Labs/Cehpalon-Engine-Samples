# Experimental operation registration generator

This Roslyn incremental generator implements the first bounded code-generation
slice of Engine issue #20. It targets `netstandard2.0` and uses the exact
`Microsoft.CodeAnalysis.CSharp` 4.14.0 build-time graph. It is not a public package,
CLI, scaffolder, transport generator, or complete #20 acceptance result.

Annotate one concrete, accessible, non-generic business handler with
`[Cehpalon.Engine.Core.Operation("catalog.read")]`. The handler must implement
exactly one `IOperationHandler<TRequest,TResponse>` contract. A dependency-injected
constructor is allowed; the application supplies `IOperationHandlerFactory`.

Add the generator as a compiler analyzer:

```xml
<ProjectReference Include="PATH/TO/Cehpalon.Engine.CodeGeneration.csproj"
                  OutputItemType="Analyzer" ReferenceOutputAssembly="false" />
```

In the same consuming compilation, register the generated typed factories:

```csharp
var builder = new OperationRegistryBuilder();
OperationRegistrations.RegisterAll(builder, handlerFactory);
var dispatcher = new OperationDispatcher(builder.Build());
```

`OperationRegistrations` is internal in `Cehpalon.Engine.Generated`. Generated
registration adds lazy typed delegates to a builder; it does not create handlers,
start modules, perform dependency injection, or activate endpoints. Each invocation
factory transfers a fresh handler to the Core dispatcher's documented ownership.
Do not return shared or pooled disposable handlers. Registration is not a batch
transaction against an already-mutated builder; start with a fresh builder and
discard it if registration fails. Configuration composition remains the runtime
authority for which module may activate or dispatch through its own entrypoint.

The generator uses semantic attribute/interface symbols, emits ordinal ID order
with LF newlines, escapes fully-qualified type names and string literals, and has
no runtime assembly scan. Any invalid candidate or duplicate ID suppresses the
entire generated registry and reports source-located compiler errors:

| Diagnostic | Rejected condition |
| --- | --- |
| CEHGEN001 | ID outside `[a-z][a-z0-9_.-]{0,127}` |
| CEHGEN002 | Non-class, abstract/static/generic handler or generic container |
| CEHGEN003 | Inaccessible or file-local handler/request/response type |
| CEHGEN004 | Missing or ambiguous operation-handler contract |
| CEHGEN005 | Two handlers claim the same operation ID |
| CEHGEN006 | Consumer declares the reserved registry as a type/namespace or blocks its namespace path |
| CEHGEN007 | Multiple operation attributes on one handler |

No annotated handler produces no generated file. Private/protected nested and
file-local types cannot be referenced by a separate generated assembly-level file.
Valid internal/public nested types, aliases, partial declarations and inherited
closed contracts are supported. Candidate identity uses semantic symbol equality,
so a file-local type cannot disappear behind a same-display-name normal type.
Attributes on every part of a partial symbol are checked before registration is
deduplicated. Generated code does not embed host/provider
objects, tenant identity, business logic, or authorization decisions.

The analyzer's dependency graph is compiler-only (`PrivateAssets=all`); the tested
consumer runtime graph contains Core and the consumer only. This is not a trimming,
NativeAOT, packaging, every-IDE/compiler-version or production claim. #3 remains
Blocked pending listed-supported Windows qualification. All runtime feature
maturity and broader release gates remain scoped by the program's current Docs.

See [contract tests](../../Tests/CodeGeneration.ContractTests/README.md) and the
[official incremental generator cookbook](https://github.com/dotnet/roslyn/blob/main/docs/features/incremental-generators.cookbook.md).
