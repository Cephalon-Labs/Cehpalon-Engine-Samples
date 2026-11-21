using System.Security;
using System.Text;
using Cehpalon.Engine.Composition;

namespace Cehpalon.Engine.Tooling;

internal static class TemplateFiles
{
    internal static ModuleDescriptor[] Catalog() =>
    [
        new("core", ModuleRole.Support),
        new("app", ModuleRole.EntryPoint, ["core"]),
        new("optional", ModuleRole.EntryPoint, ["core"])
    ];

    internal static SortedDictionary<string, byte[]> Create(string name, string engineRoot, byte[] global, byte[] nuget, byte[] manifest)
    {
        var files = new SortedDictionary<string, byte[]>(StringComparer.Ordinal);
        void Add(string path, string value) => files.Add(path, new UTF8Encoding(false, true).GetBytes(value.Replace("\r\n", "\n") + "\n"));
        string Project(string project) => SecurityElement.Escape(Path.Combine(engineRoot, "src", project, project + ".csproj").Replace('\\', '/'))!;
        Add("Consumer.csproj", $$"""
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net11.0</TargetFramework>
    <AssemblyName>PortableConsumer.{{name}}</AssemblyName>
    <RootNamespace>PortableConsumers.Generated</RootNamespace>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <Deterministic>true</Deterministic>
    <IsPackable>false</IsPackable>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
    <EmitCompilerGeneratedFiles>true</EmitCompilerGeneratedFiles>
    <CompilerGeneratedFilesOutputPath>$(BaseIntermediateOutputPath)generated</CompilerGeneratedFilesOutputPath>
    <ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally>
    <EnableDefaultCompileItems>false</EnableDefaultCompileItems>
  </PropertyGroup>
  <ItemGroup>
    <Compile Include="Program.cs" />
    <Compile Include="Catalog.cs" />
    <ProjectReference Include="{{Project("Cehpalon.Engine.Core")}}" />
    <ProjectReference Include="{{Project("Cehpalon.Engine.Composition")}}" />
    <ProjectReference Include="{{Project("Cehpalon.Engine.CodeGeneration")}}" OutputItemType="Analyzer" ReferenceOutputAssembly="false" />
    <None Update="appsettings.json" CopyToOutputDirectory="PreserveNewest" />
    <None Update="appsettings.off.json" CopyToOutputDirectory="PreserveNewest" />
  </ItemGroup>
</Project>
""");
        Add("Program.cs", $$"""
using System.Text;
using System.Text.Json;
using Cehpalon.Engine.Composition;
using Cehpalon.Engine.Core;
using PortableConsumers.Generated;

var counters = new Counters();
var json = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
if (args.Length > 1)
{
    Console.Error.WriteLine(JsonSerializer.Serialize(new { status = "failed", code = "usage.config", message = "Use zero arguments or one configuration path." }, json));
    return 2;
}
var configPath = args.Length == 1 ? args[0] : Path.Combine(AppContext.BaseDirectory, "appsettings.json");
try
{
    // Compile the full startup snapshot before receiving any module factory.
    var bytes = File.ReadAllBytes(configPath);
    if (bytes.Length > CompositionCompiler.MaximumConfigurationBytes) throw new InvalidDataException();
    var text = new UTF8Encoding(false, true).GetString(bytes).TrimStart('\uFEFF');
    var compilation = CompositionCompiler.Compile(text, ModuleCatalog.Create());
    if (!compilation.IsSuccess)
    {
        Console.Error.WriteLine(JsonSerializer.Serialize(new { status = "failed", code = "config.invalid",
            diagnostics = compilation.Diagnostics.Select(diagnostic => new { diagnostic.Code, path = "$.Cehpalon", message = "Configuration violates the selected portable profile." }),
            factories = new { core = counters.CoreFactories, app = counters.AppFactories, optional = counters.OptionalFactories },
            handlersConstructed = counters.HandlersConstructed, handlersDisposed = counters.HandlersDisposed,
            dispatches = counters.Dispatches, modulesDisposed = counters.ModulesDisposed }, json));
        return 2;
    }
    AppModule? app = null;
    string? response = null;
    await using (var lease = await PlanActivator.ActivateAsync(compilation.Plan!,
    [
        new("core", cancellation =>
        {
            cancellation.ThrowIfCancellationRequested();
            counters.CoreFactories++;
            return ValueTask.FromResult<IAsyncDisposable>(new OwnedModule(counters));
        }),
        new("app", cancellation =>
        {
            cancellation.ThrowIfCancellationRequested();
            counters.AppFactories++;
            app = new AppModule(counters);
            return ValueTask.FromResult<IAsyncDisposable>(app);
        }),
        new("optional", cancellation =>
        {
            counters.OptionalFactories++;
            throw new InvalidOperationException("The optional fixture must stay disabled.");
        })
    ]))
    {
        if (app is not null)
        {
            var result = await app.Dispatcher.DispatchAsync<EchoRequest, EchoResponse>("sample.echo", new("hello"), new("sample-call"));
            if (!result.IsSuccess) throw new InvalidOperationException("The sample operation failed.");
            response = result.Value.Message;
        }
    }
    // Lifecycle counters are reported only after every owned module is cleaned up.
    Console.WriteLine(JsonSerializer.Serialize(new { status = "passed", profile = "portable-request-reply", activationOrder = compilation.Plan!.ActivationOrder,
        factories = new { core = counters.CoreFactories, app = counters.AppFactories, optional = counters.OptionalFactories },
        handlersConstructed = counters.HandlersConstructed, handlersDisposed = counters.HandlersDisposed,
        dispatches = counters.Dispatches, modulesDisposed = counters.ModulesDisposed, response }, json));
    return 0;
}
catch
{
    Console.Error.WriteLine(JsonSerializer.Serialize(new { status = "failed", code = "consumer.failure", message = "The local consumer failed; no provider or platform qualification is implied.",
        factories = new { core = counters.CoreFactories, app = counters.AppFactories, optional = counters.OptionalFactories },
        handlersConstructed = counters.HandlersConstructed, handlersDisposed = counters.HandlersDisposed,
        dispatches = counters.Dispatches, modulesDisposed = counters.ModulesDisposed }, json));
    return 3;
}
""");
        Add("Catalog.cs", $$"""
using Cehpalon.Engine.Composition;
using Cehpalon.Engine.Core;

namespace PortableConsumers.Generated;

internal static class ModuleCatalog
{
    internal static ModuleDescriptor[] Create() =>
    [
        new("core", ModuleRole.Support),
        new("app", ModuleRole.EntryPoint, ["core"]),
        new("optional", ModuleRole.EntryPoint, ["core"])
    ];
}

internal sealed class Counters
{
    internal int CoreFactories, AppFactories, OptionalFactories;
    internal int HandlersConstructed, HandlersDisposed, Dispatches, ModulesDisposed;
}

internal sealed record EchoRequest(string Message);
internal sealed record EchoResponse(string Message);

// Plain Core metadata grants no identity, membership or tenant authority.
[Operation("sample.echo")]
internal sealed class EchoHandler : IOperationHandler<EchoRequest, EchoResponse>, IDisposable
{
    private readonly Counters counters;
    internal EchoHandler(Counters counters) { this.counters = counters; counters.HandlersConstructed++; }
    public ValueTask<OperationResult<EchoResponse>> HandleAsync(EchoRequest request, OperationContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        counters.Dispatches++;
        return ValueTask.FromResult(OperationResult<EchoResponse>.Success(new(request.Message)));
    }
    public void Dispose() => counters.HandlersDisposed++;
}

internal sealed class HandlerFactory(Counters counters) : IOperationHandlerFactory
{
    public THandler Create<THandler>() where THandler : class => typeof(THandler) == typeof(EchoHandler)
        ? (THandler)(object)new EchoHandler(counters) : throw new InvalidOperationException("Unknown generated handler.");
}

internal sealed class AppModule : IAsyncDisposable
{
    private readonly Counters counters;
    internal OperationDispatcher Dispatcher { get; }
    internal AppModule(Counters counters)
    {
        this.counters = counters;
        var registry = new OperationRegistryBuilder();
        // Typed code-generation output adds lazy factories without constructing handlers.
        Cehpalon.Engine.Generated.OperationRegistrations.RegisterAll(registry, new HandlerFactory(counters));
        Dispatcher = new OperationDispatcher(registry.Build());
    }
    public ValueTask DisposeAsync() { counters.ModulesDisposed++; return ValueTask.CompletedTask; }
}

internal sealed class OwnedModule(Counters counters) : IAsyncDisposable
{
    public ValueTask DisposeAsync() { counters.ModulesDisposed++; return ValueTask.CompletedTask; }
}
""");
        Add("appsettings.json", Configuration(true));
        Add("appsettings.off.json", Configuration(false));
        files.Add("global.json", global);
        files.Add("NuGet.Config", nuget);
        files.Add("engine-source.json", manifest);
        Add("README.md", $$"""
# {{name}} — experimental portable request/reply consumer

This generated console application uses the existing Engine Core, Composition and
operation-registration generator through explicit local source project references.
Its assembly is PortableConsumer.{{name}} and its fixed code namespace is
PortableConsumers.Generated, avoiding collisions with framework/Engine names.
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
""");
        return files;
    }

    private static string Configuration(bool enabled) => $$"""
{
  "Cehpalon": {
    "SchemaVersion": 1,
    "Architecture": "Modular",
    "Topology": "SingleProcess",
    "Pattern": "RequestReply",
    "Modules": {
      "app": { "Enabled": {{(enabled ? "true" : "false")}} },
      "optional": { "Enabled": false }
    }
  }
}
""";
}
