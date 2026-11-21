using System.Reflection;
using System.Security;
using System.Text;
using System.Xml.Linq;
using Cehpalon.Engine.Composition;

namespace Cehpalon.Engine.Tooling;

internal static class SmallApiTemplateFiles
{
    internal const string Profile = "small-api";
    internal static readonly string[] SourcePaths =
    [
        "src/Cehpalon.Engine.Identity.Contracts/Cehpalon.Engine.Identity.Contracts.csproj",
        "src/Cehpalon.Engine.Identity.Contracts/IdentityContracts.cs", "src/Cehpalon.Engine.Identity.Contracts/packages.lock.json",
        "src/Cehpalon.Engine.Tenancy/Cehpalon.Engine.Tenancy.csproj", "src/Cehpalon.Engine.Tenancy/Contracts.cs",
        "src/Cehpalon.Engine.Tenancy/TenantOperationDispatcher.cs", "src/Cehpalon.Engine.Tenancy/packages.lock.json",
        "src/Cehpalon.Engine.Transports.Http/Cehpalon.Engine.Transports.Http.csproj",
        "src/Cehpalon.Engine.Transports.Http/Contracts.cs", "src/Cehpalon.Engine.Transports.Http/OperationHttpAdapter.cs",
        "src/Cehpalon.Engine.Transports.Http/packages.lock.json",
        "src/Cehpalon.Engine.Transports.GraphQL/Cehpalon.Engine.Transports.GraphQL.csproj",
        "src/Cehpalon.Engine.Transports.GraphQL/GraphQLAdapter.cs", "src/Cehpalon.Engine.Transports.GraphQL/GraphQLOperationCatalog.cs",
        "src/Cehpalon.Engine.Transports.GraphQL/packages.lock.json"
    ];
    internal static ModuleDescriptor[] Catalog() =>
    [
        new("host", ModuleRole.Support), new("api", ModuleRole.EntryPoint, ["host"]),
        new("graphql", ModuleRole.EntryPoint, ["host"]), new("worker", ModuleRole.EntryPoint),
        new("database", ModuleRole.EntryPoint), new("cache", ModuleRole.EntryPoint),
        new("broker", ModuleRole.EntryPoint), new("ai", ModuleRole.EntryPoint), new("retrieval", ModuleRole.EntryPoint)
    ];
    internal static bool Supported(ActivationPlan plan) => plan.ActivationOrder.All(id => id is "host" or "api" or "graphql");

    internal static bool PackagePolicy(byte[] bytes)
    {
        var document = XDocument.Parse(new UTF8Encoding(false, true).GetString(bytes));
        bool Pinned(string name, string expected)
        {
            var versions = document.Descendants("PackageVersion").Where(x => (string?)x.Attribute("Include") == name).ToArray();
            return versions.Length == 1 && (string?)versions[0].Attribute("Version") == expected;
        }
        return Pinned("Microsoft.AspNetCore.Authentication.JwtBearer", "[11.0.0-rc.3.26522.148]")
            && Pinned("HotChocolate.AspNetCore", "[16.7.1]");
    }

    internal static SortedDictionary<string, byte[]> Create(string name, string engineRoot, byte[] global, byte[] nuget, byte[] manifest)
    {
        var files = new SortedDictionary<string, byte[]>(StringComparer.Ordinal);
        var utf8 = new UTF8Encoding(false, true);
        void Add(string path, string value) => files.Add(path, utf8.GetBytes(value.Replace("\r\n", "\n") + "\n"));
        foreach (var filename in new[] { "Program.cs", "SelfTest.cs", "FixtureHost.cs", "Catalog.cs", "ContractExport.cs" })
        {
            using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("SmallApi." + filename + ".txt")
                ?? throw new InvalidOperationException("Missing bundled Small API source.");
            using var reader = new StreamReader(stream, utf8);
            var text = reader.ReadToEnd();
            if (filename == "ContractExport.cs") text = text.Replace("__CEHPALON_ENGINE_SOURCE_ROOT__",
                System.Text.Json.JsonSerializer.Serialize(engineRoot), StringComparison.Ordinal);
            files.Add(filename, utf8.GetBytes(text));
        }
        string Project(string project) => SecurityElement.Escape(Path.Combine(engineRoot, "src", project, project + ".csproj").Replace('\\', '/'))!;
        Add("Consumer.csproj", $$"""
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net11.0</TargetFramework>
    <AssemblyName>PortableConsumer.{{name}}</AssemblyName>
    <RootNamespace>PortableConsumers.Generated</RootNamespace>
    <ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors><Deterministic>true</Deterministic>
    <IsPackable>false</IsPackable><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
    <ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally>
    <EmitCompilerGeneratedFiles>true</EmitCompilerGeneratedFiles>
    <CompilerGeneratedFilesOutputPath>$(BaseIntermediateOutputPath)generated</CompilerGeneratedFilesOutputPath>
    <EnableDefaultCompileItems>false</EnableDefaultCompileItems>
    <EnableDefaultContentItems>false</EnableDefaultContentItems>
  </PropertyGroup>
  <ItemGroup>
    <Compile Include="Program.cs" /><Compile Include="SelfTest.cs" /><Compile Include="FixtureHost.cs" /><Compile Include="Catalog.cs" /><Compile Include="ContractExport.cs" />
    <Content Include="appsettings*.json" CopyToOutputDirectory="PreserveNewest" />
    <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="[11.0.0-rc.3.26522.148]" />
    <ProjectReference Include="{{Project("Cehpalon.Engine.Core")}}" />
    <ProjectReference Include="{{Project("Cehpalon.Engine.Composition")}}" />
    <ProjectReference Include="{{Project("Cehpalon.Engine.Identity.Contracts")}}" />
    <ProjectReference Include="{{Project("Cehpalon.Engine.Tenancy")}}" />
    <ProjectReference Include="{{Project("Cehpalon.Engine.Transports.Http")}}" />
    <ProjectReference Include="{{Project("Cehpalon.Engine.Transports.GraphQL")}}" />
    <ProjectReference Include="{{Project("Cehpalon.Engine.CodeGeneration")}}" OutputItemType="Analyzer" ReferenceOutputAssembly="false" />
  </ItemGroup>
</Project>
""");
        Add("appsettings.json", Configuration(true, false));
        Add("appsettings.graphql.json", Configuration(true, true));
        Add("appsettings.graphql-only.json", Configuration(false, true));
        Add("appsettings.off.json", Configuration(false, false));
        files.Add("global.json", global); files.Add("NuGet.Config", nuget); files.Add("engine-source.json", manifest);
        Add("README.md", $$"""
# {{name}} - experimental protected Small API

This generated source-checkout consumer uses existing Core, Composition, Identity,
Tenancy, HTTP/GraphQL adapters and actual typed/lazy generated Core gateways.
It is a bounded HTTPS/JWT fixture-backed profile, not production scaffolding,
a real IdP/provider, database/RLS proof or an installable distribution.
Assembly PortableConsumer.{{name}} and fixed namespace PortableConsumers.Generated
avoid framework/Engine naming collisions.

The CLI only writes these fourteen files; no build, download, installation or service
is executed by generation. With the exact SDK pinned by global.json installed:

```text
dotnet build Consumer.csproj -c Release
dotnet run --project Consumer.csproj -c Release --no-build -- --self-test --output <new-report.json>
dotnet run --project Consumer.csproj -c Release --no-build -- --export-contracts --config appsettings.graphql.json --output <new-contract-directory>
dotnet run --project Consumer.csproj -c Release --no-build -- --serve --config appsettings.json --certificate <user.pfx> --public-key <RS256-public.pem> --ready <new-ready.json>
```

Only explicit --self-test creates ephemeral private JWT/TLS fixture keys. Its tests
read the four emitted configurations beside the executable and exercise actual
HTTPS requests, authentication, both cross-tenant denial directions, revocation,
owner/default-policy rejection, typed generated dispatch, disabled endpoints/modules,
invalid startup, in-flight cancellation and owned shutdown. This is correctness
evidence; timings are not performance/production qualification. Raw keys/tokens are
never written to output. A fresh report path is mandatory.

Normal --serve requires caller-provided TLS PFX (password via CEHPALON_TLS_PASSWORD)
and an RSA public PEM of at least2048bits. No host trust or credentials are invented.
It binds HTTPS HTTP/1.1 on IPv4 loopback at an ephemeral port and atomically publishes
a new readiness JSON with address/counters only; existing readiness is refused.
JWT issuer is urn:cehpalon:small-api-fixture, audience cehpalon-small-api-fixture,
algorithm RS256 and type at+jwt; validated subject alice has tenant-a membership,
bob has tenant-b. Both tenants share IDs in the bounded synthetic memory store.
Membership/resource/policy are fresh fixture authority, not real provider integration.
Caller tenant/role/subject headers and Core correlation metadata grant no authority.
Optional --max-concurrent-operations <positive-int> on --serve sets one in-process
business-handler limit shared by the enabled HTTP and GraphQL entrypoints. Admission
follows tenant authorization and capacity is held through handler cleanup. Full
capacity returns operation.capacity_exceeded. Run --self-test-capacity --output
<new-report.json> for the bounded protected HTTPS fixture. Optional
--max-concurrent-operations-per-tenant <positive-int> requires a host limit at least
as large. Both limits count admitted business operations. The partition key is the
authorized tenant. Run --self-test-tenant-capacity --output <new-report.json>
to verify that another tenant can use spare host capacity. The host closes both
kinds of budget at shutdown and waits for admitted work within the shutdown
timeout. Readiness and the post-cleanup stopped report include aggregate capacity
snapshots when a budget is configured. Tenant snapshots contain counts only.
Run --self-test-drain --output <new-report.json> for that lifecycle check.
The generated host offers CreateBudgetMetrics with a host-selected meter name.
Its caller owns collection and disposal. Run --self-test-live-metrics --output
<new-report.json> for protected HTTP/GraphQL traffic with periodic collection and
an admitted write held across shutdown.

Type `stop` followed by Enter, or Ctrl+C, for awaited listener/handler cleanup and
a stopped JSON report. Redirected stdin EOF alone keeps the host alive without
polling; an explicit stop command or Ctrl+C remains necessary.

After building, --export-contracts --config <json> --output <new-directory> writes
offline transport artifacts without WebApplication, TLS/key reads, handlers or
tenant authority calls. It first validates the same Composition/capability plan.
manifest.json is always present; enabled API adds openapi.json and enabled GraphQL
adds schema.graphql from the actual pinned vendor schema. All-off adds neither.
The same typed catalog drives runtime mapping and export; generated operation IDs
are checked with a throwing handler factory that must remain uncalled. Enabled
GraphQL export explicitly constructs/disposes its offline schema service provider
and reports those counters; disabled GraphQL performs no such registration.

HTTP schemas use the adapter's serializer policy and its actual problem envelope.
The object-only request root is explicit; inline schema $id resources preserve
local $ref resolution. These are structural shapes, not complete acceptance rules:
custom validators, CLR numeric bounds, duplicate JSON names, Unicode/byte limits,
tenant policy and business constraints remain enforced by actual runtime checks.
Nullable success roots remain possible as Core allows. No credential or host
readiness is required to export, and HTTP introspection/schema endpoints stay off.
Output is new-only staged publication; artifacts contain no timestamps/output paths.

appsettings.json enables API only, appsettings.graphql.json enables API+GraphQL,
appsettings.graphql-only.json enables GraphQL only, appsettings.off.json disables
all entrypoints. Off configuration imports no TLS/JWT files and constructs no store,
WebApplication or services. GraphQL-disabled skips vendor service registration and mapping;
package/source presence is not activation. /health is anonymous readiness only.
Business routes /api/catalog/get,list,set and optional POST-only /graphql require
valid JWT and TenantOperationDispatcher checks. GraphQL IDE/schema/introspection,
WebSockets/batching/multipart/incremental execution remain disabled by the adapter.
Worker/database/cache/broker/AI/retrieval are unsupported sentinel capabilities;
enabling them fails before any host/module factory. The sole supported tuple is
Modular / SingleProcess / RequestReply.

engine-source.json records observed selected editable source bytes, not immutable
Git/build attestation or a complete source inventory. Source paths and inherited
SDK/MSBuild parent policy must be trusted. Revalidate actual source and package
locks before reusing evidence. GraphQL/JWT versions are pinned to the observed Engine
package policy, not claimed latest. Compiler-only CodeGeneration/Roslyn must not
appear in the runtime dependency graph. Full #20 tooling benchmark, arbitrary transport schema
generation, packaging/global-tool, AOT/trimming, #3 and production gates remain open.
""");
        return files;
    }

    private static string Configuration(bool api, bool graphql) => $$"""
{
  "Cehpalon": {
    "SchemaVersion": 1, "Architecture": "Modular", "Topology": "SingleProcess", "Pattern": "RequestReply",
    "Modules": {
      "api": { "Enabled": {{(api ? "true" : "false")}} },
      "graphql": { "Enabled": {{(graphql ? "true" : "false")}} },
      "worker": { "Enabled": false }, "database": { "Enabled": false },
      "cache": { "Enabled": false }, "broker": { "Enabled": false },
      "ai": { "Enabled": false }, "retrieval": { "Enabled": false }
    }
  }
}
""";
}
