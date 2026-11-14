"""Build actual generated contracts, then compare exports with the live typed fixture."""
import argparse
import hashlib
import json
import os
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
CONFIGS = {'api': ('appsettings.json', True, False),
           'both': ('appsettings.graphql.json', True, True),
           'graphql': ('appsettings.graphql-only.json', False, True),
           'off': ('appsettings.off.json', False, False)}
EXPECTED = {'Consumer.csproj', 'Program.cs', 'SelfTest.cs', 'FixtureHost.cs', 'Catalog.cs', 'ContractExport.cs',
            'appsettings.json', 'appsettings.graphql.json', 'appsettings.graphql-only.json',
            'appsettings.off.json', 'global.json', 'NuGet.Config', 'engine-source.json', 'README.md'}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dotnet', required=True)
    parser.add_argument('--engine-root', default=str(ROOT.parent / 'Cehpalon-Engine'))
    parser.add_argument('--output', required=True)
    parser.add_argument('--integration', action='store_true')
    args = parser.parse_args()
    engine = Path(args.engine_root).resolve()
    output = (ROOT / args.output).resolve()
    private = (ROOT / '.local').resolve()
    if output == private or not output.is_relative_to(private):
        raise ValueError('Use a fresh directory beneath ignored Samples .local')
    output.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, DOTNET_NOLOGO='1', DOTNET_CLI_TELEMETRY_OPTOUT='1')
    report = {'started_utc': datetime.now(timezone.utc).isoformat(), 'status': 'started', 'commands': [], 'checks': [],
              'harness_sha256': sha(Path(__file__)),
              'scope': 'Bounded offline schema and actual localhost fixture differential proof; not arbitrary schemas, validator/tenant authority equivalence, performance, real IdP/provider or production qualification'}

    def save():
        (output / 'manifest.json').write_text(json.dumps(report, indent=2, ensure_ascii=True) + '\n', encoding='utf-8', newline='\n')

    def check(ok, description):
        if not ok:
            raise ValueError(description)
        report['checks'].append(description)

    def run(argv, cwd, log, expected=0):
        argv = list(map(str, argv))
        try:
            result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=240)
        except subprocess.TimeoutExpired as error:
            (output / log).write_bytes((error.stdout or b'') + (error.stderr or b''))
            report['commands'].append({'argv': argv, 'cwd': str(cwd), 'exit': None, 'timed_out_seconds': 240,
                                       'log': log, 'sha256': sha(output / log)})
            save()
            raise
        (output / log).write_bytes(result.stdout + result.stderr)
        report['commands'].append({'argv': argv, 'cwd': str(cwd), 'exit': result.returncode, 'log': log, 'sha256': sha(output / log)})
        save()
        if result.returncode != expected:
            raise RuntimeError(f'Expected exit {expected}, got {result.returncode}; retained {log}')
        return result.stdout.decode('utf-8-sig').strip()

    save()
    try:
        revision = run(['git', 'rev-parse', 'HEAD'], engine, 'engine-head.txt')
        dirty = run(['git', 'status', '--porcelain'], engine, 'engine-status.txt')
        report.update(engine_revision=revision, source_state='uncommitted integration' if dirty else 'exact clean committed source')
        report['engine_source_sha256'] = {p.relative_to(engine).as_posix(): sha(p)
            for folder in ['src/Cehpalon.Engine.Tooling', 'src/Cehpalon.Engine.Transports.Http', 'src/Cehpalon.Engine.Transports.GraphQL']
            for p in sorted((engine / folder).rglob('*')) if p.is_file() and not {'bin', 'obj'}.intersection(p.relative_to(engine / folder).parts)}
        lock = read(ROOT / 'tooling-contracts/engine-lock.json')
        if not args.integration:
            check(not dirty and re.fullmatch('[a-f0-9]{40}', lock['engine_revision']) is not None
                  and revision == lock['engine_revision'], 'actual clean Engine revision matches consumer lock')
        report['sdk'] = run([args.dotnet, '--version'], engine, 'sdk-version.txt')
        check(report['sdk'] == lock['sdk'], 'exact pinned SDK selected')
        source_engine = engine
        if not args.integration:
            source_engine = output / 'engine source ไทย & spaces'
            run(['git', 'clone', '--local', '--no-hardlinks', '--no-checkout', engine, source_engine], ROOT, 'clone.txt')
            run(['git', 'checkout', '--detach', revision], source_engine, 'checkout.txt')
            check(run(['git', 'rev-parse', 'HEAD'], source_engine, 'clone-head.txt') == revision
                  and not run(['git', 'status', '--porcelain'], source_engine, 'clone-status.txt'), 'real clean source clone under escaped path')
        engine_artifacts = output / 'engine-artifacts'
        cli_project = engine / 'src/Cehpalon.Engine.Tooling/Cehpalon.Engine.Tooling.csproj'
        run([args.dotnet, 'restore', cli_project, '--locked-mode', '--configfile', engine / 'NuGet.Config', '--artifacts-path', engine_artifacts], engine, 'cli-restore.txt')
        run([args.dotnet, 'build', cli_project, '-c', 'Release', '--no-restore', '--artifacts-path', engine_artifacts,
             '-p:UseSharedCompilation=false', '-warnaserror'], engine, 'cli-build.txt')
        cli = [args.dotnet, engine_artifacts / 'bin/Cehpalon.Engine.Tooling/release/cehpalon.dll']
        consumer = output / 'generated contracts ไทย & spaces'
        run(cli + ['new', '--profile', 'small-api', '--name', 'System', '--output', consumer, '--engine-root', source_engine], ROOT, 'new.txt')
        check({p.name for p in consumer.iterdir()} == EXPECTED, 'actual fourteen-file schema-capable Small API scaffold')
        report['generated_files_sha256'] = {p.name: sha(p) for p in sorted(consumer.iterdir())}
        observed = read(consumer / 'engine-source.json')
        report['observed_source_manifest'] = observed
        check(observed.get('provenance') == 'observed-source-bytes-not-git-attestation', 'source observation boundary explicit')
        seen = set()
        for item in observed['inputs']:
            relative = Path(item['path']); path = (source_engine / relative).resolve()
            check(not relative.is_absolute() and path.is_relative_to(source_engine) and item['path'] not in seen,
                  'unique bounded observed input ' + item['path'])
            seen.add(item['path'])
            check(sha(path) == item['sha256'] and path.stat().st_size == item['bytes'], 'observed bytes match ' + item['path'])
        check(len(seen) == 32, 'exact selected thirty-two source inputs')
        artifacts = output / 'consumer-artifacts'
        run([args.dotnet, 'restore', consumer / 'Consumer.csproj', '--configfile', consumer / 'NuGet.Config', '--artifacts-path', artifacts], consumer, 'consumer-restore.txt')
        check((consumer / 'packages.lock.json').is_file(), 'actual consumer package lock created')
        lock_hash = sha(consumer / 'packages.lock.json')
        (output / 'consumer-packages.lock.json').write_bytes((consumer / 'packages.lock.json').read_bytes())
        run([args.dotnet, 'restore', consumer / 'Consumer.csproj', '--locked-mode', '--configfile', consumer / 'NuGet.Config', '--artifacts-path', artifacts], consumer, 'consumer-locked-restore.txt')
        check(sha(consumer / 'packages.lock.json') == lock_hash, 'locked consumer restore preserves actual graph')
        run([args.dotnet, 'build', consumer / 'Consumer.csproj', '-c', 'Release', '--no-restore', '--artifacts-path', artifacts,
             '-p:UseSharedCompilation=false', '-warnaserror'], consumer, 'consumer-build.txt')
        registries = list((artifacts / 'obj').rglob('OperationRegistrations.g.cs'))
        check(len(registries) == 1, 'one actual emitted registry')
        text = registries[0].read_text(encoding='utf-8-sig')
        check(text.count('builder.Register<') == text.count('factory.Create<') == 3
              and all('"' + x + '"' in text for x in ['catalog.get', 'catalog.list', 'catalog.set']), 'three actual typed lazy generated gateways')
        (output / 'OperationRegistrations.g.cs.txt').write_bytes(registries[0].read_bytes())
        report['generated_registry_sha256'] = sha(registries[0])
        assembly = artifacts / 'bin/Consumer/release/PortableConsumer.System.dll'
        libraries = read(assembly.with_suffix('.deps.json'))['libraries']
        check(not any(any(x in name.lower() for x in ['codeanalysis', 'codegeneration', 'tooling']) for name in libraries), 'compiler/Tooling excluded from consumer runtime')
        report['runtime_libraries'] = sorted(libraries)
        exports = export_cases(args.dotnet, assembly, consumer, output, run, check, report)
        helper = output / 'schema-wire-proof'
        helper.mkdir()
        project = HELPER_PROJECT.replace('@@PROJECT@@', escape(str(consumer / 'Consumer.csproj'), {'"': '&quot;'}))
        (helper / 'SchemaWireProof.csproj').write_text(project, encoding='utf-8', newline='\n')
        (helper / 'Program.cs').write_text(HELPER_SOURCE, encoding='utf-8', newline='\n')
        (helper / 'global.json').write_bytes((consumer / 'global.json').read_bytes())
        (helper / 'NuGet.Config').write_bytes((consumer / 'NuGet.Config').read_bytes())
        report['proof_helper_sha256'] = sha(helper / 'Program.cs')
        helper_artifacts = output / 'proof-artifacts'
        run([args.dotnet, 'restore', helper / 'SchemaWireProof.csproj', '--configfile', helper / 'NuGet.Config', '--artifacts-path', helper_artifacts], helper, 'proof-restore.txt')
        run([args.dotnet, 'build', helper / 'SchemaWireProof.csproj', '-c', 'Release', '--no-restore', '--artifacts-path', helper_artifacts,
             '-p:UseSharedCompilation=false', '-warnaserror'], helper, 'proof-build.txt')
        result_path = output / 'schema-wire-proof.json'
        run([args.dotnet, helper_artifacts / 'bin/SchemaWireProof/release/SchemaWireProof.dll', consumer, output, result_path, args.dotnet, assembly], helper, 'schema-wire-proof.txt')
        actual = read(result_path)
        check(actual.get('failed') == 0 and actual.get('passed', 0) > 0, 'actual HTTPS/runtime schema differential helper passes')
        report['wire_differential'] = actual
        report.update(status='passed', finished_utc=datetime.now(timezone.utc).isoformat(), consumer_lock_sha256=lock_hash)
    except Exception as error:
        report.update(status='failed', error=str(error), finished_utc=datetime.now(timezone.utc).isoformat())
        save()
        raise
    save()
    print(json.dumps({'status': report['status'], 'checks': len(report['checks']), 'differential_checks': report['wire_differential']['passed'], 'output': str(output)}))


def export_cases(dotnet, assembly, consumer, output, run, check, report):
    observations = {}
    for name, (filename, api, graphql) in CONFIGS.items():
        target = output / ('export-' + name)
        twin = output / ('export-' + name + '-twin')
        for destination, suffix in [(target, ''), (twin, '-twin')]:
            run([dotnet, assembly, '--export-contracts', '--config', consumer / filename, '--output', destination], consumer, 'export-' + name + suffix + '.txt')
        files = {'manifest.json'} | ({'openapi.json'} if api else set()) | ({'schema.graphql'} if graphql else set())
        check({p.name for p in target.iterdir()} == files, name + ' exports only enabled artifact filenames')
        check({p.name: sha(p) for p in target.iterdir()} == {p.name: sha(p) for p in twin.iterdir()}, name + ' artifacts deterministic across two output destinations')
        document = read(target / 'manifest.json')
        observations[name] = document
        check(document.get('profile') == 'small-api', name + ' export declares bounded profile')
        values = document['counters']
        for metric in ['HandlerFactoryCalls', 'DispatchCalls', 'HostFactories', 'TlsReads', 'AuthorityCalls']:
            check(values.get(metric) == 0, name + ' export performs zero ' + metric)
        check(values.get('HttpSchemaOperations') == (3 if api else 0), name + ' selected HTTP typed schema operation count')
        for metric in ['GraphQLRegistrations', 'GraphQLSchemaBuilds', 'GraphQLProvidersCreated', 'GraphQLProvidersDisposed']:
            check(values.get(metric) == (1 if graphql else 0), name + ' honest selected schema-compiler lifetime: ' + metric)
        check((values.get('GraphQLServices', 0) > 0) if graphql else values.get('GraphQLServices') == 0,
              name + ' disabled GraphQL registers no vendor services')
        check(document.get('generatedOperationIds') == ['catalog.get', 'catalog.list', 'catalog.set'], name + ' generated registry IDs checked without handler factory')
        check(document.get('httpOperationIds') == (['catalog.get', 'catalog.list', 'catalog.set'] if api else []), name + ' HTTP metadata matches selected operations')
        for artifact in document.get('artifacts', []):
            path = target / artifact['name']
            check(path.name in files and sha(path) == artifact['sha256'] and path.stat().st_size == artifact['bytes'],
                  name + ' manifest identifies actual published bytes: ' + path.name)
        if api:
            schema = read(target / 'openapi.json')
            check(str(schema.get('openapi', '')).startswith('3.1.'), name + ' declares OpenAPI3.1 schema dialect')
            check(set(schema['paths']) == {'/api/catalog/get', '/api/catalog/list', '/api/catalog/set'}, name + ' exports actual three typed HTTP operation routes')
            check({v['post']['operationId'] for v in schema['paths'].values()} == {'catalog.get', 'catalog.list', 'catalog.set'}, name + ' operation IDs match actual generated registry')
    invalid = read(consumer / 'appsettings.json'); invalid['Cehpalon']['Pattern'] = 'Unsupported'
    worker = read(consumer / 'appsettings.json'); worker['Cehpalon']['Modules']['worker'] = {'Enabled': True}
    for name, config in [('invalid', invalid), ('worker', worker)]:
        path = output / (name + '-config.json'); path.write_text(json.dumps(config), encoding='utf-8')
        target = output / ('rejected-' + name)
        run([dotnet, assembly, '--export-contracts', '--config', path, '--output', target], consumer, 'export-' + name + '.txt', expected=2)
        check(not target.exists(), name + ' configuration rejects before publishing output')
        failure = read(output / ('export-' + name + '.txt'))
        check(all(v == 0 for v in failure['counters'].values()), name + ' rejection reports zero artifact/service/handler work')
    for name, kind in [('existing-directory', 'directory'), ('existing-empty-directory', 'empty-directory'), ('existing-file', 'file')]:
        target = output / name
        if kind == 'directory':
            target.mkdir(); (target / 'outsider.txt').write_bytes(b'outsider\n'); before = sha(target / 'outsider.txt')
        elif kind == 'empty-directory':
            target.mkdir(); before = None
        else:
            target.write_bytes(b'outsider\n'); before = sha(target)
        run([dotnet, assembly, '--export-contracts', '--config', consumer / 'appsettings.graphql.json', '--output', target], consumer, 'export-' + name + '.txt', expected=3)
        check((not list(target.iterdir())) if kind == 'empty-directory' else (sha(target / 'outsider.txt') if kind == 'directory' else sha(target)) == before,
              name + ' refused without overwrite')
    link = output / 'linked-parent'; actual = output / 'link-target'; actual.mkdir()
    link.symlink_to(actual, target_is_directory=True)
    run([dotnet, assembly, '--export-contracts', '--config', consumer / 'appsettings.json', '--output', link / 'consumer'], consumer, 'export-link.txt', expected=3)
    check(not (actual / 'consumer').exists(), 'observed symlink/reparse ancestor rejected without publication')
    dangling = output / 'dangling-target'; dangling.symlink_to(output / 'missing-link-target', target_is_directory=True)
    run([dotnet, assembly, '--export-contracts', '--config', consumer / 'appsettings.json', '--output', dangling], consumer, 'export-dangling.txt', expected=3)
    check(dangling.is_symlink() and not (output / 'missing-link-target').exists(), 'dangling target remains untouched')
    source_root = Path(read(consumer / 'engine-source.json')['sourceRoot'])
    protected = source_root / 'src' / ('ContractExportMustNotCreate-' + uuid.uuid4().hex)
    run([dotnet, assembly, '--export-contracts', '--config', consumer / 'appsettings.json', '--output', protected], consumer, 'export-checkout-source.txt', expected=3)
    check(not protected.exists(), 'known Engine checkout src is not an export destination')
    report['export_observations'] = observations
    return observations


HELPER_PROJECT = '''<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net11.0</TargetFramework>
  <ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable><TreatWarningsAsErrors>true</TreatWarningsAsErrors>
  <IsPackable>false</IsPackable><ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally></PropertyGroup>
  <ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App" />
  <ProjectReference Include="@@PROJECT@@" /></ItemGroup>
</Project>
'''

HELPER_SOURCE = r'''using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using HotChocolate.Execution;
using HotChocolate.Language;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using PortableConsumers.Generated;

var consumer = Path.GetFullPath(args[0]);
var output = Path.GetFullPath(args[1]);
var resultPath = Path.GetFullPath(args[2]);
var dotnet = Path.GetFullPath(args[3]);
var consumerAssembly = Path.GetFullPath(args[4]);
var cases = new List<object>();
var observations = new List<object>();
var failed = 0;
void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
async Task Check(string name, Func<Task> test)
{
    try { await test(); cases.Add(new { name, passed = true }); }
    catch (Exception error) { failed++; cases.Add(new { name, passed = false, error = error.ToString() }); }
}
var profiles = new[] { (Name:"api", File:"appsettings.json", Api:true, GraphQL:false),
    (Name:"both", File:"appsettings.graphql.json", Api:true, GraphQL:true),
    (Name:"graphql", File:"appsettings.graphql-only.json", Api:false, GraphQL:true) };
using var tls = new TlsFixture();
using var jwt = new JwtFixture();
foreach (var profile in profiles)
{
    await using var host = new FixtureHost();
    await host.Start(File.ReadAllText(Path.Combine(consumer, profile.File)), tls, jwt);
    using var client = tls.Client(host.Address);
    var openapiPath = Path.Combine(output, "export-" + profile.Name, "openapi.json");
    JsonNode? openapi = profile.Api ? JsonNode.Parse(File.ReadAllText(openapiPath))! : null;
    JsonNode Schema(string operation, bool request, int status = 200)
    {
        var post = openapi!["paths"]!["/api/catalog/" + operation]!["post"]!;
        return request ? post["requestBody"]!["content"]!["application/json"]!["schema"]!
            : post["responses"]![status.ToString(System.Globalization.CultureInfo.InvariantCulture)]!["content"]![status == 200 ? "application/json" : "application/problem+json"]!["schema"]!;
    }
    async Task<(int Status, JsonNode? Body, string? ContentType)> Send(string path, object body, string? subject = "alice", string? explicitToken = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body) };
        if (subject is not null || explicitToken is not null) request.Headers.Authorization = new("Bearer", explicitToken ?? jwt.Token(subject!));
        request.Headers.Add("X-Tenant", "tenant-b"); request.Headers.Add("X-Subject", "bob"); request.Headers.Add("X-Role", "admin");
        using var response = await client.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        return ((int)response.StatusCode, string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text), response.Content.Headers.ContentType?.MediaType);
    }
    if (profile.Api)
    {
        await Check(profile.Name + ": OpenAPI routes equal actual mapped POST endpoints", () =>
        {
            var mapped = ((IEndpointRouteBuilder)host.Application!).DataSources.SelectMany(x => x.Endpoints)
                .OfType<RouteEndpoint>().Where(e => e.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods.Contains("POST") == true)
                .Select(e => e.RoutePattern.RawText!).Where(p => p.StartsWith("/api/", StringComparison.Ordinal)).Order(StringComparer.Ordinal).ToArray();
            Require(mapped.SequenceEqual(openapi!["paths"]!.AsObject().Select(x => x.Key).Order(StringComparer.Ordinal)), "Export/runtime paths differ.");
            return Task.CompletedTask;
        });
        await Check(profile.Name + ": actual authenticated get/list/set requests and successful responses satisfy exported shape", async () =>
        {
            foreach (var (operation, input) in new (string,object)[] {
                ("get", new { tenant="tenant-a", id=1 }), ("list", new { tenant="tenant-a", page=0 }),
                ("set", new { tenant="tenant-a", id=2, expectedRevision=0, label="schema-proof" }) })
            {
                var node = JsonSerializer.SerializeToNode(input)!;
                Require(Shape.Accept(Schema(operation, true), node), "Valid request disagrees with exported schema: " + operation);
                var response = await Send("/api/catalog/" + operation, input);
                Require(response.Status == 200 && response.ContentType == "application/json" && Shape.Accept(Schema(operation, false), response.Body), "Actual response disagrees with exported schema: " + operation);
                if (operation == "list") Require(response.Body!["items"]!.AsArray().Count == 20, "Nested array response changed.");
                else Require(response.Body!["amountMinorUnits"]!.GetValue<long>() > 0, "Int64 field did not survive wire serialization.");
                observations.Add(new { profile=profile.Name, operation, response.Status, response.ContentType, body=response.Body });
            }
        });
        await Check(profile.Name + ": exported request shapes reject missing/null/unmapped properties and array root, matching actual adapter", async () =>
        {
            foreach (var input in new JsonNode?[] { JsonNode.Parse("{\"tenant\":\"tenant-a\"}"),
                JsonNode.Parse("{\"tenant\":null,\"id\":1}"), JsonNode.Parse("{\"tenant\":\"tenant-a\",\"id\":1,\"unknown\":true}"), new JsonArray(), null })
            {
                Require(!Shape.Accept(Schema("get", true), input), "Export accepted a structurally invalid request.");
                var before = host.Store.Work;
                using var request = new HttpRequestMessage(HttpMethod.Post, "/api/catalog/get") { Content = new StringContent(input?.ToJsonString() ?? "null", Encoding.UTF8, "application/json") };
                request.Headers.Authorization = new("Bearer", jwt.Token());
                using var response = await client.SendAsync(request);
                Require((int)response.StatusCode == 400 && host.Store.Work == before, "Adapter accepted invalid shape or did business.");
            }
        });
        await Check(profile.Name + ": shape-valid id0 still fails custom validation before business", async () =>
        {
            var invalid = new { tenant="tenant-a", id=0 };
            Require(Shape.Accept(Schema("get", true), JsonSerializer.SerializeToNode(invalid)), "Schema incorrectly pretends to model custom id predicate.");
            var before = host.Store.Work; var response = await Send("/api/catalog/get", invalid);
            Require(response.Status == 400 && response.Body?["code"]?.GetValue<string>() == "validation.failed"
                && response.ContentType == "application/problem+json" && Shape.Accept(Schema("get", false, 400), response.Body) && host.Store.Work == before,
                "Custom validator / error envelope differed.");
            observations.Add(new { profile=profile.Name, operation="schema-valid-custom-invalid", response.Status, body=response.Body });
        });
        await Check(profile.Name + ": schema-valid cross-tenant requests deny both directions before business", async () =>
        {
            foreach (var (tenant, subject) in new[] { ("tenant-b", "alice"), ("tenant-a", "bob") })
            {
                var input = new { tenant, id=1 }; Require(Shape.Accept(Schema("get", true), JsonSerializer.SerializeToNode(input)), "Tenant policy leaked into JSON shape.");
                var before = host.Store.Work; var response = await Send("/api/catalog/get", input, subject);
                Require(response.Status == 403 && response.ContentType == "application/problem+json" && response.Body?["code"]?.GetValue<string>() == "access.denied"
                    && Shape.Accept(Schema("get", false, 403), response.Body) && host.Store.Work == before, "Cross-tenant error/authority disagreed with contract.");
                observations.Add(new { profile=profile.Name, operation="cross-tenant", tenant, subject, response.Status, body=response.Body });
            }
        });
        await Check(profile.Name + ": OpenAPI documents unauthenticated response without invented body schema", async () =>
        {
            var before = host.Store.Work; var response = await Send("/api/catalog/get", new { tenant="tenant-a",id=1 }, null);
            Require(response.Status == 401 && host.Store.Work == before, "Anonymous request did work.");
            Require(openapi!["paths"]!["/api/catalog/get"]!["post"]!["responses"]!["401"]!["content"] is null, "401 advertised a mandatory invented envelope.");
        });
        await Check(profile.Name + ": API-only GraphQL remains absent with no vendor registration", async () =>
        {
            if (profile.GraphQL) return;
            var response = await Send("/graphql", new { query="{ __typename }" });
            Require(response.Status == 404 && host.Counters.GraphQLFactories == 0 && host.Counters.GraphQLServices == 0, "Offline artifact work enabled runtime GraphQL.");
        });
    }
    if (profile.GraphQL)
    {
        await Check(profile.Name + ": exported SDL AST equals complete actual enabled runtime schema AST", async () =>
        {
            var executor = await host.Application!.Services.GetRequiredService<IRequestExecutorProvider>().GetExecutorAsync();
            var actual = Utf8GraphQLParser.Parse(executor.Schema.ToString()).ToString();
            var exported = Utf8GraphQLParser.Parse(File.ReadAllText(Path.Combine(output, "export-" + profile.Name, "schema.graphql"))).ToString();
            Require(actual == exported, "Export/runtime schema AST differs.");
            observations.Add(new { profile=profile.Name, actualSchema=actual, astIdentical=true });
        });
        await Check(profile.Name + ": actual GraphQL query and cross-tenant error preserve typed schema and authority", async () =>
        {
            string Query(string tenant) => "{ catalogItem(input:{tenant:\"" + tenant + "\",id:1}){tenant id label revision amountMinorUnits} }";
            var own = await Send("/graphql", new { query=Query("tenant-a") });
            Require(own.Status == 200 && own.Body?["errors"] is null && own.Body?["data"]?["catalogItem"]?["tenant"]?.GetValue<string>() == "tenant-a", "Actual GraphQL shape/owner request failed.");
            var before = host.Store.Work; var cross = await Send("/graphql", new { query=Query("tenant-b") });
            Require(cross.Status == 200 && cross.Body?["errors"]?[0]?["extensions"]?["code"]?.GetValue<string>() == "access.denied" && host.Store.Work == before, "GraphQL crossed tenant after offline export.");
        });
        await Check(profile.Name + ": offline schema file does not enable public introspection or schema download", async () =>
        {
            var response = await Send("/graphql", new { query="{ __schema { types { name } } }" });
            Require(response.Body?["errors"] is not null && !response.Body!.ToJsonString().Contains("\"types\"", StringComparison.Ordinal), "Introspection exposed.");
            foreach (var path in new[] { "/graphql?sdl", "/graphql/schema.graphql", "/graphql/ui", "/graphql?query={__typename}" })
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, path); request.Headers.Authorization = new("Bearer", jwt.Token());
                using var result = await client.SendAsync(request); Require(!result.IsSuccessStatusCode, "Offline export enabled HTTP exposure: " + path);
            }
        });
        if (!profile.Api)
            await Check(profile.Name + ": GraphQL-only still has no API mapping or handler work on API route", async () =>
            {
                var before = host.Store.Work; var response = await Send("/api/catalog/get", new { tenant="tenant-a", id=1 });
                Require(response.Status == 404 && host.Counters.ApiFactories == 0 && host.Store.Work == before, "GraphQL-only enabled API.");
            });
    }
    await Check(profile.Name + ": actual enabled host closes listener and balances handler disposal", async () =>
    {
        var address = host.Address; await host.DisposeAsync();
        Require(host.Store.Factories == host.Store.Disposals && host.Counters.HostDisposals == 1 && host.Counters.ForbiddenFactories == 0, "Owned cleanup changed.");
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        try { await socket.ConnectAsync(IPAddress.Loopback, address.Port); throw new InvalidOperationException("Listener remains open."); }
        catch (SocketException) { }
    });
}
await Check("late publication write denial preserves real GraphQL schema/provider cleanup counters", async () =>
{
    var parent = OperatingSystem.IsWindows() ? Path.Combine(output, "owned-readonly-export-parent")
        : Path.Combine(Path.GetTempPath(), "cehpalon-contract-readonly-" + Guid.NewGuid().ToString("N"));
    Require(!Directory.Exists(parent) && !File.Exists(parent), "Use a new owned permission fixture.");
    Directory.CreateDirectory(parent);
    DirectorySecurity? originalDacl = null;
    UnixFileMode? originalMode = null;
    var destination = Path.Combine(parent, "new-contracts");
    Process? process = null;
    try
    {
        if (OperatingSystem.IsWindows())
        {
            var directory = new DirectoryInfo(parent);
            // Access-only save/restore does not request owner mutation privileges.
            originalDacl = directory.GetAccessControl(AccessControlSections.Access);
            var sid = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException();
            var restricted = new DirectorySecurity();
            restricted.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            restricted.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.ReadAndExecute,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            directory.SetAccessControl(restricted);
            var observed = directory.GetAccessControl(AccessControlSections.Access);
            var rules = observed.GetAccessRules(true,true,typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
            Require(observed.AreAccessRulesProtected && rules.Length == 1 && rules[0].IdentityReference == sid
                && rules[0].AccessControlType == AccessControlType.Allow && (rules[0].FileSystemRights & FileSystemRights.Write) == 0,
                "Owned permission fixture is not read/execute-only.");
        }
        else
        {
            originalMode = File.GetUnixFileMode(parent);
            File.SetUnixFileMode(parent, UnixFileMode.UserRead | UnixFileMode.UserExecute);
            Require(File.GetUnixFileMode(parent) == (UnixFileMode.UserRead | UnixFileMode.UserExecute), "Native permission fixture is not Unix0500.");
        }
        var start = new ProcessStartInfo(dotnet) { UseShellExecute=false, RedirectStandardOutput=true, RedirectStandardError=true };
        foreach (var argument in new[] { consumerAssembly, "--export-contracts", "--config", Path.Combine(consumer,"appsettings.graphql.json"), "--output", destination }) start.ArgumentList.Add(argument);
        process = Process.Start(start) ?? throw new InvalidOperationException("Child exporter did not start.");
        var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        await process.WaitForExitAsync(timeout.Token);
        var outText = await stdout; var errorText = await stderr;
        Require(process.ExitCode == 3 && string.IsNullOrWhiteSpace(outText) && !Directory.Exists(destination), "Export unexpectedly published into denied parent.");
        var result = JsonNode.Parse(errorText)!; var counters = result["counters"]!;
        Require(result["code"]?.GetValue<string>() == "export.failure"
            && counters["GraphQLProvidersCreated"]?.GetValue<int>() == 1 && counters["GraphQLProvidersDisposed"]?.GetValue<int>() == 1
            && counters["GraphQLSchemaBuilds"]?.GetValue<int>() == 1 && counters["GraphQLRegistrations"]?.GetValue<int>() == 1,
            "Late failure falsely hid schema construction or failed to await provider disposal.");
        foreach (var metric in new[] { "HandlerFactoryCalls", "DispatchCalls", "HostFactories", "TlsReads", "AuthorityCalls" })
            Require(counters[metric]?.GetValue<int>() == 0, "Late failed export did unexpected work: " + metric);
        observations.Add(new { phase="late-publication-denied", expectedExit=3, stdout=outText, stderr=result,
            permissionPolicy=OperatingSystem.IsWindows()?"current-user-only protected read/execute DACL":"native Unix0500 parent",
            outputAbsent=true, secrets=false });
    }
    finally
    {
        if (process is not null) { if (!process.HasExited) { process.Kill(); await process.WaitForExitAsync(); } process.Dispose(); }
        if (OperatingSystem.IsWindows() && originalDacl is not null) new DirectoryInfo(parent).SetAccessControl(originalDacl);
        if (!OperatingSystem.IsWindows() && originalMode is not null) File.SetUnixFileMode(parent, originalMode.Value);
    }
});
var report = new { passed=cases.Count-failed, failed, scope="Actual generated runtime HTTPS routes/SDL AST/JSON-shape differential fixture; independent bounded keyword interpreter is not an arbitrary JSON Schema validator or tenant authority.",
    checks=cases, observations, schemaKeywords=Shape.Used.Order(StringComparer.Ordinal).ToArray() };
File.WriteAllText(resultPath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented=true }) + "\n", new UTF8Encoding(false));
Console.WriteLine(JsonSerializer.Serialize(new { report.passed, report.failed }));
return failed == 0 ? 0 : 1;

static class Shape
{
    internal static readonly HashSet<string> Used = new(StringComparer.Ordinal);
    private static readonly HashSet<string> Supported = new(["$id","$schema","$comment","title","description","type","properties","required","additionalProperties","items","minimum","maximum","format","pattern","enum","const","allOf","anyOf","oneOf","$ref","$defs"], StringComparer.Ordinal);
    internal static bool Accept(JsonNode schema, JsonNode? value) => Match(schema, value, schema);
    private static bool Match(JsonNode schema, JsonNode? value, JsonNode root)
    {
        if (schema is JsonValue boolean && boolean.TryGetValue<bool>(out var pass)) return pass;
        foreach (var item in schema.AsObject())
        {
            Used.Add(item.Key); if (!Supported.Contains(item.Key)) throw new InvalidOperationException("Unimplemented schema keyword: " + item.Key);
        }
        if (schema["$id"] is not null) root = schema;
        if (schema["$ref"] is JsonValue reference)
        {
            var text = reference.GetValue<string>(); if (!text.StartsWith("#/", StringComparison.Ordinal)) throw new InvalidOperationException("Unsupported schema reference.");
            JsonNode? target = root;
            foreach (var part in text[2..].Split('/')) target = target?[part.Replace("~1", "/", StringComparison.Ordinal).Replace("~0", "~", StringComparison.Ordinal)];
            if (target is null || !Match(target, value, root)) return false;
        }
        if (schema["allOf"] is JsonArray all && !all.All(s => Match(s!, value, root))) return false;
        if (schema["anyOf"] is JsonArray any && !any.Any(s => Match(s!, value, root))) return false;
        if (schema["oneOf"] is JsonArray one && one.Count(s => Match(s!, value, root)) != 1) return false;
        var kind = value?.GetValueKind() ?? JsonValueKind.Null;
        bool Is(string type) => type switch {
            "object" => kind==JsonValueKind.Object, "array" => kind==JsonValueKind.Array, "string" => kind==JsonValueKind.String,
            "integer" => kind==JsonValueKind.Number && decimal.TryParse(value!.ToJsonString(), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var n) && decimal.Truncate(n)==n,
            "number" => kind==JsonValueKind.Number, "boolean" => kind is JsonValueKind.True or JsonValueKind.False, "null" => kind==JsonValueKind.Null,
            _ => throw new InvalidOperationException("Unknown schema type.") };
        if (schema["type"] is JsonArray union) { if (!union.Any(t => Is(t!.GetValue<string>()))) return false; }
        else if (schema["type"] is JsonValue type && !Is(type.GetValue<string>())) return false;
        if (schema["enum"] is JsonArray options && !options.Any(o => JsonNode.DeepEquals(o,value))) return false;
        if (schema["const"] is JsonNode constant && !JsonNode.DeepEquals(constant,value)) return false;
        if (kind==JsonValueKind.Object)
        {
            var obj=value!.AsObject(); var properties=schema["properties"]?.AsObject();
            if (schema["required"] is JsonArray required && required.Any(p => !obj.ContainsKey(p!.GetValue<string>()))) return false;
            foreach (var item in obj)
            {
                if (properties?.TryGetPropertyValue(item.Key,out var property)==true) { if (!Match(property!,item.Value,root)) return false; }
                else if (schema["additionalProperties"] is JsonValue restriction && restriction.TryGetValue<bool>(out var allow) && !allow) return false;
            }
        }
        if (kind==JsonValueKind.Array && schema["items"] is JsonNode items && value!.AsArray().Any(item => !Match(items,item,root))) return false;
        if (kind==JsonValueKind.Number)
        {
            var number=decimal.Parse(value!.ToJsonString(), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture);
            if (schema["minimum"] is JsonNode min && number < decimal.Parse(min.ToJsonString(),System.Globalization.CultureInfo.InvariantCulture)) return false;
            if (schema["maximum"] is JsonNode max && number > decimal.Parse(max.ToJsonString(),System.Globalization.CultureInfo.InvariantCulture)) return false;
            if (schema["format"]?.GetValue<string>() is string format)
            {
                if (format=="int32" && (number<int.MinValue || number>int.MaxValue)) return false;
                if (format=="int64" && (number<long.MinValue || number>long.MaxValue)) return false;
                if (format is not ("int32" or "int64" or "float" or "double" or "decimal")) throw new InvalidOperationException("Unimplemented numeric format.");
            }
        }
        if (kind==JsonValueKind.String && schema["pattern"] is JsonNode pattern && !System.Text.RegularExpressions.Regex.IsMatch(value!.GetValue<string>(),pattern.GetValue<string>(),System.Text.RegularExpressions.RegexOptions.CultureInvariant)) return false;
        return true;
    }
}
'''

if __name__ == '__main__':
    main()
