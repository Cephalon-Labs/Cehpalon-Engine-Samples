using System.Text.Json;
using System.Diagnostics;
using System.Net;
using SmallApi.Benchmark;

var managedEntryTimestamp=Stopwatch.GetTimestamp();
string? Option(string name)=>args.FirstOrDefault(a=>a.StartsWith("--"+name+"=",StringComparison.Ordinal))?[(name.Length+3)..];
IPAddress? FixtureIpOption(string flag, string prefix)
{
    string? value = null;
    foreach (var argument in args)
    {
        if (argument == flag) throw new ArgumentException($"{flag} requires an explicit address.");
        if (!argument.StartsWith(prefix, StringComparison.Ordinal)) continue;
        if (value is not null) throw new ArgumentException($"{flag} may be specified once.");
        value = argument[prefix.Length..];
    }

    if (value is null) return null;
    if (!IPAddress.TryParse(value, out var address) || !PrivateFixtureAddress.IsSupported(address) ||
        !StringComparer.Ordinal.Equals(value, address.ToString()))
        throw new ArgumentException($"{flag} requires a canonical RFC1918 IPv4 address.");
    return address;
}

var fixtureListenIp = FixtureIpOption("--fixture-listen-ip", "--fixture-listen-ip=");
var fixturePeerIp = FixtureIpOption("--fixture-peer-ip", "--fixture-peer-ip=");
var fixtureDirectory = Option("fixture-dir");
var fixturePath = Option("create-fixture");
if (fixturePath is not null)
{
    if (fixturePeerIp is not null) throw new ArgumentException("--fixture-peer-ip is only valid when serving a private fixture.");
    fixturePath=Path.GetFullPath(fixturePath);if(Directory.Exists(fixturePath))throw new IOException("Fixture directory must be new.");Directory.CreateDirectory(fixturePath);
    if(!OperatingSystem.IsWindows())File.SetUnixFileMode(fixturePath,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
    using var fixture=new TlsFixture(fixtureListenIp:fixtureListenIp);
    File.WriteAllBytes(Path.Combine(fixturePath,"root-ca.der"),fixture.Root.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert));
    var privatePath=Path.Combine(fixturePath,"server.pfx");var privateBytes=fixture.ExportPrivateFixture();File.WriteAllBytes(privatePath,privateBytes);System.Security.Cryptography.CryptographicOperations.ZeroMemory(privateBytes);
    if(!OperatingSystem.IsWindows())File.SetUnixFileMode(privatePath,UnixFileMode.UserRead|UnixFileMode.UserWrite);
    Console.WriteLine(JsonSerializer.Serialize(new{created=true,certificateSha256=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(fixture.Server.RawData)).ToLowerInvariant()},Wire.Json));return 0;
}
// Empty IDE launch is a finite correctness smoke test. Existing explicit modes
// and nonempty serve invocations retain their original benchmark protocol.
var mode=Option("mode")??(args.Length==0?"self-test":"serve");
string? privateReadyPath = null;
if (fixtureListenIp is not null || fixturePeerIp is not null)
{
    if (mode != "serve" || args.Contains("--load-client"))
        throw new ArgumentException("Private fixture addresses are only valid when creating or serving an HTTPS fixture.");
    PrivateFixtureAddress.ValidateServe(fixtureListenIp, fixturePeerIp, fixtureDirectory, tls:true);
    var privateReady = Option("ready-file");
    if (string.IsNullOrWhiteSpace(privateReady)) throw new ArgumentException("--ready-file is required to serve a private fixture.");
    privateReadyPath = Path.GetFullPath(privateReady);
}
using var startupTrace=Option("startup-trace") is { } tracePath?new StartupTrace(tracePath,managedEntryTimestamp):null;
if(mode=="conformance")
{
    var type=typeof(BenchmarkHost).Assembly.GetType("SmallApi.Benchmark.Conformance")??throw new InvalidOperationException("Conformance module must be integrated.");
    return await (Task<int>)type.GetMethod("RunAsync")!.Invoke(null,[Option("output")??throw new ArgumentException("--output required")])!;
}
if(args.Contains("--load-client") || mode=="load-client")
{
    var type=typeof(BenchmarkHost).Assembly.GetType("SmallApi.Benchmark.LoadDriver")??throw new InvalidOperationException("Load driver must be integrated.");
    return await (Task<int>)type.GetMethod("RunAsync")!.Invoke(null,[args])!;
}
var variant=Option("variant")??"engine";var transport=Option("transport")??"http";
await using var host=await BenchmarkHost.StartAsync(variant,transport,fixtureDirectory:fixtureDirectory,startupTrace:startupTrace,
    fixtureListenIp:fixtureListenIp,fixturePeerIp:fixturePeerIp);
if(mode=="self-test")
{
    using var client=host.Client();using var response=await client.PostAsJsonAsync("/api/catalog/get",new GetItem(1));response.EnsureSuccessStatusCode();var item=await response.Content.ReadFromJsonAsync<Item>();
    if(item is null || item.Id!=1 || item.Label!="item-00001")throw new InvalidOperationException("Self-test response differs.");
    if(transport=="graphql")
    {
        using var gql=await client.PostAsJsonAsync("/graphql",new{query="{catalogItem(input:{id:1}){id label revision amountMinorUnits}}"});
        var body=await gql.Content.ReadFromJsonAsync<JsonElement>();if(body.TryGetProperty("errors",out _))throw new InvalidOperationException("GraphQL self-test failed: "+body);
        if(body.GetProperty("data").GetProperty("catalogItem").GetProperty("id").GetInt32()!=1)throw new InvalidOperationException("GraphQL response differs.");
    }
    Console.WriteLine(JsonSerializer.Serialize(new{passed=true,ready=host.Ready()},Wire.Json));return 0;
}
var readyPath=privateReadyPath??Path.GetFullPath(Option("ready-file")??throw new ArgumentException("--ready-file required"));
startupTrace?.Mark("ready.file.begin");
Directory.CreateDirectory(Path.GetDirectoryName(readyPath)!);
var readyWorkingPath=readyPath+".writing";
await using(var stream=new FileStream(readyWorkingPath,FileMode.CreateNew,FileAccess.Write))
{
    await JsonSerializer.SerializeAsync(stream,host.Ready(),Wire.Json);
    await stream.FlushAsync();
}
File.Move(readyWorkingPath,readyPath,overwrite:false);
startupTrace?.Mark("ready.file.end");
Console.WriteLine("READY");
while(await Console.In.ReadLineAsync() is { } line)if(line=="STOP")break;
startupTrace?.Mark("shutdown.begin");
await host.DisposeAsync();
startupTrace?.Mark("shutdown.end");
if(Option("state-file") is { } statePath)
{
    Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(statePath))!);
    await using var stream=new FileStream(statePath,FileMode.CreateNew,FileAccess.Write);await JsonSerializer.SerializeAsync(stream,host.State(),Wire.Json);
}
return 0;
