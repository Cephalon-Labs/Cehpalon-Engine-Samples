using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using HotChocolate.AspNetCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using Path = System.IO.Path;

var results = new List<CheckResult>();
var output = args.FirstOrDefault(a => a.StartsWith("--output="))?["--output=".Length..]
    ?? Path.Combine("evidence", $"{(OperatingSystem.IsWindows() ? "win" : "linux")}-smoke.json");

async Task Run(string name, Func<Task> action)
{
    try { await action(); results.Add(new(name, "Passed", null)); Console.WriteLine("PASS " + name); }
    catch (Exception error)
    {
        var details = error.GetType().FullName;
        if (name.StartsWith("https-") || name.StartsWith("graphql-") || name.StartsWith("jwt-") || name.StartsWith("http-request-"))
            for (Exception? current = error; current is not null; current = current.InnerException) details += " | " + current.GetType().Name + ": " + current.Message;
        results.Add(new(name, "Failed", details)); Console.WriteLine("FAIL " + name + ": " + details);
    }
}

void Require(bool value, string message) { if (!value) throw new InvalidOperationException(message); }

await Run("net11-runtime-and-architecture", () =>
{
    Require(Environment.Version.Major == 11, "Expected runtime major 11");
    Require(RuntimeInformation.ProcessArchitecture == Architecture.X64, "Expected x64");
    return Task.CompletedTask;
});

await Run("platform-config-provider-precedence", () =>
{
    var config = new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?> { ["Qualification:Enabled"] = "true", ["Qualification:Name"] = "base" })
        .AddInMemoryCollection(new Dictionary<string, string?> { ["Qualification:Enabled"] = "false" }).Build();
    using var configurationLifetime = (IDisposable)config;
    Require(config.GetValue<bool>("Qualification:Enabled") == false && config["Qualification:Name"] == "base", "Configuration precedence changed");
    return Task.CompletedTask;
});

await Run("npgsql-assembly-and-datasource-disposal", async () =>
{
    var settings = new NpgsqlConnectionStringBuilder { Host = "127.0.0.1", Port = 9, Database = "qualification", Username = "qualification", SslMode = SslMode.Disable };
    await using var source = new NpgsqlDataSourceBuilder(settings.ConnectionString).Build();
    using var cancelled = new CancellationTokenSource();
    cancelled.Cancel();
    try { await source.OpenConnectionAsync(cancelled.Token); throw new InvalidOperationException("Precancelled connection unexpectedly opened"); }
    catch (OperationCanceledException) { }
});

await Run("rabbitmq-client-assembly-and-configuration", () =>
{
    var factory = new ConnectionFactory { HostName = "127.0.0.1", Port = 9, AutomaticRecoveryEnabled = true, RequestedConnectionTimeout = TimeSpan.FromMilliseconds(500) };
    Require(factory.AutomaticRecoveryEnabled && factory.RequestedConnectionTimeout == TimeSpan.FromMilliseconds(500), "Client options not preserved");
    Require(typeof(IChannel).Assembly.GetName().Name == "RabbitMQ.Client", "Unexpected client assembly");
    return Task.CompletedTask;
});

using var issuerKey = RSA.Create(2048);
var signingKey = new RsaSecurityKey(issuerKey);
var issuer = "https://qualification.invalid/issuer";
var audience = "qualification-api";
using var rootKey = RSA.Create(2048);
var rootRequest = new CertificateRequest("CN=Cehpalon qualification fixture CA", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
using var rootCertificate = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(2));
using var leafKey = RSA.Create(2048);
var leafRequest = new CertificateRequest("CN=localhost", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
var names = new SubjectAlternativeNameBuilder(); names.AddDnsName("localhost"); names.AddIpAddress(IPAddress.Loopback);
leafRequest.CertificateExtensions.Add(names.Build());
using var leafPublic = leafRequest.Create(rootCertificate, DateTimeOffset.UtcNow.AddMinutes(-2), DateTimeOffset.UtcNow.AddHours(1), RandomNumberGenerator.GetBytes(16));
using var keyedLeaf = leafPublic.CopyWithPrivateKey(leafKey);
// Schannel cannot use an ephemeral server key. This import uses a temporary user
// key container deleted on certificate disposal; no certificate trust store is changed.
using var serverCertificate = X509CertificateLoader.LoadPkcs12(keyedLeaf.Export(X509ContentType.Pfx), null,
    OperatingSystem.IsWindows() ? X509KeyStorageFlags.UserKeySet : X509KeyStorageFlags.EphemeralKeySet);
var cancellationStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
var cancellationObserved = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
var builder = WebApplication.CreateSlimBuilder();
builder.Logging.ClearProviders();
builder.Logging.AddConsole().SetMinimumLevel(LogLevel.Warning).AddFilter("Microsoft.AspNetCore.Server.Kestrel.Https", LogLevel.Debug);
builder.WebHost.ConfigureKestrel(server => server.Listen(IPAddress.Loopback, 0, listen => { listen.Protocols = HttpProtocols.Http1; listen.UseHttps(serverCertificate); }));
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true, IssuerSigningKey = signingKey,
        ValidateIssuer = true, ValidIssuer = issuer, ValidateAudience = true, ValidAudience = audience,
        ValidateLifetime = true, RequireExpirationTime = true, RequireSignedTokens = true, ClockSkew = TimeSpan.Zero,
        ValidAlgorithms = [SecurityAlgorithms.RsaSha256]
    };
});
builder.Services.AddAuthorization();
builder.Services.AddGraphQLServer().AddQueryType<QualificationQuery>();
await using var application = builder.Build();
application.UseAuthentication(); application.UseAuthorization();
application.MapGet("/health", () => Results.Json(new { status = "ok" }));
application.MapGet("/jwt", (ClaimsPrincipal principal) => Results.Json(new { authenticated = principal.Identity!.IsAuthenticated })).RequireAuthorization();
application.MapGet("/cancel", async (CancellationToken token) =>
{
    cancellationStarted.TrySetResult();
    try { await Task.Delay(TimeSpan.FromSeconds(10), token); }
    catch (OperationCanceledException) { cancellationObserved.TrySetResult(); throw; }
    return Results.Ok();
});
application.MapGraphQLHttp("/graphql").WithOptions(options => { options.EnableGetRequests = false; options.EnableSchemaRequests = false; });
var started = false;
await Run("https-and-http-only-graphql-startup", async () => { await application.StartAsync(); started = true; });

HttpClient Client(string? expectedHost = null)
{
    var policy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck };
    policy.CustomTrustStore.Add(rootCertificate);
    var handler = new SocketsHttpHandler { UseProxy = false, SslOptions = new SslClientAuthenticationOptions { CertificateChainPolicy = policy } };
    if (expectedHost is not null)
    {
        var port = new Uri(application.Urls.Single()).Port;
        handler.ConnectCallback = async (_, token) => { var socket = new Socket(SocketType.Stream, ProtocolType.Tcp); await socket.ConnectAsync(IPAddress.Loopback, port, token); return new NetworkStream(socket, true); };
    }
    return new HttpClient(handler) { BaseAddress = new Uri(expectedHost is null ? application.Urls.Single() : $"https://{expectedHost}:{new Uri(application.Urls.Single()).Port}"), Timeout = TimeSpan.FromSeconds(10) };
}

if (started)
{
    using var client = Client();
    await Run("https-fixture-custom-ca-chain-and-hostname", async () => { using var response = await client.GetAsync("/health"); Require(response.IsSuccessStatusCode, "HTTPS fixture health failed"); });
    await Run("https-rejects-wrong-hostname", async () =>
    {
        using var mismatch = Client("wrong-host.invalid");
        try { using var response = await mismatch.GetAsync("/health"); throw new InvalidOperationException("Invalid hostname accepted"); }
        catch (HttpRequestException error) when (error.InnerException is System.Security.Authentication.AuthenticationException) { }
    });
    await Run("graphql-http-query-and-no-ide", async () =>
    {
        using var response = await client.PostAsync("/graphql", new StringContent("{\"query\":\"{ ping }\"}", Encoding.UTF8, "application/json"));
        var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Require(response.IsSuccessStatusCode && json.RootElement.GetProperty("data").GetProperty("ping").GetString() == "pong", "GraphQL query mismatch");
        using var ide = await client.GetAsync("/graphql");
        Require(!ide.IsSuccessStatusCode, "HTTP GET unexpectedly enabled");
        using var schema = await client.GetAsync("/graphql?sdl");
        Require(!schema.IsSuccessStatusCode, "Schema download unexpectedly enabled");
    });

    string Token(string tokenIssuer, string tokenAudience, bool expired = false)
    {
        var now = DateTime.UtcNow;
        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(tokenIssuer, tokenAudience, [new Claim("sub", "fixture-user")], now.AddMinutes(-2), expired ? now.AddMinutes(-1) : now.AddMinutes(2), new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256)));
    }
    async Task<HttpStatusCode> JwtStatus(string? token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/jwt");
        if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await client.SendAsync(request);
        return response.StatusCode;
    }
    await Run("jwt-valid-rs256-and-required-authentication", async () =>
    {
        Require(await JwtStatus(Token(issuer, audience)) == HttpStatusCode.OK, "Valid fixture JWT rejected");
        Require(await JwtStatus(null) == HttpStatusCode.Unauthorized, "Missing JWT accepted");
    });
    await Run("jwt-rejects-wrong-issuer-audience-expiry-signature", async () =>
    {
        var good = Token(issuer, audience); var parts = good.Split('.');
        var bytes = parts[2].ToCharArray(); bytes[10] = bytes[10] == 'A' ? 'B' : 'A'; parts[2] = new string(bytes);
        foreach (var token in new[] { Token("https://wrong.invalid/", audience), Token(issuer, "wrong"), Token(issuer, audience, true), string.Join('.', parts) })
            Require(await JwtStatus(token) == HttpStatusCode.Unauthorized, "Invalid fixture JWT accepted");
    });
    await Run("http-request-abort-reaches-handler-and-cleans-up", async () =>
    {
        using var cancellation = new CancellationTokenSource();
        var request = client.GetAsync("/cancel", cancellation.Token);
        await cancellationStarted.Task.WaitAsync(TimeSpan.FromSeconds(3));
        cancellation.Cancel();
        try { await request; throw new InvalidOperationException("Cancelled request completed"); } catch (OperationCanceledException) { }
        await cancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(3));
    });
    await Run("owned-host-graceful-shutdown", async () => { using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5)); await application.StopAsync(deadline.Token); });
}

var postgres = Environment.GetEnvironmentVariable("QUALIFICATION_POSTGRES");
if (string.IsNullOrWhiteSpace(postgres)) results.Add(new("npgsql-real-provider-transaction-query-cancellation", "Not run", "Owned fixture connection not supplied"));
else await Run("npgsql-real-provider-transaction-query-cancellation", async () =>
{
    await using var source = new NpgsqlDataSourceBuilder(postgres).Build();
    await using var connection = await source.OpenConnectionAsync();
    await using (var create = new NpgsqlCommand("CREATE TEMP TABLE qualification_rows (id integer PRIMARY KEY, value text NOT NULL)", connection)) await create.ExecuteNonQueryAsync();
    await using (var tx = await connection.BeginTransactionAsync())
    {
        await using var insert = new NpgsqlCommand("INSERT INTO qualification_rows VALUES (1, 'rollback')", connection, tx); await insert.ExecuteNonQueryAsync(); await tx.RollbackAsync();
    }
    await using (var count = new NpgsqlCommand("SELECT count(*) FROM qualification_rows", connection)) Require((long)(await count.ExecuteScalarAsync())! == 0, "Rollback leaked row");
    await using (var tx = await connection.BeginTransactionAsync())
    {
        await using var insert = new NpgsqlCommand("INSERT INTO qualification_rows VALUES (@id, @value)", connection, tx); insert.Parameters.AddWithValue("id", 2); insert.Parameters.AddWithValue("value", "committed"); await insert.ExecuteNonQueryAsync(); await tx.CommitAsync();
    }
    await using (var query = new NpgsqlCommand("SELECT value FROM qualification_rows WHERE id=2", connection)) Require((string)(await query.ExecuteScalarAsync())! == "committed", "Committed query mismatch");
    using var deadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
    await using (var sleep = new NpgsqlCommand("SELECT pg_sleep(10)", connection))
    {
        try { await sleep.ExecuteNonQueryAsync(deadline.Token); throw new InvalidOperationException("PG sleep ignored cancellation"); } catch (OperationCanceledException) { }
    }
    await using (var health = new NpgsqlCommand("SELECT 1", connection)) Require((int)(await health.ExecuteScalarAsync())! == 1, "Connection unusable after cancellation");
});

var rabbitUri = Environment.GetEnvironmentVariable("QUALIFICATION_RABBIT_URI");
if (string.IsNullOrWhiteSpace(rabbitUri)) results.Add(new("rabbitmq-real-provider-confirm-manual-ack", "Not run", "Owned fixture connection not supplied"));
else await Run("rabbitmq-real-provider-confirm-manual-ack", async () =>
{
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
    var factory = new ConnectionFactory { Uri = new Uri(rabbitUri), AutomaticRecoveryEnabled = false };
    await using var connection = await factory.CreateConnectionAsync(deadline.Token);
    await using var channel = await connection.CreateChannelAsync(new CreateChannelOptions(publisherConfirmationsEnabled: true, publisherConfirmationTrackingEnabled: true), deadline.Token);
    var name = "qualification-" + Guid.NewGuid().ToString("N");
    await channel.QueueDeclareAsync(name, durable: true, exclusive: false, autoDelete: false,
        arguments: new Dictionary<string, object?> { ["x-queue-type"] = "quorum" }, cancellationToken: deadline.Token);
    var payload = Encoding.UTF8.GetBytes("qualification-payload");
    await channel.BasicPublishAsync("", name, mandatory: true, basicProperties: new BasicProperties { MessageId = "qualification-message", Persistent = true }, body: payload, cancellationToken: deadline.Token);
    var message = await channel.BasicGetAsync(name, autoAck: false, cancellationToken: deadline.Token);
    Require(message is not null && message.Body.Span.SequenceEqual(payload), "Broker payload mismatch");
    await channel.BasicNackAsync(message!.DeliveryTag, multiple: false, requeue: true, cancellationToken: deadline.Token);
    var replay = await channel.BasicGetAsync(name, autoAck: false, cancellationToken: deadline.Token);
    Require(replay is not null && replay.Redelivered && replay.BasicProperties.MessageId == "qualification-message", "Expected redelivery not observed");
    await channel.BasicAckAsync(replay!.DeliveryTag, multiple: false, cancellationToken: deadline.Token);
    // MessageCount only reports ready messages, not this channel's unacked ones.
    // Close-ok is a broker-visible barrier: any still-unacked delivery must become
    // ready again before an independent channel can verify the owned queue empty.
    await channel.CloseAsync(deadline.Token);
    await using var verificationChannel = await connection.CreateChannelAsync(cancellationToken: deadline.Token);
    var stateAfterClose = await verificationChannel.QueueDeclarePassiveAsync(name, deadline.Token);
    Require(stateAfterClose.MessageCount == 0, "Message requeued when original channel closed after ack");
    var remaining = await verificationChannel.BasicGetAsync(name, autoAck: false, cancellationToken: deadline.Token);
    Require(remaining is null, "Independent channel found an unacknowledged message after close barrier");
    await verificationChannel.QueueDeleteAsync(name, cancellationToken: deadline.Token);
});

var report = new
{
    observedAtUtc = DateTimeOffset.UtcNow,
    framework = RuntimeInformation.FrameworkDescription, runtime = Environment.Version.ToString(), os = RuntimeInformation.OSDescription,
    architecture = RuntimeInformation.ProcessArchitecture.ToString(),
    scope = "Platform and third-party qualification smoke only; not Engine composition/tenancy/E2E/benchmark/production proof. HTTPS uses an ephemeral custom test CA; JWT uses fixture keys.",
    passed = results.Count(r => r.Status == "Passed"), failed = results.Count(r => r.Status == "Failed"), notRun = results.Count(r => r.Status == "Not run"), results
};
Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
await File.WriteAllTextAsync(output, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine($"Qualification: {report.passed} passed, {report.failed} failed, {report.notRun} not run");
return report.failed == 0 ? 0 : 1;

public sealed record CheckResult(string Name, string Status, string? Detail);
public sealed class QualificationQuery { public string Ping() => "pong"; }
