using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace MetricsOverhead;

public static class Client
{
    private readonly record struct Row(int Index, int Lane, long Scheduled, long Sent, long Completed,
        int Status, int Bytes, string Outcome);
    private sealed record Phase(string Name, int Rate, long Origin, long Completed, Row[] Rows);
    private sealed record Tls(int Lane, string Protocol, string Cipher, string HttpVersion, long Ticks);

    public static async Task<int> Run(Dictionary<string, string> options)
    {
        using var input = JsonDocument.Parse(await Console.In.ReadLineAsync() ?? throw new IOException());
        var config = input.RootElement;
        var address = new Uri(config.GetProperty("address").GetString()!);
        if (!address.IsLoopback || address.Scheme != "https") throw new ArgumentException();
        using var root = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(config.GetProperty("root").GetString()!));
        var tokens = new[] { config.GetProperty("alice").GetString()!, config.GetProperty("bob").GetString()! };
        var clients = new HttpClient[32];
        var tls = new ConcurrentQueue<Tls>();
        var busy = new int[32];
        var payloads = Enumerable.Range(0, 4).Select(lane => Payload(lane, false)).ToArray();
        var phases = new List<Phase>();
        var status = "failed";
        string? failure = null;
        var prepared = 0;
        var denials = 0;
        var expectedConnections = 0;

        HttpRequestMessage Request(int lane, bool denied = false)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, lane % 4 >= 2 ? "/graphql" : "/api/catalog/get")
            {
                Version = HttpVersion.Version11, VersionPolicy = HttpVersionPolicy.RequestVersionExact,
                Content = new ByteArrayContent(denied ? Payload(lane, true) : payloads[lane % 4])
            };
            request.Content.Headers.ContentType = new("application/json");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens[lane % 2]);
            request.Headers.Add("X-Tenant", lane % 2 == 0 ? "tenant-b" : "tenant-a");
            return request;
        }

        async Task<(int Status, int Bytes)> Validate(HttpResponseMessage response, int lane, bool denied = false)
        {
            var bytes = await response.Content.ReadAsByteArrayAsync();
            using var body = JsonDocument.Parse(bytes);
            var value = body.RootElement;
            if (denied)
            {
                var code = lane % 4 >= 2 ? value.GetProperty("errors")[0].GetProperty("extensions").GetProperty("code") : value.GetProperty("code");
                if ((int)response.StatusCode != (lane % 4 >= 2 ? 200 : 403) || code.GetString() != "access.denied") throw new InvalidDataException();
            }
            else
            {
                if (response.StatusCode != HttpStatusCode.OK) throw new InvalidDataException();
                if (lane % 4 >= 2) value = value.GetProperty("data").GetProperty("catalogItem");
                if (value.GetProperty("tenant").GetString() != (lane % 2 == 0 ? "tenant-a" : "tenant-b")
                    || value.GetProperty("id").GetInt32() != 1 || value.GetProperty("revision").GetInt32() != 0
                    || value.GetProperty("label").GetString() != "item-00001" || value.GetProperty("amountMinorUnits").GetInt64() != 17)
                    throw new InvalidDataException();
            }
            return ((int)response.StatusCode, bytes.Length);
        }

        async Task<Phase> Load(string name, int count, int rate)
        {
            var rows = new Row[count];
            var tasks = new Task[count];
            var origin = Entry.Now + Stopwatch.Frequency / 10;
            async Task Send(int i, int lane, long due)
            {
                var sent = Entry.Now;
                try
                {
                    using var request = Request(lane);
                    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                    using var response = await clients[lane].SendAsync(request, deadline.Token);
                    var result = await Validate(response, lane);
                    rows[i] = new(i, lane, due, sent, Entry.Now, result.Status, result.Bytes, "passed");
                }
                catch (Exception error) { rows[i] = new(i, lane, due, sent, Entry.Now, 0, 0, error.GetType().Name); }
                finally { Volatile.Write(ref busy[lane], 0); }
            }
            for (var i = 0; i < count; i++)
            {
                var due = origin + i * Stopwatch.Frequency / rate;
                while (Entry.Now < due) await Task.Delay(1);
                var lane = i % clients.Length;
                if (Interlocked.CompareExchange(ref busy[lane], 1, 0) != 0)
                {
                    rows[i] = new(i, lane, due, 0, Entry.Now, 0, 0, "dropped");
                    tasks[i] = Task.CompletedTask;
                }
                else tasks[i] = Send(i, lane, due);
            }
            await Task.WhenAll(tasks);
            return new(name, rate, origin, Entry.Now, rows);
        }

        try
        {
            for (var i = 0; i < clients.Length; i++)
            {
                var lane = i;
                var chain = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck };
                chain.CustomTrustStore.Add(root);
                var handler = new SocketsHttpHandler { UseProxy = false, MaxConnectionsPerServer = 1,
                    SslOptions = new SslClientAuthenticationOptions { EnabledSslProtocols = SslProtocols.Tls13, CertificateChainPolicy = chain } };
                handler.PlaintextStreamFilter = (context, _) =>
                {
                    if (context.PlaintextStream is not SslStream ssl || ssl.SslProtocol != SslProtocols.Tls13
                        || context.NegotiatedHttpVersion != HttpVersion.Version11) throw new InvalidOperationException();
                    tls.Enqueue(new(lane, ssl.SslProtocol.ToString(), ssl.NegotiatedCipherSuite.ToString(), context.NegotiatedHttpVersion.ToString(), Entry.Now));
                    return ValueTask.FromResult(context.PlaintextStream);
                };
                clients[i] = new(handler) { BaseAddress = address, Timeout = TimeSpan.FromSeconds(10) };
            }
            // Keep all response leases open until every independent connection has reached headers.
            var requests = Enumerable.Range(0, 32).Select(i => Request(i)).ToArray();
            var responses = new HttpResponseMessage?[32];
            try
            {
                await Task.WhenAll(Enumerable.Range(0, 32).Select(async i =>
                    responses[i] = await clients[i].SendAsync(requests[i], HttpCompletionOption.ResponseHeadersRead)));
                if (tls.Count != 32 || tls.Select(t => t.Lane).Distinct().Count() != 32) throw new InvalidOperationException();
                foreach (var i in Enumerable.Range(0, 32)) { await Validate(responses[i]!, i); prepared++; }
            }
            finally
            {
                foreach (var response in responses) response?.Dispose();
                foreach (var request in requests) request.Dispose();
            }
            for (var i = 0; i < 4; i++)
            {
                using var request = Request(i, true);
                using var response = await clients[i].SendAsync(request);
                await Validate(response, i, true);
                denials++;
            }
            expectedConnections = tls.Count;
            var conformance = options["--profile"] == "conformance";
            phases.Add(await Load("warmup", conformance ? 128 : 1500, conformance ? 128 : 500));
            Entry.Signal(new { kind = "warmed", passed = phases[0].Rows.All(r => r.Outcome == "passed"), connections = tls.Count });
            if (await Console.In.ReadLineAsync() != "MEASURE") throw new InvalidOperationException();
            phases.Add(await Load("measured", conformance ? 256 : 5000, conformance ? 128 : 500));
            status = phases.All(p => p.Rows.All(r => r.Outcome == "passed")) && tls.Count == expectedConnections ? "passed" : "failed";
            // Send before serializing any rows; controller closes the server measurement bracket first.
            Entry.Signal(new { kind = "measured", status, connections = tls.Count });
            if (await Console.In.ReadLineAsync() != "PERSIST") throw new InvalidOperationException();
        }
        catch (Exception error) { status = "failed"; failure = error.GetType().Name; }
        finally
        {
            foreach (var client in clients) client?.Dispose();
            await Entry.Save(options["--output"], new { status, failureType = failure,
                environment = Entry.EnvironmentInfo(), prepared, crossTenantDenials = denials,
                expectedConnections, tls = tls.ToArray(), phases });
        }
        Entry.Signal(new { kind = "persisted", status });
        return status == "passed" ? 0 : 1;
    }

    private static byte[] Payload(int lane, bool denied)
    {
        var tenant = (lane % 2 == 0) != denied ? "tenant-a" : "tenant-b";
        return Encoding.UTF8.GetBytes(lane % 4 >= 2
            ? JsonSerializer.Serialize(new { query = "query($input:GetItemInput!){catalogItem(input:$input){tenant id label revision amountMinorUnits}}", variables = new { input = new { tenant, id = 1 } } })
            : JsonSerializer.Serialize(new { tenant, id = 1 }));
    }
}
