using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Cehpalon.Engine.Composition;

namespace SmallApi.Benchmark;

/// <summary>Deterministic conformance, deliberately separate from load/startup/RSS measurements.</summary>
public static class Conformance
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private const string Seed = "cehpalon-small-api-v1:20261027";
    private sealed record CorpusCase(int Index, string Operation, JsonElement Input, string ExpectedCode, JsonElement? ExpectedValue);
    private sealed record Corpus(CorpusCase[] Cases, Item[] Initial, Item[] Final);
    private sealed record Reply(int Status, JsonElement Body);

    public static async Task<int> RunAsync(string outputDirectory)
    {
        var output = Path.GetFullPath(outputDirectory);
        if (Directory.Exists(output) || File.Exists(output)) throw new IOException("Use a new conformance output directory.");
        Directory.CreateDirectory(output);
        var corpus = BuildCorpus();
        // Freeze expected data and ordered cases before constructing either transport or host.
        var dataset = JsonSerializer.SerializeToUtf8Bytes(corpus.Initial, Json);
        var requests = JsonSerializer.SerializeToUtf8Bytes(corpus.Cases, Json);
        var finalDataset = JsonSerializer.SerializeToUtf8Bytes(corpus.Final, Json);
        await File.WriteAllBytesAsync(Path.Combine(output, "dataset.json"), dataset);
        await File.WriteAllBytesAsync(Path.Combine(output, "ordered-corpus.json"), requests);
        var declaration = new
        {
            seed = Seed, cases = 1000, recordCount = 10000,
            stopwatchFrequency = Stopwatch.Frequency,
            categories = new { success = 500, conflict = 100, notFound = 100, validation = 200, cancelled = 100 },
            datasetSha256 = Sha(dataset), orderedCorpusSha256 = Sha(requests), finalDatasetSha256 = Sha(finalDataset),
            serialization = "System.Text.Json web camelCase, compact UTF8 without BOM or trailing newline; Item declaration order",
            cancellation = new { requestsPerLane = 100, handlerDelayMilliseconds = 5000, scheduledAbortMilliseconds = 50, maximumServerAckAfterActualAbortMilliseconds = 100 },
            cleanup = new { startsStopsPerLane = 30, maximumShutdownMilliseconds = 5000 },
            scope = "Public synthetic 10000-record fixture; correctness only. Same-process restarts are not fresh-process startup measurements. Not tenant/IdP/provider/production proof."
        };
        await WriteNew(Path.Combine(output, "predeclared.json"), declaration);

        var lanes = new List<object>();
        var totalFailed = 0;
        foreach (var variant in new[] { "baseline", "engine" })
        foreach (var transport in new[] { "http", "graphql" })
        {
            var lane = variant + "-" + transport;
            var laneDirectory = Path.Combine(output, lane);
            Directory.CreateDirectory(laneDirectory);
            var checks = new List<object>();
            var failed = 0;
            async Task Check(string name, Func<Task> action)
            {
                try { await action(); checks.Add(new { name, passed = true }); }
                catch (Exception error) { failed++; checks.Add(new { name, passed = false, error = error.ToString() }); }
            }
            try
            {
                await using var host = await BenchmarkHost.StartAsync(variant, transport);
                using var client = host.Client();
                await Check("TLS/readiness and fixed dataset", async () =>
                {
                    var reply = await Send(client, transport, "get", JsonSerializer.SerializeToElement(new GetItem(1), Json));
                    Require(reply.Status == 200, "Initial verified request failed.");
                    Require(Equivalent(Value(reply, transport, "get"), JsonSerializer.SerializeToElement(corpus.Initial[0], Json)), "Initial item differs.");
                    Require(host.Store.Snapshot().Length == 10000, "Dataset has wrong key count.");
                });
                host.Reset();
                var results = new List<object>();
                foreach (var item in corpus.Cases)
                {
                    var beforeWrites = host.Store.Writes;
                    try
                    {
                        if (item.ExpectedCode == "operation.cancelled")
                        {
                            var cancelled = await Cancel(client, host, transport, item.Input, item.Index);
                            results.Add(cancelled);
                            if (!cancelled.Passed) failed++;
                        }
                        else
                        {
                            var reply = await Send(client, transport, item.Operation, item.Input);
                            var code = Code(reply, transport);
                            if (item.ExpectedCode == "success")
                            {
                                Require(reply.Status == 200 && code is null, "Expected success; actual status/code " + reply.Status + "/" + code);
                                Require(item.ExpectedValue is { } expected && Equivalent(Value(reply, transport, item.Operation), expected), "Business response differs from frozen model.");
                            }
                            else
                            {
                                var status = transport == "graphql" ? 200 : item.ExpectedCode switch { "resource.not_found" => 404, "resource.conflict" => 409, _ => 400 };
                                Require(reply.Status == status && code == item.ExpectedCode, "Expected " + status + "/" + item.ExpectedCode + "; actual " + reply.Status + "/" + code);
                                Require(host.Store.Writes == beforeWrites, "Rejected request mutated data.");
                            }
                            results.Add(new { item.Index, item.Operation, passed = true, expectedCode = item.ExpectedCode, status = reply.Status, actualCode = code ?? "success" });
                        }
                    }
                    catch (Exception error)
                    {
                        failed++;
                        results.Add(new { item.Index, item.Operation, passed = false, expectedCode = item.ExpectedCode, error = error.ToString() });
                    }
                }
                await WriteNew(Path.Combine(laneDirectory, "case-results.json"), results);
                await Check("all 1000 ordered cases accounted for", () =>
                {
                    Require(results.Count == 1000, "Corpus omitted cases."); return Task.CompletedTask;
                });
                await Check("final fixed-size state matches independent frozen model", () =>
                {
                    var snapshot = host.Store.Snapshot();
                    Require(snapshot.Length == 10000 && Sha(JsonSerializer.SerializeToUtf8Bytes(snapshot, Json)) == declaration.finalDatasetSha256, "Lost mutation, unexpected key, or final state mismatch.");
                    Require(host.Store.Writes == 100, "Exactly 100 successful frozen updates were expected.");
                    return Task.CompletedTask;
                });
                await Check("strict negative request handling before business writes", async () =>
                {
                    var before = host.Store.Writes;
                    foreach (var payload in new[] { "{", "null", "[]", new string(' ', 16 * 1024 + 1) })
                    {
                        var reply = await SendRaw(client, transport == "graphql" ? "/graphql" : "/api/catalog/get", payload);
                        Require(reply.Status >= 400, "Malformed, wrong-shape or oversized envelope accepted.");
                    }
                    foreach (var input in new[] { "{\"id\":\"wrong\"}", "{\"id\":null}", "{}" })
                    {
                        var reply = await Send(client, transport, "get", JsonDocument.Parse(input).RootElement.Clone());
                        Require(reply.Status >= 400 || Code(reply, transport) is not null, "Invalid required value accepted.");
                    }
                    Require(host.Store.Writes == before, "Malformed request mutated business data.");
                });
                if (transport == "http") await Check("10000 API requests retain zero disabled registrations/factories", async () =>
                {
                    await Parallel.ForEachAsync(Enumerable.Range(1, 10000), new ParallelOptions { MaxDegreeOfParallelism = 16 }, async (id, cancellation) =>
                    {
                        var response = await Send(client, transport, "get", JsonSerializer.SerializeToElement(new GetItem(id), Json), cancellation);
                        Require(response.Status == 200 && Value(response, transport, "get").GetProperty("id").GetInt32() == id, "Activation exercise returned wrong record.");
                    });
                    Require(host.Probes.GraphQLFactories == 0 && host.Probes.GraphQLServices == 0 && host.Probes.ForbiddenFactories == 0, "Disabled module registered/activated.");
                    using var response = await client.GetAsync("/graphql");
                    Require(response.StatusCode == HttpStatusCode.NotFound, "Disabled GraphQL endpoint exposed.");
                });
                var address = host.Address;
                await Check("owned shutdown <=5s and listener closed", async () =>
                {
                    var started = Stopwatch.GetTimestamp();
                    await host.DisposeAsync();
                    var elapsed = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                    Require(elapsed <= 5000, "Shutdown exceeded 5 seconds.");
                    Require(host.Store.Factories == host.Store.Disposals, "Owned handler disposal mismatch.");
                    Require(host.Probes.ForbiddenFactories == 0, "Forbidden module activation.");
                    await RequireListenerClosed(address);
                });
                await WriteNew(Path.Combine(laneDirectory, "main-host-probes.json"), host.Probes);
            }
            catch (Exception error) { failed++; checks.Add(new { name = "host/corpus infrastructure", passed = false, error = error.ToString() }); }

            var cycles = new List<object>();
            for (var cycle = 0; cycle < 30; cycle++)
            {
                try
                {
                    await using var host = await BenchmarkHost.StartAsync(variant, transport);
                    using var client = host.Client();
                    var reply = await Send(client, transport, "get", JsonSerializer.SerializeToElement(new GetItem(1), Json));
                    Require(reply.Status == 200, "Restart did not serve a verified item.");
                    var address = host.Address;
                    var started = Stopwatch.GetTimestamp(); await host.DisposeAsync();
                    var elapsed = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                    Require(elapsed <= 5000, "Restart shutdown exceeded 5 seconds.");
                    Require(host.Store.Factories == host.Store.Disposals && host.Probes.ForbiddenFactories == 0, "Restart ownership/forbidden work mismatch.");
                    if (transport == "http") Require(host.Probes.GraphQLFactories == 0 && host.Probes.GraphQLServices == 0, "GraphQL activation during API restart.");
                    await RequireListenerClosed(address);
                    cycles.Add(new { cycle, passed = true, shutdownMilliseconds = elapsed, factories = host.Store.Factories, disposals = host.Store.Disposals });
                }
                catch (Exception error) { failed++; cycles.Add(new { cycle, passed = false, error = error.ToString() }); }
            }
            await WriteNew(Path.Combine(laneDirectory, "lifecycle-cycles.json"), cycles);
            await WriteNew(Path.Combine(laneDirectory, "checks.json"), checks);
            lanes.Add(new { variant, transport, failed, corpusCasesPlanned = 1000, cancellationCasesPlanned = 100, lifecycleCyclesPlanned = 30 });
            totalFailed += failed;
        }
        var preflight = await PreflightChecks();
        totalFailed += preflight.Count(x => !x.Passed);
        await WriteNew(Path.Combine(output, "configuration-preflight.json"), preflight);
        await WriteNew(Path.Combine(output, "summary.json"), new { observedAtUtc = DateTimeOffset.UtcNow, status = totalFailed == 0 ? "passed" : "failed", failed = totalFailed, lanes, declaration, scope = declaration.scope });
        return totalFailed == 0 ? 0 : 1;
    }

    private sealed record CancellationResult(int Index, string Operation, bool Passed, string ExpectedCode, long RequestStartedTimestamp, long ScheduledAbortTimestamp, long ActualAbortTimestamp, long HandlerEnteredTimestamp, long ServerAcknowledgedTimestamp, double ActualAbortAfterStartMilliseconds, double ServerAckAfterAbortMilliseconds, bool HandlerEnteredBeforeAbort, bool NoMutationAfterAck, bool OwnedHandlerCompleted, string? Failure);

    private static async Task<CancellationResult> Cancel(HttpClient client, BenchmarkHost host, string transport, JsonElement input, int index)
    {
        host.Store.ResetCancellationSignals(); host.EnableDelay(true);
        var beforeWrites = host.Store.Writes;
        using var cancellation = new CancellationTokenSource();
        var started = Stopwatch.GetTimestamp();
        var scheduled = started + (long)Math.Ceiling(Stopwatch.Frequency * .05);
        var task = Send(client, transport, "set", input, cancellation.Token);
        var actualAbort = 0L; var acknowledged = 0L; var entered = 0L;
        var localCancelled = false; var observed = false; var owned = false; var noMutation = false;
        string? failure = null;
        try
        {
            while (Stopwatch.GetTimestamp() < scheduled)
            {
                var remaining = Stopwatch.GetElapsedTime(Stopwatch.GetTimestamp(), scheduled);
                await Task.Delay(remaining > TimeSpan.FromMilliseconds(1) ? remaining : TimeSpan.FromMilliseconds(1));
            }
            actualAbort = Stopwatch.GetTimestamp(); cancellation.Cancel();
            try { await task; } catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { localCancelled = true; }
            try { await host.Store.CancelObserved.Task.WaitAsync(TimeSpan.FromSeconds(5)); observed = true; } catch (TimeoutException) { }
            acknowledged = host.Store.CancellationObservedTimestamp; entered = host.Store.DelayEnteredTimestamp;
            var drainStarted = Stopwatch.GetTimestamp();
            while (host.Store.Factories != host.Store.Disposals && Stopwatch.GetElapsedTime(drainStarted) < TimeSpan.FromSeconds(5)) await Task.Delay(1);
            owned = host.Store.Factories == host.Store.Disposals;
            noMutation = host.Store.Writes == beforeWrites;
            var ackMilliseconds = acknowledged > 0 ? Stopwatch.GetElapsedTime(actualAbort, acknowledged).TotalMilliseconds : double.PositiveInfinity;
            var entryBeforeAbort = entered > 0 && entered >= started && entered <= actualAbort;
            if (!localCancelled) failure = "Client request did not observe cancellation.";
            else if (!entryBeforeAbort) failure = "The 5-second delayed handler had not entered before scheduled client abort.";
            else if (!observed || ackMilliseconds is < 0 or > 100) failure = "Server cancellation acknowledgement exceeded the 100ms budget or was absent.";
            else if (!owned) failure = "Server-owned handler did not complete disposal after acknowledgement.";
            else if (!noMutation) failure = "Cancelled operation mutated data.";
            return new(index, "set", failure is null, "operation.cancelled", started, scheduled, actualAbort, entered, acknowledged,
                Stopwatch.GetElapsedTime(started, actualAbort).TotalMilliseconds, double.IsFinite(ackMilliseconds) ? ackMilliseconds : -1,
                entryBeforeAbort, noMutation, owned, failure);
        }
        catch (Exception error)
        {
            entered = host.Store.DelayEnteredTimestamp; acknowledged = host.Store.CancellationObservedTimestamp;
            return new(index, "set", false, "operation.cancelled", started, scheduled, actualAbort, entered, acknowledged,
                actualAbort > 0 ? Stopwatch.GetElapsedTime(started, actualAbort).TotalMilliseconds : -1,
                actualAbort > 0 && acknowledged > 0 ? Stopwatch.GetElapsedTime(actualAbort, acknowledged).TotalMilliseconds : -1,
                entered > 0 && entered <= actualAbort, host.Store.Writes == beforeWrites,
                host.Store.Factories == host.Store.Disposals, error.ToString());
        }
        finally { host.EnableDelay(false); }
    }

    private static Corpus BuildCorpus()
    {
        var initial = Enumerable.Range(1, 10000).Select(id => new Item(id, $"item-{id:D5}", 0, id * 17L)).ToArray();
        var model = initial.ToDictionary(item => item.Id);
        var cases = new List<CorpusCase>();
        void Add(string operation, object request, string expectedCode, object? expected = null)
            => cases.Add(new(cases.Count, operation, JsonSerializer.SerializeToElement(request, Json), expectedCode, expected is null ? null : JsonSerializer.SerializeToElement(expected, Json)));
        for (var block = 0; block < 100; block++)
        {
            var id = SeededId(block * 10); Add("get", new GetItem(id), "success", model[id]);
            var page = (SeededId(block * 10 + 1) - 1) % 500;
            Add("list", new ListItems(page), "success", new ItemPage(Enumerable.Range(1 + page * 20, 20).Select(key => model[key]).ToArray()));
            var lane = block % 32; var ordinal = block / 32; var writeId = 1 + lane + 32 * (ordinal % 312);
            var previous = model[writeId]; var label = $"lane-{lane}-write-{ordinal}";
            var updated = previous with { Label = label, Revision = previous.Revision + 1 };
            Add("set", new SetLabel(writeId, previous.Revision, label), "success", updated); model[writeId] = updated;
            Add("get", new GetItem(writeId), "success", updated);
            Add("set", new SetLabel(writeId, previous.Revision, "intentional-conflict"), "resource.conflict");
            Add("get", new GetItem(10001), "resource.not_found");
            Add("get", new GetItem(0), "validation.failed");
            var another = SeededId(block * 10 + 7); Add("get", new GetItem(another), "success", model[another]);
            Add("set", new SetLabel(writeId, updated.Revision, new string('x', 65)), "validation.failed");
            Add("set", new SetLabel(writeId, updated.Revision, "must-not-be-written"), "operation.cancelled");
        }
        return new(cases.ToArray(), initial, model.Values.OrderBy(item => item.Id).ToArray());
    }

    private static int SeededId(int index)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(Seed + ":" + index.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        return (int)(BinaryPrimitives.ReadUInt64BigEndian(hash.AsSpan(0, 8)) % 10000) + 1;
    }
    private static string Sha(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    private static bool Equivalent(JsonElement actual, JsonElement expected) => JsonNode.DeepEquals(JsonNode.Parse(actual.GetRawText()), JsonNode.Parse(expected.GetRawText()));
    private static void Require(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    private static async Task WriteNew(string path, object value)
    { await using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None); await JsonSerializer.SerializeAsync(stream, value, new JsonSerializerOptions(Json) { WriteIndented = true, IncludeFields = true }); }
    private static async Task<Reply> Send(HttpClient client, string transport, string operation, JsonElement input, CancellationToken cancellation = default)
    {
        var (field, selection, type) = operation switch
        {
            "get" => ("catalogItem", "id label revision amountMinorUnits", "GetItemInput!"),
            "list" => ("catalogPage", "items { id label revision amountMinorUnits }", "ListItemsInput!"),
            _ => ("setLabel", "id label revision amountMinorUnits", "SetLabelInput!")
        };
        using var request = new HttpRequestMessage(HttpMethod.Post, transport == "graphql" ? "/graphql" : "/api/catalog/" + operation)
        {
            Content = JsonContent.Create(transport == "graphql" ? (object)new { query = $"{(operation == "set" ? "mutation" : "query")}($input:{type}){{{field}(input:$input){{{selection}}}}}", variables = new { input } } : input, options: Json)
        };
        using var response = await client.SendAsync(request, cancellation);
        var raw = await response.Content.ReadAsStringAsync(cancellation);
        return new((int)response.StatusCode, string.IsNullOrWhiteSpace(raw) ? JsonSerializer.SerializeToElement(new { }) : JsonDocument.Parse(raw).RootElement.Clone());
    }
    private static async Task<Reply> SendRaw(HttpClient client, string path, string payload)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = new StringContent(payload, Encoding.UTF8, "application/json") };
        using var response = await client.SendAsync(request);
        var raw = await response.Content.ReadAsStringAsync();
        return new((int)response.StatusCode, string.IsNullOrWhiteSpace(raw) ? JsonSerializer.SerializeToElement(new { }) : JsonDocument.Parse(raw).RootElement.Clone());
    }
    private static string? Code(Reply reply, string transport)
    {
        if (transport == "graphql" && reply.Body.TryGetProperty("errors", out var errors)) return errors[0].GetProperty("extensions").GetProperty("code").GetString();
        return reply.Body.TryGetProperty("code", out var code) ? code.GetString() : null;
    }
    private static JsonElement Value(Reply reply, string transport, string operation) => transport == "graphql"
        ? reply.Body.GetProperty("data").GetProperty(operation switch { "get" => "catalogItem", "list" => "catalogPage", _ => "setLabel" }) : reply.Body;
    private static async Task RequireListenerClosed(Uri address)
    {
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        try { await socket.ConnectAsync(IPAddress.Loopback, address.Port); throw new InvalidOperationException("Owned listener remained open after disposal."); }
        catch (SocketException) { }
    }
    private sealed record PreflightResult(string Name, bool Passed, string? Error);
    private static Task<List<PreflightResult>> PreflightChecks()
    {
        var results = new List<PreflightResult>();
        var valid = BenchmarkHost.Config(true, false);
        var disabledDependency = JsonNode.Parse(valid)!;
        disabledDependency["Cehpalon"]!["Modules"]!["host"] = JsonSerializer.SerializeToNode(new { Enabled = false });
        foreach (var (name, configuration) in new[]
        {
            ("unknown module", valid.Replace("\"api\"", "\"unknown\"", StringComparison.Ordinal)),
            ("incompatible pattern", valid.Replace("RequestReply", "Unsupported", StringComparison.Ordinal)),
            ("explicit false dependency", disabledDependency.ToJsonString())
        })
        {
            try { Require(!BenchmarkHost.ValidateConfiguration(configuration).IsSuccess, "Invalid configuration accepted."); results.Add(new(name, true, null)); }
            catch (Exception error) { results.Add(new(name, false, error.ToString())); }
        }
        try
        {
            var allOff = BenchmarkHost.ValidateConfiguration(BenchmarkHost.Config(false, false));
            Require(allOff.IsSuccess && allOff.Plan!.ActivationOrder.Count == 0, "All-off plan contains work.");
            results.Add(new("all-off plan contains zero activations", true, null));
        }
        catch (Exception error) { results.Add(new("all-off plan contains zero activations", false, error.ToString())); }
        try
        {
            var cycle = CompositionCompiler.Compile(valid, [new("api", ModuleRole.EntryPoint, ["host"]), new("host", ModuleRole.Support, ["api"]), new("graphql", ModuleRole.EntryPoint), new("worker", ModuleRole.EntryPoint)]);
            Require(!cycle.IsSuccess && cycle.Diagnostics.Any(diagnostic => diagnostic.Code == "CAT_CYCLE"), "Cyclic startup catalog accepted.");
            results.Add(new("cyclic metadata catalog rejected by pure preactivation compiler", true, null));
        }
        catch (Exception error) { results.Add(new("cyclic metadata catalog rejected by pure preactivation compiler", false, error.ToString())); }
        return Task.FromResult(results);
    }
}
