using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Text.Json;
using PortableConsumers.Generated;

internal static class SmallApiHistogramProbe
{
    private const string DispatchMeter = "Cehpalon.Engine.Core";
    private const string LifecycleMeter = "Cehpalon.Engine.Composition";
    private const string DispatchName = "cehpalon.operation.dispatch.duration";
    private const string LifecycleName = "cehpalon.module.lifecycle.duration";

    public static async Task<int> Main(string[] args)
    {
        if (args.Length != 2 || args[0] is not ("healthy" or "publication-fault" or "measurement-fault"))
            throw new ArgumentException("Expected observer mode and a new JSON report path.");
        var mode = args[0];
        var publications = new ConcurrentQueue<string>();
        var measurements = new ConcurrentQueue<Measurement>();
        var checks = new List<object>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, current) =>
        {
            if (!Matches(instrument)) return;
            publications.Enqueue(instrument.Name);
            current.EnableMeasurementEvents(instrument);
            if (mode == "publication-fault")
                throw new InvalidOperationException("Synthetic first publication failure.");
        };
        listener.SetMeasurementEventCallback<double>((instrument, seconds, tags, _) =>
        {
            var lifecycle = instrument.Name == LifecycleName;
            var valid = double.IsFinite(seconds) && seconds >= 0 && instrument.Unit == "s" &&
                tags.Length == (lifecycle ? 2 : 1) && tags[^1].Key == "outcome" &&
                (!lifecycle || tags[0].Key == "phase");
            var phase = lifecycle && tags.Length > 0 ? tags[0].Value as string : null;
            var outcome = tags.Length > 0 ? tags[^1].Value as string : null;
            measurements.Enqueue(new(instrument.Name, phase, outcome, valid));
            if (mode == "measurement-fault")
                throw new InvalidOperationException("Synthetic measurement failure.");
        });
        listener.Start();

        using var tls = new TlsFixture();
        using var jwt = new JwtFixture();
        await using (var off = new FixtureHost())
        {
            await off.Start(FixtureHost.Config(api: false, graphql: false), tls, jwt);
            Require(off.Application is null && off.Counters.HostFactories == 0 &&
                publications.IsEmpty && measurements.IsEmpty, "All-off host performed instrument or module work.");
        }

        await ExerciseHost();
        if (mode == "publication-fault")
        {
            listener.Dispose();
            await ExerciseHost();
        }

        Require(publications.Order(StringComparer.Ordinal).SequenceEqual(
            new[] { LifecycleName, DispatchName }.Order(StringComparer.Ordinal)),
            "Expected exactly one first publication per instrument.");
        using var stream = new FileStream(args[1], FileMode.CreateNew, FileAccess.Write);
        JsonSerializer.Serialize(stream, new
        {
            mode, runtime = RuntimeInformation.FrameworkDescription, os = RuntimeInformation.OSDescription,
            publications, checks, measurements
        }, new JsonSerializerOptions { WriteIndented = true });
        return 0;

        async Task ExerciseHost()
        {
            await using var host = new FixtureHost();
            var lifecycleExpected = mode == "publication-fault" ? 0 : 3;
            var start = measurements.Count;
            await host.Start(FixtureHost.Config(api: true, graphql: true), tls, jwt);
            CheckDelta(start, LifecycleName, "activation", "success", lifecycleExpected);
            using var client = tls.Client(host.Address);
            foreach (var graphQl in new[] { false, true })
            {
                await Request(graphQl, "tenant-a", true, "owner", 2);
                await Request(graphQl, "tenant-b", true, "cross-tenant", 1);
                await Request(graphQl, "tenant-a", false, "anonymous", 0);
            }
            start = measurements.Count;
            await host.DisposeAsync();
            CheckDelta(start, LifecycleName, "disposal", "success", lifecycleExpected);
            Require(host.Counters.HostFactories == 1 && host.Counters.HostDisposals == 1 &&
                host.Counters.ForbiddenFactories == 0 && host.Store.Factories == 2 && host.Store.Disposals == 2,
                "Expected one host lifetime and exactly two owned handlers.");
            await host.DisposeAsync();
            CheckDelta(start, LifecycleName, "disposal", "success", lifecycleExpected);

            async Task Request(bool graphQl, string tenant, bool authenticated, string scenario, int expected)
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, graphQl ? "/graphql" : "/api/catalog/get");
                var input = new { tenant, id = 1 };
                request.Content = JsonContent.Create(graphQl ? (object)new
                {
                    query = "query($input: GetItemInput!) { catalogItem(input: $input) { id tenant } }",
                    variables = new { input }
                } : input);
                if (authenticated) request.Headers.Authorization = new("Bearer", jwt.Token());
                request.Headers.Add("X-Tenant", "tenant-b");
                var before = measurements.Count;
                using var response = await client.SendAsync(request);
                var status = (int)response.StatusCode;
                if (!authenticated)
                    Require(response.StatusCode == HttpStatusCode.Unauthorized, "Anonymous request was accepted.");
                else
                {
                    using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                    var payload = json.RootElement;
                    if (scenario == "owner")
                    {
                        var item = graphQl ? payload.GetProperty("data").GetProperty("catalogItem") : payload;
                        Require(status == 200 && item.GetProperty("id").GetInt32() == 1 &&
                            item.GetProperty("tenant").GetString() == "tenant-a", "Owner data differed.");
                    }
                    else
                    {
                        var code = graphQl
                            ? payload.GetProperty("errors")[0].GetProperty("extensions").GetProperty("code")
                            : payload.GetProperty("code");
                        Require(status == (graphQl ? 200 : 403) && code.GetString() == "access.denied",
                            "Cross-tenant request did not receive access.denied.");
                    }
                }
                var measured = mode == "publication-fault" ? 0 : expected;
                CheckDelta(before, DispatchName, null, scenario == "owner" ? "success" : "failure", measured);
                checks.Add(new { transport = graphQl ? "graphql" : "http", scenario, status, observations = measured });
            }
        }

        void CheckDelta(int start, string instrument, string? phase, string outcome, int count)
        {
            var delta = measurements.ToArray().Skip(start).ToArray();
            Require(delta.Length == count && delta.All(value => value == new Measurement(instrument, phase, outcome, true)),
                $"Unexpected {instrument} {phase} {outcome} observations. Expected {count}, received {delta.Length}.");
        }
    }

    private static bool Matches(Instrument instrument) =>
        (instrument.Meter.Name == DispatchMeter && instrument.Name == DispatchName) ||
        (instrument.Meter.Name == LifecycleMeter && instrument.Name == LifecycleName);

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private sealed record Measurement(string Name, string? Phase, string? Outcome, bool Valid);
}
