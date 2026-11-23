using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using Cehpalon.Engine.Core;
using Microsoft.AspNetCore.Http.Features;
using PortableConsumers.Generated;

internal static partial class DispatchCorrelationProbe
{
    private const string RequestHeader = "X-Cehpalon-Proof-Request";
    private const string ServerActivity = "Microsoft.AspNetCore.Hosting.HttpRequestIn";
    private const string DispatchMeter = "Cehpalon.Engine.Core";
    private const string DispatchHistogram = "cehpalon.operation.dispatch.duration";
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(6);
    private static readonly ConcurrentDictionary<string, RequestCapture> requests = new();
    private static readonly AsyncLocal<RequestCapture?> current = new();
    private static int unscopedSignals;

    internal static OperationDispatcher CreateDispatcher(OperationRegistry registry) =>
        current.Value?.Enabled == true ? new(registry, RecordCompletion) : new(registry);

    private static void RecordCompletion(OperationDispatchCompletion completion)
    {
        if (current.Value is { } capture)
        {
            if (capture.Cleanup is { } cleanup)
                capture.CleanupBeforeCompletion = cleanup.Completed && cleanup.Store.Disposals == 1;
            capture.Records.Enqueue(completion);
        }
        else
            Interlocked.Increment(ref unscopedSignals);
    }

    internal static async Task ObserveRequest(HttpContext http, RequestDelegate next)
    {
        if (!requests.TryGetValue(http.Request.Headers[RequestHeader].ToString(), out var capture))
            throw new InvalidOperationException("Network request was not assigned to a proof case.");
        var trace = http.Features.Get<IHttpActivityFeature>()?.Activity;
        Require(http.Request.IsHttps && trace is
            { Kind: ActivityKind.Server, OperationName: ServerActivity } && ReferenceEquals(trace, Activity.Current),
            "Expected ASP.NET Core's native HTTPS request Activity.");
        Require(http.Request.Headers["traceparent"].ToString() == capture.TraceParent &&
            http.Request.Headers.Authorization.ToString() == capture.Authorization,
            "Transport did not preserve the fixture's inbound trace or authorization case.");
        http.TraceIdentifier = capture.CorrelationSentinel;
        trace!.AddBaggage("private.proof", capture.BaggageSentinel);
        trace.SetTag("private.proof", capture.TagSentinel);
        trace.TraceStateString = "proof=" + capture.TraceStateSentinel;
        capture.Native = new(trace.IdFormat, trace.TraceId, trace.SpanId, trace.ParentSpanId);
        var previous = current.Value;
        current.Value = capture;
        try
        {
            await next(http);
        }
        finally
        {
            current.Value = previous;
            capture.Returned.TrySetResult();
        }
    }

    public static async Task<int> Main(string[] args)
    {
        var drain = args is [_, "--drain"];
        Require((args.Length == 1 || drain) && Environment.Version == new Version(11, 0, 0),
            "Expected report path, an optional drain mode and .NET 11.0.0 runtime.");
        Require(typeof(OperationDispatchCompletion).GetProperties().Select(property => property.Name)
            .Order(StringComparer.Ordinal).SequenceEqual(new[] { "Duration", "Outcome", "SpanId", "TraceId" }),
            "Completion DTO property allowlist differs.");

        using var activity = new ActivityListener
        {
            ShouldListenTo = source => source.Name == "Microsoft.AspNetCore",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.PropagationData,
            SampleUsingParentId = (ref ActivityCreationOptions<string> _) => ActivitySamplingResult.PropagationData,
        };
        ActivitySource.AddActivityListener(activity);
        using var meter = new MeterListener();
        meter.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == DispatchMeter && instrument.Name == DispatchHistogram)
                listener.EnableMeasurementEvents(instrument);
        };
        meter.SetMeasurementEventCallback<double>((instrument, seconds, tags, _) =>
        {
            var valid = instrument.Unit == "s" && double.IsFinite(seconds) && seconds >= 0 &&
                tags.Length == 1 && tags[0].Key == "outcome" && tags[0].Value is string;
            if (current.Value is { } capture)
                capture.Histograms.Enqueue(valid ? (string)tags[0].Value! : "invalid");
            else
                Interlocked.Increment(ref unscopedSignals);
        });
        meter.Start();
        if (drain)
            return await RunDrainProof(args[0]);

        var checks = new List<CaseReceipt>();
        var shutdowns = 0;
        using var tls = new TlsFixture();
        using var jwt = new JwtFixture();
        await using (var allOff = new FixtureHost())
        {
            await allOff.Start(FixtureHost.Config(api: false, graphql: false), tls, jwt);
            Require(allOff.Application is null && allOff.Counters.HostFactories == 0,
                "All-off plan performed module-owned work.");
        }
        await ExerciseHost(enabled: true, expectedDisposals: 14);
        await ExerciseHost(enabled: false, expectedDisposals: 2);
        Require(requests.IsEmpty && unscopedSignals == 0, "Observed signals outside their HTTPS request scope.");
        Require(checks.Count == 17 && checks.Sum(row => row.Records) == 16 && checks.Sum(row => row.Histograms) == 34,
            "HTTPS case, completion, or histogram totals differed.");
        using var output = new FileStream(args[0], FileMode.CreateNew, FileAccess.Write);
        JsonSerializer.Serialize(output, new
        {
            outcome = "passed", runtime = RuntimeInformation.FrameworkDescription, os = RuntimeInformation.OSDescription,
            allOff = true, shutdowns, cases = checks, unscopedSignals
        }, new JsonSerializerOptions { WriteIndented = true });
        return 0;

        async Task ExerciseHost(bool enabled, int expectedDisposals)
        {
            await using var host = new FixtureHost();
            await host.Start(FixtureHost.Config(api: true, graphql: true), tls, jwt);
            var address = host.Address;
            using var client = tls.Client(address);
            foreach (var graphQl in new[] { false, true })
            {
                await Check(graphQl, "owner", enabled, "valid", ResponseKind.Owner);
                if (enabled)
                {
                    await Check(graphQl, "authenticated-tenant-denial", enabled, "valid", ResponseKind.TenantDenied);
                    await Check(graphQl, "anonymous", enabled, "valid", ResponseKind.Anonymous);
                    await Check(graphQl, "absent-parent", enabled, "absent", ResponseKind.Owner);
                    await Check(graphQl, "malformed-parent", enabled, "malformed", ResponseKind.Owner);
                }
            }
            if (enabled)
            {
                await Overlapping(host.Store, client, [
                    NewCapture(false, "overlapping-requests", enabled, "valid", ResponseKind.Owner, 1),
                    NewCapture(true, "overlapping-requests", enabled, "valid", ResponseKind.Owner, 1),
                    NewCapture(false, "overlapping-requests", enabled, "valid", ResponseKind.Owner, 1),
                    NewCapture(true, "overlapping-requests", enabled, "valid", ResponseKind.Owner, 1),
                ]);
                await Overlapping(host.Store, client, [
                    NewCapture(true, "parallel-graphql-fields", enabled, "valid", ResponseKind.Owner, 4),
                ]);
            }
            await host.DisposeAsync();
            await host.DisposeAsync();
            Require(host.Counters.HostFactories == 1 && host.Counters.HostDisposals == 1 &&
                host.Counters.ForbiddenFactories == 0 && host.Store.Factories == expectedDisposals &&
                host.Store.Disposals == expectedDisposals, "Owned factory and disposal counts differed.");
            using var socket = new TcpClient();
            try
            {
                await socket.ConnectAsync(IPAddress.Loopback, address.Port).WaitAsync(Deadline);
                throw new InvalidOperationException("The owned HTTPS port remained open.");
            }
            catch (SocketException error) when (error.SocketErrorCode == SocketError.ConnectionRefused)
            {
                shutdowns++;
            }

            async Task Check(bool graphQl, string name, bool on, string header, ResponseKind result)
            {
                var capture = NewCapture(graphQl, on ? name : "opt-out-owner", on, header, result, 1);
                checks.Add(await Send(client, capture));
            }
        }

        async Task Overlapping(CatalogStore store, HttpClient client, RequestCapture[] captures)
        {
            var initialDisposals = store.Disposals;
            var entered = CatalogStore.NewSignal();
            var release = CatalogStore.NewSignal();
            store.ReadWaits = 0;
            store.ReadsEntered = entered;
            store.ReadRelease = release;
            var responses = Task.WhenAll(captures.Select(capture => Send(client, capture)));
            try
            {
                await entered.Task.WaitAsync(Deadline);
                Require(store.ReadWaits == 4 && !responses.IsCompleted && store.Disposals == initialDisposals &&
                    captures.All(capture => capture.Native is not null && capture.Records.IsEmpty && capture.Histograms.IsEmpty),
                    "Four real catalog reads did not overlap before cleanup and observation.");
                Require(captures.Select(capture => capture.Native!.TraceId).Distinct().Count() == captures.Length &&
                    captures.Select(capture => capture.Native!.SpanId).Distinct().Count() == captures.Length,
                    "Expected distinct native trace and span IDs across overlapping HTTP requests.");
            }
            finally
            {
                release.TrySetResult();
                try
                {
                    await responses;
                }
                finally
                {
                    store.ReadRelease = null;
                    store.ReadsEntered = null;
                }
            }
            checks.AddRange(responses.Result.Select(row => row with { OverlappingReads = 4 }));
        }

        RequestCapture NewCapture(bool graphQl, string scenario, bool enabled, string header, ResponseKind response, int fields) =>
            new(graphQl, scenario, enabled, header, response, fields,
                response == ResponseKind.Anonymous ? "" : "Bearer " + jwt.Token());
    }

    private static async Task<CaseReceipt> Send(HttpClient client, RequestCapture capture)
    {
        Require(requests.TryAdd(capture.Key, capture), "Duplicate fixture request key.");
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post,
                capture.GraphQl ? "/graphql" : capture.Cleanup is null ? "/api/catalog/get" : "/api/catalog/set");
            var tenant = capture.Response == ResponseKind.TenantDenied ? "tenant-b" : "tenant-a";
            if (capture.Cleanup is not null)
            {
                var input = new { tenant, id = 1, expectedRevision = 0, label = capture.MutationSentinel };
                request.Content = JsonContent.Create(capture.GraphQl ? new
                {
                    query = $"mutation {capture.QuerySentinel}($input: SetLabelInput!) {{ field1: setLabel(input: $input) {{ id tenant label revision }} }}",
                    variables = new { input }
                } : (object)input);
            }
            else
                request.Content = ReadContent(capture, tenant);
            request.Headers.Add(RequestHeader, capture.Key);
            request.Headers.Add("X-Tenant", "tenant-b");
            request.Headers.Add("X-Proof-Private", capture.HeaderSentinel);
            if (capture.Authorization.Length != 0)
                request.Headers.Add("Authorization", capture.Authorization);
            if (capture.TraceParent.Length != 0)
                request.Headers.Add("traceparent", capture.TraceParent);
            using var response = await client.SendAsync(request);
            await capture.Returned.Task.WaitAsync(Deadline);
            var status = (int)response.StatusCode;
            if (capture.Response == ResponseKind.Anonymous)
                Require(status == 401, "Anonymous request was accepted.");
            else
                await VerifyResponse(response, capture, tenant);

            var native = capture.Native ?? throw new InvalidOperationException("Native request Activity was not recorded.");
            if (capture.Header == "valid")
                Require(native.Format == ActivityIdFormat.W3C && native.TraceId == capture.SentTraceId &&
                    native.ParentSpanId == capture.SentParentSpanId && native.SpanId != native.ParentSpanId,
                    "Native server trace did not link to the supplied valid parent.");
            var expectedOutcome = capture.Response switch
            {
                ResponseKind.Owner => OperationDispatchOutcome.Success,
                ResponseKind.CleanupFault => OperationDispatchOutcome.Fault,
                _ => OperationDispatchOutcome.Failure,
            };
            var expectedCount = capture.Response == ResponseKind.Anonymous || !capture.Enabled ? 0 : capture.Fields;
            var expectedHistograms = capture.Response switch
            {
                ResponseKind.Owner => 2 * capture.Fields,
                ResponseKind.TenantDenied or ResponseKind.Overloaded => 1,
                ResponseKind.CleanupFault => 2,
                _ => 0
            };
            var records = capture.Records.ToArray();
            Require(records.Length == expectedCount && capture.Histograms.Count == expectedHistograms &&
                capture.Histograms.All(item => item == expectedOutcome.ToString().ToLowerInvariant()),
                "Outer completion or Core histogram counts and outcomes differed.");
            ActivityTraceId? traceId = native.Format == ActivityIdFormat.W3C ? native.TraceId : null;
            ActivitySpanId? spanId = native.Format == ActivityIdFormat.W3C ? native.SpanId : null;
            foreach (var record in records)
            {
                Require(record.Outcome == expectedOutcome && record.Duration >= TimeSpan.Zero &&
                    record.TraceId == traceId && record.SpanId == spanId,
                    "Completion outcome, duration, or native Activity equality differed.");
                ValidateStructuredRecord(record, capture);
            }
            return new(capture.GraphQl ? "graphql" : "http", capture.Scenario, capture.Header, capture.Enabled,
                status, native.Format.ToString(), records.Length, expectedHistograms,
                records.Length == 0 ? null : expectedOutcome.ToString(), records.Length == 0 ? null : true,
                records.Length == 0 ? null : true);
        }
        finally
        {
            requests.TryRemove(capture.Key, out _);
        }
    }

    private static HttpContent ReadContent(RequestCapture capture, string tenant)
    {
        var inputs = Enumerable.Range(1, capture.Fields)
            .ToDictionary(index => $"input{index}", index => new { tenant, id = index });
        var selection = capture.CheckFreshRevision ? "id tenant revision" : "id tenant";
        var fields = Enumerable.Range(1, capture.Fields)
            .Select(index => $"field{index}: catalogItem(input: $input{index}) {{ {selection} }}");
        var queryVariables = inputs.Keys.Select(name => $"${name}: GetItemInput!");
        var query = $"query {capture.QuerySentinel}({string.Join(", ", queryVariables)}) {{ {string.Join(" ", fields)} }}";
        return JsonContent.Create(capture.GraphQl ? new { query, variables = inputs } : (object)inputs["input1"]);
    }

    private static async Task VerifyResponse(HttpResponseMessage response, RequestCapture capture, string tenant)
    {
        var status = (int)response.StatusCode;
        var body = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(body);
        var json = document.RootElement;
        if (capture.Response == ResponseKind.Owner)
        {
            Require(status == 200, "Owner returned an unexpected status.");
            for (var field = 1; field <= capture.Fields; field++)
            {
                var item = capture.GraphQl ? json.GetProperty("data").GetProperty($"field{field}") : json;
                Require(item.GetProperty("id").GetInt32() == field &&
                    item.GetProperty("tenant").GetString() == tenant, "Owner data differed.");
                if (capture.CheckFreshRevision || capture.Cleanup is not null)
                    Require(item.GetProperty("revision").GetInt32() == (capture.CheckFreshRevision ? 0 : 1),
                        "Expected initial restart data or the one admitted write.");
            }
            return;
        }

        var (httpStatus, errorCode, message) = capture.Response switch
        {
            ResponseKind.TenantDenied => (403, "access.denied", "Access denied."),
            ResponseKind.Overloaded => (503, "operation.capacity_exceeded", "Operation capacity is temporarily unavailable."),
            ResponseKind.CleanupFault => (500, "internal.error", "An internal error occurred."),
            _ => throw new InvalidOperationException("Unexpected response case."),
        };
        var error = capture.GraphQl ? json.GetProperty("errors")[0] : json;
        var code = capture.GraphQl ? error.GetProperty("extensions").GetProperty("code") : error.GetProperty("code");
        Require(status == (capture.GraphQl ? 200 : httpStatus) && code.GetString() == errorCode &&
            error.GetProperty("message").GetString() == message &&
            !body.Contains(capture.CleanupFaultSentinel, StringComparison.Ordinal),
            "Public error response differed or exposed the private fault.");
    }

    private static void ValidateStructuredRecord(OperationDispatchCompletion record, RequestCapture capture)
    {
        var payload = JsonSerializer.Serialize(new
        {
            eventName = OperationDispatchCompletion.EventName,
            outcome = record.Outcome.ToString(),
            durationTicks = record.Duration.Ticks,
            traceId = record.TraceId?.ToHexString(),
            spanId = record.SpanId?.ToHexString()
        });
        using var json = JsonDocument.Parse(payload);
        Require(json.RootElement.EnumerateObject().Select(value => value.Name).Order(StringComparer.Ordinal)
            .SequenceEqual(new[] { "durationTicks", "eventName", "outcome", "spanId", "traceId" }) &&
            json.RootElement.GetProperty("eventName").GetString() == "cehpalon.operation.dispatch.completed",
            "Structured event field allowlist differed.");
        var sentinels = new[] { capture.Key, capture.CorrelationSentinel, capture.BaggageSentinel, capture.TagSentinel,
            capture.TraceStateSentinel, capture.HeaderSentinel, capture.QuerySentinel, capture.Authorization,
            capture.TraceParent, capture.MutationSentinel, capture.CleanupFaultSentinel,
            "tenant-a", "tenant-b", "catalog.get", "catalog.set", "alice" };
        Require(sentinels.Where(value => value.Length != 0).All(value => !payload.Contains(value, StringComparison.Ordinal)),
            "A private fixture value appeared in the completion projection.");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private enum ResponseKind { Owner, TenantDenied, Anonymous, Overloaded, CleanupFault }

    private sealed class RequestCapture(bool graphQl, string scenario, bool enabled, string header,
        ResponseKind response, int fields, string authorization)
    {
        public string Key { get; } = Guid.NewGuid().ToString("N");
        public bool GraphQl { get; } = graphQl;
        public string Scenario { get; } = scenario;
        public bool Enabled { get; } = enabled;
        public string Header { get; } = header;
        public ResponseKind Response { get; } = response;
        public int Fields { get; } = fields;
        public string Authorization { get; } = authorization;
        public ActivityTraceId SentTraceId { get; } = ActivityTraceId.CreateRandom();
        public ActivitySpanId SentParentSpanId { get; } = ActivitySpanId.CreateRandom();
        public string TraceParent => Header switch
        {
            "absent" => "",
            "malformed" => "malformed-" + Key,
            _ => $"00-{SentTraceId}-{SentParentSpanId}-01",
        };
        public string CorrelationSentinel => "correlation-" + Key;
        public string BaggageSentinel => "baggage-" + Key;
        public string TraceStateSentinel => "tracestate-" + Key;
        public string TagSentinel => "tag-" + Key;
        public string HeaderSentinel => "header-" + Key;
        public string QuerySentinel => "query_" + Key;
        public string MutationSentinel => "mutation-" + Key;
        public string CleanupFaultSentinel => "cleanup-fault-" + Key;
        public bool CheckFreshRevision { get; init; }
        public CleanupGate? Cleanup { get; init; }
        public bool CleanupBeforeCompletion;
        public NativeCapture? Native;
        public ConcurrentQueue<OperationDispatchCompletion> Records { get; } = new();
        public ConcurrentQueue<string> Histograms { get; } = new();
        public TaskCompletionSource Returned { get; } = CatalogStore.NewSignal();
    }

    private sealed record NativeCapture(ActivityIdFormat Format, ActivityTraceId TraceId, ActivitySpanId SpanId,
        ActivitySpanId ParentSpanId);

    private sealed record CaseReceipt(string Transport, string Scenario, string Header, bool Enabled, int Status,
        string NativeFormat, int Records, int Histograms, string? Outcome, bool? TraceMatchesNative,
        bool? PrivateValuesExcluded, int OverlappingReads = 0);
}
