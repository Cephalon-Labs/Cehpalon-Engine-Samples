extern alias securityapi;
using System.Diagnostics;
using System.Net;
using System.Text.Json;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;
using Npgsql;
using securityapi::SecurityApi;

namespace AuditOutbox;

public static partial class ResourceTransportChecks
{
    private const int MeasurementRowsPerTenant = 256;
    private const int MeasurementDistractorsPerTenant = 64;
    private static readonly TimeSpan MeasurementReadDeadline = TimeSpan.FromSeconds(2);
    private static readonly string[] MeasurementFields =
        ["title", "secret", "category", "count", "retained", "enabled", "comment", "rank"];

    public static async Task<int> RunHistoryMeasurementAsync(string[] args)
    {
        var deadlineEnabled = args.Length == 5 && args[1] == "serve" && args[4] == "deadline";
        if ((args.Length != 4 && !deadlineEnabled) || args[1] is not ("seed" or "serve" or "verify-deadline" or "verify-timeout-wire"))
        {
            Console.Error.WriteLine("Usage: --measure-audit-history seed|serve|verify-deadline|verify-timeout-wire <private-connection-file> <owned-schema> [deadline for serve]");
            return 2;
        }

        var connection = (await File.ReadAllTextAsync(args[2])).Trim();
        var settings = new NpgsqlConnectionStringBuilder(connection);
        if (settings.Pooling || settings.Host != "127.0.0.1")
            throw new ArgumentException("Use the owned loopback fixture connection with Pooling=false.");
        var store = new PostgresStore(connection, args[3]);

        if (args[1] == "seed")
        {
            await store.Initialize();
            await using var provision = await IndexedProfileComposition.ActivateAsync(
                IndexedProfileComposition.Configuration(true), args[3], IndexedProfileOpenMode.CreateNew,
                _ => ValueTask.FromResult(connection), new());
            var storage = provision.Storage ?? throw new InvalidOperationException("Fixture storage was not created.");
            foreach (var tenant in new[] { "A", "B" })
            {
                for (var key = 1; key <= MeasurementRowsPerTenant; key++)
                    await storage.AppendOnceAsync(MeasurementRow(key, tenant, "shared"), default);
                for (var key = MeasurementRowsPerTenant + 1; key <= MeasurementRowsPerTenant + MeasurementDistractorsPerTenant; key++)
                    await storage.AppendOnceAsync(MeasurementRow(key, tenant, "other"), default);
            }

            using var version = JsonDocument.Parse(await store.VersionSettings());
            WriteMeasurement(new { kind = "seeded", resource_rows = 2 * MeasurementRowsPerTenant,
                distractor_rows = 2 * MeasurementDistractorsPerTenant, settings = version.RootElement });
            return 0;
        }

        using var tls = new TlsFixture();
        using var jwt = new JwtFixture();
        var fixture = new Fixture(store, connection, args[2], tls, jwt);
        var policy = new TenantChangeAuditPolicy(TenantChangeAuditMode.BeforeAfterSnapshots,
            [new("entity.update", "update", "entity", MeasurementFields.Select(name => new TenantChangeFieldRule(name, name == "secret")))]);
        if (args[1] == "verify-timeout-wire")
        {
            await VerifyTimeoutWireAsync(() => new Fixture(store, connection, args[2], tls, jwt), policy);
            return 0;
        }
        if (args[1] == "verify-deadline")
        {
            foreach (var graph in new[] { false, true })
            foreach (var scenario in new[] { "deadline-elapses", "caller-with-deadline", "caller-without-deadline", "null-outlasts-deadline" })
                await VerifyMeasurementDeadlineAsync(new Fixture(store, connection, args[2], tls, jwt), graph, scenario, policy);
            return 0;
        }
        TimeSpan? readTimeout = deadlineEnabled ? MeasurementReadDeadline : null;
        await using var host = await fixture.Start(new(true, true, ReadTimeout: readTimeout)
            { ResourceHistoryEnabled = true, ReceiptLookupEnabled = false }, policy);
        WriteMeasurement(new { kind = "ready", port = host.Address.Port, ca = tls.Root.ExportCertificatePem(),
            a = fixture.Token("resource-a"), b = fixture.Token("resource-b"), both = fixture.Token("resource-both"),
            history_only = fixture.Token("history-only"), read_timeout_ms = readTimeout?.TotalMilliseconds });

        while (true)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            switch (await Console.In.ReadLineAsync(timeout.Token))
            {
                case "snapshot":
                    var allocated = GC.GetTotalAllocatedBytes(precise: true);
                    WriteMeasurement(new { kind = "snapshot", allocated,
                        collections = new[] { GC.CollectionCount(0), GC.CollectionCount(1), GC.CollectionCount(2) },
                        queries = fixture.Source.ResourceQueries, handlers = fixture.Probe.ResourceHandlerFactories,
                        results = fixture.Probe.ResourceReaderResults, active = fixture.Probe.ActiveDispatches });
                    break;
                case "revoke":
                    fixture.Authority.MembershipRevoked = true;
                    WriteMeasurement(new { kind = "revoked" });
                    break;
                case "restore":
                    fixture.Authority.MembershipRevoked = false;
                    WriteMeasurement(new { kind = "restored" });
                    break;
                case "stop":
                case null:
                    return 0;
                default:
                    throw new InvalidOperationException("Unknown measurement controller command.");
            }
        }
    }

    private static async Task VerifyMeasurementDeadlineAsync(Fixture fixture, bool graph, string scenario, TenantChangeAuditPolicy policy)
    {
        var useDeadline = scenario is "deadline-elapses" or "caller-with-deadline";
        await using var host = await fixture.Start(Options(graph, useDeadline ? MeasurementReadDeadline : null), policy);
        using var client = fixture.Client(host);
        using var caller = new CancellationTokenSource();
        var sql = fixture.Sql();
        await using var blocker = await sql.Hold();
        var elapsed = Stopwatch.StartNew();
        var pending = fixture.Send(client, graph, Q(limit: 25), fixture.Token(), cancellationToken: caller.Token);
        var signalMs = 0d;
        var completionMs = 0d;
        try
        {
            var pid = await sql.Observe(fixture.Probe, pending, caller.Token).WaitAsync(Watchdog);
            Require((fixture.Probe.LastResourceWorkToken != fixture.Probe.LastResourceDispatchToken) == useDeadline);
            if (scenario == "null-outlasts-deadline")
            {
                await Task.Delay(MeasurementReadDeadline + TimeSpan.FromMilliseconds(250));
                Require(!pending.IsCompleted && !fixture.Probe.LastResourceWorkToken.IsCancellationRequested &&
                    fixture.Probe.ResourceReaderResults == 0);
                signalMs = elapsed.Elapsed.TotalMilliseconds;
                await blocker.DisposeAsync();
                Require((await pending.WaitAsync(Watchdog)).Success(graph));
            }
            else
            {
                if (scenario == "deadline-elapses")
                {
                    var reply = await pending.WaitAsync(Watchdog);
                    Require(reply.Status == (graph ? HttpStatusCode.OK : HttpStatusCode.InternalServerError) &&
                        reply.Error(graph, "internal.error") && !reply.Body.Contains(fixture.Store.Schema, StringComparison.Ordinal) &&
                        elapsed.Elapsed >= MeasurementReadDeadline - TimeSpan.FromMilliseconds(50));
                    Require(!caller.IsCancellationRequested && !fixture.Probe.LastResourceDispatchToken.IsCancellationRequested);
                }
                else
                {
                    signalMs = elapsed.Elapsed.TotalMilliseconds;
                    Require(!useDeadline || elapsed.Elapsed < MeasurementReadDeadline);
                    caller.Cancel();
                    Require(await Failure(() => pending).WaitAsync(Watchdog) is OperationCanceledException);
                    await Wait(() => fixture.Probe.LastResourceDispatchToken.IsCancellationRequested).WaitAsync(Watchdog);
                }
                await Wait(() => fixture.Probe.LastResourceWorkToken.IsCancellationRequested).WaitAsync(Watchdog);
                Require(fixture.Probe.ResourceReaderResults == 0);
            }

            await Wait(() => fixture.Probe.ActiveDispatches == 0 && fixture.Probe.CompletedDispatches == 1).WaitAsync(Watchdog);
            await sql.Quiescent(pid);
            completionMs = elapsed.Elapsed.TotalMilliseconds;
        }
        finally
        {
            caller.Cancel();
            await blocker.DisposeAsync();
            await Join(pending);
        }
        Require((await fixture.Send(client, graph, Q(limit: 25), fixture.Token())).Success(graph) &&
            fixture.Source.ResourceQueries == 2 && fixture.Source.LookupQueries == 0 &&
            fixture.Probe.ResourceReaderResults == (scenario == "null-outlasts-deadline" ? 2 : 1));
        WriteMeasurement(new { kind = "deadline_control", transport = graph ? "graphql" : "http", scenario,
            work_token_linked = useDeadline, read_timeout_ms = useDeadline ? MeasurementReadDeadline.TotalMilliseconds : (double?)null,
            lock_observed_before_signal = true, joined_backend = true, successful_reuse = true,
            signal_ms = signalMs > 0 ? signalMs : (double?)null, completion_ms = completionMs });
    }

    private static void WriteMeasurement(object value)
    {
        Console.WriteLine(JsonSerializer.Serialize(value));
        Console.Out.Flush();
    }

    private static TenantChangeAuditRecord MeasurementRow(int key, string tenant, string resource)
    {
        var receipt = new TenantChangeReceipt(Key(key), new PrincipalId("audit-history-measurement", "fixture-writer"),
            "fixture-service", new(tenant), "entity.update", "update", "entity", resource, "fixture-v1",
            TenantChangeKind.Update, "0", "1");
        var attributes = MeasurementFields.Select(field => new TenantChangeField(field,
            TenantChangeValue.Text("before:" + field), TenantChangeValue.Text($"after:{tenant}:{key}:{field}")));
        return new(receipt, DateTimeOffset.UnixEpoch.AddDays(20000), TenantChangeAuditMode.BeforeAfterSnapshots,
            attributes.Append(new("unknown", TenantChangeValue.Text("hidden-before"), TenantChangeValue.Text("hidden-after"))));
    }
}
