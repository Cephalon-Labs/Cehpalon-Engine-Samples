extern alias securityapi;
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
    private static readonly string[] MeasurementFields =
        ["title", "secret", "category", "count", "retained", "enabled", "comment", "rank"];

    public static async Task<int> RunHistoryMeasurementAsync(string[] args)
    {
        if (args.Length != 4 || args[1] is not ("seed" or "serve"))
        {
            Console.Error.WriteLine("Usage: --measure-audit-history seed|serve <private-connection-file> <owned-schema>");
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
        await using var host = await fixture.Start(new(true, true) { ResourceHistoryEnabled = true, ReceiptLookupEnabled = false }, policy);
        WriteMeasurement(new { kind = "ready", port = host.Address.Port, ca = tls.Root.ExportCertificatePem(),
            a = fixture.Token("resource-a"), b = fixture.Token("resource-b"), both = fixture.Token("resource-both"),
            history_only = fixture.Token("history-only") });

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
