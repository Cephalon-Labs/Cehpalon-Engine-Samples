using System.Net;
using Cehpalon.Engine.Tenancy;
using Cehpalon.Engine.Transports.Http;

namespace AuditOutbox;

public static partial class ResourceTransportChecks
{
    private static async Task VerifyTimeoutWireAsync(Func<Fixture> create, TenantChangeAuditPolicy policy, bool collectStatistics = false)
    {
        var optedIn = new AuditReceiptTransportOptions(true, true, ReadTimeout: MeasurementReadDeadline)
            { ResourceHistoryEnabled = true, ReportReadTimeout = true, CollectReadStatistics = collectStatistics };
        var timeoutSchema = ContractOpenApi(await AuditReadContractExport.BuildArtifactsAsync(optedIn));
        var defaultSchema = ContractOpenApi(await AuditReadContractExport.BuildArtifactsAsync(optedIn with { ReportReadTimeout = false }));
        var disabledSchema = ContractOpenApi(await AuditReadContractExport.BuildArtifactsAsync(optedIn with { ReadTimeout = null }));
        var graphOnly = await AuditReadContractExport.BuildArtifactsAsync(optedIn with { HttpEnabled = false });
        Require(!graphOnly.Files.ContainsKey("openapi.json"));
        foreach (var path in new[] { AuditReceiptTransportHost.LookupPath, AuditReceiptTransportHost.ResourceHistoryPath })
        {
            Require(ContractResponseSchema(timeoutSchema, path, "504") is not null);
            Require(defaultSchema["paths"]![path]!["post"]!["responses"]!["504"] is null &&
                disabledSchema["paths"]![path]!["post"]!["responses"]!["504"] is null);
        }
        WriteMeasurement(new { kind = "wire_timeout_schema", selected_paths = 2,
            legacy_and_null_have_no_504 = true, graphql_only_has_no_http_contract = true });

        foreach (var graph in new[] { false, true })
        foreach (var lookup in new[] { false, true })
        foreach (var scenario in new[] { "typed-timeout", "legacy-timeout", "provider-timeout", "caller-abort", "cross-tenant" })
        {
            var fixture = create();
            var options = optedIn with { HttpEnabled = !graph, GraphQLEnabled = graph, ReceiptLookupEnabled = lookup,
                ResourceHistoryEnabled = !lookup, ReportReadTimeout = scenario != "legacy-timeout" };
            await using var host = await fixture.Start(options, policy);
            Require(host.ReadStatistics == (collectStatistics ? new TenantChangeAuditReadStatisticsSnapshot() : null));
            using var client = fixture.Client(host);
            using var caller = new CancellationTokenSource();
            var sql = fixture.Sql();
            Task<Reply> Send(string subject, CancellationToken token = default) => lookup
                ? fixture.Receipt(client, graph, fixture.Token(subject), token)
                : fixture.Send(client, graph, Q(limit: 1), fixture.Token(subject), cancellationToken: token);
            int QueryCount() => lookup ? fixture.Source.LookupQueries : fixture.Source.ResourceQueries;
            int Results() => lookup ? fixture.Probe.ReaderResults : fixture.Probe.ResourceReaderResults;
            int Handlers() => lookup ? fixture.Probe.HandlerFactories : fixture.Probe.ResourceHandlerFactories;
            CancellationToken DispatchToken() => lookup ? fixture.Probe.LastDispatchToken : fixture.Probe.LastResourceDispatchToken;
            CancellationToken WorkToken() => lookup ? fixture.Probe.LastWorkToken : fixture.Probe.LastResourceWorkToken;

            var lockObserved = false;
            var quiescentUnderLock = false;
            int? status = null;
            string? code = null;
            if (scenario == "cross-tenant")
            {
                var reply = await Send("resource-b");
                Require(reply.Error(graph, "access.denied") && QueryCount() == 0 && Handlers() == 0);
                status = (int)reply.Status;
                code = "access.denied";
            }
            else if (scenario == "provider-timeout")
            {
                static Task ForeignTimeout(CancellationToken _) => throw new TimeoutException("private provider connection detail");
                if (lookup) fixture.Probe.AfterProviderRead = ForeignTimeout;
                else fixture.Probe.AfterResourceProviderRead = ForeignTimeout;
                var reply = await Send("both-reader");
                Require(reply.Error(graph, "internal.error") && !reply.Body.Contains("private provider", StringComparison.Ordinal));
                Require(reply.Status == (graph ? HttpStatusCode.OK : HttpStatusCode.InternalServerError) &&
                    QueryCount() == 1 && !WorkToken().IsCancellationRequested);
                status = (int)reply.Status;
                code = "internal.error";
                fixture.Probe.AfterProviderRead = null;
                fixture.Probe.AfterResourceProviderRead = null;
            }
            else
            {
                await using var blocker = await sql.Hold();
                var pending = Send("both-reader", caller.Token);
                try
                {
                    var pid = await sql.Observe(fixture.Probe, pending, caller.Token, lookup).WaitAsync(Watchdog);
                    lockObserved = true;
                    TenantChangeAuditReadStatisticsSnapshot? initial = collectStatistics ? default(TenantChangeAuditReadStatisticsSnapshot) : null;
                    Require(host.ReadStatistics == initial);
                    if (scenario == "caller-abort")
                    {
                        caller.Cancel();
                        Require(await Failure(() => pending).WaitAsync(Watchdog) is OperationCanceledException);
                        await Wait(() => DispatchToken().IsCancellationRequested).WaitAsync(Watchdog);
                    }
                    else
                    {
                        var reply = await pending.WaitAsync(Watchdog);
                        var expected = scenario == "typed-timeout" ? TransportErrors.AuditReadTimeoutCode : "internal.error";
                        var expectedStatus = graph ? HttpStatusCode.OK : scenario == "typed-timeout"
                            ? HttpStatusCode.GatewayTimeout : HttpStatusCode.InternalServerError;
                        Require(reply.Status == expectedStatus && reply.Error(graph, expected) &&
                            !reply.Body.Contains(fixture.Store.Schema, StringComparison.Ordinal) &&
                            !DispatchToken().IsCancellationRequested && !caller.IsCancellationRequested);
                        if (scenario == "typed-timeout")
                        {
                            Require(reply.Body.Contains(TransportErrors.AuditReadTimeout().Message, StringComparison.Ordinal));
                            if (!graph)
                            {
                                var path = lookup ? AuditReceiptTransportHost.LookupPath : AuditReceiptTransportHost.ResourceHistoryPath;
                                Require(ContractShape(ContractResponseSchema(timeoutSchema, path, "504"), reply.Root));
                            }
                        }
                        status = (int)reply.Status;
                        code = expected;
                    }
                    await Wait(() => WorkToken().IsCancellationRequested && fixture.Probe.ActiveDispatches == 0).WaitAsync(Watchdog);
                    await sql.Quiescent(pid);
                    quiescentUnderLock = true;
                }
                finally
                {
                    caller.Cancel();
                    await blocker.DisposeAsync();
                    await Join(pending);
                }
            }

            Require(Results() == 0 && fixture.Probe.ActiveDispatches == 0);
            TenantChangeAuditReadStatisticsSnapshot failed = scenario switch
            {
                "typed-timeout" or "legacy-timeout" => new(0, 1, 0, 0),
                "provider-timeout" => new(0, 0, 0, 1),
                "caller-abort" => new(0, 0, 1, 0),
                _ => default
            };
            var failureSnapshot = host.ReadStatistics;
            TenantChangeAuditReadStatisticsSnapshot? expectedFailure = collectStatistics ? failed : null;
            Require(failureSnapshot == expectedFailure);
            var queries = QueryCount();
            Require((await Send("both-reader")).Success(graph) && QueryCount() == queries + 1 && Results() == 1);
            TenantChangeAuditReadStatisticsSnapshot? expectedReuse = collectStatistics ? failed with { Succeeded = 1 } : null;
            Require(host.ReadStatistics == expectedReuse);
            WriteMeasurement(new { kind = "wire_timeout_control", transport = graph ? "graphql" : "http",
                operation = lookup ? "receipt" : "resource", scenario, status, code, source_queries = queries,
                lock_observed = lockObserved, quiescent_under_lock = quiescentUnderLock,
                no_failed_result_published = true, successful_reuse = true });
            if (collectStatistics)
                WriteMeasurement(new { kind = "read_statistics_control", transport = graph ? "graphql" : "http",
                    operation = lookup ? "receipt" : "resource", scenario, failure_snapshot = failureSnapshot, snapshot_after_reuse = host.ReadStatistics });
        }

        if (collectStatistics)
        {
            await using var inactive = await AuditReceiptTransportHost.ActivateAsync(optedIn with { HttpEnabled = false, GraphQLEnabled = false });
            Require(inactive.App is null && inactive.ReadStatistics is null);
            var fixture = create();
            await using var mixed = await fixture.Start(optedIn, policy);
            using var client = fixture.Client(mixed);
            var result = await fixture.Siblings(client, fixture.Token("both-reader"), mixed: true);
            Require(result.Success(true) && fixture.Source.ResourceQueries == 1 && fixture.Source.LookupQueries == 1);
            Require(mixed.ReadStatistics == new TenantChangeAuditReadStatisticsSnapshot(2, 0, 0, 0));
            WriteMeasurement(new { kind = "read_statistics_shared", inactive_has_no_collector = true, snapshot = mixed.ReadStatistics });
        }
    }
}
