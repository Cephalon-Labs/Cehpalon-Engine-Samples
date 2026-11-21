extern alias securityapi;
using System.Net;
using System.Text.Json;
using Cehpalon.Engine.Tenancy;
using securityapi::SecurityApi;

namespace AuditOutbox;

public static partial class ResourceTransportChecks
{
    // These are deliberate post-SQL completion holds. They prove server/slot ownership,
    // not that a database query remains active after its response has arrived.
    private sealed class AdmissionHold(int maximumHeld)
    {
        private readonly TaskCompletionSource release = Signal();
        private readonly TaskCompletionSource cancelled = Signal();
        private int calls, held;
        public int Held => Volatile.Read(ref held);
        public Task Cancelled => cancelled.Task;
        public void Release() => release.TrySetResult();
        public async Task After(CancellationToken token)
        {
            if (Interlocked.Increment(ref calls) > maximumHeld) return;
            Interlocked.Increment(ref held);
            using var registration = token.Register(() => cancelled.TrySetResult());
            await release.Task.ConfigureAwait(false);
        }
        public Task Entered(int count) => Wait(() => Held == count).WaitAsync(Watchdog);
    }

    private static TenantOperationConcurrencySnapshot AdmissionSnapshot(AuditReceiptTransportHost host)
        => host.ConcurrencySnapshot ?? throw new InvalidOperationException("Expected selected audit-read capacity.");

    private static void AdmissionCounts(AuditReceiptTransportHost host, int operations, int tenants, bool closed = false)
    {
        var value = AdmissionSnapshot(host);
        Require(value.Total.ActiveOperations == operations && value.ActiveTenants == tenants && value.Total.IsAdmissionClosed == closed);
    }

    private static void Capacity(Reply reply, bool graph)
    {
        Require(reply.Error(graph, "operation.capacity_exceeded"));
        Require(reply.Status == (graph ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable));
        Require(!reply.Body.Contains("shared", StringComparison.Ordinal));
    }

    private static AuditReceiptTransportOptions AdmissionOptions(bool graph, int total = 1, int perTenant = 1,
        bool bothTransports = false, TimeSpan? timeout = null)
        => new(bothTransports || !graph, bothTransports || graph, true, timeout)
        {
            ReceiptLookupEnabled = true, ResourceHistoryEnabled = true,
            ConcurrencyLimits = new(total, perTenant)
        };

    public static async Task RunAdmission(Func<string, Func<Task>, Task> check,
        Func<Task<PostgresStore>> createStore, string connection, string connectionFile, Action<object> observe)
    {
        using var tls = new TlsFixture();
        using var jwt = new JwtFixture();
        using var wrongJwt = new JwtFixture();
        async Task<Fixture> Create()
        {
            var store = await createStore();
            await using (var provision = await IndexedProfileComposition.ActivateAsync(
                IndexedProfileComposition.Configuration(true), store.Schema, IndexedProfileOpenMode.CreateNew,
                _ => ValueTask.FromResult(connection), new()))
            {
                var writer = provision.Storage ?? throw new InvalidOperationException("Missing admission fixture writer.");
                await writer.AppendOnceAsync(Record(Key(1)), default);
                await writer.AppendOnceAsync(Record(Key(1), "B"), default);
            }
            return new(store, connection, connectionFile, tls, jwt);
        }

        await check("audit admission preserves positional ABI and inert invalid unused limits", async () =>
        {
            var original = new AuditReceiptTransportOptions(true, false, true, null);
            var (http, graph, security, timeout) = original;
            Require(http && !graph && security && timeout is null && original.ConcurrencyLimits is null);
            foreach (var options in new[] {
                new AuditReceiptTransportOptions(false, false, false, TimeSpan.FromTicks(-1)) {
                    ResourceHistoryEnabled = true, ConcurrencyLimits = new(0, -1) },
                new AuditReceiptTransportOptions(true, true, false, TimeSpan.FromTicks(-1)) {
                    ReceiptLookupEnabled = false, ResourceHistoryEnabled = false, ConcurrencyLimits = new(0, -1) } })
            {
                var callbacks = 0; var probe = new AuditReceiptTransportProbe();
                await using var host = await AuditReceiptTransportHost.ActivateAsync(options,
                    _ => { callbacks++; throw new InvalidOperationException(); },
                    () => { callbacks++; throw new InvalidOperationException(); },
                    _ => { callbacks++; throw new InvalidOperationException(); }, probe);
                Require(callbacks == 0 && probe.BudgetFactories == 0 && host.ConcurrencySnapshot is null &&
                    host.App is null && host.Source is null && host.Plan.ActivationOrder.Count == 0 &&
                    probe.HostFactories == 0 && probe.SourceFactories == 0 && probe.SecurityFactories == 0 &&
                    probe.HttpEndpoints == 0 && probe.GraphQLEndpoints == 0);
            }
            observe(new { phase = "audit_admission_compatibility", positional_abi_preserved = true,
                default_null = true, inert_callbacks_and_budget_factories = 0 });
        });

        await check("audit admission rejects selected invalid limits before caller factories", async () =>
        {
            foreach (var limits in new AuditReadConcurrencyLimits[] { new(0, 1), new(1, 0), new(1, 2), new(-1, 1) })
            {
                var callbacks = 0; var probe = new AuditReceiptTransportProbe();
                var error = await Failure(() => AuditReceiptTransportHost.ActivateAsync(
                    AdmissionOptions(false) with { ConcurrencyLimits = limits },
                    _ => { callbacks++; throw new InvalidOperationException(); },
                    () => { callbacks++; throw new InvalidOperationException(); },
                    _ => { callbacks++; throw new InvalidOperationException(); }, probe).AsTask()).WaitAsync(Watchdog);
                Require(error is ArgumentOutOfRangeException && callbacks == 0 && probe.HostFactories == 0 &&
                    probe.SourceFactories == 0 && probe.SecurityFactories == 0);
            }
            observe(new { phase = "audit_admission_invalid_limits", invalid_profiles = 4,
                caller_factories = 0, source_and_credential_work = 0 });
        });

        await check("audit admission selected hosts own independent aggregate budgets", async () =>
        {
            var first = await Create(); var second = await Create();
            var firstHold = new AdmissionHold(1); var secondHold = new AdmissionHold(1);
            first.Probe.AfterResourceProviderRead = firstHold.After;
            second.Probe.AfterResourceProviderRead = secondHold.After;
            await using var firstHost = await first.Start(AdmissionOptions(false));
            await using var secondHost = await second.Start(AdmissionOptions(true));
            using var firstClient = first.Client(firstHost); using var secondClient = second.Client(secondHost);
            using var callers = new CancellationTokenSource();
            var a = first.Send(firstClient, false, token: first.Token(), cancellationToken: callers.Token);
            var b = second.Send(secondClient, true, token: second.Token(), cancellationToken: callers.Token);
            try
            {
                await Task.WhenAll(firstHold.Entered(1), secondHold.Entered(1));
                AdmissionCounts(firstHost, 1, 1); AdmissionCounts(secondHost, 1, 1);
                Require(first.Probe.BudgetFactories == 1 && second.Probe.BudgetFactories == 1);
                Capacity(await first.Send(firstClient, false, token: first.Token()), false);
                Capacity(await second.Send(secondClient, true, token: second.Token()), true);
                var aggregate = JsonSerializer.Serialize(AdmissionSnapshot(firstHost));
                Require(!aggregate.Contains("resource-a", StringComparison.Ordinal) && !aggregate.Contains("shared", StringComparison.Ordinal));
                firstHold.Release(); secondHold.Release();
                Require((await a.WaitAsync(Watchdog)).Success(false) && (await b.WaitAsync(Watchdog)).Success(true));
                AdmissionCounts(firstHost, 0, 0); AdmissionCounts(secondHost, 0, 0);
            }
            finally { callers.Cancel(); firstHold.Release(); secondHold.Release(); await Join(Task.WhenAll(a, b)); }
            observe(new { phase = "audit_admission_independent_hosts", selected_host_budget_factories = 2,
                positive_same_tenant_overlap_across_hosts = true, aggregate_counts_only = true });
        });

        await check("audit admission stop fault joins mixed empty and populated reads before source disposal", async () =>
        {
            var f = await Create(); var resourceHold = new AdmissionHold(1); var receiptHold = new AdmissionHold(1);
            f.Probe.AfterResourceProviderRead = resourceHold.After; f.Probe.AfterProviderRead = receiptHold.After;
            var stopFault = new IOException("Owned admission stop control.");
            f.Probe.StopApplicationAsync = _ => throw stopFault;
            var host = await f.Start(AdmissionOptions(false, 2, 2, bothTransports: true));
            using var client = f.Client(host); using var callers = new CancellationTokenSource();
            var resource = f.Send(client, false, Q(id: "absent"), f.Token("both-reader"), cancellationToken: callers.Token);
            var receipt = f.Receipt(client, true, f.Token("both-reader"), callers.Token);
            Task? disposal = null;
            try
            {
                await Task.WhenAll(resourceHold.Entered(1), receiptHold.Entered(1));
                AdmissionCounts(host, 2, 1);
                disposal = host.DisposeAsync().AsTask();
                await f.Probe.AdmissionClosed.Task.WaitAsync(Watchdog);
                AdmissionCounts(host, 2, 1, true);
                Require(!disposal.IsCompleted && f.Probe.SourceDisposals == 0 && !f.Source.IsDisposed);
                resourceHold.Release();
                var empty = await resource.WaitAsync(Watchdog);
                Require(empty.Success(false) && Keys(empty, false).Length == 0);
                await Wait(() => AdmissionSnapshot(host).Total.ActiveOperations == 1).WaitAsync(Watchdog);
                Require(!disposal.IsCompleted && f.Probe.SourceDisposals == 0);
                receiptHold.Release();
                var populated = await receipt.WaitAsync(Watchdog);
                Require(populated.Success(true) && populated.Root.GetProperty("data").GetProperty("trailReceipt").GetProperty("record").ValueKind == JsonValueKind.Object);
                var error = await Failure(() => disposal!).WaitAsync(Watchdog);
                Require(Has(error, stopFault)); AdmissionCounts(host, 0, 0, true);
                Require(f.Probe.SourceDisposals == 1 && f.Source.IsDisposed && f.Source.DataSourceDisposals == 1 &&
                    f.Probe.ActiveDispatches == 0 && f.Probe.DrainCompleted.Task.IsCompleted);
            }
            finally
            {
                callers.Cancel(); resourceHold.Release(); receiptHold.Release();
                await Join(Task.WhenAll(resource, receipt));
                disposal ??= host.DisposeAsync().AsTask(); await Join(disposal);
            }
            observe(new { phase = "audit_admission_mixed_shutdown", empty_resource_and_populated_receipt = true,
                stop_fault_preserved = true, both_admissions_closed_permanently = true,
                all_server_work_joined_before_single_source_disposal = true });
        });

        foreach (var graph in new[] { false, true })
        {
            var label = graph ? "GraphQL" : "HTTP";
            await check(label + " null audit budget preserves overlapping scheduled default reads", async () =>
            {
                var f = await Create(); var hold = new AdmissionHold(2); f.Probe.AfterResourceProviderRead = hold.After;
                await using var host = await f.Start(Options(graph)); using var client = f.Client(host);
                using var callers = new CancellationTokenSource(); var start = Signal();
                var tasks = Enumerable.Range(0, 2).Select(_ => Task.Run(async () =>
                { await start.Task; return await f.Send(client, graph, token: f.Token(), cancellationToken: callers.Token); })).ToArray();
                var all = Task.WhenAll(tasks); start.TrySetResult();
                try
                {
                    await hold.Entered(2); Require(host.ConcurrencySnapshot is null && f.Probe.BudgetFactories == 0 && f.Source.ResourceQueries == 2);
                    hold.Release(); Require((await all.WaitAsync(Watchdog)).All(x => x.Success(graph)));
                }
                finally { callers.Cancel(); start.TrySetResult(); hold.Release(); await Join(all); }
                observe(new { phase = "audit_admission_null_overlap", transport = label, scheduled_overlapping_reads = 2,
                    budget_factories = 0, unchanged_unlimited_path = true });
            });

            await check(label + " saturated tenant A rejects its reads while same-ID tenant B succeeds", async () =>
            {
                var f = await Create(); var hold = new AdmissionHold(1); f.Probe.AfterResourceProviderRead = hold.After;
                await using var host = await f.Start(AdmissionOptions(graph, 2, 1)); using var client = f.Client(host);
                using var callers = new CancellationTokenSource();
                var a = f.Send(client, graph, token: f.Token("resource-both"), cancellationToken: callers.Token);
                try
                {
                    await hold.Entered(1); AdmissionCounts(host, 1, 1);
                    var queries = f.Source.ResourceQueries; var handlers = f.Probe.ResourceHandlerFactories;
                    Capacity(await f.Send(client, graph, token: f.Token("resource-both")), graph);
                    Capacity(await f.Receipt(client, graph, f.Token("both-reader")), graph);
                    Require(f.Source.ResourceQueries == queries && f.Probe.ResourceHandlerFactories == handlers && f.Probe.HandlerFactories == 0 && f.Source.LookupQueries == 0);
                    var b = await f.Send(client, graph, Q(tenant: "B"), f.Token("resource-both"));
                    Require(b.Success(graph) && Keys(b, graph).Single() == Key(1) && b.Value(graph).GetProperty("entries")[0].GetProperty("tenant").GetString() == "B");
                    AdmissionCounts(host, 1, 1); hold.Release();
                    var pageA = await a.WaitAsync(Watchdog);
                    Require(pageA.Success(graph) && Keys(pageA, graph).Single() == Key(1) && pageA.Value(graph).GetProperty("entries")[0].GetProperty("tenant").GetString() == "A");
                    AdmissionCounts(host, 0, 0);
                }
                finally { callers.Cancel(); hold.Release(); await Join(a); }
                observe(new { phase = "audit_admission_tenant_isolation", transport = label, total = 2, per_tenant = 1,
                    same_principal_switches_A_B = true, identical_receipt_resource_IDs_isolated = true,
                    A_capacity_denial_has_no_handler_or_source = true, B_admitted_below_total = true });
            });

            await check(label + " A plus B total saturation rejects authorized work before handler source", async () =>
            {
                var f = await Create(); var hold = new AdmissionHold(2); f.Probe.AfterResourceProviderRead = hold.After;
                await using var host = await f.Start(AdmissionOptions(graph, 2, 2)); using var client = f.Client(host);
                using var callers = new CancellationTokenSource();
                var a = f.Send(client, graph, token: f.Token("resource-both"), cancellationToken: callers.Token);
                var b = f.Send(client, graph, Q(tenant: "B"), f.Token("resource-both"), cancellationToken: callers.Token);
                try
                {
                    await hold.Entered(2); AdmissionCounts(host, 2, 2);
                    var queries = f.Source.ResourceQueries; var handlers = f.Probe.ResourceHandlerFactories;
                    Capacity(await f.Send(client, graph, token: f.Token("resource-both")), graph);
                    Capacity(await f.Receipt(client, graph, f.Token("both-reader")), graph);
                    Require(f.Source.ResourceQueries == queries && f.Probe.ResourceHandlerFactories == handlers && f.Source.LookupQueries == 0 && f.Probe.HandlerFactories == 0);
                    hold.Release(); Require((await Task.WhenAll(a, b).WaitAsync(Watchdog)).All(x => x.Success(graph)));
                    AdmissionCounts(host, 0, 0);
                }
                finally { callers.Cancel(); hold.Release(); await Join(Task.WhenAll(a, b)); }
                observe(new { phase = "audit_admission_total_capacity", transport = label, total = 2, per_tenant = 2,
                    positive_A_B_overlap = true, rejected_handler_and_query_delta = 0 });
            });

            await check(label + " authentication and fresh tenant authority precede saturated capacity", async () =>
            {
                var f = await Create(); var hold = new AdmissionHold(1); f.Probe.AfterResourceProviderRead = hold.After;
                await using var host = await f.Start(AdmissionOptions(graph)); using var client = f.Client(host);
                using var callers = new CancellationTokenSource();
                var pending = f.Send(client, graph, token: f.Token(), cancellationToken: callers.Token);
                try
                {
                    await hold.Entered(1); var queries = f.Source.ResourceQueries; var handlers = f.Probe.ResourceHandlerFactories;
                    var invalid = await f.Send(client, graph, token: wrongJwt.Token("resource-a"));
                    Require(!invalid.Success(graph) && !invalid.Error(graph, "operation.capacity_exceeded"));
                    Require((await f.Send(client, graph, Q(tenant: "B"), f.Token())).Error(graph, "access.denied"));
                    foreach (var subject in new[] { "no-role", "wrong-attribute", "receipt-only", "history-only", "entity-only" })
                        Require((await f.Send(client, graph, token: f.Token(subject))).Error(graph, "access.denied"));
                    f.Authority.MembershipRevoked = true;
                    Require((await f.Send(client, graph, token: f.Token())).Error(graph, "access.denied"));
                    f.Authority.MembershipRevoked = false;
                    Require(f.Source.ResourceQueries == queries && f.Probe.ResourceHandlerFactories == handlers);
                    AdmissionCounts(host, 1, 1); hold.Release(); Require((await pending.WaitAsync(Watchdog)).Success(graph));
                    AdmissionCounts(host, 0, 0);
                }
                finally { f.Authority.MembershipRevoked = false; callers.Cancel(); hold.Release(); await Join(pending); }
                observe(new { phase = "audit_admission_authority_before_capacity", transport = label,
                    invalid_signature_and_forged_tenant_denied = true, separate_operation_grant_required = true,
                    revoked_membership_denied_during_saturation = true, denied_slot_query_handler_delta = 0 });
            });

            await check(label + " provider and corruption faults release audit capacity with redacted errors", async () =>
            {
                var f = await Create(); await using var host = await f.Start(AdmissionOptions(graph)); using var client = f.Client(host);
                f.Probe.AfterResourceProviderRead = _ => throw new IOException("PRIVATE-ADMISSION-PROVIDER " + f.Store.Schema);
                var failure = await f.Send(client, graph, token: f.Token());
                Require(failure.Error(graph, "internal.error") && !failure.Body.Contains("PRIVATE-ADMISSION-PROVIDER", StringComparison.Ordinal) && !failure.Body.Contains(f.Store.Schema, StringComparison.Ordinal));
                AdmissionCounts(host, 0, 0); f.Probe.AfterResourceProviderRead = null;
                await f.Sql().Payload(Key(1), Record(Key(1), "B"));
                try
                {
                    var corrupt = await f.Send(client, graph, token: f.Token());
                    Require(corrupt.Error(graph, "internal.error") && !corrupt.Body.Contains(f.Store.Schema, StringComparison.Ordinal));
                    AdmissionCounts(host, 0, 0);
                }
                finally { await f.Sql().Payload(Key(1), Record(Key(1))); }
                var valid = await f.Send(client, graph, token: f.Token());
                Require(valid.Success(graph) && Keys(valid, graph).Single() == Key(1)); AdmissionCounts(host, 0, 0);
                observe(new { phase = "audit_admission_fault_release", transport = label,
                    provider_and_wrong_tenant_payload_errors_redacted = true, capacity_released_after_faults = true,
                    repaired_authorized_replacement_succeeds = true });
            });

            await check(label + " client abort retains admitted slot until held post-SQL server completion", async () =>
            {
                var f = await Create(); var hold = new AdmissionHold(1); f.Probe.AfterResourceProviderRead = hold.After;
                await using var host = await f.Start(AdmissionOptions(graph)); using var client = f.Client(host);
                using var caller = new CancellationTokenSource();
                var pending = f.Send(client, graph, token: f.Token(), cancellationToken: caller.Token);
                try
                {
                    await hold.Entered(1); caller.Cancel();
                    Require(await Failure(() => pending).WaitAsync(Watchdog) is OperationCanceledException);
                    await hold.Cancelled.WaitAsync(Watchdog); AdmissionCounts(host, 1, 1);
                    Require(f.Probe.ActiveDispatches == 1 && f.Probe.ResourceReaderResults == 0);
                    Capacity(await f.Send(client, graph, token: f.Token()), graph);
                    Require(f.Source.ResourceQueries == 1 && f.Probe.ResourceHandlerFactories == 1);
                    hold.Release(); await Wait(() => f.Probe.ActiveDispatches == 0).WaitAsync(Watchdog);
                    AdmissionCounts(host, 0, 0);
                    Require((await f.Send(client, graph, token: f.Token())).Success(graph)); AdmissionCounts(host, 0, 0);
                    await f.Sql().AppQuiescent();
                }
                finally { caller.Cancel(); hold.Release(); await Join(pending); }
                observe(new { phase = "audit_admission_client_abort_ownership", transport = label,
                    client_completed_before_held_server = true, post_SQL_hold_not_active_SQL_claim = true,
                    cancelled_work_retains_slot_until_join = true, replacement_after_join_succeeds = true });
            });

            await check(label + " cooperative read timeout retains slot until held completion is released", async () =>
            {
                var f = await Create(); var hold = new AdmissionHold(1); f.Probe.AfterResourceProviderRead = hold.After;
                await using var host = await f.Start(AdmissionOptions(graph, timeout: Budget)); using var client = f.Client(host);
                using var caller = new CancellationTokenSource();
                var pending = f.Send(client, graph, token: f.Token(), cancellationToken: caller.Token);
                try
                {
                    await hold.Entered(1); await hold.Cancelled.WaitAsync(Watchdog);
                    Require(f.Probe.LastResourceWorkToken.IsCancellationRequested && !pending.IsCompleted);
                    AdmissionCounts(host, 1, 1); Capacity(await f.Send(client, graph, token: f.Token()), graph);
                    Require(f.Source.ResourceQueries == 1 && f.Probe.ResourceHandlerFactories == 1);
                    hold.Release(); Require(!(await pending.WaitAsync(Watchdog)).Success(graph));
                    AdmissionCounts(host, 0, 0);
                    Require((await f.Send(client, graph, token: f.Token())).Success(graph)); AdmissionCounts(host, 0, 0);
                    await f.Sql().AppQuiescent();
                }
                finally { caller.Cancel(); hold.Release(); await Join(pending); }
                observe(new { phase = "audit_admission_private_budget_ownership", transport = label,
                    cooperative_reader_timeout = true, work_token_cancelled_while_post_SQL_server_held = true,
                    no_early_slot_release = true, replacement_after_join_succeeds = true });
            });

            await check(label + " receipt resource cross-protocol calls and GraphQL fields share audit budget", async () =>
            {
                var f = await Create(); var hold = new AdmissionHold(1); f.Probe.AfterResourceProviderRead = hold.After;
                await using var host = await f.Start(AdmissionOptions(graph, bothTransports: true)); using var client = f.Client(host);
                using var caller = new CancellationTokenSource();
                var pending = f.Send(client, graph, token: f.Token("resource-both"), cancellationToken: caller.Token);
                try
                {
                    await hold.Entered(1); Capacity(await f.Receipt(client, !graph, f.Token("both-reader")), !graph);
                    var memberships = f.Authority.MembershipCalls;
                    var siblings = await f.Siblings(client, f.Token("resource-both"));
                    Require(siblings.Root.GetProperty("errors").GetArrayLength() == 2 &&
                        siblings.Root.GetProperty("errors").EnumerateArray().All(x => x.GetProperty("extensions").GetProperty("code").GetString() == "operation.capacity_exceeded") &&
                        f.Authority.MembershipCalls == memberships + 2 && f.Source.ResourceQueries == 1 &&
                        f.Probe.ResourceHandlerFactories == 1 && f.Source.LookupQueries == 0 && f.Probe.HandlerFactories == 0);
                    AdmissionCounts(host, 1, 1); hold.Release(); Require((await pending.WaitAsync(Watchdog)).Success(graph));
                    Require((await f.Receipt(client, !graph, f.Token("both-reader"))).Success(!graph));
                    Require(f.Probe.BudgetFactories == 1); AdmissionCounts(host, 0, 0);
                }
                finally { caller.Cancel(); hold.Release(); await Join(pending); }
                observe(new { phase = "audit_admission_shared_transports", transport = label, one_host_budget = true,
                    cross_protocol_receipt_resource_capacity_shared = true, two_aliases_check_fresh_membership = true,
                    rejected_handler_query_delta = 0 });
            });

            await check(label + " eight synchronized A B workers obey atomic total and tenant limits", async () =>
            {
                var f = await Create(); var hold = new AdmissionHold(2); f.Probe.AfterResourceProviderRead = hold.After;
                await using var host = await f.Start(AdmissionOptions(graph, 2, 1)); using var client = f.Client(host);
                using var callers = new CancellationTokenSource(); var start = Signal();
                var tasks = Enumerable.Range(0, 8).Select(i => Task.Run(async () =>
                {
                    await start.Task;
                    return await f.Send(client, graph, Q(tenant: i % 2 == 0 ? "A" : "B"), f.Token("resource-both"), cancellationToken: callers.Token);
                })).ToArray();
                var all = Task.WhenAll(tasks); start.TrySetResult();
                try
                {
                    await hold.Entered(2); await Wait(() => tasks.Count(t => t.IsCompleted) == 6).WaitAsync(Watchdog);
                    AdmissionCounts(host, 2, 2); Require(f.Source.ResourceQueries == 2 && f.Probe.ResourceHandlerFactories == 2);
                    foreach (var done in tasks.Where(t => t.IsCompleted)) Capacity(await done, graph);
                    hold.Release(); var results = await all.WaitAsync(Watchdog);
                    Require(results.Count(r => r.Success(graph)) == 2 && results.Count(r => r.Error(graph, "operation.capacity_exceeded")) == 6);
                    var successfulTenants = results.Where(r => r.Success(graph)).Select(r => r.Value(graph).GetProperty("entries")[0].GetProperty("tenant").GetString()).Order().ToArray();
                    Require(successfulTenants.SequenceEqual(new[] { "A", "B" })); AdmissionCounts(host, 0, 0);
                }
                finally { callers.Cancel(); start.TrySetResult(); hold.Release(); await Join(all); }
                observe(new { phase = "audit_admission_scheduled_workers", transport = label, scheduled_workers = 8,
                    held_before_release = 2, capacity_responses_before_release = 6, total_limit = 2, per_tenant_limit = 1,
                    one_success_for_each_tenant = true, unconditional_aggregate_join = true });
            });

            await check(label + " fresh revocation during saturation and after release preserves isolation", async () =>
            {
                var f = await Create(); var hold = new AdmissionHold(1); f.Probe.AfterResourceProviderRead = hold.After;
                await using var host = await f.Start(AdmissionOptions(graph)); using var client = f.Client(host);
                using var caller = new CancellationTokenSource();
                var pending = f.Send(client, graph, token: f.Token("resource-both"), cancellationToken: caller.Token);
                async Task Denials()
                {
                    var queries = f.Source.ResourceQueries; var handlers = f.Probe.ResourceHandlerFactories;
                    f.Authority.MembershipRevoked = true;
                    Require((await f.Send(client, graph, token: f.Token("resource-both"))).Error(graph, "access.denied"));
                    f.Authority.MembershipRevoked = false; f.Authority.ResourceRevoked = true;
                    Require((await f.Send(client, graph, token: f.Token("resource-both"))).Error(graph, "access.denied"));
                    f.Authority.ResourceRevoked = false; f.Authority.PolicyRevoked = true;
                    Require((await f.Send(client, graph, token: f.Token("resource-both"))).Error(graph, "access.denied"));
                    f.Authority.PolicyRevoked = false;
                    Require(f.Source.ResourceQueries == queries && f.Probe.ResourceHandlerFactories == handlers);
                }
                try
                {
                    await hold.Entered(1); await Denials(); AdmissionCounts(host, 1, 1);
                    hold.Release(); Require((await pending.WaitAsync(Watchdog)).Success(graph));
                    AdmissionCounts(host, 0, 0); await Denials(); AdmissionCounts(host, 0, 0);
                    var b = await f.Send(client, graph, Q(tenant: "B"), f.Token("resource-both"));
                    Require(b.Success(graph) && b.Value(graph).GetProperty("entries")[0].GetProperty("tenant").GetString() == "B");
                    Require((await f.Send(client, graph, Q(tenant: "B"), f.Token())).Error(graph, "access.denied"));
                    AdmissionCounts(host, 0, 0);
                }
                finally
                {
                    f.Authority.MembershipRevoked = false; f.Authority.ResourceRevoked = false; f.Authority.PolicyRevoked = false;
                    caller.Cancel(); hold.Release(); await Join(pending);
                }
                observe(new { phase = "audit_admission_fresh_revocation", transport = label,
                    membership_resource_policy_checked_at_capacity_and_after_release = true,
                    fresh_authorized_B_succeeds = true, A_identity_cannot_forge_B = true, denied_slot_query_handler_delta = 0 });
            });
        }
    }
}
