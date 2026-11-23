using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using Cehpalon.Engine.Core;
using PortableConsumers.Generated;

internal static partial class DispatchCorrelationProbe
{
    internal static async ValueTask DisposeOwnedHandler(CatalogStore store, Action dispose)
    {
        var capture = current.Value;
        var gate = capture?.Cleanup;
        if (gate is not null)
        {
            Require(ReferenceEquals(gate.Store, store) && gate.Entered.TrySetResult(),
                "Unexpected owning store or duplicate owned cleanup.");
            await gate.Release.Task.WaitAsync(Deadline);
        }

        dispose();
        if (gate is not null)
        {
            gate.Completed = true;
            if (gate.Fault)
                throw new InvalidOperationException(capture!.CleanupFaultSentinel);
        }
    }

    private static async Task<int> RunDrainProof(string report)
    {
        using var tls = new TlsFixture();
        using var jwt = new JwtFixture();
        var lanes = new List<DrainLane>();
        foreach (bool tenantLimited in new[] { false, true })
            lanes.Add(await DrainAndRestart(tls, jwt, tenantLimited));

        var cases = lanes.SelectMany(lane => lane.Cases).ToArray();
        Require(cases.Length == 18 && cases.Sum(row => row.Records) == 14 &&
            cases.Sum(row => row.Histograms) == 20 && requests.IsEmpty && unscopedSignals == 0,
            "Drain wire, completion, histogram, or request-scope totals differed.");
        using var output = new FileStream(report, FileMode.CreateNew, FileAccess.Write);
        JsonSerializer.Serialize(output, new
        {
            outcome = "passed", runtime = RuntimeInformation.FrameworkDescription, os = RuntimeInformation.OSDescription,
            lanes, wireCases = cases.Length, completions = cases.Sum(row => row.Records),
            histograms = cases.Sum(row => row.Histograms), unscopedSignals
        }, new JsonSerializerOptions { WriteIndented = true });
        return 0;
    }

    private static async Task<DrainLane> DrainAndRestart(TlsFixture tls, JwtFixture jwt, bool tenantLimited)
    {
        const int limit = 2;
        var cases = new List<CaseReceipt>();
        var configuration = FixtureHost.Config(api: true, graphql: true);
        var tenantLimit = tenantLimited ? limit : (int?)null;
        await using var host = new FixtureHost();
        await host.Start(configuration, tls, jwt, limit, tenantLimit);
        var address = host.Address;
        using var client = tls.Client(address);
        var store = host.Store;
        var gate = new CleanupGate(store, fault: tenantLimited);
        var writeRelease = CatalogStore.NewSignal();
        store.WriteRelease = writeRelease;
        store.DelayWrites = true;
        var held = new RequestCapture(!tenantLimited, "admitted-during-close", true, "valid",
            gate.Fault ? ResponseKind.CleanupFault : ResponseKind.Owner, 1, "Bearer " + jwt.Token()) { Cleanup = gate };
        var pending = Send(client, held);
        Task? drain = null, stopping = null;
        OperationConcurrencySnapshot open, closed, atCleanup;
        try
        {
            await store.WriteEntered.Task.WaitAsync(Deadline);
            open = Snapshot(host, 1, false, tenantLimited);

            drain = host.CloseAdmissionForProof();
            closed = Snapshot(host, 1, true, tenantLimited);
            Require(!drain.IsCompleted && !pending.IsCompleted && store is { Factories: 1, Writes: 0, Disposals: 0 },
                "Admission close did not leave the entered write pending.");
            await CancelOneWaiter(host);
            Require(!drain.IsCompleted && !pending.IsCompleted, "Cancelling one waiter released admitted work.");
            Snapshot(host, 1, true, tenantLimited);

            foreach (bool graphQl in new[] { false, true })
            {
                cases.Add(await Send(client, Capture(graphQl, "authorized-after-close", ResponseKind.Overloaded)));
                cases.Add(await Send(client, Capture(graphQl, "authenticated-denial-after-close", ResponseKind.TenantDenied)));
                cases.Add(await Send(client, Capture(graphQl, "anonymous-after-close", ResponseKind.Anonymous)));
            }
            Require(store is { Factories: 1, Constructors: 1, Reads: 0, Writes: 0, Disposals: 0 } &&
                held.Records.IsEmpty && held.Histograms.IsEmpty && !pending.IsCompleted && !drain.IsCompleted,
                "Rejected calls performed business work or completed the admitted dispatch.");

            writeRelease.TrySetResult();
            await gate.Entered.Task.WaitAsync(Deadline);
            atCleanup = Snapshot(host, 1, true, tenantLimited);
            Require(store is { Writes: 1, Disposals: 0 } && held.Records.IsEmpty && held.Histograms.IsEmpty &&
                !pending.IsCompleted && !drain.IsCompleted, "Admission or observer did not wait through owned cleanup.");
            stopping = host.DisposeAsync().AsTask();
            Require(!stopping.IsCompleted && host.Counters.HostDisposals == 0 &&
                store.Disposals == 0 && held.Records.IsEmpty, "Generated shutdown completed before owned cleanup.");
            gate.Release.TrySetResult();

            cases.Add(await pending.WaitAsync(Deadline));
            await Task.WhenAll(drain, stopping).WaitAsync(Deadline);
        }
        catch
        {
            writeRelease.TrySetResult();
            gate.Release.TrySetResult();
            try
            {
                await Task.WhenAll(pending, drain ?? Task.CompletedTask, stopping ?? Task.CompletedTask).WaitAsync(Deadline);
            }
            catch (Exception)
            {
                // Retain the matrix failure while joining the owned attempts.
            }
            throw;
        }
        await host.DisposeAsync();
        var drained = Snapshot(host, 0, true, tenantLimited);
        Require(gate.Completed && held.CleanupBeforeCompletion &&
            store is { Factories: 1, Writes: 1, Disposals: 1 } &&
            host.Counters is { HostFactories: 1, HostDisposals: 1, ForbiddenFactories: 0 },
            "Terminal completion, owned handler cleanup, or host disposal differed.");
        await RequireClosed(address);

        await using var restarted = new FixtureHost();
        await restarted.Start(configuration, tls, jwt, limit, tenantLimit);
        var restartedAddress = restarted.Address;
        var restartedOpen = Snapshot(restarted, 0, false, tenantLimited);
        using var restartClient = tls.Client(restartedAddress);
        foreach (bool graphQl in new[] { false, true })
        {
            var fresh = Capture(graphQl, "fresh-host-owner", ResponseKind.Owner, checkRevision: true);
            cases.Add(await Send(restartClient, fresh));
            Require(fresh.Native!.TraceId != held.Native!.TraceId && fresh.Native.SpanId != held.Native.SpanId,
                "Restarted request reused the original admitted request's native trace or span.");
        }
        Require(restarted.Store is { Factories: 2, Reads: 2, Writes: 0, Disposals: 2 },
            "Expected fresh catalog state and the two restarted reads.");
        await restarted.DisposeAsync();
        await RequireClosed(restartedAddress);
        Require(restarted.Counters is { HostFactories: 1, HostDisposals: 1, ForbiddenFactories: 0 },
            "Fresh host did not own and dispose its lifetime once.");

        return new(tenantLimited ? "tenant" : "total", gate.Fault ? "fault" : "success",
            open, closed, atCleanup, drained, restartedOpen, cases);

        RequestCapture Capture(bool graphQl, string scenario, ResponseKind kind, bool checkRevision = false) =>
            new(graphQl, scenario, true, "valid", kind, 1, kind == ResponseKind.Anonymous ? "" : "Bearer " + jwt.Token())
                { CheckFreshRevision = checkRevision };

        static OperationConcurrencySnapshot Snapshot(FixtureHost host, int active, bool closed, bool tenantLimited)
        {
            var capacity = new OperationConcurrencySnapshot(limit, active, closed);
            Require(host.CapacitySnapshot == capacity, "Aggregate admission snapshot differed.");
            if (tenantLimited)
            {
                var tenant = host.TenantCapacitySnapshot;
                Require(tenant is not null && tenant.Value.Total == capacity &&
                    tenant.Value.MaximumConcurrentOperationsPerTenant == limit && tenant.Value.ActiveTenants == active,
                    "Aggregate tenant admission snapshot differed.");
            }
            return capacity;
        }
    }

    private static async Task CancelOneWaiter(FixtureHost host)
    {
        using var source = new CancellationTokenSource();
        var wait = host.CloseAdmissionForProof(source.Token);
        Require(!wait.IsCompleted, "A second drain wait completed while the admitted handler was held.");
        source.Cancel();
        try
        {
            await wait.WaitAsync(Deadline);
            throw new InvalidOperationException("The canceled waiter completed successfully.");
        }
        catch (OperationCanceledException error) when (error.CancellationToken == source.Token)
        {
            // Cancellation is scoped to this wait.
        }
    }

    private static async Task RequireClosed(Uri address)
    {
        using var socket = new TcpClient();
        try
        {
            await socket.ConnectAsync(IPAddress.Loopback, address.Port).WaitAsync(Deadline);
            throw new InvalidOperationException("An owned HTTPS listener remained open.");
        }
        catch (SocketException error) when (error.SocketErrorCode == SocketError.ConnectionRefused)
        {
            // A fresh loopback connection independently verified closure.
        }
    }

    private sealed class CleanupGate(CatalogStore store, bool fault)
    {
        public CatalogStore Store { get; } = store;
        public bool Fault { get; } = fault;
        public TaskCompletionSource Entered { get; } = CatalogStore.NewSignal();
        public TaskCompletionSource Release { get; } = CatalogStore.NewSignal();
        public bool Completed;
    }

    private sealed record DrainLane(string Budget, string CleanupOutcome,
        OperationConcurrencySnapshot Open, OperationConcurrencySnapshot Closed, OperationConcurrencySnapshot HeldCleanup,
        OperationConcurrencySnapshot Drained, OperationConcurrencySnapshot RestartedOpen, IReadOnlyList<CaseReceipt> Cases)
    {
        public bool CanceledWaitDidNotReleaseWork => true;
        public bool CompletionAfterOwnedCleanup => true;
        public bool OwnedListenerClosed => true;
        public bool FreshListenerClosed => true;
    }
}
