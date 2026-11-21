using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;

static class BoundedDrainChecks
{
    static void Require(bool value) { if (!value) throw new InvalidOperationException("Bounded drain assertion failed."); }
    static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T error) { return error; } throw new InvalidOperationException("Expected " + typeof(T).Name); }
    static TenantChangeAuditOutboxRelay Relay(Harness h, Source source, Sink sink, TimeSpan? timeout = null)
        => TenantChangeAuditOutboxRelay.ActivateWithBudget(true, timeout, () => source, () => sink, timeProvider: h.Clock)!;
    static void Progress(TenantChangeAuditOutboxDrainException error, int started, int completed, int prior, int interrupted, bool maybe)
    {
        Require(error.Tenant.Value == "A" && error.StartedBatches == started && error.CompletedBatches == completed
            && error.CompletedAcknowledgedCount == prior && error.InterruptedAcknowledgedCount == interrupted
            && error.AcknowledgedCount == prior + interrupted && error.MayHaveDelivered == maybe
            && ReferenceEquals(error.PrimaryFailure, error.InnerException));
    }
    static async Task<TenantChangeAuditOutboxRelayException> Prior(string tenant)
    {
        var h = new Harness(); var source = new Source(h, 4, tenant); var sink = new Sink();
        sink.Hook = (_, _) => { if (sink.Calls == 4) throw new IOException("Prior private delivery failure."); return ValueTask.CompletedTask; };
        TenantChangeAuditOutboxRelayException? prior = null;
        await h.Run(async c => prior = await Throws<TenantChangeAuditOutboxRelayException>(() => Relay(h, source, sink).RelayAsync(c).AsTask()), tenant);
        Require(prior!.AcknowledgedCount == 3 && prior.MayHaveDelivered);
        return prior;
    }
    public static async Task Run(Func<string, Func<Task>, Task> check)
    {
        await check("drain exact optional public shape and immutable progress", () =>
        {
            var parameters = typeof(TenantChangeAuditOutboxRelay).GetMethod("DrainAsync")!.GetParameters();
            Require(parameters.Length == 5 && (int)parameters[1].DefaultValue! == 16 && (int)parameters[2].DefaultValue! == 2048 && (int)parameters[3].DefaultValue! == 128);
            foreach (var type in new[] { typeof(TenantChangeAuditOutboxDrainResult), typeof(TenantChangeAuditOutboxDrainException) })
                Require(type.GetProperties().Where(p => p.DeclaringType == type).All(p => p.SetMethod is null));
            return Task.CompletedTask;
        });
        foreach (var bad in new[] { (0, 1, 1), (17, 1, 1), (1, 0, 1), (1, 2049, 1), (1, 1, 0), (1, 1, 129) })
            await check("drain invalid bounds before claim " + bad, async () =>
            {
                var h = new Harness(); var source = new Source(h, 1); var sink = new Sink();
                await h.Run(async c => { await Throws<ArgumentOutOfRangeException>(() => Relay(h, source, sink).DrainAsync(c, bad.Item1, bad.Item2, bad.Item3).AsTask()); });
                Require(source.Claims == 0 && sink.Calls == 0);
            });
        await check("drain null context fails before claim", async () =>
        { var h = new Harness(); var source = new Source(h, 1); await Throws<ArgumentNullException>(() => Relay(h, source, new()).DrainAsync(null!).AsTask()); Require(source.Claims == 0); });
        await check("drain pre-canceled caller raw original token before claim", async () =>
        {
            var h = new Harness(); var source = new Source(h, 1); using var caller = new CancellationTokenSource(); caller.Cancel();
            await h.Run(async c => Require((await Throws<OperationCanceledException>(() => Relay(h, source, new()).DrainAsync(c, cancellationToken: caller.Token).AsTask())).CancellationToken == caller.Token));
            Require(source.Claims == 0);
        });
        foreach (var operation in new[] { "document.update", "audit.history" })
            await check("drain wrong permission raw before claim " + operation, async () =>
            {
                var h = new Harness(); var source = new Source(h, 1);
                await h.Run(async c => { await Throws<TenantAccessDeniedException>(() => Relay(h, source, new()).DrainAsync(c).AsTask()); }, operation: operation);
                Require(source.Claims == 0);
            });
        await check("drain expired checked scope raw before claim", async () =>
        {
            var h = new Harness(); var source = new Source(h, 1);
            await h.Run(async c => { h.Clock.Advance(); await Throws<TenantAccessDeniedException>(() => Relay(h, source, new()).DrainAsync(c).AsTask()); });
            Require(source.Claims == 0);
        });
        await check("drain disposed checked scope raw before claim", async () =>
        {
            var h = new Harness(); var source = new Source(h, 1); TenantOperationContext? held = null;
            await h.Run(c => { held = c; return Task.CompletedTask; });
            await Throws<TenantAccessDeniedException>(() => Relay(h, source, new()).DrainAsync(held!).AsTask()); Require(source.Claims == 0);
        });
        await check("drain empty source NoProgress and one completed batch", async () =>
        {
            var h = new Harness(); var source = new Source(h, 0);
            await h.Run(async c => { var r = await Relay(h, source, new()).DrainAsync(c); Require(r.Tenant.Value == "A" && r.CompletedBatches == 1 && r.AcknowledgedCount == 0 && r.StopReason == TenantChangeAuditOutboxDrainStopReason.NoProgress); });
            Require(source.Claims == 1 && source.Releases == 0);
        });
        await check("drain empty claimed lease NoProgress does not claim global empty", async () =>
        {
            var h = new Harness(); var source = new Source(h, 1); source.ClaimHook = (tenant, _, _) => ValueTask.FromResult<TenantChangeAuditOutboxLease?>(source.Lease(tenant, []));
            await h.Run(async c => { var r = await Relay(h, source, new()).DrainAsync(c, 1, 1, 1); Require(r.StopReason == TenantChangeAuditOutboxDrainStopReason.NoProgress && r.AcknowledgedCount == 0); });
            Require(source.Rows.Count == 1 && source.Releases == 1);
        });
        await check("drain positive underfilled batches continue to later work", async () =>
        {
            var h = new Harness(); var source = new Source(h, 5) { Underfill = 2 }; var sink = new Sink();
            await h.Run(async c => { var r = await Relay(h, source, sink).DrainAsync(c, maximumPerBatch: 4); Require(r.CompletedBatches == 4 && r.AcknowledgedCount == 5 && r.StopReason == TenantChangeAuditOutboxDrainStopReason.NoProgress); });
            Require(source.Requested.SequenceEqual(new[] { 4, 4, 4, 4 }) && source.Releases == 3 && sink.Calls == 5);
            Require(h.Identities == 1 && h.Memberships == 1 && h.Resources == 1 && h.Policies == 1);
        });
        await check("drain remaining record limit constrains last claim", async () =>
        {
            var h = new Harness(); var source = new Source(h, 9);
            await h.Run(async c => { var r = await Relay(h, source, new()).DrainAsync(c, maximumRecords: 5, maximumPerBatch: 3); Require(r.AcknowledgedCount == 5 && r.CompletedBatches == 2 && r.StopReason == TenantChangeAuditOutboxDrainStopReason.RecordLimit); });
            Require(source.Requested.SequenceEqual(new[] { 3, 2 }) && source.Rows.Count == 4 && source.Releases == 2);
        });
        await check("drain batch limit stops without extra claim", async () =>
        {
            var h = new Harness(); var source = new Source(h, 9);
            await h.Run(async c => { var r = await Relay(h, source, new()).DrainAsync(c, maximumBatches: 2, maximumPerBatch: 2); Require(r.CompletedBatches == 2 && r.AcknowledgedCount == 4 && r.StopReason == TenantChangeAuditOutboxDrainStopReason.BatchLimit); });
            Require(source.Claims == 2 && source.Rows.Count == 5);
        });
        await check("drain record limit wins simultaneous batch cap", async () =>
        {
            var h = new Harness(); var source = new Source(h, 2);
            await h.Run(async c => { var r = await Relay(h, source, new()).DrainAsync(c, 1, 1, 1); Require(r.StopReason == TenantChangeAuditOutboxDrainStopReason.RecordLimit && r.AcknowledgedCount == 1); });
            Require(source.Claims == 1);
        });
        await check("drain maximum caps acknowledged without overflow or extra batch", async () =>
        {
            var h = new Harness(); var source = new Source(h, 2049);
            await h.Run(async c => { var r = await Relay(h, source, new()).DrainAsync(c); Require(r.CompletedBatches == 16 && r.AcknowledgedCount == 2048 && r.StopReason == TenantChangeAuditOutboxDrainStopReason.RecordLimit); });
            Require(source.Claims == 16 && source.Releases == 16 && source.Rows.Count == 1 && source.Requested.All(x => x == 128));
        });
        foreach (var completed in new[] { false, true })
            await check("drain raw claim fault preserves exact failure and earlier totals " + completed, async () =>
            {
                var h = new Harness(); var source = new Source(h, 4); var fault = new IOException("Claim failed.");
                source.ClaimHook = (tenant, max, _) => source.Claims == (completed ? 2 : 1) ? throw fault : ValueTask.FromResult(source.DefaultClaim(tenant, max));
                await h.Run(async c => { var e = await Throws<TenantChangeAuditOutboxDrainException>(() => Relay(h, source, new()).DrainAsync(c, maximumPerBatch: 1).AsTask()); Progress(e, completed ? 2 : 1, completed ? 1 : 0, completed ? 1 : 0, 0, completed); Require(ReferenceEquals(e.PrimaryFailure, fault)); });
                Require(source.Claims == (completed ? 2 : 1) && source.Releases == (completed ? 1 : 0));
            });
        foreach (var phase in new[] { "sink", "ack", "release" })
            await check("drain earlier and interrupted progress with owned failure " + phase, async () =>
            {
                var h = new Harness(); var source = new Source(h, 5); var sink = new Sink(); var fault = new IOException("Current phase failed.");
                if (phase == "sink") sink.Hook = (_, _) => sink.Calls == 4 ? throw fault : ValueTask.CompletedTask;
                if (phase == "ack") source.AckHook = (_, _) => source.Acks == 4 ? throw fault : ValueTask.FromResult(true);
                if (phase == "release") source.ReleaseHook = _ => source.Releases == 2 ? throw fault : ValueTask.CompletedTask;
                await h.Run(async c =>
                {
                    var e = await Throws<TenantChangeAuditOutboxDrainException>(() => Relay(h, source, sink).DrainAsync(c, maximumPerBatch: 2).AsTask());
                    Progress(e, 2, 1, 2, phase == "release" ? 2 : 1, true);
                    var child = (TenantChangeAuditOutboxRelayException)e.PrimaryFailure;
                    Require(ReferenceEquals(phase == "release" ? child.ReleaseFailure : child.PrimaryFailure, fault));
                });
                Require(source.Claims == 2 && source.Releases == 2);
            });
        await check("drain interrupted primary and cleanup failures remain separate", async () =>
        {
            var h = new Harness(); var source = new Source(h, 2); var sink = new Sink(); var primary = new IOException("Sink."); var release = new IOException("Release.");
            sink.Hook = (_, _) => throw primary; source.ReleaseHook = _ => throw release;
            await h.Run(async c => { var e = await Throws<TenantChangeAuditOutboxDrainException>(() => Relay(h, source, sink).DrainAsync(c).AsTask()); Progress(e, 1, 0, 0, 0, true); var child = (TenantChangeAuditOutboxRelayException)e.PrimaryFailure; Require(ReferenceEquals(child.PrimaryFailure, primary) && ReferenceEquals(child.ReleaseFailure, release)); });
            Require(source.Claims == 1 && source.Releases == 1);
        });
        foreach (var tenant in new[] { "A", "B" })
            foreach (var phase in new[] { "claim", "sink" })
                foreach (var earlier in new[] { false, true })
                    await check("drain prior exception identity isolation " + tenant + phase + earlier, async () =>
                    {
                        var prior = await Prior(tenant); var h = new Harness(); var source = new Source(h, 6); var sink = new Sink();
                        if (phase == "claim") source.ClaimHook = (t, max, _) => source.Claims == (earlier ? 2 : 1) ? throw prior : ValueTask.FromResult(source.DefaultClaim(t, max));
                        else sink.Hook = (_, _) => sink.Calls == (earlier ? 4 : 2) ? throw prior : ValueTask.CompletedTask;
                        await h.Run(async c =>
                        {
                            var e = await Throws<TenantChangeAuditOutboxDrainException>(() => Relay(h, source, sink).DrainAsync(c, maximumPerBatch: 2).AsTask());
                            Progress(e, earlier ? 2 : 1, earlier ? 1 : 0, earlier ? 2 : 0, phase == "sink" ? 1 : 0, earlier || phase == "sink");
                            if (phase == "claim") Require(ReferenceEquals(e.PrimaryFailure, prior));
                            else Require(!ReferenceEquals(e.PrimaryFailure, prior) && ReferenceEquals(((TenantChangeAuditOutboxRelayException)e.PrimaryFailure).PrimaryFailure, prior));
                        });
                        Require(source.Claims == (earlier ? 2 : 1) && source.Releases == (earlier ? 1 : 0) + (phase == "sink" ? 1 : 0));
                    });
        foreach (var tenant in new[] { "A", "B" })
            await check("drain outer postguard prior exception cannot inject progress " + tenant, async () =>
            {
                var prior = await Prior(tenant); var h = new Harness(); var source = new Source(h, 3);
                source.ReleaseHook = _ => { h.Clock.OnNthUtc(3, () => throw prior); return ValueTask.CompletedTask; };
                await h.Run(async c => { var e = await Throws<TenantChangeAuditOutboxDrainException>(() => Relay(h, source, new()).DrainAsync(c, maximumPerBatch: 2).AsTask()); Progress(e, 1, 1, 2, 0, true); Require(ReferenceEquals(e.PrimaryFailure, prior)); });
                Require(source.Claims == 1 && source.Releases == 1);
            });
        foreach (var cancel in new[] { false, true })
            await check("drain outer postguard records successful batch before rejection " + cancel, async () =>
            {
                var h = new Harness(); var source = new Source(h, 3); using var caller = new CancellationTokenSource();
                source.ReleaseHook = _ => { h.Clock.OnNthUtc(cancel ? 2 : 3, () => { if (cancel) caller.Cancel(); else h.Clock.Advance(); }); return ValueTask.CompletedTask; };
                await h.Run(async c => { var e = await Throws<TenantChangeAuditOutboxDrainException>(() => Relay(h, source, new()).DrainAsync(c, maximumPerBatch: 2, cancellationToken: caller.Token).AsTask()); Progress(e, 1, 1, 2, 0, true); Require(cancel ? e.PrimaryFailure is OperationCanceledException oce && oce.CancellationToken == caller.Token : e.PrimaryFailure is TenantAccessDeniedException); });
                Require(source.Claims == 1 && source.Releases == 1);
            });
        await check("drain cancellation during sink preserves owned partial and cleanup", async () =>
        {
            var h = new Harness(); var source = new Source(h, 3); var sink = new Sink(); using var caller = new CancellationTokenSource();
            sink.Hook = (_, token) => { if (sink.Calls == 2) { caller.Cancel(); token.ThrowIfCancellationRequested(); } return ValueTask.CompletedTask; };
            await h.Run(async c => { var e = await Throws<TenantChangeAuditOutboxDrainException>(() => Relay(h, source, sink).DrainAsync(c, cancellationToken: caller.Token).AsTask()); Progress(e, 1, 0, 0, 1, true); Require(((TenantChangeAuditOutboxRelayException)e.PrimaryFailure).PrimaryFailure is OperationCanceledException oce && oce.CancellationToken == caller.Token); });
            Require(source.Releases == 1 && !source.ReleaseToken.IsCancellationRequested);
        });
        await check("drain fresh replay after partial failure preserves receipt idempotence", async () =>
        {
            var h = new Harness(); var source = new Source(h, 4); var sink = new Sink();
            source.AckHook = (_, _) => source.Acks == 2 ? throw new IOException("Lost ack.") : ValueTask.FromResult(true);
            await h.Run(async c => { var e = await Throws<TenantChangeAuditOutboxDrainException>(() => Relay(h, source, sink).DrainAsync(c, maximumPerBatch: 2).AsTask()); Progress(e, 1, 0, 0, 1, true); });
            Require(sink.Receipts.Count == 2 && source.Rows.Count == 3);
            source.AckHook = null;
            await h.Run(async c => { var r = await Relay(h, source, sink).DrainAsync(c, maximumPerBatch: 2); Require(r.AcknowledgedCount == 3 && r.CompletedBatches == 3 && r.StopReason == TenantChangeAuditOutboxDrainStopReason.NoProgress); });
            Require(source.Rows.Count == 0 && sink.Receipts.Count == 4 && sink.Calls == 5);
        });
        await check("drain configured work tokens are distinct per batch and caller preserved by null policy", async () =>
        {
            var h = new Harness(); var source = new Source(h, 2); using var caller = new CancellationTokenSource();
            await h.Run(async c => { var r = await Relay(h, source, new(), TimeSpan.FromSeconds(5)).DrainAsync(c, maximumPerBatch: 1, cancellationToken: caller.Token); Require(r.AcknowledgedCount == 2); });
            Require(source.Tokens.Count == 3 && source.Tokens.Distinct().Count() == 3 && source.Tokens.All(t => t.CanBeCanceled && t != caller.Token));
            var next = new Source(h, 1);
            await h.Run(async c => { await Relay(h, next, new()).DrainAsync(c, 1, 1, 1, caller.Token); });
            Require(next.Tokens.Single() == caller.Token);
        });
        foreach (var earlier in new[] { false, true })
            await check("drain cooperative claim timeout preserves completed progress " + earlier, async () =>
            {
                var h = new Harness(); var source = new Source(h, 3);
                var signal = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                source.ClaimHook = async (tenant, max, token) =>
                {
                    if (source.Claims != (earlier ? 2 : 1)) return source.DefaultClaim(tenant, max);
                    using var registration = token.Register(() => signal.TrySetResult());
                    await signal.Task;
                    token.ThrowIfCancellationRequested();
                    return null;
                };
                await h.Run(async c =>
                {
                    var pending = Relay(h, source, new(), TimeSpan.FromMilliseconds(40)).DrainAsync(c, maximumPerBatch: 1).AsTask();
                    try
                    {
                        var e = await Throws<TenantChangeAuditOutboxDrainException>(() => pending).WaitAsync(TimeSpan.FromSeconds(5));
                        Progress(e, earlier ? 2 : 1, earlier ? 1 : 0, earlier ? 1 : 0, 0, earlier);
                        Require(e.PrimaryFailure is TimeoutException);
                    }
                    finally
                    {
                        signal.TrySetResult();
                        // Observe/join owned work even if the watchdog/test assertion failed.
                        try { await pending; } catch (Exception) { }
                    }
                });
                Require(source.Claims == (earlier ? 2 : 1) && source.Releases == (earlier ? 1 : 0));
            });
        await check("drain tenant partition leaves foreign pending records untouched", async () =>
        {
            var h = new Harness(); var source = new Source(h, 2); source.Rows.Add(Row("B")); var sink = new Sink();
            await h.Run(async c => { var r = await Relay(h, source, sink).DrainAsync(c, maximumPerBatch: 1); Require(r.Tenant.Value == "A" && r.AcknowledgedCount == 2); });
            Require(source.Rows.Count == 1 && source.Rows[0].Receipt.Tenant.Value == "B" && sink.Tenants.SetEquals(["A"]));
        });
    }
    static TenantChangeAuditRecord Row(string tenant) => new(new(Guid.NewGuid(), new("issuer", "service"), "Bearer", new(tenant), "document.update", "write", "document", "entity", "acl", TenantChangeKind.Update), DateTimeOffset.Parse("2026-11-21T00:00:00Z"), TenantChangeAuditMode.MetadataOnly, []);
    sealed class Source(Harness h, int count, string tenant = "A") : ITenantChangeAuditOutboxSource
    {
        public List<TenantChangeAuditRecord> Rows { get; } = Enumerable.Range(0, count).Select(_ => Row(tenant)).ToList();
        public int Claims, Acks, Releases; public int Underfill = 128;
        public List<int> Requested { get; } = []; public List<CancellationToken> Tokens { get; } = []; public CancellationToken ReleaseToken;
        public Func<TenantId, int, CancellationToken, ValueTask<TenantChangeAuditOutboxLease?>>? ClaimHook;
        public Func<Guid, CancellationToken, ValueTask<bool>>? AckHook;
        public Func<CancellationToken, ValueTask>? ReleaseHook;
        public TenantChangeAuditOutboxLease Lease(TenantId owner, IEnumerable<TenantChangeAuditRecord> rows) => new(owner, Guid.NewGuid(), h.Clock.Now.AddSeconds(15), rows);
        public TenantChangeAuditOutboxLease? DefaultClaim(TenantId owner, int max)
        { var rows = Rows.Where(r => r.Receipt.Tenant.Equals(owner)).Take(Math.Min(Underfill, max)).ToArray(); return rows.Length == 0 ? null : Lease(owner, rows); }
        public ValueTask<TenantChangeAuditOutboxLease?> ClaimAsync(TenantId owner, int max, TimeSpan duration, CancellationToken token)
        { Claims++; Requested.Add(max); Tokens.Add(token); return ClaimHook?.Invoke(owner, max, token) ?? ValueTask.FromResult(DefaultClaim(owner, max)); }
        public async ValueTask<bool> AcknowledgeAsync(TenantChangeAuditOutboxLease lease, Guid receipt, CancellationToken token)
        { Acks++; if (AckHook is not null && !await AckHook(receipt, token)) return false; return Rows.RemoveAll(x => x.Receipt.Tenant.Equals(lease.Tenant) && x.Receipt.ReceiptId == receipt) == 1; }
        public ValueTask ReleaseAsync(TenantChangeAuditOutboxLease lease, CancellationToken token)
        { Releases++; ReleaseToken = token; return ReleaseHook?.Invoke(token) ?? ValueTask.CompletedTask; }
    }
    sealed class Sink : ITenantChangeAuditIdempotentSink
    {
        public int Calls; public HashSet<Guid> Receipts { get; } = []; public HashSet<string> Tenants { get; } = [];
        public Func<TenantChangeAuditRecord, CancellationToken, ValueTask>? Hook;
        public async ValueTask AppendOnceAsync(TenantChangeAuditRecord record, CancellationToken token)
        { Calls++; if (Hook is not null) await Hook(record, token); Receipts.Add(record.Receipt.ReceiptId); Tenants.Add(record.Receipt.Tenant.Value); }
    }
    sealed class ProbeClock : TimeProvider
    {
        public DateTimeOffset Now = DateTimeOffset.Parse("2026-11-21T00:00:00Z"); long ticks; int remaining; Action? action;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override DateTimeOffset GetUtcNow() { if (action is not null && --remaining == 0) { var run = action; action = null; run(); } return Now; }
        public override long GetTimestamp() => ticks;
        public void Advance() { Now += TimeSpan.FromMinutes(2); ticks += TimeSpan.FromMinutes(2).Ticks; }
        public void OnNthUtc(int read, Action callback) { remaining = read; action = callback; }
    }
    sealed class Harness : IIdentitySource, ITenantMembershipSource, IResourceScopeSource, ITenantAccessPolicy
    {
        public ProbeClock Clock { get; } = new(); public int Identities, Memberships, Resources, Policies;
        readonly TenantOperationRegistry registry; Func<TenantOperationContext, Task> body = _ => Task.CompletedTask;
        public Harness()
        {
            var b = new TenantOperationRegistryBuilder();
            foreach (var item in new[] { ("outbox.relay", "relay", "audit-outbox"), ("document.update", "write", "document"), ("audit.history", "read", "audit-trail") })
                b.Register<string, bool>(item.Item1, item.Item2, item.Item3, x => x, x => new(new(x), "tenant"), () => new Handler(this));
            registry = b.Build();
        }
        public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken token) { Identities++; return ValueTask.FromResult<IdentitySnapshot?>(new(new("issuer", "service"), "Bearer", Clock.Now.AddMinutes(-1), Clock.Now.AddMinutes(5))); }
        public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot identity, TenantId tenant, CancellationToken token) { Memberships++; return ValueTask.FromResult<TenantMembershipSnapshot?>(new(identity.Principal, tenant, true, Clock.Now.AddMinutes(-1), Clock.Now.AddMinutes(5), "membership")); }
        public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId tenant, string kind, string id, CancellationToken token) { Resources++; return ValueTask.FromResult<ResourceScopeSnapshot?>(new(tenant, kind, id, "acl")); }
        public ValueTask<bool> IsAllowedAsync(TenantAccessRequest request, CancellationToken token) { Policies++; return ValueTask.FromResult(true); }
        public async Task Run(Func<TenantOperationContext, Task> callback, string tenant = "A", string operation = "outbox.relay")
        {
            Exception? failure = null; var entered = false;
            body = async c => { entered = true; try { await callback(c); } catch (Exception e) { failure = e; throw; } };
            var services = new TenantSecurityServices(this, new(["issuer"], ["Bearer"]), this, this, TimeSpan.FromMinutes(1), this, Clock);
            await new TenantOperationDispatcher(registry, services).DispatchAsync<string, bool>(operation, tenant, new("drain-fixture"));
            if (failure is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
            Require(entered);
        }
        sealed class Handler(Harness h) : ITenantOperationHandler<string, bool>
        { public async ValueTask<OperationResult<bool>> HandleAsync(string request, TenantOperationContext context, CancellationToken token) { await h.body(context); return OperationResult<bool>.Success(true); } }
    }
}
