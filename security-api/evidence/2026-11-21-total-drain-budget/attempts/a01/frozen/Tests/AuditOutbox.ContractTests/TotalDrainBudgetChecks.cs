using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;

static class TotalDrainBudgetChecks
{
    static void Require(bool value) { if (!value) throw new InvalidOperationException("Total drain assertion failed."); }
    static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    { try { await action(); } catch (T error) { return error; } throw new InvalidOperationException("Expected " + typeof(T).Name); }
    static TenantChangeAuditOutboxRelay Relay(Harness h, Source s, Sink sink, TimeSpan? batch = null)
        => TenantChangeAuditOutboxRelay.ActivateWithBudget(true, batch, () => s, () => sink, timeProvider: h.Clock)!;
    static void Progress(TenantChangeAuditOutboxDrainException e, int completed, int prior, int interrupted, bool maybe)
    { Require(e.Tenant.Value == "A" && e.CompletedBatches == completed && e.CompletedAcknowledgedCount == prior && e.InterruptedAcknowledgedCount == interrupted && e.AcknowledgedCount == prior + interrupted && e.MayHaveDelivered == maybe && ReferenceEquals(e.PrimaryFailure, e.InnerException)); }
    sealed class Signals
    {
        public TaskCompletionSource Canceled { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Finish { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async ValueTask Wait(CancellationToken token, bool hold = false)
        { using var registration = token.Register(() => Canceled.TrySetResult()); await Canceled.Task; if (hold) await Finish.Task; }
        public async Task<T> Observe<T>(Task task) where T : Exception
        {
            try { return await Throws<T>(() => task).WaitAsync(TimeSpan.FromSeconds(5)); }
            finally { Canceled.TrySetResult(); Finish.TrySetResult(); try { await task; } catch (Exception) { } }
        }
    }
    static async Task<TenantChangeAuditOutboxRelayException> Prior(string tenant)
    {
        var h = new Harness(); var source = new Source(h, 4, tenant); var sink = new Sink(); var fault = new OperationCanceledException(new CancellationToken(true));
        sink.Hook = (_, _) => sink.Calls == 4 ? throw fault : ValueTask.CompletedTask;
        TenantChangeAuditOutboxRelayException? result = null;
        await h.Run(async c => { result = await Throws<TenantChangeAuditOutboxRelayException>(() => Relay(h, source, sink).RelayAsync(c).AsTask()); }, tenant);
        Require(result!.AcknowledgedCount == 3 && ReferenceEquals(result.PrimaryFailure, fault)); return result;
    }
    public static async Task Run(Func<string, Func<Task>, Task> check)
    {
        await check("total distinct API and original Drain CLR optional parameters", () =>
        {
            var t = typeof(TenantChangeAuditOutboxRelay); var a = t.GetMethod("DrainAsync")!.GetParameters(); var b = t.GetMethod("DrainWithBudgetAsync")!.GetParameters();
            Require(a.Length == 5 && b.Length == 6 && b[1].ParameterType == typeof(TimeSpan?) && !b[1].IsOptional && b.Skip(2).All(p => p.IsOptional));
            Require((int)a[1].DefaultValue! == 16 && (int)b[2].DefaultValue! == 16 && (int)b[3].DefaultValue! == 2048 && (int)b[4].DefaultValue! == 128); return Task.CompletedTask;
        });
        foreach (var timeout in new[] { TimeSpan.Zero, TimeSpan.FromTicks(-1), TimeSpan.FromMinutes(1) + TimeSpan.FromTicks(1) })
            await check("total invalid budget before work " + timeout.Ticks, async () =>
            { var h = new Harness(); var s = new Source(h, 1); await h.Run(async c => { await Throws<ArgumentOutOfRangeException>(() => Relay(h, s, new()).DrainWithBudgetAsync(c, timeout).AsTask()); }); Require(s.Claims == 0); });
        foreach (var limits in new[] { (0, 1, 1), (17, 1, 1), (1, 0, 1), (1, 2049, 1), (1, 1, 0), (1, 1, 129) })
            await check("total original bounds before work " + limits, async () =>
            { var h = new Harness(); var s = new Source(h, 1); await h.Run(async c => { await Throws<ArgumentOutOfRangeException>(() => Relay(h, s, new()).DrainWithBudgetAsync(c, TimeSpan.FromSeconds(5), limits.Item1, limits.Item2, limits.Item3).AsTask()); }); Require(s.Claims == 0); });
        foreach (var bound in new[] { TimeSpan.FromTicks(1), TimeSpan.FromMinutes(1) })
            await check("total inclusive budget bounds admit raw pre-caller rejection " + bound.Ticks, async () =>
            { var h = new Harness(); var s = new Source(h, 1); using var caller = new CancellationTokenSource(); caller.Cancel(); await h.Run(async c => Require((await Throws<OperationCanceledException>(() => Relay(h, s, new()).DrainWithBudgetAsync(c, bound, cancellationToken: caller.Token).AsTask())).CancellationToken == caller.Token)); Require(s.Claims == 0); });
        foreach (var perBatch in new[] { false, true })
        await check("total minute bound normal completion and independent release " + perBatch, async () =>
        {
            var h = new Harness(); var s = new Source(h, 1);
            await h.Run(async c => { var r = await Relay(h, s, new(), perBatch ? TimeSpan.FromSeconds(5) : null).DrainWithBudgetAsync(c, TimeSpan.FromMinutes(1)); Require(r.AcknowledgedCount == 1 && r.StopReason == TenantChangeAuditOutboxDrainStopReason.NoProgress); });
            Require(s.Claims == 2 && s.Releases == 1 && s.Tokens.All(t => t.CanBeCanceled) && s.Tokens.Distinct().Count() == (perBatch ? 2 : 1) && s.ReleaseToken != s.Tokens[0] && !s.ReleaseToken.IsCancellationRequested);
        });
        await check("total null context rejected before work", async () =>
        { var h = new Harness(); var s = new Source(h, 1); await Throws<ArgumentNullException>(() => Relay(h, s, new()).DrainWithBudgetAsync(null!, TimeSpan.FromSeconds(5)).AsTask()); Require(s.Claims == 0); });
        foreach (var old in new[] { true, false }) foreach (var phase in new[] { "claim", "sink" })
            await check("total null legacy exact token and OCE reference " + old + phase, async () =>
            {
                var h = new Harness(); var s = new Source(h, 1); var sink = new Sink(); using var caller = new CancellationTokenSource(); var fault = new OperationCanceledException(new CancellationToken(true));
                if (phase == "claim") s.ClaimHook = (_, _, token) => { Require(token == caller.Token); caller.Cancel(); throw fault; };
                else sink.Hook = (_, token) => { Require(token == caller.Token); caller.Cancel(); throw fault; };
                await h.Run(async c => { var relay = Relay(h, s, sink); var e = await Throws<TenantChangeAuditOutboxDrainException>(() => (old ? relay.DrainAsync(c, cancellationToken: caller.Token) : relay.DrainWithBudgetAsync(c, null, cancellationToken: caller.Token)).AsTask()); Require(ReferenceEquals(phase == "claim" ? e.PrimaryFailure : ((TenantChangeAuditOutboxRelayException)e.PrimaryFailure).PrimaryFailure, fault)); });
            });
        foreach (var phase in new[] { "claim", "sink", "ack", "second-claim" })
            await check("total token reaches awaited phase with owned counts " + phase, async () =>
            {
                var h = new Harness(); var s = new Source(h, 3); var sink = new Sink(); var signal = new Signals();
                async ValueTask Stop(CancellationToken token) { await signal.Wait(token); token.ThrowIfCancellationRequested(); }
                if (phase is "claim" or "second-claim") s.ClaimHook = async (t, max, token) => { if (phase == "second-claim" && s.Claims == 1) return s.DefaultClaim(t, max); await Stop(token); return null; };
                if (phase == "sink") sink.Hook = (_, token) => Stop(token);
                if (phase == "ack") s.AckHook = async (_, token) => { await Stop(token); return true; };
                await h.Run(async c =>
                {
                    var e = await signal.Observe<TenantChangeAuditOutboxDrainException>(Relay(h, s, sink).DrainWithBudgetAsync(c, TimeSpan.FromMilliseconds(80), maximumPerBatch: 1).AsTask());
                    Progress(e, phase == "second-claim" ? 1 : 0, phase == "second-claim" ? 1 : 0, 0, phase != "claim");
                    var p = phase is "claim" or "second-claim" ? e.PrimaryFailure : ((TenantChangeAuditOutboxRelayException)e.PrimaryFailure).PrimaryFailure;
                    Require(p is TimeoutException timeout && timeout.Message.Contains("drain", StringComparison.Ordinal));
                });
                Require(s.Releases == (phase == "claim" ? 0 : 1) && !s.ReleaseToken.IsCancellationRequested); if (phase == "second-claim") Require(s.Tokens[0] == s.Tokens[1]);
            });
        foreach (var empty in new[] { false, true })
            await check("total late known or null claim rejects success " + empty, async () =>
            {
                var h = new Harness(); var s = new Source(h, 1); var signal = new Signals(); s.ClaimHook = async (t, max, token) => { await signal.Wait(token); return empty ? null : s.DefaultClaim(t, max); };
                await h.Run(async c => { var e = await signal.Observe<TenantChangeAuditOutboxDrainException>(Relay(h, s, new()).DrainWithBudgetAsync(c, TimeSpan.FromMilliseconds(80)).AsTask()); Progress(e, 0, 0, 0, false); Require(empty ? e.PrimaryFailure is TimeoutException : ((TenantChangeAuditOutboxRelayException)e.PrimaryFailure).PrimaryFailure is TimeoutException); });
                Require(s.Releases == (empty ? 0 : 1) && s.Acks == 0);
            });
        await check("total held uncooperative sink is joined before fresh replay dedup", async () =>
        {
            var h = new Harness(); var s = new Source(h, 1); var sink = new Sink(); var signal = new Signals(); sink.Hook = (_, token) => signal.Wait(token, true);
            await h.Run(async c =>
            {
                var pending = Relay(h, s, sink).DrainWithBudgetAsync(c, TimeSpan.FromMilliseconds(80)).AsTask();
                try { await signal.Canceled.Task.WaitAsync(TimeSpan.FromSeconds(5)); Require(!pending.IsCompleted && s.Acks == 0 && s.Releases == 0); }
                finally { signal.Canceled.TrySetResult(); signal.Finish.TrySetResult(); try { await pending; } catch (Exception) { } }
                var e = await Throws<TenantChangeAuditOutboxDrainException>(() => pending); Progress(e, 0, 0, 0, true); Require(((TenantChangeAuditOutboxRelayException)e.PrimaryFailure).PrimaryFailure is TimeoutException);
            });
            Require(sink.Receipts.Count == 1 && s.Rows.Count == 1 && s.Releases == 1); sink.Hook = null;
            await h.Run(async c => Require((await Relay(h, s, sink).DrainWithBudgetAsync(c, null)).AcknowledgedCount == 1));
            Require(sink.Calls == 2 && sink.Receipts.Count == 1 && s.Rows.Count == 0);
        });
        await check("total late true ack preserves interrupted count", async () =>
        {
            var h = new Harness(); var s = new Source(h, 1); var signal = new Signals(); s.AckHook = async (_, token) => { await signal.Wait(token); return true; };
            await h.Run(async c => { var e = await signal.Observe<TenantChangeAuditOutboxDrainException>(Relay(h, s, new()).DrainWithBudgetAsync(c, TimeSpan.FromMilliseconds(80)).AsTask()); Progress(e, 0, 0, 1, true); Require(((TenantChangeAuditOutboxRelayException)e.PrimaryFailure).PrimaryFailure is TimeoutException); }); Require(s.Rows.Count == 0 && s.Releases == 1);
        });
        foreach (var phase in new[] { "claim", "sink", "ack" }) foreach (var both in new[] { false, true })
            await check("total caller precedence and original caller token " + phase + both, async () =>
            {
                var h = new Harness(); var s = new Source(h, 1); var sink = new Sink(); var signal = new Signals(); using var caller = new CancellationTokenSource();
                async ValueTask Stop(CancellationToken token) { if (both) await signal.Wait(token); caller.Cancel(); token.ThrowIfCancellationRequested(); }
                if (phase == "claim") s.ClaimHook = async (_, _, token) => { await Stop(token); return null; };
                if (phase == "sink") sink.Hook = (_, token) => Stop(token);
                if (phase == "ack") s.AckHook = async (_, token) => { await Stop(token); return true; };
                await h.Run(async c => { var e = await signal.Observe<TenantChangeAuditOutboxDrainException>(Relay(h, s, sink).DrainWithBudgetAsync(c, both ? TimeSpan.FromMilliseconds(80) : TimeSpan.FromSeconds(5), cancellationToken: caller.Token).AsTask()); var p = phase == "claim" ? e.PrimaryFailure : ((TenantChangeAuditOutboxRelayException)e.PrimaryFailure).PrimaryFailure; Require(p is OperationCanceledException oce && oce.CancellationToken == caller.Token); }); Require(!s.ReleaseToken.IsCancellationRequested);
            });
        foreach (var lateCaller in new[] { false, true })
            await check("total unrelated OCE early selection survives cleanup expiry " + lateCaller, async () =>
            {
                var h = new Harness(); var s = new Source(h, 1); var sink = new Sink(); var signal = new Signals(); using var caller = new CancellationTokenSource(); var fault = new OperationCanceledException(new CancellationToken(true));
                sink.Hook = (_, token) => { Require(!token.IsCancellationRequested); throw fault; };
                s.ReleaseHook = async token => { await signal.Wait(s.Tokens[0]); if (lateCaller) caller.Cancel(); Require(!token.IsCancellationRequested); };
                await h.Run(async c => { var e = await signal.Observe<TenantChangeAuditOutboxDrainException>(Relay(h, s, sink).DrainWithBudgetAsync(c, TimeSpan.FromSeconds(2), cancellationToken: caller.Token).AsTask()); var child = (TenantChangeAuditOutboxRelayException)e.PrimaryFailure; Require(ReferenceEquals(child.PrimaryFailure, fault) && child.ReleaseFailure is null); Progress(e, 0, 0, 0, true); });
            });
        await check("total selected timeout survives caller arriving during release", async () =>
        {
            var h = new Harness(); var s = new Source(h, 1); var sink = new Sink(); var signal = new Signals(); using var caller = new CancellationTokenSource(); var fault = new OperationCanceledException(new CancellationToken(true));
            sink.Hook = async (_, token) => { await signal.Wait(token); throw fault; }; s.ReleaseHook = _ => { caller.Cancel(); return ValueTask.CompletedTask; };
            await h.Run(async c => { var e = await signal.Observe<TenantChangeAuditOutboxDrainException>(Relay(h, s, sink).DrainWithBudgetAsync(c, TimeSpan.FromMilliseconds(80), cancellationToken: caller.Token).AsTask()); var p = ((TenantChangeAuditOutboxRelayException)e.PrimaryFailure).PrimaryFailure; Require(p is TimeoutException timeout && timeout.Message.Contains("drain", StringComparison.Ordinal) && ReferenceEquals(timeout.InnerException, fault)); });
        });
        foreach (var perBatch in new[] { false, true })
            await check("total selected caller or perbatch fault survives controlled cleanup gate " + perBatch, async () =>
            {
                var h = new Harness(); var s = new Source(h, 1); var sink = new Sink(); var signal = new Signals(); using var caller = new CancellationTokenSource(); var fault = new OperationCanceledException(new CancellationToken(true));
                var releaseEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                sink.Hook = async (_, token) => { if (perBatch) await signal.Wait(token); else { Require(!token.IsCancellationRequested); caller.Cancel(); } throw fault; };
                s.ReleaseHook = async token => { caller.Cancel(); Require(!token.IsCancellationRequested); releaseEntered.TrySetResult(); await signal.Finish.Task; };
                await h.Run(async c =>
                {
                    var pending = Relay(h, s, sink, perBatch ? TimeSpan.FromMilliseconds(40) : null).DrainWithBudgetAsync(c, TimeSpan.FromMinutes(1), cancellationToken: caller.Token).AsTask();
                    try { await releaseEntered.Task.WaitAsync(TimeSpan.FromSeconds(5)); Require(!pending.IsCompleted); }
                    finally { signal.Canceled.TrySetResult(); signal.Finish.TrySetResult(); try { await pending; } catch (Exception) { } }
                    var e = await Throws<TenantChangeAuditOutboxDrainException>(() => pending); var p = ((TenantChangeAuditOutboxRelayException)e.PrimaryFailure).PrimaryFailure;
                    Require(perBatch ? p is TimeoutException timeout && timeout.Message.Contains("relay", StringComparison.Ordinal) && ReferenceEquals(timeout.InnerException, fault) : p is OperationCanceledException oce && oce.CancellationToken == caller.Token && ReferenceEquals(oce.InnerException, fault));
                });
            });
        foreach (var canceled in new[] { false, true })
            await check("total release-only fault stays independent after expiry " + canceled, async () =>
            {
                var h = new Harness(); var s = new Source(h, 1); var signal = new Signals(); Exception fault = canceled ? new OperationCanceledException(new CancellationToken(true)) : new IOException("Release-only.");
                s.ReleaseHook = async token => { await signal.Wait(s.Tokens[0]); Require(!token.IsCancellationRequested); throw fault; };
                await h.Run(async c => { var e = await signal.Observe<TenantChangeAuditOutboxDrainException>(Relay(h, s, new()).DrainWithBudgetAsync(c, TimeSpan.FromMilliseconds(80)).AsTask()); var child = (TenantChangeAuditOutboxRelayException)e.PrimaryFailure; Require(child.PrimaryFailure is null && ReferenceEquals(child.ReleaseFailure, fault)); Progress(e, 0, 0, 1, true); });
            });
        await check("total cleanup expiry withholds success and retains ack count", async () =>
        {
            var h = new Harness(); var s = new Source(h, 1); var signal = new Signals(); s.ReleaseHook = async token => { await signal.Wait(s.Tokens[0]); Require(!token.IsCancellationRequested); };
            await h.Run(async c => { var e = await signal.Observe<TenantChangeAuditOutboxDrainException>(Relay(h, s, new()).DrainWithBudgetAsync(c, TimeSpan.FromMilliseconds(80)).AsTask()); Progress(e, 0, 0, 1, true); Require(((TenantChangeAuditOutboxRelayException)e.PrimaryFailure).PrimaryFailure is TimeoutException); });
        });
        await check("total outer continuation expiry counts successful child before rejection", async () =>
        {
            var h = new Harness(); var s = new Source(h, 2); var signal = new Signals();
            s.ReleaseHook = _ => { h.Clock.OnNthUtc(3, () => signal.Wait(s.Tokens[0]).AsTask().GetAwaiter().GetResult()); return ValueTask.CompletedTask; };
            await h.Run(async c =>
            {
                var pending = Task.Run(async () => await Relay(h, s, new()).DrainWithBudgetAsync(c, TimeSpan.FromMilliseconds(80), maximumPerBatch: 1));
                var e = await signal.Observe<TenantChangeAuditOutboxDrainException>(pending);
                Progress(e, 1, 1, 0, true); Require(e.StartedBatches == 1 && e.PrimaryFailure is TimeoutException);
            });
            Require(s.Claims == 1 && s.Releases == 1);
        });
        foreach (var tenant in new[] { "A", "B" }) foreach (var phase in new[] { "claim", "sink" })
            await check("total foreign RelayException identity not reclassified or borrowed " + tenant + phase, async () =>
            {
                var prior = await Prior(tenant); var h = new Harness(); var s = new Source(h, 2); var sink = new Sink(); var signal = new Signals();
                if (phase == "claim") s.ClaimHook = async (_, _, token) => { await signal.Wait(token); throw prior; };
                else sink.Hook = async (_, token) => { if (sink.Calls == 2) { await signal.Wait(token); throw prior; } };
                await h.Run(async c => { var e = await signal.Observe<TenantChangeAuditOutboxDrainException>(Relay(h, s, sink).DrainWithBudgetAsync(c, TimeSpan.FromMilliseconds(80)).AsTask()); Progress(e, 0, 0, phase == "claim" ? 0 : 1, phase != "claim"); Require(phase == "claim" ? ReferenceEquals(e.PrimaryFailure, prior) : ReferenceEquals(((TenantChangeAuditOutboxRelayException)e.PrimaryFailure).PrimaryFailure, prior)); });
            });
        foreach (var expired in new[] { false, true })
            await check("total scope guard rejection before provider work " + expired, async () =>
            { var h = new Harness(); var s = new Source(h, 1); await h.Run(async c => { if (expired) h.Clock.Advance(); await Throws<TenantAccessDeniedException>(() => Relay(h, s, new()).DrainWithBudgetAsync(c, TimeSpan.FromSeconds(5)).AsTask()); }, operation: expired ? "outbox.relay" : "audit.history"); Require(s.Claims == 0); });
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
