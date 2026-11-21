using Cehpalon.Engine.Tenancy;

static class RelayBudgetChecks
{
    static void Require(bool value) { if (!value) throw new InvalidOperationException("Relay budget assertion failed."); }
    static async Task<T> Throws<T>(Func<Task> body) where T : Exception
    { try { await body(); } catch (T error) { return error; } throw new InvalidOperationException("Expected " + typeof(T).Name); }
    static async Task Expired(CancellationToken token)
    {
        var signal = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var registration = token.Register(() => signal.TrySetResult());
        await signal.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Require(token.IsCancellationRequested);
    }
    static readonly TimeSpan Budget = TimeSpan.FromMilliseconds(40);
    static TenantChangeAuditRecord Row() => new(new(Guid.NewGuid(), new("issuer", "service"), "Bearer", new("A"),
        "document.update", "write", "document", "entity-1", "acl1", TenantChangeKind.Update, "v1", "v2"),
        DateTimeOffset.Parse("2026-11-21T00:00:00Z"), TenantChangeAuditMode.MetadataOnly, []);
    static TenantChangeAuditOutboxRelay Relay(Fixture f, Source source, Sink sink, TimeSpan? timeout = null)
        => TenantChangeAuditOutboxRelay.ActivateWithBudget(true, timeout, () => source, () => sink, timeProvider: f.Clock)!;
    static Task Context(Fixture fixture, Func<TenantOperationContext, Task> action)
        => fixture.Run(action, "outbox.relay");
    public static async Task Run(Func<string, Func<Task>, Task> check)
    {
        await check("budget original Activate CLR signature and distinct optional API", () =>
        {
            var methods = typeof(TenantChangeAuditOutboxRelay).GetMethods();
            var old = methods.Single(x => x.Name == "Activate").GetParameters();
            var current = methods.Single(x => x.Name == "ActivateWithBudget").GetParameters();
            Require(old.Length == 5 && old[0].ParameterType == typeof(bool) && old.Skip(1).All(p => p.IsOptional));
            Require(current.Length == 6 && current[1].ParameterType == typeof(TimeSpan?) && !current[1].IsOptional && current.Skip(2).All(p => p.IsOptional));
            return Task.CompletedTask;
        });
        await check("budget disabled skips all poisoned factories and invalid bounds", () =>
        {
            Require(TenantChangeAuditOutboxRelay.ActivateWithBudget(false, TimeSpan.Zero, () => throw new IOException(),
                () => throw new IOException(), TimeSpan.Zero) is null);
            Require(TenantChangeAuditOutboxRelay.ActivateWithBudget(false, TimeSpan.MinValue) is null);
            return Task.CompletedTask;
        });
        foreach (var timeout in new[] { TimeSpan.Zero, TimeSpan.FromTicks(-1), TimeSpan.FromMinutes(1) + TimeSpan.FromTicks(1) })
            await check("budget invalid bound before factory " + timeout.Ticks, async () =>
            {
                var calls = 0;
                await Throws<ArgumentOutOfRangeException>(() => { TenantChangeAuditOutboxRelay.ActivateWithBudget(true, timeout,
                    () => { calls++; throw new IOException(); }, () => throw new IOException()); return Task.CompletedTask; });
                Require(calls == 0);
            });
        foreach (var timeout in new[] { TimeSpan.FromTicks(1), TimeSpan.FromMinutes(1) })
            await check("budget inclusive activation bound " + timeout.Ticks, () =>
            { var f = new Fixture(); Require(Relay(f, new(f), new(), timeout) is not null); return Task.CompletedTask; });
        foreach (var legacy in new[] { true, false })
            await check("budget null legacy keeps exact provider token and fault references " + legacy, async () =>
            {
                var f = new Fixture(); var source = new Source(f); var sink = new Sink(); using var caller = new CancellationTokenSource();
                var relay = legacy ? TenantChangeAuditOutboxRelay.Activate(true, () => source, () => sink, timeProvider: f.Clock)! : Relay(f, source, sink);
                await Context(f, async c => Require(await relay.RelayAsync(c, cancellationToken: caller.Token) == 1));
                Require(source.ClaimToken == caller.Token && source.AckToken == caller.Token && sink.Token == caller.Token);
                using var foreign = new CancellationTokenSource(); var error = new OperationCanceledException(foreign.Token);
                source.Claim = _ => throw error;
                await Context(f, async c => Require(ReferenceEquals(await Throws<OperationCanceledException>(() => relay.RelayAsync(c).AsTask()), error)));
                source.Claim = null; sink.Append = _ => throw error;
                await Context(f, async c => Require(ReferenceEquals((await Throws<TenantChangeAuditOutboxRelayException>(() => relay.RelayAsync(c).AsTask())).PrimaryFailure, error)));
            });
        await check("budget configured same linked work token and independent release token", async () =>
        {
            var f = new Fixture(); var source = new Source(f); var sink = new Sink(); using var caller = new CancellationTokenSource();
            await Context(f, async c => Require(await Relay(f, source, sink, TimeSpan.FromSeconds(5)).RelayAsync(c, cancellationToken: caller.Token) == 1));
            Require(source.ClaimToken.CanBeCanceled && source.ClaimToken != caller.Token && source.ClaimToken == sink.Token && sink.Token == source.AckToken);
            Require(source.ReleaseToken.CanBeCanceled && source.ReleaseToken != source.ClaimToken && !source.ReleaseToken.IsCancellationRequested);
        });
        await check("budget pre-cancel caller original token and zero claim", async () =>
        {
            var f = new Fixture(); var source = new Source(f); using var caller = new CancellationTokenSource(); caller.Cancel();
            await Context(f, async c => Require((await Throws<OperationCanceledException>(() => Relay(f, source, new(), Budget).RelayAsync(c, cancellationToken: caller.Token).AsTask())).CancellationToken == caller.Token));
            Require(source.Claims == 0);
        });
        foreach (var phase in new[] { "claim", "sink", "ack" })
            await check("budget cooperative cancellation and quiescence " + phase, async () =>
            {
                var f = new Fixture(); var source = new Source(f); var sink = new Sink(); var finished = false;
                async ValueTask Stop(CancellationToken token) { try { await Expired(token); token.ThrowIfCancellationRequested(); } finally { finished = true; } }
                if (phase == "claim") source.Claim = async token => { await Stop(token); return source.Lease(); };
                if (phase == "sink") sink.Append = Stop;
                if (phase == "ack") source.Ack = async token => { await Stop(token); return true; };
                await Context(f, async c =>
                {
                    if (phase == "claim") await Throws<TimeoutException>(() => Relay(f, source, sink, Budget).RelayAsync(c).AsTask());
                    else { var error = await Throws<TenantChangeAuditOutboxRelayException>(() => Relay(f, source, sink, Budget).RelayAsync(c).AsTask()); Require(error.PrimaryFailure is TimeoutException && error.MayHaveDelivered && error.AcknowledgedCount == 0 && error.ReleaseFailure is null); }
                });
                Require(finished && source.Releases == (phase == "claim" ? 0 : 1) && !source.ReleaseToken.IsCancellationRequested);
            });
        foreach (var nullLease in new[] { false, true })
            await check("budget late known or null claim cannot report success " + nullLease, async () =>
            {
                var f = new Fixture(); var source = new Source(f); var sink = new Sink();
                source.Claim = async token => { await Expired(token); return nullLease ? null : source.Lease(); };
                await Context(f, async c =>
                {
                    if (nullLease) await Throws<TimeoutException>(() => Relay(f, source, sink, Budget).RelayAsync(c).AsTask());
                    else { var e = await Throws<TenantChangeAuditOutboxRelayException>(() => Relay(f, source, sink, Budget).RelayAsync(c).AsTask()); Require(e.PrimaryFailure is TimeoutException && !e.MayHaveDelivered && e.AcknowledgedCount == 0); }
                });
                Require(source.Releases == (nullLease ? 0 : 1) && sink.Calls == 0 && source.Acks == 0);
            });
        foreach (var phase in new[] { "claim", "sink", "ack" })
            foreach (var both in new[] { false, true })
                await check("budget observed caller precedence and original token " + phase + both, async () =>
                {
                    var f = new Fixture(); var source = new Source(f); var sink = new Sink(); using var caller = new CancellationTokenSource();
                    async ValueTask Stop(CancellationToken token) { if (both) await Expired(token); caller.Cancel(); token.ThrowIfCancellationRequested(); }
                    if (phase == "claim") source.Claim = async token => { await Stop(token); return source.Lease(); };
                    if (phase == "sink") sink.Append = Stop;
                    if (phase == "ack") source.Ack = async token => { await Stop(token); return true; };
                    await Context(f, async c =>
                    {
                        Exception e = phase == "claim"
                            ? await Throws<OperationCanceledException>(() => Relay(f, source, sink, both ? Budget : TimeSpan.FromSeconds(5)).RelayAsync(c, cancellationToken: caller.Token).AsTask())
                            : (await Throws<TenantChangeAuditOutboxRelayException>(() => Relay(f, source, sink, both ? Budget : TimeSpan.FromSeconds(5)).RelayAsync(c, cancellationToken: caller.Token).AsTask())).PrimaryFailure!;
                        Require(e is OperationCanceledException oce && oce.CancellationToken == caller.Token);
                    });
                    Require(!source.ReleaseToken.IsCancellationRequested);
                });
        foreach (var phase in new[] { "claim", "sink", "ack" })
            foreach (var cancel in new[] { false, true })
                await check("budget unrelated fault exact reference " + phase + cancel, async () =>
                {
                    var f = new Fixture(); var source = new Source(f); var sink = new Sink();
                    Exception fault = cancel ? new OperationCanceledException(new CancellationToken(true)) : new IOException("Trusted fixture fault.");
                    async ValueTask Fail(CancellationToken token) { if (!cancel) await Expired(token); throw fault; }
                    if (phase == "claim") source.Claim = async token => { await Fail(token); return null; };
                    if (phase == "sink") sink.Append = Fail;
                    if (phase == "ack") source.Ack = async token => { await Fail(token); return true; };
                    await Context(f, async c =>
                    {
                        Exception e = phase == "claim" ? await Throws<Exception>(() => Relay(f, source, sink, cancel ? TimeSpan.FromSeconds(5) : Budget).RelayAsync(c).AsTask())
                            : (await Throws<TenantChangeAuditOutboxRelayException>(() => Relay(f, source, sink, cancel ? TimeSpan.FromSeconds(5) : Budget).RelayAsync(c).AsTask())).PrimaryFailure!;
                        Require(ReferenceEquals(e, fault));
                    });
                });
        await check("budget late acknowledge preserves acknowledged count and delivery uncertainty", async () =>
        {
            var f = new Fixture(); var source = new Source(f); var sink = new Sink(); source.Ack = async token => { await Expired(token); return true; };
            await Context(f, async c => { var e = await Throws<TenantChangeAuditOutboxRelayException>(() => Relay(f, source, sink, Budget).RelayAsync(c).AsTask()); Require(e.AcknowledgedCount == 1 && e.MayHaveDelivered && e.PrimaryFailure is TimeoutException); });
            Require(source.Releases == 1);
        });
        await check("budget uncooperative sink completes before return and fresh replay deduplicates", async () =>
        {
            var f = new Fixture(); var source = new Source(f); var sink = new Sink(); var completed = false;
            sink.Append = async token => { await Expired(token); completed = true; };
            await Context(f, async c => { var e = await Throws<TenantChangeAuditOutboxRelayException>(() => Relay(f, source, sink, Budget).RelayAsync(c).AsTask()); Require(e.MayHaveDelivered && e.AcknowledgedCount == 0 && e.PrimaryFailure is TimeoutException); });
            Require(completed && sink.Receipts.Count == 1 && source.Acks == 0 && source.Releases == 1);
            sink.Append = null;
            await Context(f, async c => Require(await Relay(f, source, sink, TimeSpan.FromSeconds(5)).RelayAsync(c) == 1));
            Require(sink.Calls == 2 && sink.Receipts.Count == 1 && source.Releases == 2);
        });
        await check("budget independent release keeps primary and release failure references separate", async () =>
        {
            var f = new Fixture(); var source = new Source(f); var sink = new Sink(); var release = new IOException("Cleanup failure.");
            sink.Append = async token => { await Expired(token); token.ThrowIfCancellationRequested(); };
            source.Release = token => { Require(!token.IsCancellationRequested && token != sink.Token); throw release; };
            await Context(f, async c => { var e = await Throws<TenantChangeAuditOutboxRelayException>(() => Relay(f, source, sink, Budget).RelayAsync(c).AsTask()); Require(e.PrimaryFailure is TimeoutException && ReferenceEquals(e.ReleaseFailure, release) && e.MayHaveDelivered); });
        });
        await check("budget remains active during independent cleanup and final success veto", async () =>
        {
            var f = new Fixture(); var source = new Source(f); var sink = new Sink();
            source.Release = async token => { await Expired(source.ClaimToken); Require(!token.IsCancellationRequested); };
            await Context(f, async c => { var e = await Throws<TenantChangeAuditOutboxRelayException>(() => Relay(f, source, sink, Budget).RelayAsync(c).AsTask()); Require(e.PrimaryFailure is TimeoutException && e.ReleaseFailure is null && e.AcknowledgedCount == 1 && e.MayHaveDelivered); });
        });
        foreach (var operation in new[] { "document.update", "audit.history" })
            await check("budget ordinary operation cannot acquire relay authority " + operation, async () =>
            {
                var f = new Fixture(); var source = new Source(f); var sink = new Sink();
                await f.Run(async c => { await Throws<TenantAccessDeniedException>(() => Relay(f, source, sink, Budget).RelayAsync(c).AsTask()); }, operation);
                Require(source.Claims == 0 && sink.Calls == 0);
            });
        await check("budget expired checked scope prevents claim", async () =>
        {
            var f = new Fixture(); var source = new Source(f); var sink = new Sink();
            await Context(f, async c => { f.Clock.Advance(TimeSpan.FromMinutes(2)); await Throws<TenantAccessDeniedException>(() => Relay(f, source, sink, Budget).RelayAsync(c).AsTask()); });
            Require(source.Claims == 0 && sink.Calls == 0);
        });
        foreach (var invalid in new[] { "foreign", "expired-scope" })
            await check("budget postclaim authority rejects before publish and releases " + invalid, async () =>
            {
                var f = new Fixture(); var source = new Source(f); var sink = new Sink();
                source.Claim = _ => { if (invalid == "expired-scope") f.Clock.Advance(TimeSpan.FromMinutes(2)); return ValueTask.FromResult<TenantChangeAuditOutboxLease?>(source.Lease(invalid == "foreign" ? new("B") : new("A"))); };
                await Context(f, async c => { var e = await Throws<TenantChangeAuditOutboxRelayException>(() => Relay(f, source, sink, TimeSpan.FromSeconds(5)).RelayAsync(c).AsTask()); Require(e.PrimaryFailure is TenantAccessDeniedException && !e.MayHaveDelivered); });
                Require(sink.Calls == 0 && source.Acks == 0 && source.Releases == 1);
            });
    }
    sealed class Source(Fixture fixture) : ITenantChangeAuditOutboxSource
    {
        public int Claims, Acks, Releases;
        public CancellationToken ClaimToken, AckToken, ReleaseToken;
        public Func<CancellationToken, ValueTask<TenantChangeAuditOutboxLease?>>? Claim;
        public Func<CancellationToken, ValueTask<bool>>? Ack;
        public Func<CancellationToken, ValueTask>? Release;
        readonly TenantChangeAuditRecord record = Row();
        public TenantChangeAuditOutboxLease Lease(TenantId? tenant = null)
        {
            var owner = tenant ?? new TenantId("A");
            var row = owner.Value == "A" ? record : new TenantChangeAuditRecord(new(record.Receipt.ReceiptId, record.Receipt.Principal,
                record.Receipt.AuthenticationScheme, owner, record.Receipt.OperationId, record.Receipt.Action, record.Receipt.ResourceKind,
                record.Receipt.ResourceId, record.Receipt.AuthorizationResourceVersion, record.Receipt.Kind, record.Receipt.BeforeEntityVersion, record.Receipt.AfterEntityVersion), record.RecordedAtUtc, record.Mode, record.Fields);
            return new(owner, Guid.NewGuid(), fixture.Clock.Now.AddSeconds(15), [row]);
        }
        public ValueTask<TenantChangeAuditOutboxLease?> ClaimAsync(TenantId tenant, int maximum, TimeSpan duration, CancellationToken token)
        { Claims++; ClaimToken = token; return Claim?.Invoke(token) ?? ValueTask.FromResult<TenantChangeAuditOutboxLease?>(Lease()); }
        public ValueTask<bool> AcknowledgeAsync(TenantChangeAuditOutboxLease lease, Guid receiptId, CancellationToken token)
        { Acks++; AckToken = token; return Ack?.Invoke(token) ?? ValueTask.FromResult(true); }
        public ValueTask ReleaseAsync(TenantChangeAuditOutboxLease lease, CancellationToken token)
        { Releases++; ReleaseToken = token; return Release?.Invoke(token) ?? ValueTask.CompletedTask; }
    }
    sealed class Sink : ITenantChangeAuditIdempotentSink
    {
        public int Calls; public CancellationToken Token; public HashSet<Guid> Receipts { get; } = [];
        public Func<CancellationToken, ValueTask>? Append;
        public async ValueTask AppendOnceAsync(TenantChangeAuditRecord record, CancellationToken token)
        { Calls++; Token = token; if (Append is not null) await Append(token); Receipts.Add(record.Receipt.ReceiptId); }
    }
}
