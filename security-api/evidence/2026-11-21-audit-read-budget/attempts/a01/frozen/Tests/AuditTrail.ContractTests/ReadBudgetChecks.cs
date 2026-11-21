using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;

static class ReadBudgetChecks
{
    static readonly TimeSpan Short = TimeSpan.FromSeconds(1), Long = TimeSpan.FromMinutes(1);
    static readonly Guid Id = Guid.Parse("00000000-0000-0000-0000-000000000001");
    static void Require(bool value) { if (!value) throw new InvalidOperationException("Read budget assertion failed."); }
    static async Task<T> Throws<T>(Func<Task> body) where T : Exception
    { try { await body(); } catch (T error) { return error; } throw new InvalidOperationException("Expected " + typeof(T).Name); }
    static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    static TenantChangeAuditPolicy Policy(bool disabled = false) => new(disabled ? TenantChangeAuditMode.Disabled : TenantChangeAuditMode.BeforeAfterSnapshots,
        [new("document.update", "write", "document", [new("title"), new("secret", true)])]);
    static TenantChangeAuditRecord Row(string tenant = "A") => new(new(Id, new("issuer", "alice"), "Bearer", new(tenant), "document.update", "write", "document", "entity", "acl", TenantChangeKind.Update),
        DateTimeOffset.UnixEpoch, TenantChangeAuditMode.BeforeAfterSnapshots, [new("title", TenantChangeValue.Text("old"), TenantChangeValue.Text("new")), new("secret", TenantChangeValue.Text("private"), TenantChangeValue.Text("private-new")), new("unknown", TenantChangeValue.Text("hidden"), TenantChangeValue.Text("hidden-new"))]);
    static object? Activate(int lane, Source source, TimeSpan? timeout, string mode = "budget", bool disabled = false, Action? factory = null)
    {
        var policy = Policy(disabled);
        Source Get() { factory?.Invoke(); return source; }
        return lane switch
        {
            0 => mode == "ctor" ? new TenantChangeAuditHistoryReader(source, policy) : mode == "legacy" ? TenantChangeAuditHistoryReader.Activate(policy, Get) : TenantChangeAuditHistoryReader.ActivateWithBudget(policy, timeout, Get),
            1 => mode == "ctor" ? new TenantChangeAuditLookupReader(source, policy) : mode == "legacy" ? TenantChangeAuditLookupReader.Activate(policy, Get) : TenantChangeAuditLookupReader.ActivateWithBudget(policy, timeout, Get),
            _ => mode == "ctor" ? new TenantChangeAuditResourceHistoryReader(source, policy) : mode == "legacy" ? TenantChangeAuditResourceHistoryReader.Activate(policy, Get) : TenantChangeAuditResourceHistoryReader.ActivateWithBudget(policy, timeout, Get)
        };
    }
    static async Task<object?> Read(object reader, TenantOperationContext context, CancellationToken token = default, bool invalid = false)
        => reader switch
        {
            TenantChangeAuditHistoryReader history => await history.ReadAsync(context, invalid ? 0 : 50, cancellationToken: token),
            TenantChangeAuditLookupReader lookup => await lookup.FindAsync(context, invalid ? Guid.Empty : Id, token),
            TenantChangeAuditResourceHistoryReader resource => await resource.ReadAsync(context, new("document", "entity", continuation: invalid ? new(new("B"), "document", "entity", Id) : null), token),
            _ => throw new InvalidOperationException()
        };
    static TenantChangeAuditRecord? Result(object? result) => result switch
    { TenantChangeAuditPage p => p.Entries.SingleOrDefault(), TenantChangeAuditResourcePage p => p.Entries.SingleOrDefault(), TenantChangeAuditRecord r => r, _ => null };
    public static async Task Run(Func<string, Func<Task>, Task> check)
    {
        foreach (var lane in new[] { 0, 1, 2 })
        {
            var label = new[] { "history", "lookup", "resource" }[lane];
            Task Case(string name, Func<Task> body) => check("read budget " + label + " " + name, body);
            await Case("disabled ignores invalid bounds and poisoned factory", () =>
            {
                var calls = 0;
                foreach (var bound in new TimeSpan?[] { null, TimeSpan.Zero, TimeSpan.FromTicks(-1), Long + TimeSpan.FromTicks(1) })
                    Require(Activate(lane, new(), bound, disabled: true, factory: () => { calls++; throw new IOException(); }) is null);
                Require(calls == 0); return Task.CompletedTask;
            });
            await Case("enabled invalid bounds precede factory", async () =>
            {
                var calls = 0;
                foreach (var bound in new[] { TimeSpan.Zero, TimeSpan.FromTicks(-1), Long + TimeSpan.FromTicks(1) })
                    await Throws<ArgumentOutOfRangeException>(() => { Activate(lane, new(), bound, factory: () => calls++); return Task.CompletedTask; });
                Require(calls == 0);
            });
            await Case("positive inclusive bound activation is lazy", () =>
            {
                var source = new Source(); var factories = 0;
                foreach (var bound in new[] { TimeSpan.FromTicks(1), Long }) Require(Activate(lane, source, bound, factory: () => factories++) is not null);
                Require(factories == 2 && source.Calls == 0); return Task.CompletedTask;
            });
            await Case("constructor legacy and null preserve tokens and exact provider faults", async () =>
            {
                foreach (var mode in new[] { "ctor", "legacy", "budget" }) foreach (var oce in new[] { false, true })
                {
                    var h = new Harness(); var s = new Source(); using var caller = new CancellationTokenSource();
                    Exception fault = oce ? new OperationCanceledException(new CancellationToken(true)) : new IOException();
                    s.Hook = token => { Require(token == caller.Token); caller.Cancel(); throw fault; };
                    await h.Run(async c => Require(ReferenceEquals(await Throws<Exception>(() => Read(Activate(lane, s, null, mode)!, c, caller.Token)), fault)));
                }
            });
            await Case("null preserves original final caller guard ordering", async () =>
            {
                foreach (var mode in new[] { "ctor", "legacy", "budget" })
                {
                    var h = new Harness(); var s = new Source(); using var caller = new CancellationTokenSource(); s.After = () => h.Clock.Arm(1, caller.Cancel);
                    await h.Run(async c => { var pending = Read(Activate(lane, s, null, mode)!, c, caller.Token); if (lane == 0) Require(Result(await pending) is not null); else Require((await Throws<OperationCanceledException>(() => pending)).CancellationToken == caller.Token); });
                }
            });
            await Case("invalid pre-cancel denied and cursor reject before source", async () =>
            {
                foreach (var kind in new[] { "input", "caller", "scope" })
                {
                    var h = new Harness(); var s = new Source(); var reader = Activate(lane, s, Long)!; using var caller = new CancellationTokenSource();
                    await h.Run(async c =>
                    {
                        if (kind == "caller") caller.Cancel(); if (kind == "scope") h.Clock.Advance();
                        if (kind == "input") await Throws<ArgumentException>(() => Read(reader, c, caller.Token, true));
                        else if (kind == "caller") Require((await Throws<OperationCanceledException>(() => Read(reader, c, caller.Token))).CancellationToken == caller.Token);
                        else await Throws<TenantAccessDeniedException>(() => Read(reader, c, caller.Token));
                    }); Require(s.Calls == 0);
                }
            });
            await Case("configured linked token successful policy projection", async () =>
            {
                var h = new Harness(); var s = new Source(); using var caller = new CancellationTokenSource(); var reader = Activate(lane, s, Long)!;
                await h.Run(async c => { var row = Result(await Read(reader, c, caller.Token))!; Require(s.Token.CanBeCanceled && s.Token != caller.Token && !s.Token.IsCancellationRequested && row.Receipt.Tenant.Value == "A" && row.Fields.Count == 2 && row.Fields.Single(f => f.Name == "secret").After.Kind == TenantChangeValueKind.Redacted); });
                caller.Cancel(); Require(!s.Token.IsCancellationRequested && s.Calls == 1);
            });
            await Case("configured tenant integrity before policy publication", async () =>
            {
                var h = new Harness(); var s = new Source { Record = Row("B") };
                await h.Run(async c => { await Throws<InvalidOperationException>(() => Read(Activate(lane, s, Long)!, c)); }); Require(s.Calls == 1);
            });
            await Case("cooperative private cancellation normalizes exact inner OCE", async () =>
            {
                var h = new Harness(); var s = new Source(); var signals = new Signals(); OperationCanceledException? original = null;
                s.Hook = async token => { await signals.Cancellation(token); original = new(token); throw original; };
                await h.Run(async c =>
                {
                    var pending = Read(Activate(lane, s, Short)!, c);
                    try { await signals.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); await signals.Expired.Task.WaitAsync(TimeSpan.FromSeconds(5)); signals.Finish.TrySetResult(); Require(ReferenceEquals((await Throws<TimeoutException>(() => pending)).InnerException, original)); }
                    finally { signals.Finish.TrySetResult(); await Join(pending); }
                });
            });
            await Case("caller cancellation normalizes original token and inner", async () =>
            {
                var h = new Harness(); var s = new Source(); using var caller = new CancellationTokenSource(); var signals = new Signals(); OperationCanceledException? original = null;
                s.Hook = async token => { await signals.Cancellation(token); original = new(token); throw original; };
                await h.Run(async c =>
                {
                    var pending = Read(Activate(lane, s, Long)!, c, caller.Token);
                    try { await signals.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); caller.Cancel(); await signals.Expired.Task.WaitAsync(TimeSpan.FromSeconds(5)); signals.Finish.TrySetResult(); var error = await Throws<OperationCanceledException>(() => pending); Require(error.CancellationToken == caller.Token && ReferenceEquals(error.InnerException, original)); }
                    finally { caller.Cancel(); signals.Finish.TrySetResult(); await Join(pending); }
                });
            });
            await Case("observed budget then caller wins at primary selection", async () =>
            {
                var h = new Harness(); var s = new Source(); using var caller = new CancellationTokenSource(); var signals = new Signals(); OperationCanceledException? original = null;
                s.Hook = async token => { await signals.Hold(token); caller.Cancel(); original = new(token); throw original; };
                await h.Run(async c =>
                {
                    var pending = Read(Activate(lane, s, Short)!, c, caller.Token);
                    try { await signals.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); await signals.Expired.Task.WaitAsync(TimeSpan.FromSeconds(5)); Require(!caller.IsCancellationRequested && !pending.IsCompleted); signals.Finish.TrySetResult(); var error = await Throws<OperationCanceledException>(() => pending); Require(error.CancellationToken == caller.Token && ReferenceEquals(error.InnerException, original)); }
                    finally { signals.Finish.TrySetResult(); await Join(pending); }
                });
            });
            await Case("foreign OCE and late non-OCE retain exact references", async () =>
            {
                var h = new Harness(); var s = new Source(); var foreign = new OperationCanceledException(new CancellationToken(true));
                s.Hook = token => { Require(!token.IsCancellationRequested); throw foreign; };
                await h.Run(async c => Require(ReferenceEquals(await Throws<OperationCanceledException>(() => Read(Activate(lane, s, Long)!, c)), foreign)));
                var late = new IOException(); var signals = new Signals(); s.Hook = async token => { await signals.Hold(token); throw late; };
                await new Harness().Run(async c =>
                {
                    var pending = Read(Activate(lane, s, Short)!, c);
                    try { await signals.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); await signals.Expired.Task.WaitAsync(TimeSpan.FromSeconds(5)); signals.Finish.TrySetResult(); Require(ReferenceEquals(await Throws<IOException>(() => pending), late)); }
                    finally { signals.Finish.TrySetResult(); await Join(pending); }
                });
            });
            foreach (var empty in new[] { false, true })
                await Case("uncooperative " + (empty ? "empty or null" : "populated") + " result stays owned after private signal", async () =>
                {
                    var h = new Harness(); var s = new Source { Empty = empty }; var signals = new Signals(); s.Hook = signals.Hold;
                    await h.Run(async c =>
                    {
                        var pending = Read(Activate(lane, s, Short)!, c);
                        try { await signals.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); await signals.Expired.Task.WaitAsync(TimeSpan.FromSeconds(5)); Require(!pending.IsCompleted); signals.Finish.TrySetResult(); await Throws<TimeoutException>(() => pending); }
                        finally { signals.Finish.TrySetResult(); await Join(pending); }
                    });
                });
            await Case("final publication private budget veto after live scope includes empty", async () =>
            {
                foreach (var empty in new[] { false, true })
                {
                    var h = new Harness(); var s = new Source { Empty = empty }; var final = Signal(); var finish = Signal(); var expired = Signal();
                    s.After = () => h.Clock.Arm(2, () => { final.TrySetResult(); finish.Task.GetAwaiter().GetResult(); });
                    await h.Run(async c =>
                    {
                        var pending = Task.Run(() => Read(Activate(lane, s, Short)!, c));
                        try
                        {
                            await final.Task.WaitAsync(TimeSpan.FromSeconds(5));
                            using var registration = s.Token.Register(() => expired.TrySetResult());
                            await expired.Task.WaitAsync(TimeSpan.FromSeconds(5)); Require(!pending.IsCompleted); finish.TrySetResult(); await Throws<TimeoutException>(() => pending);
                        }
                        finally { finish.TrySetResult(); await Join(pending); }
                    });
                }
            });
            await Case("post-await scope denial latches and final caller veto", async () =>
            {
                var h = new Harness(); var s = new Source { After = null }; s.After = h.Clock.Advance; var reader = Activate(lane, s, Long)!;
                await h.Run(async c => { await Throws<TenantAccessDeniedException>(() => Read(reader, c)); h.Clock.Restore(); await Throws<TenantAccessDeniedException>(() => Read(reader, c)); }); Require(s.Calls == 1);
                foreach (var empty in new[] { false, true })
                {
                    var other = new Harness(); var source = new Source { Empty = empty }; using var caller = new CancellationTokenSource(); source.After = () => other.Clock.Arm(2, caller.Cancel);
                    await other.Run(async c => Require((await Throws<OperationCanceledException>(() => Read(Activate(lane, source, Long)!, c, caller.Token))).CancellationToken == caller.Token));
                }
            });
        }
    }
    static async Task Join(Task pending) { try { await pending; } catch (Exception) { } }
    sealed class Signals
    {
        internal TaskCompletionSource Entered { get; } = Signal(); internal TaskCompletionSource Expired { get; } = Signal(); internal TaskCompletionSource Finish { get; } = Signal();
        internal async ValueTask Hold(CancellationToken token)
        { using var registration = token.Register(() => Expired.TrySetResult()); Entered.TrySetResult(); await Finish.Task; }
        internal async ValueTask Cancellation(CancellationToken token)
        { using var registration = token.Register(() => Expired.TrySetResult()); Entered.TrySetResult(); await Task.WhenAny(Expired.Task, Finish.Task); }
    }
    sealed class Source : ITenantChangeAuditHistorySource, ITenantChangeAuditLookupSource, ITenantChangeAuditResourceHistorySource
    {
        internal int Calls; internal CancellationToken Token; internal bool Empty; internal TenantChangeAuditRecord Record = Row(); internal Action? After;
        internal Func<CancellationToken, ValueTask>? Hook;
        async ValueTask Before(CancellationToken token) { Calls++; Token = token; if (Hook is not null) await Hook(token); After?.Invoke(); }
        public async ValueTask<TenantChangeAuditPage> ReadAsync(TenantId tenant, int limit, string? cursor, CancellationToken token) { await Before(token); return new(Empty ? [] : [Record]); }
        public async ValueTask<TenantChangeAuditRecord?> FindAsync(TenantId tenant, Guid id, CancellationToken token) { await Before(token); return Empty ? null : Record; }
        public async ValueTask<TenantChangeAuditResourcePage> ReadAsync(TenantId tenant, TenantChangeAuditResourceQuery query, CancellationToken token) { await Before(token); return new(Empty ? [] : [Record]); }
    }
    sealed class ProbeClock : TimeProvider
    {
        static readonly DateTimeOffset Initial = DateTimeOffset.Parse("2026-11-21T00:00:00Z"); internal DateTimeOffset Now = Initial; long ticks; int remaining; Action? action;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override DateTimeOffset GetUtcNow() { if (action is not null && --remaining == 0) { var next = action; action = null; next(); } return Now; }
        public override long GetTimestamp() => ticks;
        internal void Arm(int reads, Action next) { remaining = reads; action = next; }
        internal void Advance() { Now += TimeSpan.FromMinutes(2); ticks += TimeSpan.FromMinutes(2).Ticks; }
        internal void Restore() { Now = Initial; ticks = 0; }
    }
    sealed class Harness : IIdentitySource, ITenantMembershipSource, IResourceScopeSource, ITenantAccessPolicy
    {
        internal ProbeClock Clock { get; } = new();
        public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken token) => ValueTask.FromResult<IdentitySnapshot?>(new(new("issuer", "alice"), "Bearer", Clock.Now.AddMinutes(-1), Clock.Now.AddMinutes(10)));
        public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot identity, TenantId tenant, CancellationToken token) => ValueTask.FromResult<TenantMembershipSnapshot?>(new(identity.Principal, tenant, true, Clock.Now.AddMinutes(-1), Clock.Now.AddMinutes(10), "member"));
        public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId tenant, string kind, string id, CancellationToken token) => ValueTask.FromResult<ResourceScopeSnapshot?>(new(tenant, kind, id, "acl"));
        public ValueTask<bool> IsAllowedAsync(TenantAccessRequest request, CancellationToken token) => ValueTask.FromResult(true);
        internal async Task Run(Func<TenantOperationContext, Task> callback)
        {
            Exception? failure = null; var entered = false;
            var registry = new TenantOperationRegistryBuilder().Register<string, bool>("trail.read-budget", "read", "audit-trail", x => x, x => new(new("A"), x), () => new Handler(async c => { entered = true; try { await callback(c); } catch (Exception e) { failure = e; throw; } })).Build();
            var services = new TenantSecurityServices(this, new(["issuer"], ["Bearer"]), this, this, TimeSpan.FromMinutes(1), this, Clock);
            await new TenantOperationDispatcher(registry, services).DispatchAsync<string, bool>("trail.read-budget", "tenant", new("read-budget-fixture"));
            if (failure is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw(); Require(entered);
        }
        sealed class Handler(Func<TenantOperationContext, Task> callback) : ITenantOperationHandler<string, bool>
        { public async ValueTask<OperationResult<bool>> HandleAsync(string request, TenantOperationContext context, CancellationToken token) { await callback(context); return OperationResult<bool>.Success(true); } }
    }
}
