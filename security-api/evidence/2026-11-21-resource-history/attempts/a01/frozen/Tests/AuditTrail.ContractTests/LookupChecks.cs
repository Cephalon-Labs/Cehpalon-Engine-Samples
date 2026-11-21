using System.Collections.Concurrent;
using System.Text.Json;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;

static class LookupChecks
{
    static void Require(bool value) { if (!value) throw new InvalidOperationException("Lookup contract assertion failed."); }
    static async Task<T> Throws<T>(Func<Task> body) where T : Exception
    { try { await body(); } catch (T error) { return error; } throw new InvalidOperationException("Expected " + typeof(T).Name); }
    static TenantChangeAuditPolicy Policy(TenantChangeAuditMode mode = TenantChangeAuditMode.BeforeAfterSnapshots)
        => new(mode, [new("document.update", "write", "document", [new("title"), new("secret", true), new("unchanged")])]);
    static TenantChangeAuditRecord Row(Guid id, string tenant = "A", TenantChangeAuditMode mode = TenantChangeAuditMode.BeforeAfterSnapshots)
    {
        var fields = new List<TenantChangeField>();
        if (mode != TenantChangeAuditMode.MetadataOnly)
        {
            fields.Add(new("title", TenantChangeValue.Text("old"), TenantChangeValue.Text("new")));
            fields.Add(new("secret", TenantChangeValue.Text("sensitive-before"), TenantChangeValue.Text("sensitive-after")));
            fields.Add(new("unknown", TenantChangeValue.Text("hidden-old"), TenantChangeValue.Text("hidden-new")));
            if (mode == TenantChangeAuditMode.BeforeAfterSnapshots) fields.Add(new("unchanged", TenantChangeValue.Text("same"), TenantChangeValue.Text("same")));
        }
        return new(new(id, new("issuer", "alice"), "Bearer", new(tenant), "document.update", "write", "document", "entity", "acl", TenantChangeKind.Update, "v1", "v2"), DateTimeOffset.Parse("2026-11-21T00:00:00Z"), mode, fields);
    }
    public static async Task Run(Func<string, Func<Task>, Task> check)
    {
        await check("lookup separate optional source and default cancellation signature", () =>
        {
            var p = typeof(TenantChangeAuditLookupReader).GetMethod("FindAsync")!.GetParameters();
            Require(p.Length == 3 && p[1].ParameterType == typeof(Guid) && p[2].IsOptional);
            Require(typeof(ITenantChangeAuditLookupSource).GetMethods().Single().Name == "FindAsync" && typeof(ITenantChangeAuditHistorySource).GetMethods().Single().Name == "ReadAsync");
            return Task.CompletedTask;
        });
        await check("lookup disabled skips poisoned source factory and construction", () =>
        {
            var calls = 0; var constructors = Source.Constructors; var disabled = Policy(TenantChangeAuditMode.Disabled);
            Require(TenantChangeAuditLookupReader.Activate(disabled, () => { calls++; throw new IOException(); }) is null && TenantChangeAuditLookupReader.Activate(disabled) is null);
            Require(calls == 0 && Source.Constructors == constructors); return Task.CompletedTask;
        });
        foreach (var invalid in new[] { "null-source", "null-policy", "disabled", "null-activation-policy", "null-factory", "null-result" })
            await check("lookup activation validation " + invalid, async () =>
            {
                if (invalid == "null-source") await Throws<ArgumentNullException>(() => { _ = new TenantChangeAuditLookupReader(null!, Policy()); return Task.CompletedTask; });
                if (invalid == "null-policy") await Throws<ArgumentNullException>(() => { _ = new TenantChangeAuditLookupReader(new Source(), null!); return Task.CompletedTask; });
                if (invalid == "disabled") await Throws<ArgumentException>(() => { _ = new TenantChangeAuditLookupReader(new Source(), Policy(TenantChangeAuditMode.Disabled)); return Task.CompletedTask; });
                if (invalid == "null-activation-policy") await Throws<ArgumentNullException>(() => { TenantChangeAuditLookupReader.Activate(null!); return Task.CompletedTask; });
                if (invalid == "null-factory") await Throws<ArgumentNullException>(() => { TenantChangeAuditLookupReader.Activate(Policy()); return Task.CompletedTask; });
                if (invalid == "null-result") await Throws<ArgumentException>(() => { TenantChangeAuditLookupReader.Activate(Policy(), () => null!); return Task.CompletedTask; });
            });
        foreach (var invalid in new[] { "null-context", "empty-id", "pre-caller", "expired", "disposed" })
            await check("lookup invalid admission performs zero query " + invalid, async () =>
            {
                var h = new Harness(); var s = new Source(); var reader = new TenantChangeAuditLookupReader(s, Policy()); var id = Guid.NewGuid();
                if (invalid == "null-context") await Throws<ArgumentNullException>(() => reader.FindAsync(null!, id).AsTask());
                else if (invalid == "disposed") { TenantOperationContext? held = null; await h.Run(c => { held = c; return Task.CompletedTask; }); await Throws<TenantAccessDeniedException>(() => reader.FindAsync(held!, id).AsTask()); }
                else await h.Run(async c =>
                {
                    if (invalid == "empty-id") await Throws<ArgumentException>(() => reader.FindAsync(c, Guid.Empty).AsTask());
                    if (invalid == "expired") { h.Clock.Advance(); await Throws<TenantAccessDeniedException>(() => reader.FindAsync(c, id).AsTask()); }
                    if (invalid == "pre-caller") { using var caller = new CancellationTokenSource(); caller.Cancel(); Require((await Throws<OperationCanceledException>(() => reader.FindAsync(c, id, caller.Token).AsTask())).CancellationToken == caller.Token); }
                });
                Require(s.Calls == 0);
            });
        foreach (var wrong in new[] { "action", "kind", "resource", "relay", "operation-history" })
            await check("lookup wrong scope denies query on already activated reader " + wrong, async () =>
            {
                var h = new Harness(); var s = new Source(); var factories = 0; var reader = TenantChangeAuditLookupReader.Activate(Policy(), () => { factories++; return s; })!;
                await h.Run(async c => { await Throws<TenantAccessDeniedException>(() => reader.FindAsync(c, Guid.NewGuid()).AsTask()); },
                    action: wrong is "action" or "relay" ? "write" : "read", kind: wrong == "kind" ? "document" : wrong == "relay" ? "audit-outbox" : wrong == "operation-history" ? "audit-history" : "audit-trail", resource: wrong == "resource" ? "entity" : "tenant");
                Require(factories == 1 && s.Calls == 0);
            });
        foreach (var none in new[] { false, true })
            await check("lookup exact caller token tenant and id reaches source " + none, async () =>
            {
                var h = new Harness(); var s = new Source(); var id = Guid.NewGuid(); s.Result = none ? null : Row(id); using var caller = new CancellationTokenSource();
                await h.Run(async c => { var found = await new TenantChangeAuditLookupReader(s, Policy()).FindAsync(c, id, caller.Token); Require(none ? found is null : found!.Receipt.ReceiptId == id); });
                var request = s.Requests.Single(); Require(request.Tenant.Value == "A" && request.Id == id && request.Token == caller.Token);
            });
        foreach (var cancel in new[] { false, true }) foreach (var faultKind in new[] { "io", "oce" })
            await check("lookup provider fault exact reference without normalization " + cancel + faultKind, async () =>
            {
                var h = new Harness(); var s = new Source(); using var caller = new CancellationTokenSource(); Exception fault = faultKind == "io" ? new IOException("Trusted lookup failure.") : new OperationCanceledException(new CancellationToken(true));
                s.Hook = (_, _, token) => { Require(token == caller.Token); if (cancel) caller.Cancel(); throw fault; };
                await h.Run(async c => Require(ReferenceEquals(await Throws<Exception>(() => new TenantChangeAuditLookupReader(s, Policy()).FindAsync(c, Guid.NewGuid(), caller.Token).AsTask()), fault)));
                Require(s.Calls == 1);
            });
        foreach (var wrong in new[] { "tenant", "id", "both" })
            await check("lookup provider identity poison rejected before projection " + wrong, async () =>
            {
                var h = new Harness(); var id = Guid.NewGuid(); var s = new Source { Result = Row(wrong is "id" or "both" ? Guid.NewGuid() : id, wrong is "tenant" or "both" ? "B" : "A") };
                await h.Run(async c => { await Throws<InvalidOperationException>(() => new TenantChangeAuditLookupReader(s, Policy(TenantChangeAuditMode.MetadataOnly)).FindAsync(c, id).AsTask()); }); Require(s.Calls == 1);
            });
        foreach (var captured in new[] { TenantChangeAuditMode.MetadataOnly, TenantChangeAuditMode.ChangedFields, TenantChangeAuditMode.BeforeAfterSnapshots })
            foreach (var current in new[] { TenantChangeAuditMode.MetadataOnly, TenantChangeAuditMode.ChangedFields, TenantChangeAuditMode.BeforeAfterSnapshots })
                await check("lookup current-policy projection and capture provenance " + captured + current, async () =>
                {
                    var h = new Harness(); var id = Guid.NewGuid(); var raw = Row(id, mode: captured); var s = new Source { Result = raw };
                    await h.Run(async c =>
                    {
                        var projected = (await new TenantChangeAuditLookupReader(s, Policy(current)).FindAsync(c, id))!;
                        var mode = captured == TenantChangeAuditMode.MetadataOnly || current == TenantChangeAuditMode.MetadataOnly ? TenantChangeAuditMode.MetadataOnly : captured == TenantChangeAuditMode.ChangedFields || current == TenantChangeAuditMode.ChangedFields ? TenantChangeAuditMode.ChangedFields : TenantChangeAuditMode.BeforeAfterSnapshots;
                        Require(!ReferenceEquals(projected, raw) && projected.Mode == mode && projected.CapturedMode == captured && projected.Receipt.ReceiptId == id && projected.RecordedAtUtc == raw.RecordedAtUtc);
                        Require(projected.Fields.Count == (mode == TenantChangeAuditMode.MetadataOnly ? 0 : mode == TenantChangeAuditMode.ChangedFields ? 2 : 3));
                        Require(projected.Fields.All(f => f.Name != "unknown") && !JsonSerializer.Serialize(projected).Contains("sensitive", StringComparison.Ordinal));
                        if (projected.Fields.Count > 0) { var secret = projected.Fields.Single(f => f.Name == "secret"); Require(secret.Before.Kind == TenantChangeValueKind.Redacted && secret.After.Kind == TenantChangeValueKind.Redacted && secret.WasChanged); }
                        await Throws<NotSupportedException>(() => { ((IList<TenantChangeField>)projected.Fields).Clear(); return Task.CompletedTask; });
                    });
                    Require(s.Result == raw && (captured == TenantChangeAuditMode.MetadataOnly || JsonSerializer.Serialize(raw).Contains("sensitive", StringComparison.Ordinal)));
                });
        foreach (var mismatch in new[] { "none", "operation", "action", "kind" })
            await check("lookup unmatched read rule strips all fields " + mismatch, async () =>
            {
                var h = new Harness(); var id = Guid.NewGuid(); var s = new Source { Result = Row(id) };
                var policy = new TenantChangeAuditPolicy(TenantChangeAuditMode.BeforeAfterSnapshots, mismatch == "none" ? [] : [new(mismatch == "operation" ? "other.update" : "document.update", mismatch == "action" ? "other" : "write", mismatch == "kind" ? "other" : "document", [new("title")])]);
                await h.Run(async c => { var r = (await new TenantChangeAuditLookupReader(s, policy).FindAsync(c, id))!; Require(r.Fields.Count == 0 && r.Mode == TenantChangeAuditMode.MetadataOnly && r.CapturedMode == TenantChangeAuditMode.BeforeAfterSnapshots); });
            });
        await check("lookup tightened read policy redacts title and immutable policy is captured", async () =>
        {
            var h = new Harness(); var id = Guid.NewGuid(); var s = new Source { Result = Row(id) }; var rules = new List<TenantChangeAuditRule> { new("document.update", "write", "document", [new("title")]) };
            var configured = new TenantChangeAuditPolicy(TenantChangeAuditMode.BeforeAfterSnapshots, rules); var prior = new TenantChangeAuditLookupReader(s, configured); rules.Clear();
            configured = new(TenantChangeAuditMode.BeforeAfterSnapshots, [new("document.update", "write", "document", [new("title", true)])]); var tightened = new TenantChangeAuditLookupReader(s, configured);
            await h.Run(async c => { var a = (await prior.FindAsync(c, id))!; var b = (await tightened.FindAsync(c, id))!; Require(a.Fields.Single().Before.TextValue == "old" && b.Fields.Count == 1 && b.Fields[0].Before.Kind == TenantChangeValueKind.Redacted && b.Fields[0].After.Kind == TenantChangeValueKind.Redacted); });
        });
        await check("lookup cannot manufacture missing snapshots from prior projection", async () =>
        {
            var h = new Harness(); var id = Guid.NewGuid(); var raw = Row(id); var projected = new TenantChangeAuditRecord(raw.Receipt, raw.RecordedAtUtc, TenantChangeAuditMode.ChangedFields, raw.Fields.Where(f => f.WasChanged), TenantChangeAuditMode.BeforeAfterSnapshots); var s = new Source { Result = projected };
            await h.Run(async c => { var r = (await new TenantChangeAuditLookupReader(s, Policy()).FindAsync(c, id))!; Require(r.Mode == TenantChangeAuditMode.ChangedFields && r.CapturedMode == TenantChangeAuditMode.BeforeAfterSnapshots && r.Fields.All(f => f.Name != "unchanged")); });
        });
        foreach (var none in new[] { false, true }) foreach (var outcome in new[] { "caller", "expiry" })
            await check("lookup held uncooperative source post-await guard " + none + outcome, async () =>
            {
                var h = new Harness(); var id = Guid.NewGuid(); var s = new Source { Result = none ? null : Row(id) }; var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); using var caller = new CancellationTokenSource();
                s.Hook = async (_, _, _) => { entered.TrySetResult(); await finish.Task; return s.Result; };
                await h.Run(async c =>
                {
                    var pending = new TenantChangeAuditLookupReader(s, Policy()).FindAsync(c, id, caller.Token).AsTask();
                    try { await entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); if (outcome == "caller") caller.Cancel(); else h.Clock.Advance(); Require(!pending.IsCompleted); }
                    finally { finish.TrySetResult(); try { await pending; } catch (Exception) { } }
                    if (outcome == "caller") Require((await Throws<OperationCanceledException>(() => pending)).CancellationToken == caller.Token); else await Throws<TenantAccessDeniedException>(() => pending);
                }); Require(s.Calls == 1);
            });
        await check("lookup cooperative provider cancellation preserves exact provider OCE and joins", async () =>
        {
            var h = new Harness(); var s = new Source(); var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); using var caller = new CancellationTokenSource(); OperationCanceledException? sourceFault = null;
            s.Hook = async (_, _, token) => { entered.TrySetResult(); try { await finish.Task.WaitAsync(token); } catch (OperationCanceledException e) { sourceFault = e; throw; } return null; };
            await h.Run(async c =>
            {
                var pending = new TenantChangeAuditLookupReader(s, Policy()).FindAsync(c, Guid.NewGuid(), caller.Token).AsTask();
                try { await entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); caller.Cancel(); var failure = await Throws<OperationCanceledException>(() => pending).WaitAsync(TimeSpan.FromSeconds(5)); Require(ReferenceEquals(failure, sourceFault) && failure.CancellationToken == caller.Token); }
                finally { finish.TrySetResult(); caller.Cancel(); try { await pending; } catch (Exception) { } }
            }); Require(s.Calls == 1);
        });
        foreach (var none in new[] { false, true })
            await check("lookup owned pending source cannot outlive checked scope authority " + none, async () =>
            {
                var h = new Harness(); var id = Guid.NewGuid(); var s = new Source { Result = none ? null : Row(id) }; var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); Task<TenantChangeAuditRecord?>? pending = null;
                s.Hook = async (_, _, _) => { entered.TrySetResult(); await finish.Task; return s.Result; };
                try { await h.Run(async c => { pending = new TenantChangeAuditLookupReader(s, Policy()).FindAsync(c, id).AsTask(); await entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); Require(!pending.IsCompleted); }); }
                finally { finish.TrySetResult(); if (pending is not null) { try { await pending; } catch (Exception) { } } }
                Require(pending is not null); await Throws<TenantAccessDeniedException>(() => pending!); Require(s.Calls == 1);
            });
        foreach (var none in new[] { false, true })
            await check("lookup null or record final guard observes caller and scope " + none, async () =>
            {
                foreach (var cancel in new[] { false, true })
                {
                    var h = new Harness(); var id = Guid.NewGuid(); var s = new Source { Result = none ? null : Row(id) }; using var caller = new CancellationTokenSource();
                    s.After = () => h.Clock.OnNthUtc(cancel ? 1 : 2, () => { if (cancel) caller.Cancel(); else h.Clock.Advance(); });
                    await h.Run(async c => { var pending = new TenantChangeAuditLookupReader(s, Policy()).FindAsync(c, id, caller.Token).AsTask(); if (cancel) Require((await Throws<OperationCanceledException>(() => pending)).CancellationToken == caller.Token); else await Throws<TenantAccessDeniedException>(() => pending); }); Require(s.Calls == 1);
                }
            });
        foreach (var none in new[] { false, true })
            await check("lookup post-await expiry latches checked scope invalid " + none, async () =>
            {
                var h = new Harness(); var id = Guid.NewGuid(); var s = new Source { Result = none ? null : Row(id), After = h.Clock.Advance }; var reader = new TenantChangeAuditLookupReader(s, Policy());
                await h.Run(async c => { await Throws<TenantAccessDeniedException>(() => reader.FindAsync(c, id).AsTask()); h.Clock.Restore(); await Throws<TenantAccessDeniedException>(() => reader.FindAsync(c, id).AsTask()); }); Require(s.Calls == 1);
            });
        await check("lookup same receipt in A and B stays tenant isolated", async () =>
        {
            var h = new Harness(); var id = Guid.NewGuid(); var a = Row(id); var b = Row(id, "B"); var s = new Source(); s.Hook = (tenant, _, _) => ValueTask.FromResult<TenantChangeAuditRecord?>(tenant.Value == "A" ? a : b); var reader = new TenantChangeAuditLookupReader(s, Policy());
            foreach (var tenant in new[] { "A", "B" }) await h.Run(async c => { var r = (await reader.FindAsync(c, id))!; Require(r.Receipt.Tenant.Value == tenant && r.Receipt.ReceiptId == id); }, tenant);
            Require(s.Requests.Select(q => q.Tenant.Value).SequenceEqual(new[] { "A", "B" }));
        });
        await check("lookup independent scheduled reads share immutable policy without tenant authority refresh", async () =>
        {
            var h = new Harness(); var s = new Source(); var rows = Enumerable.Range(0, 8).Select(_ => Row(Guid.NewGuid())).ToDictionary(r => r.Receipt.ReceiptId); var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var calls = 0;
            s.Hook = async (tenant, id, _) => { Require(tenant.Value == "A"); if (Interlocked.Increment(ref calls) == 8) entered.TrySetResult(); await finish.Task; return rows[id]; };
            await h.Run(async c =>
            {
                var reader = new TenantChangeAuditLookupReader(s, Policy()); var pending = rows.Keys.Select(id => Task.Run(async () => await reader.FindAsync(c, id))).ToArray();
                try { await entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); Require(pending.All(t => !t.IsCompleted)); }
                finally { finish.TrySetResult(); try { await Task.WhenAll(pending); } catch (Exception) { } }
                var found = await Task.WhenAll(pending); Require(found.All(r => r is not null) && found.Select(r => r!.Receipt.ReceiptId).ToHashSet().SetEquals(rows.Keys));
            }); Require(s.Calls == 8 && h.Identities == 1);
        });
    }
    sealed class Source : ITenantChangeAuditLookupSource
    {
        public static int Constructors; public Source() { Interlocked.Increment(ref Constructors); }
        public int Calls; public TenantChangeAuditRecord? Result; public Action? After;
        public ConcurrentQueue<(TenantId Tenant, Guid Id, CancellationToken Token)> Requests { get; } = new();
        public Func<TenantId, Guid, CancellationToken, ValueTask<TenantChangeAuditRecord?>>? Hook;
        public async ValueTask<TenantChangeAuditRecord?> FindAsync(TenantId tenant, Guid id, CancellationToken token)
        { Interlocked.Increment(ref Calls); Requests.Enqueue((tenant, id, token)); var result = Hook is null ? Result : await Hook(tenant, id, token); After?.Invoke(); return result; }
    }
    sealed class ProbeClock : TimeProvider
    {
        static readonly DateTimeOffset Initial = DateTimeOffset.Parse("2026-11-21T00:00:00Z"); public DateTimeOffset Now = Initial; long ticks; int remaining; Action? action;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override DateTimeOffset GetUtcNow() { if (action is not null && --remaining == 0) { var run = action; action = null; run(); } return Now; }
        public override long GetTimestamp() => ticks;
        public void Advance() { Now += TimeSpan.FromMinutes(2); ticks += TimeSpan.FromMinutes(2).Ticks; }
        public void Restore() { Now = Initial; ticks = 0; }
        public void OnNthUtc(int read, Action callback) { remaining = read; action = callback; }
    }
    sealed class Harness : IIdentitySource, ITenantMembershipSource, IResourceScopeSource, ITenantAccessPolicy
    {
        public ProbeClock Clock { get; } = new(); public int Identities;
        public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken token) { Identities++; return ValueTask.FromResult<IdentitySnapshot?>(new(new("issuer", "alice"), "Bearer", Clock.Now.AddMinutes(-1), Clock.Now.AddMinutes(10))); }
        public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot identity, TenantId tenant, CancellationToken token) => ValueTask.FromResult<TenantMembershipSnapshot?>(new(identity.Principal, tenant, true, Clock.Now.AddMinutes(-1), Clock.Now.AddMinutes(10), "member"));
        public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId tenant, string kind, string id, CancellationToken token) => ValueTask.FromResult<ResourceScopeSnapshot?>(new(tenant, kind, id, "acl"));
        public ValueTask<bool> IsAllowedAsync(TenantAccessRequest request, CancellationToken token) => ValueTask.FromResult(true);
        public async Task Run(Func<TenantOperationContext, Task> callback, string tenant = "A", string action = "read", string kind = "audit-trail", string resource = "tenant")
        {
            var entered = false; Exception? failure = null;
            var registry = new TenantOperationRegistryBuilder().Register<string, bool>("trail.lookup", action, kind, x => x, x => new(new(tenant), x), () => new Handler(async c => { entered = true; try { await callback(c); } catch (Exception e) { failure = e; throw; } })).Build();
            var services = new TenantSecurityServices(this, new(["issuer"], ["Bearer"]), this, this, TimeSpan.FromMinutes(1), this, Clock);
            await new TenantOperationDispatcher(registry, services).DispatchAsync<string, bool>("trail.lookup", resource, new("lookup-fixture"));
            if (failure is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw(); Require(entered);
        }
        sealed class Handler(Func<TenantOperationContext, Task> callback) : ITenantOperationHandler<string, bool>
        { public async ValueTask<OperationResult<bool>> HandleAsync(string request, TenantOperationContext context, CancellationToken token) { await callback(context); return OperationResult<bool>.Success(true); } }
    }
}
