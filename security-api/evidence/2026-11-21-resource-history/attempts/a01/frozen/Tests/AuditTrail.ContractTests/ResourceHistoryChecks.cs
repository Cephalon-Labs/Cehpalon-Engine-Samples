using System.Collections.Concurrent;
using System.Text.Json;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;

static class ResourceHistoryChecks
{
    static void Require(bool value) { if (!value) throw new InvalidOperationException("Resource history assertion failed."); }
    static async Task<T> Throws<T>(Func<Task> body) where T : Exception
    { try { await body(); } catch (T error) { return error; } throw new InvalidOperationException("Expected " + typeof(T).Name); }
    static readonly Guid[] Keys = new[] { "00000000000000000000000000000001", "0000000000000000000000000000000f", "00000000000000000000000000000100", "0000000000000000ff00000000000000", "00000000000000010000000000000000", "000000000000ffff0000000000000000", "00000000ffffffff0000000000000000", "00000001000000000000000000000000", "7fffffffffffffffffffffffffffffff", "80000000000000000000000000000000", "ffffffffffffffffffffffffffffffff" }.Select(x => Guid.ParseExact(x, "N")).ToArray();
    static TenantChangeAuditPolicy Policy(TenantChangeAuditMode mode = TenantChangeAuditMode.BeforeAfterSnapshots)
        => new(mode, [new("document.update", "write", "document", [new("title"), new("secret", true), new("unchanged")])]);
    static TenantChangeAuditRecord Row(Guid id, string tenant = "A", string kind = "document", string resource = "entity", TenantChangeAuditMode mode = TenantChangeAuditMode.BeforeAfterSnapshots)
    {
        var fields = new List<TenantChangeField>();
        if (mode != TenantChangeAuditMode.MetadataOnly)
        {
            fields.Add(new("title", TenantChangeValue.Text("old"), TenantChangeValue.Text("new")));
            fields.Add(new("secret", TenantChangeValue.Text("private-before"), TenantChangeValue.Text("private-after")));
            fields.Add(new("unknown", TenantChangeValue.Text("unknown-old"), TenantChangeValue.Text("unknown-new")));
            if (mode == TenantChangeAuditMode.BeforeAfterSnapshots) fields.Add(new("unchanged", TenantChangeValue.Text("same"), TenantChangeValue.Text("same")));
        }
        return new(new(id, new("issuer", "alice"), "Bearer", new(tenant), "document.update", "write", kind, resource, "acl", TenantChangeKind.Update, "v1", "v2"), DateTimeOffset.Parse("2026-11-21T00:00:00Z"), mode, fields);
    }
    static TenantChangeAuditResourceCursor Cursor(Guid id, string tenant = "A", string kind = "document", string resource = "entity") => new(new(tenant), kind, resource, id);
    static TenantChangeAuditResourceQuery Query(int limit = 50, TenantChangeAuditResourceCursor? cursor = null, string kind = "document", string resource = "entity") => new(kind, resource, limit, cursor);
    public static async Task Run(Func<string, Func<Task>, Task> check)
    {
        await check("resource history typed contracts optional shape and immutable DTOs", () =>
        {
            var q = Query(); Require(q.Limit == 50 && q.Continuation is null);
            foreach (var type in new[] { typeof(TenantChangeAuditResourceCursor), typeof(TenantChangeAuditResourceQuery), typeof(TenantChangeAuditResourcePage) }) Require(type.GetProperties().All(p => p.SetMethod is null));
            var p = typeof(TenantChangeAuditResourceHistoryReader).GetMethod("ReadAsync")!.GetParameters(); Require(p.Length == 3 && p[1].ParameterType == typeof(TenantChangeAuditResourceQuery) && p[2].IsOptional);
            Require(typeof(ITenantChangeAuditHistorySource).GetMethods().Single().Name == "ReadAsync" && typeof(ITenantChangeAuditLookupSource).GetMethods().Single().Name == "FindAsync");
            return Task.CompletedTask;
        });
        foreach (var kind in new string?[] { null, "", "Document", "bad kind", "bad\n", new('k', 129) })
            await check("resource history invalid kind constructor " + (kind is null ? "null" : JsonSerializer.Serialize(kind)), async () =>
            { await Throws<ArgumentException>(() => { _ = Query(kind: kind!); return Task.CompletedTask; }); await Throws<ArgumentException>(() => { _ = Cursor(Keys[0], kind: kind!); return Task.CompletedTask; }); });
        foreach (var id in new string?[] { null, "", " ", "bad\n", "\ud800", new('x', 513) })
            await check("resource history invalid opaque id constructor " + (id is null ? "null" : JsonSerializer.Serialize(id)), async () =>
            { await Throws<ArgumentException>(() => { _ = Query(resource: id!); return Task.CompletedTask; }); await Throws<ArgumentException>(() => { _ = Cursor(Keys[0], resource: id!); return Task.CompletedTask; }); });
        foreach (var limit in new[] { 0, 201, int.MinValue, int.MaxValue })
            await check("resource history query bound rejects " + limit, async () => { await Throws<ArgumentOutOfRangeException>(() => { _ = Query(limit); return Task.CompletedTask; }); });
        await check("resource history inclusive boundaries unicode opaque id and cursor value selection", async () =>
        {
            Require(Query(1).Limit == 1 && Query(200).Limit == 200 && Query(kind: new('k', 128), resource: new('x', 512)).ResourceId.Length == 512);
            Require(Query(resource: "เอกสาร/😀:Case?").ResourceId == "เอกสาร/😀:Case?");
            await Throws<ArgumentNullException>(() => { _ = new TenantChangeAuditResourceCursor(null!, "document", "entity", Keys[0]); return Task.CompletedTask; });
            await Throws<ArgumentException>(() => { _ = Cursor(Guid.Empty); return Task.CompletedTask; });
        });
        await check("resource history page freezes input and read-only view", async () =>
        {
            var list = new List<TenantChangeAuditRecord> { Row(Keys[0]) }; var next = Cursor(Keys[0]); var page = new TenantChangeAuditResourcePage(list, next); list.Clear();
            Require(page.Entries.Count == 1 && ReferenceEquals(page.NextCursor, next)); await Throws<NotSupportedException>(() => { ((IList<TenantChangeAuditRecord>)page.Entries).Clear(); return Task.CompletedTask; });
            await Throws<ArgumentNullException>(() => { _ = new TenantChangeAuditResourcePage(null!); return Task.CompletedTask; });
            await Throws<ArgumentException>(() => { _ = new TenantChangeAuditResourcePage([null!]); return Task.CompletedTask; });
        });
        await check("resource history page bounds infinite enumeration at201 and disposes iterator", async () =>
        {
            var observed = 0; var disposed = false; IEnumerable<TenantChangeAuditRecord> Infinite() { try { while (true) { observed++; yield return Row(Keys[0]); } } finally { disposed = true; } }
            await Throws<ArgumentException>(() => { _ = new TenantChangeAuditResourcePage(Infinite()); return Task.CompletedTask; }); Require(observed == 201 && disposed);
            Require(new TenantChangeAuditResourcePage(Enumerable.Repeat(Row(Keys[0]), 200)).Entries.Count == 200);
        });
        await check("resource history disabled skips factory and construction", () =>
        {
            var before = Source.Constructors; var calls = 0; var disabled = Policy(TenantChangeAuditMode.Disabled);
            Require(TenantChangeAuditResourceHistoryReader.Activate(disabled, () => { calls++; throw new IOException(); }) is null && TenantChangeAuditResourceHistoryReader.Activate(disabled) is null && calls == 0 && before == Source.Constructors); return Task.CompletedTask;
        });
        foreach (var invalid in new[] { "source", "policy", "disabled", "activation-policy", "factory", "factory-null" })
            await check("resource history activation validation " + invalid, async () =>
            {
                if (invalid == "source") await Throws<ArgumentNullException>(() => { _ = new TenantChangeAuditResourceHistoryReader(null!, Policy()); return Task.CompletedTask; });
                if (invalid == "policy") await Throws<ArgumentNullException>(() => { _ = new TenantChangeAuditResourceHistoryReader(new Source(), null!); return Task.CompletedTask; });
                if (invalid == "disabled") await Throws<ArgumentException>(() => { _ = new TenantChangeAuditResourceHistoryReader(new Source(), Policy(TenantChangeAuditMode.Disabled)); return Task.CompletedTask; });
                if (invalid == "activation-policy") await Throws<ArgumentNullException>(() => { TenantChangeAuditResourceHistoryReader.Activate(null!); return Task.CompletedTask; });
                if (invalid == "factory") await Throws<ArgumentNullException>(() => { TenantChangeAuditResourceHistoryReader.Activate(Policy()); return Task.CompletedTask; });
                if (invalid == "factory-null") await Throws<ArgumentException>(() => { TenantChangeAuditResourceHistoryReader.Activate(Policy(), () => null!); return Task.CompletedTask; });
            });
        foreach (var invalid in new[] { "context", "query", "caller", "expired", "disposed" })
            await check("resource history admission rejection before query " + invalid, async () =>
            {
                var h = new Harness(); var s = new Source(); var reader = new TenantChangeAuditResourceHistoryReader(s, Policy());
                if (invalid == "context") await Throws<ArgumentNullException>(() => reader.ReadAsync(null!, Query()).AsTask());
                else if (invalid == "disposed") { TenantOperationContext? held = null; await h.Run(c => { held = c; return Task.CompletedTask; }); await Throws<TenantAccessDeniedException>(() => reader.ReadAsync(held!, Query()).AsTask()); }
                else await h.Run(async c =>
                {
                    if (invalid == "query") await Throws<ArgumentNullException>(() => reader.ReadAsync(c, null!).AsTask());
                    if (invalid == "caller") { using var caller = new CancellationTokenSource(); caller.Cancel(); Require((await Throws<OperationCanceledException>(() => reader.ReadAsync(c, Query(), caller.Token).AsTask())).CancellationToken == caller.Token); }
                    if (invalid == "expired") { h.Clock.Advance(); await Throws<TenantAccessDeniedException>(() => reader.ReadAsync(c, Query()).AsTask()); }
                }); Require(s.Calls == 0);
            });
        foreach (var wrong in new[] { "action", "kind", "resource", "relay", "operation-history" })
            await check("resource history scope denial differs from disabled activation " + wrong, async () =>
            {
                var h = new Harness(); var s = new Source(); var factories = 0; var reader = TenantChangeAuditResourceHistoryReader.Activate(Policy(), () => { factories++; return s; })!;
                await h.Run(async c => { await Throws<TenantAccessDeniedException>(() => reader.ReadAsync(c, Query()).AsTask()); }, action: wrong is "action" or "relay" ? "write" : "read", kind: wrong == "kind" ? "document" : wrong == "relay" ? "audit-outbox" : wrong == "operation-history" ? "audit-history" : "audit-trail", resource: wrong == "resource" ? "entity" : "tenant"); Require(factories == 1 && s.Calls == 0);
            });
        foreach (var poison in new[] { "tenant", "kind", "id", "id-case" })
            await check("resource history input cursor binding fails after scope before I/O " + poison, async () =>
            {
                var h = new Harness(); var s = new Source(); var cursor = Cursor(Keys[0], poison == "tenant" ? "B" : "A", poison == "kind" ? "other" : "document", poison == "id" ? "other" : poison == "id-case" ? "Entity" : "entity");
                var reader = new TenantChangeAuditResourceHistoryReader(s, Policy());
                await h.Run(async c => { await Throws<ArgumentException>(() => reader.ReadAsync(c, Query(cursor: cursor)).AsTask()); });
                await h.Run(async c => { await Throws<TenantAccessDeniedException>(() => reader.ReadAsync(c, Query(cursor: cursor)).AsTask()); }, kind: "document"); Require(s.Calls == 0);
            });
        await check("resource history source receives same immutable query and original caller token", async () =>
        {
            var h = new Harness(); var s = new Source(); var query = Query(1, Cursor(Keys[0])); using var caller = new CancellationTokenSource();
            await h.Run(async c => { var page = await new TenantChangeAuditResourceHistoryReader(s, Policy()).ReadAsync(c, query, caller.Token); Require(page.Entries.Count == 0); });
            var request = s.Requests.Single(); Require(request.Tenant.Value == "A" && ReferenceEquals(query, request.Query) && request.Token == caller.Token);
        });
        foreach (var cancel in new[] { false, true }) foreach (var oce in new[] { false, true })
            await check("resource history provider error exact reference " + cancel + oce, async () =>
            {
                var h = new Harness(); var s = new Source(); using var caller = new CancellationTokenSource(); Exception fault = oce ? new OperationCanceledException(new CancellationToken(true)) : new IOException("Provider failure.");
                s.Hook = (_, _, token) => { Require(token == caller.Token); if (cancel) caller.Cancel(); throw fault; };
                await h.Run(async c => Require(ReferenceEquals(await Throws<Exception>(() => new TenantChangeAuditResourceHistoryReader(s, Policy()).ReadAsync(c, Query(), caller.Token).AsTask()), fault))); Require(s.Calls == 1);
            });
        foreach (var poison in new[] { "null", "oversize", "tenant", "kind", "id", "id-case", "duplicate", "descending", "input-equal", "input-backwards", "late-duplicate" })
            await check("resource history whole page integrity before projection " + poison, async () =>
            {
                var h = new Harness(); var s = new Source(); var rows = new[] { Row(Keys[0]), Row(Keys[1]) }; var query = Query();
                if (poison == "null") s.Page = null!;
                else
                {
                    if (poison == "oversize") query = Query(1);
                    if (poison is "tenant" or "kind" or "id" or "id-case") rows[1] = Row(Keys[1], poison == "tenant" ? "B" : "A", poison == "kind" ? "other" : "document", poison == "id" ? "other" : poison == "id-case" ? "Entity" : "entity");
                    if (poison == "duplicate") rows[1] = Row(Keys[0]);
                    if (poison == "descending") rows = [Row(Keys[9]), Row(Keys[8])];
                    if (poison == "input-equal") query = Query(cursor: Cursor(Keys[0]));
                    if (poison == "input-backwards") query = Query(cursor: Cursor(Keys[2]));
                    if (poison == "late-duplicate") rows = [Row(Keys[0]), Row(Keys[1]), Row(Keys[1])];
                    s.Page = new(rows);
                }
                await h.Run(async c => { await Throws<InvalidOperationException>(() => new TenantChangeAuditResourceHistoryReader(s, Policy(TenantChangeAuditMode.MetadataOnly)).ReadAsync(c, query).AsTask()); }); Require(s.Calls == 1);
            });
        foreach (var poison in new[] { "empty", "tenant", "kind", "id", "id-case", "before-last", "after-last" })
            await check("resource history output cursor integrity " + poison, async () =>
            {
                var h = new Harness(); var s = new Source(); var next = Cursor(poison == "before-last" ? Keys[0] : poison == "after-last" ? Keys[2] : Keys[1], poison == "tenant" ? "B" : "A", poison == "kind" ? "other" : "document", poison == "id" ? "other" : poison == "id-case" ? "Entity" : "entity");
                s.Page = new(poison == "empty" ? [] : [Row(Keys[1])], next);
                await h.Run(async c => { await Throws<InvalidOperationException>(() => new TenantChangeAuditResourceHistoryReader(s, Policy()).ReadAsync(c, Query()).AsTask()); }); Require(s.Calls == 1);
            });
        foreach (var count in new[] { 0, 1, 50, 200 })
            await check("resource history legal empty short full bounded page " + count, async () =>
            {
                var h = new Harness(); var s = new Source(); var rows = Enumerable.Range(1, count).Select(i => Row(Guid.ParseExact(i.ToString("x32"), "N"))).ToArray(); s.Page = new(rows);
                await h.Run(async c => { var page = await new TenantChangeAuditResourceHistoryReader(s, Policy()).ReadAsync(c, Query(count == 200 ? 200 : 50)); Require(page.Entries.Count == count && page.NextCursor is null && !ReferenceEquals(page, s.Page)); });
            });
        await check("resource history underfilled continuation and changed page size are legal", async () =>
        {
            var h = new Harness(); var s = new Source { Page = new([Row(Keys[0])], Cursor(Keys[0])) }; var reader = new TenantChangeAuditResourceHistoryReader(s, Policy());
            await h.Run(async c => { var first = await reader.ReadAsync(c, Query(50)); Require(first.Entries.Count == 1 && first.NextCursor!.AfterReceiptId == Keys[0]); s.Page = new([Row(Keys[1])]); var second = await reader.ReadAsync(c, Query(1, first.NextCursor)); Require(second.Entries.Single().Receipt.ReceiptId == Keys[1]); }); Require(s.Calls == 2);
        });
        await check("resource history canonical high-bit receipt order is not recorded-time order", async () =>
        {
            Require(Keys.Select(k => k.ToString("N")).SequenceEqual(Keys.Select(k => k.ToString("N")).Order(StringComparer.Ordinal)));
            var h = new Harness(); var s = new Source { Page = new(Keys.Select((key, index) => { var row = Row(key); return new TenantChangeAuditRecord(row.Receipt, row.RecordedAtUtc.AddMinutes(-index), row.Mode, row.Fields); })) };
            await h.Run(async c => { var page = await new TenantChangeAuditResourceHistoryReader(s, Policy()).ReadAsync(c, Query()); Require(page.Entries.Select(r => r.Receipt.ReceiptId).SequenceEqual(Keys) && page.Entries[0].RecordedAtUtc > page.Entries[^1].RecordedAtUtc); });
        });
        await check("resource history caller-constructed bound bookmark needs no row or authenticity", async () =>
        {
            var h = new Harness(); var s = new Source { Page = new([Row(Keys[2])]) }; var query = Query(cursor: Cursor(Keys[1]));
            await h.Run(async c => { Require((await new TenantChangeAuditResourceHistoryReader(s, Policy()).ReadAsync(c, query)).Entries.Single().Receipt.ReceiptId == Keys[2]); }); Require(s.Calls == 1 && ReferenceEquals(s.Requests.Single().Query, query));
        });
        foreach (var capture in new[] { TenantChangeAuditMode.MetadataOnly, TenantChangeAuditMode.ChangedFields, TenantChangeAuditMode.BeforeAfterSnapshots })
            foreach (var current in new[] { TenantChangeAuditMode.MetadataOnly, TenantChangeAuditMode.ChangedFields, TenantChangeAuditMode.BeforeAfterSnapshots })
                await check("resource history current-policy capture projection " + capture + current, async () =>
                {
                    var h = new Harness(); var raw = Row(Keys[0], mode: capture); var s = new Source { Page = new([raw], Cursor(Keys[0])) };
                    await h.Run(async c =>
                    {
                        var page = await new TenantChangeAuditResourceHistoryReader(s, Policy(current)).ReadAsync(c, Query()); var row = page.Entries.Single();
                        var mode = capture == TenantChangeAuditMode.MetadataOnly || current == TenantChangeAuditMode.MetadataOnly ? TenantChangeAuditMode.MetadataOnly : capture == TenantChangeAuditMode.ChangedFields || current == TenantChangeAuditMode.ChangedFields ? TenantChangeAuditMode.ChangedFields : TenantChangeAuditMode.BeforeAfterSnapshots;
                        Require(!ReferenceEquals(row, raw) && row.Mode == mode && row.CapturedMode == capture && row.Fields.Count == (mode == TenantChangeAuditMode.MetadataOnly ? 0 : mode == TenantChangeAuditMode.ChangedFields ? 2 : 3));
                        Require(page.NextCursor == s.Page.NextCursor && row.Fields.All(f => f.Name != "unknown") && !JsonSerializer.Serialize(row).Contains("private-", StringComparison.Ordinal));
                        if (row.Fields.Count > 0) { var secret = row.Fields.Single(f => f.Name == "secret"); Require(secret.Before.Kind == TenantChangeValueKind.Redacted && secret.After.Kind == TenantChangeValueKind.Redacted && secret.WasChanged); }
                    });
                });
        await check("resource history immutable captured policy requires explicitly selected new reader", async () =>
        {
            var h = new Harness(); var s = new Source { Page = new([Row(Keys[0])]) }; var rules = new List<TenantChangeAuditRule> { new("document.update", "write", "document", [new("title")]) }; var configured = new TenantChangeAuditPolicy(TenantChangeAuditMode.BeforeAfterSnapshots, rules); var original = new TenantChangeAuditResourceHistoryReader(s, configured); rules.Clear();
            configured = new(TenantChangeAuditMode.BeforeAfterSnapshots, [new("document.update", "write", "document", [new("title", true)])]); var tightened = new TenantChangeAuditResourceHistoryReader(s, configured);
            await h.Run(async c => { Require((await original.ReadAsync(c, Query())).Entries.Single().Fields.Single().Before.TextValue == "old"); var row = (await tightened.ReadAsync(c, Query())).Entries.Single(); Require(row.Fields.Count == 1 && row.Fields[0].Before.Kind == TenantChangeValueKind.Redacted && row.Fields[0].After.Kind == TenantChangeValueKind.Redacted); });
        });
        await check("resource history unknown rule and prior reduced capture never manufacture fields", async () =>
        {
            var h = new Harness(); var raw = Row(Keys[0]); var reduced = new TenantChangeAuditRecord(raw.Receipt, raw.RecordedAtUtc, TenantChangeAuditMode.ChangedFields, raw.Fields.Where(f => f.WasChanged), TenantChangeAuditMode.BeforeAfterSnapshots); var s = new Source { Page = new([reduced]) };
            await h.Run(async c => { var row = (await new TenantChangeAuditResourceHistoryReader(s, Policy()).ReadAsync(c, Query())).Entries.Single(); Require(row.Mode == TenantChangeAuditMode.ChangedFields && row.CapturedMode == TenantChangeAuditMode.BeforeAfterSnapshots && row.Fields.All(f => f.Name != "unchanged")); var metadata = (await new TenantChangeAuditResourceHistoryReader(s, new(TenantChangeAuditMode.BeforeAfterSnapshots)).ReadAsync(c, Query())).Entries.Single(); Require(metadata.Mode == TenantChangeAuditMode.MetadataOnly && metadata.Fields.Count == 0); });
        });
        foreach (var empty in new[] { false, true }) foreach (var outcome in new[] { "caller", "expiry" })
            await check("resource history held source completion guard " + empty + outcome, async () =>
            {
                var h = new Harness(); var s = new Source { Page = new(empty ? [] : [Row(Keys[0])]) }; var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); using var caller = new CancellationTokenSource();
                s.Hook = async (_, _, _) => { entered.TrySetResult(); await finish.Task; return s.Page; };
                await h.Run(async c =>
                {
                    var pending = new TenantChangeAuditResourceHistoryReader(s, Policy()).ReadAsync(c, Query(), caller.Token).AsTask();
                    try { await entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); if (outcome == "caller") caller.Cancel(); else h.Clock.Advance(); Require(!pending.IsCompleted); }
                    finally { finish.TrySetResult(); try { await pending; } catch (Exception) { } }
                    if (outcome == "caller") Require((await Throws<OperationCanceledException>(() => pending)).CancellationToken == caller.Token); else await Throws<TenantAccessDeniedException>(() => pending);
                }); Require(s.Calls == 1);
            });
        foreach (var empty in new[] { false, true })
            await check("resource history pending source cannot outlive disposed checked scope " + empty, async () =>
            {
                var h = new Harness(); var s = new Source { Page = new(empty ? [] : [Row(Keys[0])]) }; var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); Task<TenantChangeAuditResourcePage>? pending = null;
                s.Hook = async (_, _, _) => { entered.TrySetResult(); await finish.Task; return s.Page; };
                try { await h.Run(async c => { pending = new TenantChangeAuditResourceHistoryReader(s, Policy()).ReadAsync(c, Query()).AsTask(); await entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); Require(!pending.IsCompleted); }); }
                finally { finish.TrySetResult(); if (pending is not null) { try { await pending; } catch (Exception) { } } }
                Require(pending is not null); await Throws<TenantAccessDeniedException>(() => pending!); Require(s.Calls == 1);
            });
        await check("resource history cooperative source cancellation preserves original error object", async () =>
        {
            var h = new Harness(); var s = new Source(); var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); using var caller = new CancellationTokenSource(); OperationCanceledException? sourceFault = null;
            s.Hook = async (_, _, token) => { entered.TrySetResult(); try { await finish.Task.WaitAsync(token); } catch (OperationCanceledException e) { sourceFault = e; throw; } return s.Page; };
            await h.Run(async c =>
            {
                var pending = new TenantChangeAuditResourceHistoryReader(s, Policy()).ReadAsync(c, Query(), caller.Token).AsTask();
                try { await entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); caller.Cancel(); var failure = await Throws<OperationCanceledException>(() => pending).WaitAsync(TimeSpan.FromSeconds(5)); Require(ReferenceEquals(failure, sourceFault) && failure.CancellationToken == caller.Token); }
                finally { finish.TrySetResult(); caller.Cancel(); try { await pending; } catch (Exception) { } }
            }); Require(s.Calls == 1);
        });
        foreach (var empty in new[] { false, true }) foreach (var cancel in new[] { false, true })
            await check("resource history final guards include empty and projected page " + empty + cancel, async () =>
            {
                var h = new Harness(); var s = new Source { Page = new(empty ? [] : [Row(Keys[0])]) }; using var caller = new CancellationTokenSource();
                s.After = () => h.Clock.OnNthUtc(cancel ? 1 : 2, () => { if (cancel) caller.Cancel(); else h.Clock.Advance(); });
                await h.Run(async c => { var pending = new TenantChangeAuditResourceHistoryReader(s, Policy()).ReadAsync(c, Query(), caller.Token).AsTask(); if (cancel) Require((await Throws<OperationCanceledException>(() => pending)).CancellationToken == caller.Token); else await Throws<TenantAccessDeniedException>(() => pending); }); Require(s.Calls == 1);
            });
        foreach (var empty in new[] { false, true })
            await check("resource history expired live scope remains latched after clock restoration " + empty, async () =>
            {
                var h = new Harness(); var s = new Source { Page = new(empty ? [] : [Row(Keys[0])]), After = h.Clock.Advance }; var reader = new TenantChangeAuditResourceHistoryReader(s, Policy());
                await h.Run(async c => { await Throws<TenantAccessDeniedException>(() => reader.ReadAsync(c, Query()).AsTask()); h.Clock.Restore(); await Throws<TenantAccessDeniedException>(() => reader.ReadAsync(c, Query()).AsTask()); }); Require(s.Calls == 1);
            });
        await check("resource history same receipt across tenants kinds and opaque resources remains partitioned", async () =>
        {
            var h = new Harness(); var s = new Source(); s.Hook = (tenant, query, _) => ValueTask.FromResult(new TenantChangeAuditResourcePage([Row(Keys[0], tenant.Value, query.ResourceKind, query.ResourceId)])); var reader = new TenantChangeAuditResourceHistoryReader(s, Policy());
            foreach (var selection in new[] { ("A", "document", "entity"), ("B", "document", "entity"), ("A", "other", "entity"), ("A", "document", "Entity"), ("A", "document", "เอกสาร/หนึ่ง") })
                await h.Run(async c => { var row = (await reader.ReadAsync(c, Query(kind: selection.Item2, resource: selection.Item3))).Entries.Single(); Require(row.Receipt.Tenant.Value == selection.Item1 && row.Receipt.ResourceKind == selection.Item2 && row.Receipt.ResourceId == selection.Item3 && row.Receipt.ReceiptId == Keys[0]); }, selection.Item1);
            Require(s.Calls == 5 && s.Requests.Select(r => (r.Tenant.Value, r.Query.ResourceKind, r.Query.ResourceId)).Distinct().Count() == 5);
        });
        await check("resource history eight independently scheduled queries share only live checked scope", async () =>
        {
            var h = new Harness(); var s = new Source(); var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var calls = 0;
            s.Hook = async (tenant, query, _) => { Require(tenant.Value == "A"); if (Interlocked.Increment(ref calls) == 8) entered.TrySetResult(); await finish.Task; return new([Row(Keys[0], resource: query.ResourceId)]); };
            await h.Run(async c =>
            {
                var reader = new TenantChangeAuditResourceHistoryReader(s, Policy()); var pending = Enumerable.Range(0, 8).Select(index => Task.Run(async () => await reader.ReadAsync(c, Query(resource: "entity" + index)))).ToArray();
                try { await entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); Require(pending.All(t => !t.IsCompleted)); }
                finally { finish.TrySetResult(); try { await Task.WhenAll(pending); } catch (Exception) { } }
                var pages = await Task.WhenAll(pending); Require(pages.Select(p => p.Entries.Single().Receipt.ResourceId).Distinct().Count() == 8);
            }); Require(s.Calls == 8 && h.Identities == 1);
        });
    }
    sealed class Source : ITenantChangeAuditResourceHistorySource
    {
        public static int Constructors; public Source() { Interlocked.Increment(ref Constructors); }
        public int Calls; public TenantChangeAuditResourcePage Page = new([]); public Action? After;
        public ConcurrentQueue<(TenantId Tenant, TenantChangeAuditResourceQuery Query, CancellationToken Token)> Requests { get; } = new();
        public Func<TenantId, TenantChangeAuditResourceQuery, CancellationToken, ValueTask<TenantChangeAuditResourcePage>>? Hook;
        public async ValueTask<TenantChangeAuditResourcePage> ReadAsync(TenantId tenant, TenantChangeAuditResourceQuery query, CancellationToken token)
        { Interlocked.Increment(ref Calls); Requests.Enqueue((tenant, query, token)); var page = Hook is null ? Page : await Hook(tenant, query, token); After?.Invoke(); return page; }
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
            var registry = new TenantOperationRegistryBuilder().Register<string, bool>("trail.resource-history", action, kind, x => x, x => new(new(tenant), x), () => new Handler(async c => { entered = true; try { await callback(c); } catch (Exception e) { failure = e; throw; } })).Build();
            var services = new TenantSecurityServices(this, new(["issuer"], ["Bearer"]), this, this, TimeSpan.FromMinutes(1), this, Clock);
            await new TenantOperationDispatcher(registry, services).DispatchAsync<string, bool>("trail.resource-history", resource, new("resource-history-fixture"));
            if (failure is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw(); Require(entered);
        }
        sealed class Handler(Func<TenantOperationContext, Task> callback) : ITenantOperationHandler<string, bool>
        { public async ValueTask<OperationResult<bool>> HandleAsync(string request, TenantOperationContext context, CancellationToken token) { await callback(context); return OperationResult<bool>.Success(true); } }
    }
}
