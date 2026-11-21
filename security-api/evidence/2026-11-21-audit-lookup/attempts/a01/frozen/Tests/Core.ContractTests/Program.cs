using System.Runtime.InteropServices;
using System.Text.Json;
using Cehpalon.Engine.Core;

var checks = new List<object>();
var failures = 0;
var context = new OperationContext("core-contracts");

async Task Check(string name, Func<Task> test)
{
    try
    {
        await test();
        checks.Add(new { name, passed = true });
    }
    catch (Exception error)
    {
        failures++;
        checks.Add(new { name, passed = false, detail = error.ToString() });
    }
}
Task Sync(Action test) { test(); return Task.CompletedTask; }
void Assert(bool condition, string message = "Assertion failed")
{
    if (!condition) throw new InvalidOperationException(message);
}
T Throws<T>(Action action) where T : Exception
{
    try { action(); } catch (T error) { return error; }
    throw new InvalidOperationException("Expected " + typeof(T).Name);
}
async Task<T> ThrowsAsync<T>(Func<Task> action) where T : Exception
{
    try { await action(); } catch (T error) { return error; }
    throw new InvalidOperationException("Expected " + typeof(T).Name);
}
OperationDispatcher Dispatcher(Func<IOperationHandler<int, int>> factory)
    => new(new OperationRegistryBuilder().Register("test.run", factory).Build());

await Check("canonical-id-grammar-and-boundaries", () => Sync(() =>
{
    foreach (var value in new[] { "a", "test.run-1_v2", new string('a', 128) }) Assert(OperationId.IsValid(value));
    foreach (var value in new string?[] { null, "", " ", "A", "aB", "0a", "a/b", "a:b", "á", "a\n", "a\0", new('a', 129) })
    {
        Assert(!OperationId.IsValid(value));
        Throws<ArgumentException>(() => OperationId.RequireValid(value));
    }
}));
await Check("attribute-validates-id-without-handler-activation", () => Sync(() =>
{
    Assert(new OperationAttribute("catalog.get").Id == "catalog.get");
    Throws<ArgumentException>(() => new OperationAttribute("Catalog.Get"));
}));
await Check("success-result-and-error-access-guard", () => Sync(() =>
{
    var result = OperationResult<int>.Success(7);
    Assert(result.IsSuccess && result.Value == 7);
    Throws<InvalidOperationException>(() => _ = result.Error);
}));
await Check("failure-result-and-value-access-guard", () => Sync(() =>
{
    var error = new OperationError("catalog.missing", "The item does not exist.");
    var result = OperationResult<int>.Failure(error);
    Assert(!result.IsSuccess && ReferenceEquals(result.Error, error));
    Throws<InvalidOperationException>(() => _ = result.Value);
    Throws<ArgumentNullException>(() => OperationResult<int>.Failure(null!));
}));
await Check("nullable-success-is-intentional", () => Sync(() => Assert(OperationResult<string?>.Success(null).Value is null)));
await Check("error-code-message-contract", () => Sync(() =>
{
    Throws<ArgumentException>(() => new OperationError("Invalid", "safe"));
    Throws<ArgumentException>(() => new OperationError("valid", " "));
    Throws<ArgumentException>(() => new OperationError("valid", new('a', 4097)));
}));
await Check("context-defensive-snapshot-and-readonly-view", () => Sync(() =>
{
    var original = new Dictionary<string, string> { ["source"] = "first" };
    var snapshot = new OperationContext("correlation", original);
    original["source"] = "changed";
    original["new"] = "added";
    Assert(snapshot.CorrelationId == "correlation" && snapshot.Metadata["source"] == "first" && snapshot.Metadata.Count == 1);
    Throws<NotSupportedException>(() => ((IDictionary<string, string>)snapshot.Metadata).Add("tamper", "no"));
}));
await Check("context-rejects-invalid-and-unbounded-metadata", () => Sync(() =>
{
    Throws<ArgumentException>(() => new OperationContext(" "));
    Throws<ArgumentException>(() => new OperationContext(new('a', 257)));
    Throws<ArgumentException>(() => new OperationContext("ok", new[] { KeyValuePair.Create("key", "first"), KeyValuePair.Create("key", "second") }));
    Throws<ArgumentException>(() => new OperationContext("ok", new[] { KeyValuePair.Create(" ", "value") }));
    Throws<ArgumentNullException>(() => new OperationContext("ok", new[] { KeyValuePair.Create("key", (string)null!) }));
    Throws<ArgumentException>(() => new OperationContext("ok", new[] { KeyValuePair.Create(new string('k', 129), "value") }));
    Throws<ArgumentException>(() => new OperationContext("ok", new[] { KeyValuePair.Create("key", new string('v', 4097)) }));
    Throws<ArgumentException>(() => new OperationContext("ok", Enumerable.Range(0, 65).Select(x => KeyValuePair.Create("key"+x, "value"))));
}));
await Check("registration-build-and-enumeration-invoke-no-factory", () => Sync(() =>
{
    var calls = 0;
    var registry = new OperationRegistryBuilder().Register<int, int>("test.run", () => { calls++; return new Handler(); }).Build();
    Assert(registry.OperationIds.SequenceEqual(new[] { "test.run" }) && calls == 0);
}));
await Check("registry-snapshot-is-independent-and-ordinally-ordered", () => Sync(() =>
{
    var builder = new OperationRegistryBuilder().Register<int, int>("z", () => new Handler());
    var old = builder.Build();
    builder.Register<int, int>("a", () => new Handler());
    var current = builder.Build();
    Assert(old.OperationIds.SequenceEqual(new[] { "z" }));
    Assert(current.OperationIds.SequenceEqual(new[] { "a", "z" }));
    Throws<NotSupportedException>(() => ((IList<string>)current.OperationIds)[0] = "tamper");
}));
await Check("duplicate-invalid-and-null-factory-registration-rejected", () => Sync(() =>
{
    var builder = new OperationRegistryBuilder().Register<int, int>("test.run", () => new Handler());
    Throws<ArgumentException>(() => builder.Register<int, int>("test.run", () => new Handler()));
    Throws<ArgumentException>(() => builder.Register<int, int>("TEST.run", () => new Handler()));
    Throws<ArgumentNullException>(() => builder.Register<int, int>("other", null!));
}));
await Check("unknown-operation-returns-known-error-with-zero-factory", async () =>
{
    var calls = 0;
    var dispatcher = Dispatcher(() => { calls++; return new Handler(); });
    var result = await dispatcher.DispatchAsync<int, int>("test.unknown", 1, context);
    Assert(!result.IsSuccess && result.Error.Code == "operation.not_found" && calls == 0);
});
await Check("request-type-mismatch-does-zero-factory-work", async () =>
{
    var calls = 0;
    var dispatcher = Dispatcher(() => { calls++; return new Handler(); });
    var result = await dispatcher.DispatchAsync<string, int>("test.run", "wrong", context);
    Assert(!result.IsSuccess && result.Error.Code == "operation.contract_mismatch" && calls == 0);
});
await Check("response-type-mismatch-does-zero-factory-work", async () =>
{
    var calls = 0;
    var dispatcher = Dispatcher(() => { calls++; return new Handler(); });
    var result = await dispatcher.DispatchAsync<int, string>("test.run", 1, context);
    Assert(!result.IsSuccess && result.Error.Code == "operation.contract_mismatch" && calls == 0);
});
await Check("invalid-context-and-id-before-factory", async () =>
{
    var calls = 0;
    var dispatcher = Dispatcher(() => { calls++; return new Handler(); });
    await ThrowsAsync<ArgumentNullException>(() => dispatcher.DispatchAsync<int, int>("test.run", 1, null!).AsTask());
    await ThrowsAsync<ArgumentException>(() => dispatcher.DispatchAsync<int, int>("Bad", 1, context).AsTask());
    Assert(calls == 0);
});
await Check("already-canceled-dispatch-before-factory", async () =>
{
    var calls = 0;
    using var cts = new CancellationTokenSource(); cts.Cancel();
    var error = await ThrowsAsync<OperationCanceledException>(() => Dispatcher(() => { calls++; return new Handler(); }).DispatchAsync<int, int>("test.run", 1, context, cts.Token).AsTask());
    Assert(calls == 0 && error.CancellationToken == cts.Token);
});
await Check("handler-receives-request-context-and-exact-token", async () =>
{
    using var cts = new CancellationTokenSource();
    var handler = new Handler((request, suppliedContext, token) =>
    {
        Assert(request == 9 && ReferenceEquals(suppliedContext, context) && token == cts.Token);
        return ValueTask.FromResult(OperationResult<int>.Success(request * 2));
    });
    var result = await Dispatcher(() => handler).DispatchAsync<int, int>("test.run", 9, context, cts.Token);
    Assert(result.Value == 18 && handler.DisposeCalls == 1);
});
await Check("factory-triggered-cancellation-skips-handler-and-disposes-owned-instance", async () =>
{
    using var cts = new CancellationTokenSource();
    var businessCalls = 0;
    var handler = new Handler((request, _, _) => { businessCalls++; return ValueTask.FromResult(OperationResult<int>.Success(request)); });
    var error = await ThrowsAsync<OperationCanceledException>(() => Dispatcher(() => { cts.Cancel(); return handler; }).DispatchAsync<int, int>("test.run", 1, context, cts.Token).AsTask());
    Assert(error.CancellationToken == cts.Token && businessCalls == 0 && handler.DisposeCalls == 1);
});
await Check("business-failure-is-preserved-and-handler-disposed", async () =>
{
    var expected = new OperationError("business.denied", "The operation was denied.");
    var handler = new Handler((_, _, _) => ValueTask.FromResult(OperationResult<int>.Failure(expected)));
    var result = await Dispatcher(() => handler).DispatchAsync<int, int>("test.run", 0, context);
    Assert(ReferenceEquals(expected, result.Error) && handler.DisposeCalls == 1);
});
await Check("unexpected-exception-propagates-and-handler-disposed", async () =>
{
    var expected = new ApplicationException("fixture exception");
    var handler = new Handler((_, _, _) => throw expected);
    var actual = await ThrowsAsync<ApplicationException>(() => Dispatcher(() => handler).DispatchAsync<int, int>("test.run", 1, context).AsTask());
    Assert(ReferenceEquals(expected, actual) && handler.DisposeCalls == 1);
});
await Check("cooperative-cancellation-propagates-and-disposes", async () =>
{
    using var cts = new CancellationTokenSource();
    var handler = new Handler((_, _, token) => { cts.Cancel(); token.ThrowIfCancellationRequested(); return ValueTask.FromResult(OperationResult<int>.Success(1)); });
    var actual = await ThrowsAsync<OperationCanceledException>(() => Dispatcher(() => handler).DispatchAsync<int, int>("test.run", 1, context, cts.Token).AsTask());
    Assert(actual.CancellationToken == cts.Token && handler.DisposeCalls == 1);
});
await Check("asynchronous-disposal-is-awaited-before-completion", async () =>
{
    var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var handler = new AsyncHandler(async () => { entered.SetResult(); await release.Task; });
    var dispatch = Dispatcher(() => handler).DispatchAsync<int, int>("test.run", 2, context).AsTask();
    await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
    Assert(!dispatch.IsCompleted && handler.AsyncDisposeCalls == 1);
    release.SetResult();
    Assert((await dispatch.WaitAsync(TimeSpan.FromSeconds(5))).Value == 2);
});
await Check("async-disposal-preferred-over-sync-without-double-dispose", async () =>
{
    var handler = new AsyncHandler(() => ValueTask.CompletedTask);
    await Dispatcher(() => handler).DispatchAsync<int, int>("test.run", 2, context);
    Assert(handler.AsyncDisposeCalls == 1 && handler.SyncDisposeCalls == 0);
});
await Check("faulty-null-result-rejected-and-handler-disposed", async () =>
{
    var handler = new Handler((_, _, _) => ValueTask.FromResult<OperationResult<int>>(null!));
    await ThrowsAsync<InvalidOperationException>(() => Dispatcher(() => handler).DispatchAsync<int, int>("test.run", 1, context).AsTask());
    Assert(handler.DisposeCalls == 1);
});
await Check("faulty-null-factory-result-rejected", async () =>
{
    await ThrowsAsync<InvalidOperationException>(() => Dispatcher(() => null!).DispatchAsync<int, int>("test.run", 1, context).AsTask());
});
await Check("factory-exception-is-not-converted-to-business-error", async () =>
{
    var expected = new ApplicationException("factory failure");
    var actual = await ThrowsAsync<ApplicationException>(() => Dispatcher(() => throw expected).DispatchAsync<int, int>("test.run", 1, context).AsTask());
    Assert(ReferenceEquals(actual, expected));
});
await Check("cleanup-only-failure-propagates", async () =>
{
    var expected = new ApplicationException("cleanup failure");
    var handler = new Handler(cleanup: () => throw expected);
    var actual = await ThrowsAsync<ApplicationException>(() => Dispatcher(() => handler).DispatchAsync<int, int>("test.run", 1, context).AsTask());
    Assert(ReferenceEquals(expected, actual) && handler.DisposeCalls == 1);
});
await Check("execution-and-cleanup-failures-both-preserved-in-order", async () =>
{
    var execution = new ApplicationException("execution");
    var cleanup = new ApplicationException("cleanup");
    var handler = new Handler((_, _, _) => throw execution, () => throw cleanup);
    var actual = await ThrowsAsync<AggregateException>(() => Dispatcher(() => handler).DispatchAsync<int, int>("test.run", 1, context).AsTask());
    Assert(actual.InnerExceptions.Count == 2 && ReferenceEquals(actual.InnerExceptions[0], execution) && ReferenceEquals(actual.InnerExceptions[1], cleanup) && handler.DisposeCalls == 1);
});
await Check("cancellation-plus-cleanup-failure-retains-cancellation-token", async () =>
{
    using var cts = new CancellationTokenSource();
    var handler = new Handler((_, _, token) => { cts.Cancel(); throw new OperationCanceledException(token); }, () => throw new ApplicationException("cleanup"));
    var actual = await ThrowsAsync<AggregateException>(() => Dispatcher(() => handler).DispatchAsync<int, int>("test.run", 1, context, cts.Token).AsTask());
    Assert(actual.InnerExceptions[0] is OperationCanceledException canceled && canceled.CancellationToken == cts.Token && handler.DisposeCalls == 1);
});
await Check("concurrent-dispatches-use-independent-owned-handlers", async () =>
{
    const int count = 64;
    var factoryCalls = 0; var entered = 0; var disposed = 0;
    var allEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var dispatcher = Dispatcher(() =>
    {
        Interlocked.Increment(ref factoryCalls);
        return new Handler(async (request, supplied, _) =>
        {
            Assert(ReferenceEquals(supplied, context));
            if (Interlocked.Increment(ref entered) == count) allEntered.TrySetResult();
            await allEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            return OperationResult<int>.Success(request);
        }, () => Interlocked.Increment(ref disposed));
    });
    var results = await Task.WhenAll(Enumerable.Range(0, count).Select(value => Task.Run(async () =>
        await dispatcher.DispatchAsync<int, int>("test.run", value, context))));
    Assert(factoryCalls == count && entered == count && disposed == count && results.Select(x => x.Value).Order().SequenceEqual(Enumerable.Range(0,count)));
});
await Check("independent-callers-share-one-business-contract-and-handler", async () =>
{
    var dispatcher = Dispatcher(() => new Handler((request, _, _) => ValueTask.FromResult(OperationResult<int>.Success(request * 3))));
    async Task<int> CallerOne(int value) => (await dispatcher.DispatchAsync<int, int>("test.run", value, context)).Value;
    async Task<int> CallerTwo(int value) => (await dispatcher.DispatchAsync<int, int>("test.run", value, context)).Value;
    Assert(await CallerOne(4) == 12 && await CallerTwo(4) == 12);
});
await Check("core-assembly-has-only-bcl-references", () => Sync(() =>
{
    var names = typeof(OperationDispatcher).Assembly.GetReferencedAssemblies().Select(x => x.Name!).ToArray();
    Assert(names.All(x => x.StartsWith("System.", StringComparison.Ordinal) || x == "netstandard"), string.Join(",", names));
}));

var output = new
{
    observedAtUtc = DateTimeOffset.UtcNow,
    framework = RuntimeInformation.FrameworkDescription,
    os = RuntimeInformation.OSDescription,
    architecture = RuntimeInformation.ProcessArchitecture.ToString(),
    scope = "BCL-only experimental Core component contracts. Not tenant/identity authority, supported-Windows/hosted-CI/transport/provider/E2E/benchmark/production qualification.",
    passed = checks.Count - failures,
    failed = failures,
    tests = checks
};
var json = JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = true });
var outputArgument = args.SingleOrDefault(x => x.StartsWith("--output=", StringComparison.Ordinal));
if (outputArgument is not null)
{
    var path = Path.GetFullPath(outputArgument[9..]);
    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
    await File.WriteAllTextAsync(path, json + "\n");
}
Console.WriteLine(json);
return failures == 0 ? 0 : 1;

sealed class Handler(
    Func<int, OperationContext, CancellationToken, ValueTask<OperationResult<int>>>? action = null,
    Action? cleanup = null) : IOperationHandler<int, int>, IDisposable
{
    public int DisposeCalls { get; private set; }
    public ValueTask<OperationResult<int>> HandleAsync(int request, OperationContext context, CancellationToken cancellationToken)
        => action?.Invoke(request, context, cancellationToken) ?? ValueTask.FromResult(OperationResult<int>.Success(request));
    public void Dispose() { DisposeCalls++; cleanup?.Invoke(); }
}

sealed class AsyncHandler(Func<ValueTask> cleanup) : IOperationHandler<int, int>, IAsyncDisposable, IDisposable
{
    public int AsyncDisposeCalls { get; private set; }
    public int SyncDisposeCalls { get; private set; }
    public ValueTask<OperationResult<int>> HandleAsync(int request, OperationContext context, CancellationToken cancellationToken)
        => ValueTask.FromResult(OperationResult<int>.Success(request));
    public async ValueTask DisposeAsync() { AsyncDisposeCalls++; await cleanup(); }
    public void Dispose() => SyncDisposeCalls++;
}
