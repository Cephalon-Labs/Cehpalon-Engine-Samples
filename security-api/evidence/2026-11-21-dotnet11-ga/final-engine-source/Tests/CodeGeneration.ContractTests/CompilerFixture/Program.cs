using System.Text.Json;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Generated;

var builder = new OperationRegistryBuilder();
var factory = new OwnedFactory();
OperationRegistrations.RegisterAll(builder, factory);
if (factory.Calls != 0) throw new InvalidOperationException("Registration eagerly created a handler");
var dispatcher = new OperationDispatcher(builder.Build());
var result = await dispatcher.DispatchAsync<EchoRequest, EchoReply>("fixture.echo", new("business"), new("consumer"));
if (!result.IsSuccess || result.Value.Text != "business:injected" || factory.Calls != 1 || EchoHandler.Disposed != 1)
    throw new InvalidOperationException("Generated dispatch or ownership failed");
using var cancel = new CancellationTokenSource();
cancel.Cancel();
try
{
    await dispatcher.DispatchAsync<EchoRequest,EchoReply>("fixture.echo",new("cancelled"),new("consumer"),cancel.Token);
    throw new InvalidOperationException("Expected cancellation");
}
catch (OperationCanceledException) { }
if (factory.Calls != 1) throw new InvalidOperationException("Cancellation created a handler");
var budget = new OperationConcurrencyBudget(1);
var bounded = await budget.DispatchAsync<EchoRequest, EchoReply>(dispatcher, "fixture.echo", new("bounded"), new("consumer"));
if (!bounded.IsSuccess || bounded.Value.Text != "bounded:injected" || factory.Calls != 2 || EchoHandler.Disposed != 2)
    throw new InvalidOperationException("Generated dispatch through the concurrency budget failed");
Console.WriteLine(JsonSerializer.Serialize(new { passed = true, handler_factory_calls = factory.Calls, handler_disposals = EchoHandler.Disposed, result = result.Value.Text, scope = "Actual SDK compiler analyzer load, generated typed registration and Core dispatch; no transport or hosted CI proof" }));

internal sealed record EchoRequest(string Text);
internal sealed record EchoReply(string Text);

[Operation("fixture.echo")]
internal sealed class EchoHandler(string suffix) : IOperationHandler<EchoRequest,EchoReply>, IDisposable
{
    internal static int Disposed;
    public ValueTask<OperationResult<EchoReply>> HandleAsync(EchoRequest request, OperationContext context, CancellationToken token)
        => new(OperationResult<EchoReply>.Success(new(request.Text + ":" + suffix)));
    public void Dispose() => Disposed++;
}

internal sealed class OwnedFactory : IOperationHandlerFactory
{
    internal int Calls;
    public THandler Create<THandler>() where THandler : class
    {
        Calls++;
        if (typeof(THandler) == typeof(EchoHandler)) return (THandler)(object)new EchoHandler("injected");
        throw new InvalidOperationException("Unexpected generated handler type");
    }
}
