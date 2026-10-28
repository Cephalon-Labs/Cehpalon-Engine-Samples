using Cehpalon.Engine.Composition;
using Cehpalon.Engine.Core;

namespace PortableConsumers.File;

internal static class ModuleCatalog
{
    internal static ModuleDescriptor[] Create() =>
    [
        new("core", ModuleRole.Support),
        new("app", ModuleRole.EntryPoint, ["core"]),
        new("optional", ModuleRole.EntryPoint, ["core"])
    ];
}

internal sealed class Counters
{
    internal int CoreFactories, AppFactories, OptionalFactories;
    internal int HandlersConstructed, HandlersDisposed, Dispatches, ModulesDisposed;
}

internal sealed record EchoRequest(string Message);
internal sealed record EchoResponse(string Message);

// Plain Core metadata grants no identity, membership or tenant authority.
[Operation("sample.echo")]
internal sealed class EchoHandler : IOperationHandler<EchoRequest, EchoResponse>, IDisposable
{
    private readonly Counters counters;
    internal EchoHandler(Counters counters) { this.counters = counters; counters.HandlersConstructed++; }
    public ValueTask<OperationResult<EchoResponse>> HandleAsync(EchoRequest request, OperationContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        counters.Dispatches++;
        return ValueTask.FromResult(OperationResult<EchoResponse>.Success(new(request.Message)));
    }
    public void Dispose() => counters.HandlersDisposed++;
}

internal sealed class HandlerFactory(Counters counters) : IOperationHandlerFactory
{
    public THandler Create<THandler>() where THandler : class => typeof(THandler) == typeof(EchoHandler)
        ? (THandler)(object)new EchoHandler(counters) : throw new InvalidOperationException("Unknown generated handler.");
}

internal sealed class AppModule : IAsyncDisposable
{
    private readonly Counters counters;
    internal OperationDispatcher Dispatcher { get; }
    internal AppModule(Counters counters)
    {
        this.counters = counters;
        var registry = new OperationRegistryBuilder();
        // Typed code-generation output adds lazy factories without constructing handlers.
        Cehpalon.Engine.Generated.OperationRegistrations.RegisterAll(registry, new HandlerFactory(counters));
        Dispatcher = new OperationDispatcher(registry.Build());
    }
    public ValueTask DisposeAsync() { counters.ModulesDisposed++; return ValueTask.CompletedTask; }
}

internal sealed class OwnedModule(Counters counters) : IAsyncDisposable
{
    public ValueTask DisposeAsync() { counters.ModulesDisposed++; return ValueTask.CompletedTask; }
}
