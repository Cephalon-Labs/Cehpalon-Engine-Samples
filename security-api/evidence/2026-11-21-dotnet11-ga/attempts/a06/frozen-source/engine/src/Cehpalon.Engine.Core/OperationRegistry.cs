using System.Collections.ObjectModel;
using System.Runtime.ExceptionServices;

namespace Cehpalon.Engine.Core;

public sealed class OperationRegistryBuilder
{
    private readonly Dictionary<string, IRegistration> registrations = new(StringComparer.Ordinal);

    /// <summary>Register a factory without invoking it. Each dispatch owns and disposes the newly returned handler.</summary>
    public OperationRegistryBuilder Register<TRequest, TResponse>(
        string id, Func<IOperationHandler<TRequest, TResponse>> factory)
    {
        OperationId.RequireValid(id);
        ArgumentNullException.ThrowIfNull(factory);
        if (!registrations.TryAdd(id, new Registration<TRequest, TResponse>(factory)))
            throw new ArgumentException($"Operation '{id}' is already registered.", nameof(id));
        return this;
    }

    /// <summary>Snapshot the mapping. Later builder edits cannot change an existing registry.</summary>
    public OperationRegistry Build() => new(registrations);
}

public sealed class OperationRegistry
{
    private readonly IReadOnlyDictionary<string, IRegistration> registrations;
    internal OperationRegistry(Dictionary<string, IRegistration> source)
    {
        registrations = new ReadOnlyDictionary<string, IRegistration>(new Dictionary<string, IRegistration>(source, StringComparer.Ordinal));
        OperationIds = Array.AsReadOnly(source.Keys.Order(StringComparer.Ordinal).ToArray());
    }
    public IReadOnlyList<string> OperationIds { get; }
    internal bool TryGet(string id, out IRegistration? registration) => registrations.TryGetValue(id, out registration);
}

public sealed class OperationDispatcher
{
    private readonly OperationRegistry registry;
    public OperationDispatcher(OperationRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(registry);
        this.registry = registry;
    }

    public ValueTask<OperationResult<TResponse>> DispatchAsync<TRequest, TResponse>(
        string id, TRequest request, OperationContext context, CancellationToken cancellationToken = default)
    {
        OperationId.RequireValid(id);
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        if (!registry.TryGet(id, out var registration))
            return ValueTask.FromResult(OperationResult<TResponse>.Failure(new OperationError(
                "operation.not_found", "The requested operation is not registered.")));
        if (registration is not Registration<TRequest, TResponse> typed)
            return ValueTask.FromResult(OperationResult<TResponse>.Failure(new OperationError(
                "operation.contract_mismatch", "The requested operation does not use these request/response contracts.")));
        return typed.DispatchAsync(request, context, cancellationToken);
    }
}

internal interface IRegistration;

internal sealed class Registration<TRequest, TResponse>(Func<IOperationHandler<TRequest, TResponse>> factory) : IRegistration
{
    internal async ValueTask<OperationResult<TResponse>> DispatchAsync(
        TRequest request, OperationContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var handler = factory() ?? throw new InvalidOperationException("The operation factory returned a null handler.");
        OperationResult<TResponse>? result = null;
        Exception? primaryFailure = null;
        try
        {
            // A synchronous factory can cancel while constructing the owned handler.
            // Keep this check inside cleanup scope so business work is skipped without leaking it.
            cancellationToken.ThrowIfCancellationRequested();
            result = await handler.HandleAsync(request, context, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidOperationException("The operation handler returned a null result.");
        }
        catch (Exception error)
        {
            primaryFailure = error;
        }

        try
        {
            if (handler is IAsyncDisposable asyncDisposable)
                await asyncDisposable.DisposeAsync().ConfigureAwait(false);
            else if (handler is IDisposable disposable)
                disposable.Dispose();
        }
        catch (Exception cleanupFailure)
        {
            if (primaryFailure is not null)
                throw new AggregateException("Operation execution and owned-handler cleanup both failed.", primaryFailure, cleanupFailure);
            throw;
        }
        if (primaryFailure is not null) ExceptionDispatchInfo.Capture(primaryFailure).Throw();
        return result!;
    }
}
