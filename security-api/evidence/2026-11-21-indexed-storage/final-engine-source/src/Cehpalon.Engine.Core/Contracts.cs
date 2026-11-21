using System.Collections.ObjectModel;
using System.Diagnostics.Metrics;

namespace Cehpalon.Engine.Core;

[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
public sealed class OperationAttribute : Attribute
{
    public OperationAttribute(string id) => Id = OperationId.RequireValid(id);
    public string Id { get; }
}

public interface IOperationHandler<TRequest, TResponse>
{
    ValueTask<OperationResult<TResponse>> HandleAsync(
        TRequest request, OperationContext context, CancellationToken cancellationToken);
}

/// <summary>A compile-time typed bridge for generated registrations. Each call transfers a new handler's ownership.</summary>
public interface IOperationHandlerFactory
{
    THandler Create<THandler>() where THandler : class;
}

/// <summary>Caller-supplied correlation metadata. This is not tenant, identity or authorization authority.</summary>
public sealed class OperationContext
{
    public OperationContext(string correlationId, IEnumerable<KeyValuePair<string, string>>? metadata = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(correlationId);
        if (correlationId.Length > 256)
            throw new ArgumentException("Correlation IDs are limited to 256 characters.", nameof(correlationId));
        CorrelationId = correlationId;
        var copy = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in metadata ?? [])
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(pair.Key);
            ArgumentNullException.ThrowIfNull(pair.Value);
            if (pair.Key.Length > 128 || pair.Value.Length > 4096)
                throw new ArgumentException("Metadata keys/values exceed the supported 128/4096 character limits.", nameof(metadata));
            if (!copy.TryAdd(pair.Key, pair.Value))
                throw new ArgumentException("Metadata keys must be unique using ordinal comparison.", nameof(metadata));
            if (copy.Count > 64)
                throw new ArgumentException("At most 64 metadata entries are supported.", nameof(metadata));
        }
        Metadata = new ReadOnlyDictionary<string, string>(copy);
    }

    public string CorrelationId { get; }
    public IReadOnlyDictionary<string, string> Metadata { get; }
}

public static class OperationId
{
    /// <summary>Canonical ASCII identifier: [a-z][a-z0-9_.-]{0,127}; comparison is ordinal.</summary>
    public static bool IsValid(string? value)
    {
        if (value is null || value.Length is < 1 or > 128 || value[0] is < 'a' or > 'z') return false;
        for (var index = 1; index < value.Length; index++)
        {
            var c = value[index];
            if (!(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '.' or '-')) return false;
        }
        return true;
    }

    public static string RequireValid(string? value)
    {
        if (!IsValid(value))
            throw new ArgumentException("An operation identifier must match [a-z][a-z0-9_.-]{0,127}.", nameof(value));
        return value!;
    }
}

/// <summary>A point-in-time aggregate observation. Reading it does not reserve capacity.</summary>
public readonly record struct OperationConcurrencySnapshot(
    int MaximumConcurrentOperations, int ActiveOperations, bool IsAdmissionClosed);

/// <summary>An opt-in, in-process concurrency limit shared by the operations that use this instance.</summary>
public sealed class OperationConcurrencyBudget
{
    /// <summary>Generic overload result for adapters that choose to expose this budget.</summary>
    public const string CapacityExceededCode = "operation.capacity_exceeded";

    private const int Closed = int.MinValue;
    // The sign bit closes admissions; the remaining bits hold the active count.
    private int admission;
    private TaskCompletionSource? drained;

    public OperationConcurrencyBudget(int maximumConcurrentOperations)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumConcurrentOperations);
        MaximumConcurrentOperations = maximumConcurrentOperations;
    }

    public int MaximumConcurrentOperations { get; }

    /// <summary>Read a coherent, detached view of the aggregate admission state.</summary>
    public OperationConcurrencySnapshot GetSnapshot()
    {
        var observed = Volatile.Read(ref admission);
        return new(MaximumConcurrentOperations, observed & int.MaxValue, observed < 0);
    }

    /// <summary>Create aggregate gauges. The caller owns the returned meter and controls collection.</summary>
    public Meter CreateMetrics(string meterName = "Cehpalon.Engine.Core.Budget")
    {
        var meter = new Meter(meterName);
        try
        {
            meter.CreateObservableGauge("cehpalon.operation_budget.active", () => GetSnapshot().ActiveOperations, "{operation}");
            meter.CreateObservableGauge("cehpalon.operation_budget.capacity", () => MaximumConcurrentOperations, "{operation}");
            meter.CreateObservableGauge("cehpalon.operation_budget.closed", () => GetSnapshot().IsAdmissionClosed ? 1 : 0,
                description: "One after admission is permanently closed, otherwise zero.");
            return meter;
        }
        catch
        {
            meter.Dispose();
            throw;
        }
    }

    /// <summary>Close admissions permanently and wait until all admitted operations finish cleanup.</summary>
    /// <remarks>Cancellation only cancels this wait. Admitted work continues and admissions stay closed.</remarks>
    public Task DrainAsync(CancellationToken cancellationToken = default)
    {
        var completion = LazyInitializer.EnsureInitialized(ref drained,
            static () => new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously));
        var previous = Interlocked.Or(ref admission, Closed);
        if (previous is 0 or Closed)
            completion.TrySetResult();

        return completion.Task.WaitAsync(cancellationToken);
    }

    /// <summary>Dispatch immediately or return a capacity failure. Admitted work holds capacity through cleanup.</summary>
    public ValueTask<OperationResult<TResponse>> DispatchAsync<TRequest, TResponse>(
        OperationDispatcher dispatcher, string id, TRequest request, OperationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(dispatcher);
        OperationId.RequireValid(id);
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        if (TryEnter())
            return DispatchAdmittedAsync<TRequest, TResponse>(dispatcher, id, request, context, cancellationToken);

        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Rejected<TResponse>.Result);
    }

    private bool TryEnter()
    {
        var observed = Volatile.Read(ref admission);
        while (observed >= 0 && observed < MaximumConcurrentOperations)
        {
            var previous = Interlocked.CompareExchange(ref admission, observed + 1, observed);
            if (previous == observed)
                return true;
            observed = previous;
        }

        return false;
    }

    private async ValueTask<OperationResult<TResponse>> DispatchAdmittedAsync<TRequest, TResponse>(
        OperationDispatcher dispatcher, string id, TRequest request, OperationContext context,
        CancellationToken cancellationToken)
    {
        try
        {
            return await dispatcher.DispatchAsync<TRequest, TResponse>(id, request, context, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            if (Interlocked.Decrement(ref admission) == Closed)
                Volatile.Read(ref drained)!.TrySetResult();
        }
    }

    private static class Rejected<T>
    {
        internal static readonly OperationResult<T> Result = OperationResult<T>.Failure(
            new OperationError(CapacityExceededCode, "Operation capacity is temporarily unavailable."));
    }
}
