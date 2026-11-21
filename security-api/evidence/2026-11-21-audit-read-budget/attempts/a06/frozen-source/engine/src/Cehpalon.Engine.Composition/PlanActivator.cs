using System.Runtime.ExceptionServices;

namespace Cehpalon.Engine.Composition;

public static class PlanActivator
{
    public static async ValueTask<ActivationLease> ActivateAsync(ActivationPlan plan,
        IEnumerable<ModuleRegistration> registrations, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(registrations);
        var entries = registrations.Take(CompositionCompiler.MaximumModules + 1).ToArray();
        if (entries.Length > CompositionCompiler.MaximumModules)
            throw new ArgumentException("Too many module registrations.", nameof(registrations));
        var known = plan.Modules.Select(m => m.Id).ToHashSet(StringComparer.Ordinal);
        var factories = new Dictionary<string, ModuleRegistration>(StringComparer.Ordinal);
        foreach (var registration in entries)
        {
            if (registration is null || !known.Contains(registration.Id))
                throw new ArgumentException("Null or unknown module registration.", nameof(registrations));
            if (!factories.TryAdd(registration.Id, registration))
                throw new ArgumentException("Duplicate module registration: " + registration.Id, nameof(registrations));
        }
        foreach (var id in plan.ActivationOrder)
            if (!factories.ContainsKey(id)) throw new ArgumentException("Missing enabled module registration: " + id, nameof(registrations));
        cancellationToken.ThrowIfCancellationRequested();
        var resources = new List<IAsyncDisposable>();
        try
        {
            foreach (var id in plan.ActivationOrder)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var resource = await factories[id].Factory(cancellationToken).ConfigureAwait(false)
                    ?? throw new InvalidOperationException("Module factory returned null: " + id);
                if (resources.Contains(resource, ReferenceEqualityComparer.Instance))
                    throw new InvalidOperationException("Module factories must transfer distinct owned resources.");
                resources.Add(resource);
                cancellationToken.ThrowIfCancellationRequested();
            }
            return new ActivationLease(resources);
        }
        catch (Exception failure)
        {
            var errors = await ActivationLease.DisposeAll(resources).ConfigureAwait(false);
            if (errors.Count != 0) throw new AggregateException("Activation failed and rollback encountered errors.", new[] { failure }.Concat(errors));
            ExceptionDispatchInfo.Capture(failure).Throw();
            throw;
        }
    }
}

/// <summary>Owns all activated resources. Concurrent disposal awaits the same cleanup task.</summary>
public sealed class ActivationLease : IAsyncDisposable
{
    private readonly IReadOnlyList<IAsyncDisposable> resources;
    private readonly object gate = new();
    private Task? disposal;

    internal ActivationLease(IEnumerable<IAsyncDisposable> resources) => this.resources = resources.ToArray();

    public ValueTask DisposeAsync()
    {
        TaskCompletionSource? completion = null;
        Task current;
        lock (gate)
        {
            if (disposal is null)
            {
                completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
                disposal = completion.Task;
            }
            current = disposal;
        }
        if (completion is not null) _ = CompleteDisposal(completion);
        return new ValueTask(current);
    }

    private async Task CompleteDisposal(TaskCompletionSource completion)
    {
        try
        {
            var errors = await DisposeAll(resources).ConfigureAwait(false);
            if (errors.Count != 0) completion.TrySetException(new AggregateException("Module cleanup encountered errors.", errors));
            else completion.TrySetResult();
        }
        catch (Exception error) { completion.TrySetException(error); }
    }

    internal static async ValueTask<IReadOnlyList<Exception>> DisposeAll(IReadOnlyList<IAsyncDisposable> resources)
    {
        var errors = new List<Exception>();
        for (var i = resources.Count - 1; i >= 0; --i)
            try { await resources[i].DisposeAsync().ConfigureAwait(false); }
            catch (Exception error) { errors.Add(error); }
        return errors;
    }
}
