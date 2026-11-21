namespace Cehpalon.Engine.Composition;

public enum ModuleRole { Support, EntryPoint }

/// <summary>Pure metadata only. Construction does not activate resources.</summary>
public sealed class ModuleDescriptor
{
    public ModuleDescriptor(string id, ModuleRole role, IEnumerable<string>? dependencies = null)
    {
        Id = id ?? throw new ArgumentNullException(nameof(id));
        Role = role;
        Dependencies = Array.AsReadOnly((dependencies ?? []).Take(CompositionCompiler.MaximumModules + 1).ToArray());
    }

    public string Id { get; }
    public ModuleRole Role { get; }
    public IReadOnlyList<string> Dependencies { get; }
}

public sealed record CompositionDiagnostic(string Code, string Path, string Message);

public sealed record ModuleDecision(string Id, ModuleRole Role, bool IsEnabled, string Reason);

/// <summary>Validated and immutable. Only the compiler can construct a plan.</summary>
public sealed class ActivationPlan
{
    internal ActivationPlan(IEnumerable<string> activationOrder, IEnumerable<ModuleDecision> modules)
    {
        ActivationOrder = Array.AsReadOnly(activationOrder.ToArray());
        Modules = Array.AsReadOnly(modules.ToArray());
    }

    public int SchemaVersion => 1;
    public string Architecture => "Modular";
    public string Topology => "SingleProcess";
    public string Pattern => "RequestReply";
    public IReadOnlyList<string> ActivationOrder { get; }
    public IReadOnlyList<ModuleDecision> Modules { get; }
    public string Explain() => string.Join(Environment.NewLine, Modules.Select(m =>
        $"{m.Id}: {(m.IsEnabled ? "enabled" : "disabled")} ({m.Reason})"));
}

public sealed class CompositionCompilation
{
    internal CompositionCompilation(ActivationPlan? plan, IEnumerable<CompositionDiagnostic> diagnostics)
    {
        Plan = plan;
        Diagnostics = Array.AsReadOnly(diagnostics.ToArray());
    }

    public bool IsSuccess => Plan is not null;
    public ActivationPlan? Plan { get; }
    public IReadOnlyList<CompositionDiagnostic> Diagnostics { get; }
}

/// <summary>Each factory transfers a newly owned resource to the activation lease.</summary>
public sealed class ModuleRegistration
{
    public ModuleRegistration(string id, Func<CancellationToken, ValueTask<IAsyncDisposable>> factory)
    {
        Id = id ?? throw new ArgumentNullException(nameof(id));
        Factory = factory ?? throw new ArgumentNullException(nameof(factory));
    }
    public string Id { get; }
    internal Func<CancellationToken, ValueTask<IAsyncDisposable>> Factory { get; }
}
