using System.Text;
using System.Text.Json;
using Cehpalon.Engine.Composition;
using Cehpalon.Engine.Core;
using PortableConsumers.File;

var counters = new Counters();
var json = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
if (args.Length > 1)
{
    Console.Error.WriteLine(JsonSerializer.Serialize(new { status = "failed", code = "usage.config", message = "Use zero arguments or one configuration path." }, json));
    return 2;
}
var configPath = args.Length == 1 ? args[0] : Path.Combine(AppContext.BaseDirectory, "appsettings.json");
try
{
    // Compile the full startup snapshot before receiving any module factory.
    var bytes = File.ReadAllBytes(configPath);
    if (bytes.Length > CompositionCompiler.MaximumConfigurationBytes) throw new InvalidDataException();
    var text = new UTF8Encoding(false, true).GetString(bytes).TrimStart('\uFEFF');
    var compilation = CompositionCompiler.Compile(text, ModuleCatalog.Create());
    if (!compilation.IsSuccess)
    {
        Console.Error.WriteLine(JsonSerializer.Serialize(new { status = "failed", code = "config.invalid",
            diagnostics = compilation.Diagnostics.Select(diagnostic => new { diagnostic.Code, path = "$.Cehpalon", message = "Configuration violates the selected portable profile." }),
            factories = new { core = counters.CoreFactories, app = counters.AppFactories, optional = counters.OptionalFactories },
            handlersConstructed = counters.HandlersConstructed, handlersDisposed = counters.HandlersDisposed,
            dispatches = counters.Dispatches, modulesDisposed = counters.ModulesDisposed }, json));
        return 2;
    }
    AppModule? app = null;
    string? response = null;
    await using (var lease = await PlanActivator.ActivateAsync(compilation.Plan!,
    [
        new("core", cancellation =>
        {
            cancellation.ThrowIfCancellationRequested();
            counters.CoreFactories++;
            return ValueTask.FromResult<IAsyncDisposable>(new OwnedModule(counters));
        }),
        new("app", cancellation =>
        {
            cancellation.ThrowIfCancellationRequested();
            counters.AppFactories++;
            app = new AppModule(counters);
            return ValueTask.FromResult<IAsyncDisposable>(app);
        }),
        new("optional", cancellation =>
        {
            counters.OptionalFactories++;
            throw new InvalidOperationException("The optional fixture must stay disabled.");
        })
    ]))
    {
        if (app is not null)
        {
            var result = await app.Dispatcher.DispatchAsync<EchoRequest, EchoResponse>("sample.echo", new("hello"), new("sample-call"));
            if (!result.IsSuccess) throw new InvalidOperationException("The sample operation failed.");
            response = result.Value.Message;
        }
    }
    // Lifecycle counters are reported only after every owned module is cleaned up.
    Console.WriteLine(JsonSerializer.Serialize(new { status = "passed", profile = "portable-request-reply", activationOrder = compilation.Plan!.ActivationOrder,
        factories = new { core = counters.CoreFactories, app = counters.AppFactories, optional = counters.OptionalFactories },
        handlersConstructed = counters.HandlersConstructed, handlersDisposed = counters.HandlersDisposed,
        dispatches = counters.Dispatches, modulesDisposed = counters.ModulesDisposed, response }, json));
    return 0;
}
catch
{
    Console.Error.WriteLine(JsonSerializer.Serialize(new { status = "failed", code = "consumer.failure", message = "The local consumer failed; no provider or platform qualification is implied.",
        factories = new { core = counters.CoreFactories, app = counters.AppFactories, optional = counters.OptionalFactories },
        handlersConstructed = counters.HandlersConstructed, handlersDisposed = counters.HandlersDisposed,
        dispatches = counters.Dispatches, modulesDisposed = counters.ModulesDisposed }, json));
    return 3;
}
