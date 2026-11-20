using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Cehpalon.Engine.Composition;
using Microsoft.IdentityModel.Tokens;

namespace PortableConsumers.Generated;

internal static class Program
{
    private const string ConcurrencyOption = "--max-concurrent-operations";
    private const string TenantConcurrencyOption = "--max-concurrent-operations-per-tenant";
    private static readonly JsonSerializerOptions Json = new() { IncludeFields = true };
    private static readonly UTF8Encoding Utf8 = new(false, true);
    public static async Task<int> Main(string[] args)
    {
        Dictionary<string, string> options;
        try
        {
            if (args.Length == 1 && args[0] == "--help")
            {
                Console.WriteLine(JsonSerializer.Serialize(new { status = "passed", commands = new[] {
                    "--self-test --output <new-report.json>",
                    "--self-test-capacity --output <new-report.json>",
                    "--self-test-tenant-capacity --output <new-report.json>",
                    "--self-test-drain --output <new-report.json>",
                    "--self-test-live-metrics --output <new-report.json>",
                    "--export-contracts --config <json> --output <new-directory>",
                    "--serve --config <json> --certificate <user.pfx> --public-key <RS256-public.pem> --ready <new-ready.json> [--max-concurrent-operations <positive-int> [--max-concurrent-operations-per-tenant <positive-int>]]" },
                    scope = "Experimental fixture-backed Small API. Type stop + Enter or Ctrl+C for owned shutdown." }, Json));
                return 0;
            }
            if (args.Length == 0 || args[0] is not ("--self-test" or "--self-test-capacity" or "--self-test-tenant-capacity" or "--self-test-drain" or "--self-test-live-metrics" or "--serve" or "--export-contracts")) return Failure("usage.command", 2);
            var required = args[0] switch { "--self-test" or "--self-test-capacity" or "--self-test-tenant-capacity" or "--self-test-drain" or "--self-test-live-metrics" => new[] { "--output" }, "--export-contracts" => new[] { "--config", "--output" },
                _ => new[] { "--config", "--certificate", "--public-key", "--ready" } };
            options = new Dictionary<string, string>(StringComparer.Ordinal);
            for (var i = 1; i < args.Length; i += 2)
                if (!(required.Contains(args[i], StringComparer.Ordinal)
                    || args[0] == "--serve" && args[i] is ConcurrencyOption or TenantConcurrencyOption) || i + 1 >= args.Length
                    || string.IsNullOrWhiteSpace(args[i + 1]) || args[i + 1].StartsWith("--", StringComparison.Ordinal)
                    || !options.TryAdd(args[i], args[i + 1])) return Failure("usage.option", 2);
            if (required.Any(key => !options.ContainsKey(key))) return Failure("usage.required", 2);
            if (args[0] == "--self-test") return await SelfTest.Run(options["--output"]);
            if (args[0] == "--self-test-capacity") return await SelfTest.RunCapacity(options["--output"]);
            if (args[0] == "--self-test-tenant-capacity") return await SelfTest.RunCapacity(options["--output"], tenantLimited: true);
            if (args[0] == "--self-test-drain") return await SelfTest.RunDrain(options["--output"]);
            if (args[0] == "--self-test-live-metrics") return await SelfTest.RunLiveMetrics(options["--output"]);
            if (args[0] == "--export-contracts") return await ContractExport.Run(options["--config"], options["--output"]);
        }
        catch (Exception)
        {
            // Routing, self-test and export failures have no serving activation.
            return Failure("consumer.failure", 3);
        }
        return await Serve(options);
    }

    // Keep serving-only trust and host work out of the command router's async state.
    private static async Task<int> Serve(Dictionary<string, string> options)
    {
        var observed = new ActivationCounters();
        try
        {
            int? maximumConcurrentOperations = null;
            if (options.TryGetValue(ConcurrencyOption, out var limit))
            {
                if (!TryParseLimit(limit, out var parsed))
                    return Failure("usage.max_concurrent_operations", 2);
                maximumConcurrentOperations = parsed;
            }
            int? maximumConcurrentOperationsPerTenant = null;
            if (options.TryGetValue(TenantConcurrencyOption, out var tenantLimit))
            {
                if (maximumConcurrentOperations is not int total || !TryParseLimit(tenantLimit, out var parsed) || parsed > total)
                    return Failure("usage.max_concurrent_operations_per_tenant", 2);
                maximumConcurrentOperationsPerTenant = parsed;
            }
            var ready = Path.GetFullPath(options["--ready"]);
            if (File.Exists(ready) || Directory.Exists(ready)) return Failure("ready.exists", 3);
            string configuration;
            try { configuration = ReadConfiguration(options["--config"]); }
            catch (Exception error) when (error is DecoderFallbackException or InvalidDataException)
            { return Failure("config.invalid", 2); }
            ActivationPlan plan;
            try { plan = FixtureHost.Compile(configuration); }
            catch (ArgumentException) { return Failure("config.invalid", 2); }
            if (plan.ActivationOrder.Count == 0)
            {
                await Ready(ready, new { status = "disabled", address = (string?)null, counters = observed,
                    scope = "No store, TLS/JWT import, services or listener created." });
                Console.WriteLine(JsonSerializer.Serialize(new { status = "disabled", counters = observed }, Json));
                return 0;
            }
            // Serving requires caller-provided trust. Ephemeral private test keys are
            // generated exclusively by the explicit --self-test command.
            using var certificate = X509CertificateLoader.LoadPkcs12FromFile(options["--certificate"],
                Environment.GetEnvironmentVariable("CEHPALON_TLS_PASSWORD"), OperatingSystem.IsWindows() ? X509KeyStorageFlags.UserKeySet : X509KeyStorageFlags.EphemeralKeySet);
            if (!certificate.HasPrivateKey || certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow
                || certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow) return Failure("trust.certificate", 3);
            var pem = File.ReadAllText(options["--public-key"], Utf8);
            if (!pem.Contains("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal)
                || pem.Contains("PRIVATE KEY", StringComparison.Ordinal)) return Failure("trust.public-key", 3);
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            if (rsa.KeySize < 2048) return Failure("trust.public-key", 3);
            // The owned host is disposed before the certificate/key even if startup
            // or readiness publication fails.
            await using var host = new FixtureHost();
            observed = host.Counters;
            await host.Start(configuration, certificate, new RsaSecurityKey(rsa.ExportParameters(false)),
                maximumConcurrentOperations, maximumConcurrentOperationsPerTenant);
            await Ready(ready, new { status = "ready", address = host.Address.AbsoluteUri, counters = host.Counters,
                capacity = host.CapacitySnapshot, tenantCapacity = host.TenantCapacitySnapshot,
                scope = "Fixture-backed tenant memberships/store; not real IdP/provider or production qualification." });
            using var stop = new CancellationTokenSource();
            ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; stop.Cancel(); };
            Console.CancelKeyPress += cancel;
            try { await ConsoleLifetime(stop.Token); }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            finally { Console.CancelKeyPress -= cancel; }
            await host.DisposeAsync();
            Console.WriteLine(JsonSerializer.Serialize(new { status = "stopped", counters = host.Counters,
                capacity = host.CapacitySnapshot, tenantCapacity = host.TenantCapacitySnapshot,
                store = new { host.Store.Factories, host.Store.Constructors, host.Store.Reads, host.Store.Writes, host.Store.Disposals } }, Json));
            return 0;
        }
        catch (Exception)
        {
            // Never expose input text, token, key, path or vendor exception details.
            return Failure("consumer.failure", 3, observed);
        }
    }

    private static bool TryParseLimit(string value, out int limit)
    {
        limit = 0;
        return value.Length <= 10 && value.All(c => c is >= '0' and <= '9')
            && int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out limit) && limit > 0;
    }

    private static async Task ConsoleLifetime(CancellationToken cancellationToken)
    {
        while (true)
        {
            // Console.In may use a synchronous OS console reader. Race the caller's
            // cancellation so Ctrl+C cannot be trapped behind an open input pipe.
            // A pending console read is background-only and ends with this process;
            // Kestrel and owned business resources are still awaited before exit.
            var line = await Task.Run(() => Console.In.ReadLine()).WaitAsync(cancellationToken);
            if (line == "stop") return;
            if (line is null) { await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); return; }
        }
    }

    internal static string ReadConfiguration(string path)
    {
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length > CompositionCompiler.MaximumConfigurationBytes) throw new InvalidDataException();
        using var buffer = new MemoryStream();
        var bytes = new byte[8192];
        int read;
        while ((read = file.Read(bytes)) != 0)
        {
            if (buffer.Length + read > CompositionCompiler.MaximumConfigurationBytes) throw new InvalidDataException();
            buffer.Write(bytes, 0, read);
        }
        return Utf8.GetString(buffer.ToArray()).TrimStart('\uFEFF');
    }

    private static async Task Ready(string path, object value)
    {
        var parent = Path.GetDirectoryName(path)!;
        if (!Directory.Exists(parent)) throw new DirectoryNotFoundException();
        var stage = Path.Combine(parent, ".cehpalon-ready-" + Guid.NewGuid().ToString("N"));
        var owned = false;
        try
        {
            await using (var file = new FileStream(stage, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { owned = true; await JsonSerializer.SerializeAsync(file, value, Json); await file.FlushAsync(); }
            File.Move(stage, path, overwrite: false);
            owned = false;
        }
        finally { if (owned) File.Delete(stage); }
    }
    private static int Failure(string code, int exit, ActivationCounters? counters = null)
    {
        Console.Error.WriteLine(JsonSerializer.Serialize(new { status = "failed", code,
            message = "Small API input, trust, configuration or fixture operation was rejected; no secrets are included.",
            counters = counters ?? new ActivationCounters() }, Json));
        return exit;
    }
}
