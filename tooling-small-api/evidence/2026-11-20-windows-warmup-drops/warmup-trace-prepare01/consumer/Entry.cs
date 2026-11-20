using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace MetricsOverhead;

public static class Entry
{
    internal static readonly JsonSerializerOptions Json = new() { IncludeFields = true };
    internal static long Now => Stopwatch.GetTimestamp();
    internal static void Signal(object value) => Console.WriteLine(JsonSerializer.Serialize(value, Json));
    internal static async Task Save(string path, object value)
    {
        await using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write);
        await JsonSerializer.SerializeAsync(file, value, Json);
    }

    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args.Length < 1 || (args.Length - 1) % 2 != 0) throw new ArgumentException();
            var options = new Dictionary<string, string>(StringComparer.Ordinal);
            for (var i = 1; i < args.Length; i += 2) options.Add(args[i], args[i + 1]);
            var profile = options["--profile"];
            if (profile is not ("conformance" or "measure")) throw new ArgumentException();
            if (File.Exists(options["--output"])) throw new IOException();
            Diagnostic.Enabled = options.GetValueOrDefault("--diagnostic-trace") == "true";
            if (Diagnostic.Enabled) await Diagnostic.Begin(args[0], options["--output"]);
            var result = args[0] switch
            {
                "host" => await Host.Run(options),
                "client" => await Client.Run(options),
                "trace-fixture" => await Diagnostic.Fixture(options),
                _ => throw new ArgumentException()
            };
            if (Diagnostic.Enabled) await Diagnostic.Finish();
            return result;
        }
        catch (Exception error)
        {
            // Do not include exception messages, private pipe input or credentials.
            Signal(new { kind = "failed", type = error.GetType().Name });
            return 1;
        }
    }

    internal static object EnvironmentInfo() => new
    {
        pid = Environment.ProcessId, framework = RuntimeInformation.FrameworkDescription,
        os = RuntimeInformation.OSDescription, architecture = RuntimeInformation.ProcessArchitecture.ToString(),
        processors = Environment.ProcessorCount, stopwatchFrequency = Stopwatch.Frequency,
        cwd = Environment.CurrentDirectory, serverGc = System.Runtime.GCSettings.IsServerGC,
        latencyMode = System.Runtime.GCSettings.LatencyMode.ToString()
    };
}
