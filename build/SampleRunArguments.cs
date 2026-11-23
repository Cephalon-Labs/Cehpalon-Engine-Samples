using System.Globalization;

namespace Cehpalon.Samples;

internal static class SampleRunArguments
{
    internal static bool TryReport(string[] args, string sample, out string output, out int exit)
    {
        output = ""; exit = 0;
        var usage = "Usage: " + sample + " [--output=<new-report.json>]\nNo arguments: run the fixture and save a fresh report under Samples .local/" + sample + "-runs.";
        if (args.Length == 1 && args[0] is "--help" or "-h") { Console.WriteLine(usage); return false; }
        if (args.Length > 1 || args.Length == 1 && (!args[0].StartsWith("--output=", StringComparison.Ordinal) || string.IsNullOrWhiteSpace(args[0][9..])))
        { Console.Error.WriteLine(usage); exit = 2; return false; }
        try { output = Path.GetFullPath(args.Length == 0 ? DefaultReport(sample) : args[0][9..]); }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or PathTooLongException)
        { Console.Error.WriteLine("Invalid report path. " + usage); exit = 2; return false; }
        if (File.Exists(output) || Directory.Exists(output))
        { Console.Error.WriteLine("Report path already exists. Choose a fresh --output path; previous reports are preserved."); exit = 2; return false; }
        Console.WriteLine("Report: " + output);
        return true;
    }

    static string DefaultReport(string sample)
    {
        string? root = null;
        foreach (var start in new[] { Environment.CurrentDirectory, AppContext.BaseDirectory })
        {
            for (var directory = new DirectoryInfo(start); directory is not null; directory = directory.Parent)
            {
                if (!File.Exists(Path.Combine(directory.FullName, "Cehpalon.Samples.slnx")) || !File.Exists(Path.Combine(directory.FullName, "global.json"))) continue;
                root = directory.FullName; break;
            }
            if (root is not null) break;
        }
        var name = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N") + ".json";
        return Path.Combine(root ?? Environment.CurrentDirectory, ".local", sample + "-runs", name);
    }
}
