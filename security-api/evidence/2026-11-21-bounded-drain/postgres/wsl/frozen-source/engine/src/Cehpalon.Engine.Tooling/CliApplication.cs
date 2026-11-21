using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cehpalon.Engine.Composition;

namespace Cehpalon.Engine.Tooling;

/// <summary>Experimental portable scaffolding; no processes or services are started.</summary>
public static class CliApplication
{
    public const string SupportedProfile = "portable-request-reply";
    public const string Version = "0.1.0-experimental";
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly StringComparison PathComparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
    private static readonly string[] SourcePaths =
    [
        "Directory.Packages.props", "NuGet.Config", "global.json",
        "src/Cehpalon.Engine.Core/Cehpalon.Engine.Core.csproj",
        "src/Cehpalon.Engine.Core/Contracts.cs", "src/Cehpalon.Engine.Core/OperationRegistry.cs",
        "src/Cehpalon.Engine.Core/OperationResult.cs", "src/Cehpalon.Engine.Core/packages.lock.json",
        "src/Cehpalon.Engine.Composition/Cehpalon.Engine.Composition.csproj",
        "src/Cehpalon.Engine.Composition/CompositionCompiler.cs", "src/Cehpalon.Engine.Composition/Contracts.cs",
        "src/Cehpalon.Engine.Composition/PlanActivator.cs", "src/Cehpalon.Engine.Composition/packages.lock.json",
        "src/Cehpalon.Engine.CodeGeneration/Cehpalon.Engine.CodeGeneration.csproj",
        "src/Cehpalon.Engine.CodeGeneration/NuGet.Config",
        "src/Cehpalon.Engine.CodeGeneration/OperationRegistryGenerator.cs",
        "src/Cehpalon.Engine.CodeGeneration/packages.lock.json"
    ];

    public static int Run(string[] args, TextWriter output, TextWriter error) =>
        Run(args, output, error, new PhysicalToolingFileSystem());

    internal static int Run(string[] args, TextWriter output, TextWriter error, IToolingFileSystem fileSystem)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(fileSystem);
        try
        {
            if (args.Length == 1 && args[0] == "--help")
            {
                Write(output, new { success = true, version = Version, commands = new[] {
                    "new --name <ASCIIUpperIdentifier> --output <new-directory> --engine-root <existing-checkout> [--profile portable-request-reply|small-api]",
                    "validate --config <file> [--profile portable-request-reply|small-api]", "--help", "--version" }, profile = SupportedProfile,
                    profiles = new[] { SupportedProfile, SmallApiTemplateFiles.Profile },
                    limits = "Experimental source-checkout profiles; Small API uses fixture-backed authority. No production/provider or Worker qualification." });
                return 0;
            }
            if (args.Length == 1 && args[0] == "--version")
            {
                Write(output, new { success = true, version = Version });
                return 0;
            }
            if (args.Length == 0) throw new UsageFailure("usage.command", "Use new, validate, --help or --version.");
            return args[0] switch
            {
                "new" => New(Parse(args, ["--name", "--output", "--engine-root", "--profile"]), output, fileSystem),
                "validate" => Validate(Parse(args, ["--config", "--profile"]), output),
                _ => throw new UsageFailure("usage.command", "Unknown command or extra arguments to --help/--version.")
            };
        }
        catch (UsageFailure failure)
        {
            Write(error, new { success = false, code = failure.Code, message = failure.Message });
            return 2;
        }
        catch (ConfigurationFailure failure)
        {
            Write(error, new { success = false, code = "config.invalid", message = "Configuration was rejected before activation.",
                    diagnostics = failure.Diagnostics.Select(diagnostic => new { diagnostic.Code, path = "$.Cehpalon", message = "Configuration violates the selected profile." }) });
            return 2;
        }
        catch (PathFailure failure)
        {
            Write(error, new { success = false, code = failure.Code, message = failure.Message });
            return 3;
        }
        catch (Exception failure) when (failure is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or System.Security.SecurityException or JsonException or System.Xml.XmlException)
        {
            // Do not expose file contents, exception paths or vendor messages.
            Write(error, new { success = false, code = "path.io", message = "The source, configuration or output path could not be safely read or written." });
            return 3;
        }
    }

    private static Dictionary<string, string> Parse(string[] args, string[] allowed)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 1; index < args.Length; index += 2)
        {
            if (!allowed.Contains(args[index], StringComparer.Ordinal))
                throw new UsageFailure("usage.option", "Unknown option; use --help for supported arguments.");
            if (index + 1 >= args.Length || string.IsNullOrWhiteSpace(args[index + 1]) || args[index + 1].StartsWith("--", StringComparison.Ordinal))
                throw new UsageFailure("usage.value", "Every option requires one nonempty value.");
            if (!result.TryAdd(args[index], args[index + 1]))
                throw new UsageFailure("usage.duplicate", "Options must not be repeated.");
        }
        return result;
    }

    private static string Required(Dictionary<string, string> options, string key) => options.TryGetValue(key, out var value)
        ? value : throw new UsageFailure("usage.required", "A required option is missing; use --help.");

    private static int Validate(Dictionary<string, string> options, TextWriter output)
    {
        var profile = Profile(options);
        var configPath = UserPath(Required(options, "--config"));
        DemandPlainAncestors(configPath);
        var compilation = CompositionCompiler.Compile(ReadConfiguration(configPath), profile == SupportedProfile ? TemplateFiles.Catalog() : SmallApiTemplateFiles.Catalog());
        if (!compilation.IsSuccess) throw new ConfigurationFailure(compilation.Diagnostics);
        if (profile == SmallApiTemplateFiles.Profile && !SmallApiTemplateFiles.Supported(compilation.Plan!))
            throw new UsageFailure("config.capability", "The small-api profile supports only host, API and GraphQL activation; disable unsupported capabilities.");
        Write(output, new { success = true, status = "passed", profile, schemaVersion = compilation.Plan!.SchemaVersion,
            activationOrder = compilation.Plan.ActivationOrder, modules = compilation.Plan.Modules });
        return 0;
    }

    private static int New(Dictionary<string, string> options, TextWriter output, IToolingFileSystem fileSystem)
    {
        var name = Required(options, "--name");
        if (!ValidName(name)) throw new UsageFailure("usage.name", "Use [A-Z][A-Za-z0-9]{0,63}, excluding reserved DOS device names.");
        var profile = Profile(options);
        var destination = Path.TrimEndingDirectorySeparator(UserPath(Required(options, "--output")));
        var engineRoot = Path.TrimEndingDirectorySeparator(UserPath(Required(options, "--engine-root")));
        if (engineRoot.IndexOfAny(['%', '$', '@', ';', '*', '?']) >= 0)
            throw new PathFailure("source.path", "Engine source paths containing MSBuild expansion, escape, wildcard or item-list metacharacters are not supported.");
        var parent = Path.GetDirectoryName(destination);
        if (string.IsNullOrEmpty(parent) || string.Equals(destination, Path.GetPathRoot(destination), PathComparison))
            throw new PathFailure("path.output", "Output must be a new child directory of an existing plain directory.");
        DemandPlainAncestors(parent);
        if (!Directory.Exists(parent)) throw new PathFailure("path.parent", "Output parent must already exist.");
        DemandAbsent(destination);
        DemandPlainAncestors(engineRoot);
        if (!Directory.Exists(engineRoot) || (!Directory.Exists(Path.Combine(engineRoot, ".git")) && !File.Exists(Path.Combine(engineRoot, ".git"))))
            throw new PathFailure("source.checkout", "Engine source must be an existing checkout with the required source inputs.");
        DemandProtectedOutput(destination, engineRoot);

        // Read all required source inputs before creating any output. This is an observed
        // byte snapshot, not a git revision or a protection against later source edits.
        var sourceBytes = new SortedDictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var path in profile == SupportedProfile ? SourcePaths : SourcePaths.Concat(SmallApiTemplateFiles.SourcePaths))
        {
            var fullPath = Path.Combine(engineRoot, path.Replace('/', Path.DirectorySeparatorChar));
            DemandPlainAncestors(fullPath);
            var bytes = File.ReadAllBytes(fullPath);
            if (bytes.Length > 4 * 1024 * 1024) throw new PathFailure("source.size", "An Engine source input exceeds the supported limit.");
            sourceBytes.Add(path, bytes);
        }
        try
        {
            ValidatePinnedInputs(sourceBytes);
            if (profile == SmallApiTemplateFiles.Profile && !SmallApiTemplateFiles.PackagePolicy(sourceBytes["Directory.Packages.props"]))
                throw new PathFailure("source.packages", "Engine package policy does not match the supported Small API profile.");
        }
        catch (Exception failure) when (failure is JsonException or System.Xml.XmlException or InvalidOperationException)
        { throw new PathFailure("source.invalid", "Engine source policy must be valid and match the supported experimental template."); }
        var inputs = sourceBytes.Select(pair => new SourceInput(pair.Key, Convert.ToHexStringLower(SHA256.HashData(pair.Value)), pair.Value.LongLength)).ToArray();
        var manifest = JsonSerializer.Serialize(new { schemaVersion = 1, provenance = "observed-source-bytes-not-git-attestation", sourceRoot = engineRoot, inputs }, JsonOptions) + "\n";
        var files = profile == SupportedProfile
            ? TemplateFiles.Create(name, engineRoot, sourceBytes["global.json"], sourceBytes["NuGet.Config"], Utf8.GetBytes(manifest))
            : SmallApiTemplateFiles.Create(name, engineRoot, sourceBytes["global.json"], sourceBytes["NuGet.Config"], Utf8.GetBytes(manifest));

        var stage = Path.Combine(parent, ".cehpalon-stage-" + Guid.NewGuid().ToString("N"));
        var owned = false;
        try
        {
            DemandAbsent(stage);
            Directory.CreateDirectory(stage);
            owned = true;
            DemandPlainAncestors(stage);
            foreach (var pair in files)
            {
                DemandPlainAncestors(stage);
                fileSystem.WriteAllBytes(Path.Combine(stage, pair.Key), pair.Value);
            }
            DemandPlainAncestors(parent);
            DemandPlainAncestors(stage);
            DemandAbsent(destination);
            fileSystem.MoveDirectory(stage, destination);
            owned = false;
        }
        finally
        {
            if (owned) CleanupStage(stage, parent, files.Keys);
        }
        Write(output, new { success = true, status = "passed", profile, name, output = destination, files = files.Keys.ToArray(), sourceInputs = inputs.Length });
        return 0;
    }

    private static string Profile(Dictionary<string, string> options)
    {
        var profile = options.GetValueOrDefault("--profile", SupportedProfile);
        if (profile is not (SupportedProfile or SmallApiTemplateFiles.Profile))
            throw new UsageFailure("usage.profile", "Supported profiles are portable-request-reply and small-api.");
        return profile;
    }

    private static void ValidatePinnedInputs(SortedDictionary<string, byte[]> inputs)
    {
        // Pin these portable template inputs rather than copying arbitrary SDK/feed policy.
        using var global = JsonDocument.Parse(inputs["global.json"]);
        if (!global.RootElement.TryGetProperty("sdk", out var sdk)
            || !sdk.TryGetProperty("version", out var version) || version.GetString() != "11.0.100"
            || !sdk.TryGetProperty("rollForward", out var roll) || roll.GetString() != "disable"
            || !sdk.TryGetProperty("allowPrerelease", out var allow) || allow.ValueKind != JsonValueKind.False)
            throw new PathFailure("source.sdk", "Engine source SDK policy does not match the supported experimental template.");
        var nuget = System.Xml.Linq.XDocument.Parse(Utf8.GetString(inputs["NuGet.Config"]));
        var sources = nuget.Root?.Element("packageSources");
        if (nuget.Root?.Name != "configuration" || sources is null || sources.Elements().Count() != 2
            || sources.Elements().First().Name != "clear" || sources.Elements().Last().Name != "add"
            || (string?)sources.Elements().Last().Attribute("key") != "nuget.org"
            || (string?)sources.Elements().Last().Attribute("value") != "https://api.nuget.org/v3/index.json"
            || (string?)sources.Elements().Last().Attribute("protocolVersion") != "3"
            || nuget.Root.Elements().Count() != 1)
            throw new PathFailure("source.feed", "Engine source package-source policy does not match the supported template.");
    }

    private static bool ValidName(string name)
    {
        if (name.Length is < 1 or > 64 || name[0] is < 'A' or > 'Z') return false;
        if (name.Any(c => !(c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9'))) return false;
        var upper = name.ToUpperInvariant();
        return upper is not ("CON" or "PRN" or "AUX" or "NUL")
            && !(upper.Length == 4 && (upper.StartsWith("COM", StringComparison.Ordinal) || upper.StartsWith("LPT", StringComparison.Ordinal)) && upper[3] is >= '1' and <= '9');
    }

    private static string UserPath(string value)
    {
        var windowsForm = value.Replace('/', '\\');
        if (windowsForm.StartsWith("\\\\?\\", StringComparison.Ordinal) || windowsForm.StartsWith("\\\\.\\", StringComparison.Ordinal))
            throw new PathFailure("path.namespace", "Windows device and extended path namespaces are not supported.");
        return Path.GetFullPath(value);
    }

    private static string ReadConfiguration(string path)
    {
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length > CompositionCompiler.MaximumConfigurationBytes)
            throw new UsageFailure("config.size", "Configuration exceeds the supported UTF-8 byte limit.");
        using var memory = new MemoryStream();
        var buffer = new byte[8192];
        int read;
        while ((read = file.Read(buffer)) != 0)
        {
            if (memory.Length + read > CompositionCompiler.MaximumConfigurationBytes)
                throw new UsageFailure("config.size", "Configuration exceeds the supported UTF-8 byte limit.");
            memory.Write(buffer, 0, read);
        }
        try { return Utf8.GetString(memory.ToArray()).TrimStart('\uFEFF'); }
        catch (DecoderFallbackException) { throw new UsageFailure("config.encoding", "Configuration must be valid UTF-8."); }
    }

    private static void DemandAbsent(string path)
    {
        if (TryAttributes(path, out _)) throw new PathFailure("path.exists", "Output or staging path already exists; no overwrite is supported.");
    }

    private static void DemandPlainAncestors(string path)
    {
        for (var current = Path.GetFullPath(path); !string.IsNullOrEmpty(current); current = Path.GetDirectoryName(current))
        {
            if (TryAttributes(current, out var attributes) && (attributes & FileAttributes.ReparsePoint) != 0)
                throw new PathFailure("path.link", "Observed symlink or reparse-point paths are not supported.");
        }
    }

    private static bool TryAttributes(string path, out FileAttributes attributes)
    {
        try { attributes = File.GetAttributes(path); return true; }
        catch (FileNotFoundException) { attributes = default; return false; }
        catch (DirectoryNotFoundException) { attributes = default; return false; }
    }

    private static void DemandProtectedOutput(string output, string engineRoot)
    {
        var roots = new HashSet<string>(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal) { engineRoot };
        for (var ancestor = Path.GetDirectoryName(engineRoot); ancestor is not null; ancestor = Path.GetDirectoryName(ancestor))
        {
            foreach (var name in new[] { "Cehpalon-Engine", "Cehpalon-Engine-Docs", "Cehpalon-Engine-Samples" })
            {
                var candidate = Path.Combine(ancestor, name);
                // Hosted runners can wrap a checkout in another same-named directory.
                // A directory name alone does not make that wrapper a checkout root.
                if (Directory.Exists(candidate) && (Directory.Exists(Path.Combine(candidate, ".git"))
                    || File.Exists(Path.Combine(candidate, ".git")))) roots.Add(candidate);
            }
        }
        foreach (var root in roots)
        {
            if (string.Equals(output, root, PathComparison)) throw new PathFailure("path.checkout", "A program checkout cannot be an output target.");
            var prefix = Path.TrimEndingDirectorySeparator(root) + Path.DirectorySeparatorChar;
            if (!output.StartsWith(prefix, PathComparison)) continue;
            var relative = output[prefix.Length..];
            if (relative != ".local" && !relative.StartsWith(".local" + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                throw new PathFailure("path.checkout", "Output inside program checkouts is limited to ignored .local descendants.");
        }
    }

    private static void CleanupStage(string stage, string parent, IEnumerable<string> expectedNames)
    {
        // No recursive deletion: verify the absolute owned target and delete only the
        // fixed files produced by this invocation. Unknown entries retain the stage.
        var fullStage = Path.GetFullPath(stage);
        if (!string.Equals(Path.GetDirectoryName(fullStage), Path.GetFullPath(parent), PathComparison)
            || !Path.GetFileName(fullStage).StartsWith(".cehpalon-stage-", StringComparison.Ordinal))
            throw new PathFailure("path.cleanup", "Owned staging path could not be verified; it was retained.");
        DemandPlainAncestors(fullStage);
        var expected = expectedNames.ToHashSet(StringComparer.Ordinal);
        foreach (var entry in Directory.EnumerateFileSystemEntries(fullStage))
        {
            if (!expected.Contains(Path.GetFileName(entry)) || (File.GetAttributes(entry) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                throw new PathFailure("path.cleanup", "Unexpected staging entry; staging was retained for inspection.");
        }
        foreach (var entry in Directory.EnumerateFileSystemEntries(fullStage))
        {
            DemandPlainAncestors(fullStage);
            if ((File.GetAttributes(entry) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                throw new PathFailure("path.cleanup", "Changed staging entry; staging was retained for inspection.");
            File.Delete(entry);
        }
        Directory.Delete(fullStage, recursive: false);
    }

    private static void Write(TextWriter writer, object value) => writer.WriteLine(JsonSerializer.Serialize(value, JsonOptions));
    private sealed record SourceInput(string Path, string Sha256, long Bytes);
    private sealed class UsageFailure(string code, string message) : Exception(message) { public string Code { get; } = code; }
    private sealed class PathFailure(string code, string message) : Exception(message) { public string Code { get; } = code; }
    private sealed class ConfigurationFailure(IReadOnlyList<CompositionDiagnostic> diagnostics) : Exception
    { public IReadOnlyList<CompositionDiagnostic> Diagnostics { get; } = diagnostics; }
}
