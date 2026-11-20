using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cehpalon.Engine.Tooling;

var checks = new List<object>();
var failures = 0;
var runRoot = Path.Combine(Path.GetTempPath(), "cehpalon-tooling-contracts-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(runRoot);
var engineRoot = FindEngineRoot();
var ordinal = 0;
string[] expectedFiles = ["Catalog.cs", "Consumer.csproj", "NuGet.Config", "Program.cs", "README.md", "appsettings.json", "appsettings.off.json", "engine-source.json", "global.json"];
string[] sourcePaths =
[
    "Directory.Packages.props", "NuGet.Config", "global.json",
    "src/Cehpalon.Engine.Core/Cehpalon.Engine.Core.csproj", "src/Cehpalon.Engine.Core/Contracts.cs",
    "src/Cehpalon.Engine.Core/OperationRegistry.cs", "src/Cehpalon.Engine.Core/OperationResult.cs", "src/Cehpalon.Engine.Core/packages.lock.json",
    "src/Cehpalon.Engine.Composition/Cehpalon.Engine.Composition.csproj", "src/Cehpalon.Engine.Composition/CompositionCompiler.cs",
    "src/Cehpalon.Engine.Composition/Contracts.cs", "src/Cehpalon.Engine.Composition/PlanActivator.cs", "src/Cehpalon.Engine.Composition/packages.lock.json",
    "src/Cehpalon.Engine.CodeGeneration/Cehpalon.Engine.CodeGeneration.csproj", "src/Cehpalon.Engine.CodeGeneration/NuGet.Config",
    "src/Cehpalon.Engine.CodeGeneration/OperationRegistryGenerator.cs", "src/Cehpalon.Engine.CodeGeneration/packages.lock.json"
];

void Assert(bool condition, string message = "Assertion failed")
{
    if (!condition) throw new InvalidOperationException(message);
}

void Check(string name, Action test)
{
    try { test(); checks.Add(new { name, passed = true }); }
    catch (Exception error) { failures++; checks.Add(new { name, passed = false, detail = error.ToString() }); }
}

string Scope()
{
    var path = Path.Combine(runRoot, (++ordinal).ToString("D3"));
    Directory.CreateDirectory(path);
    return path;
}

CliResult Invoke(string[] arguments, IToolingFileSystem? fileSystem = null)
{
    using var output = new StringWriter(System.Globalization.CultureInfo.InvariantCulture);
    using var error = new StringWriter(System.Globalization.CultureInfo.InvariantCulture);
    var code = fileSystem is null ? CliApplication.Run(arguments, output, error) : CliApplication.Run(arguments, output, error, fileSystem);
    return new(code, output.ToString(), error.ToString());
}
CliResult Run(params string[] arguments) => Invoke(arguments);

string[] NewArguments(string target, string name = "Demo", string? root = null)
    => ["new", "--name", name, "--output", target, "--engine-root", root ?? engineRoot];

Dictionary<string, string> Snapshot(string root)
    => Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
        .ToDictionary(path => Path.GetRelativePath(root, path).Replace('\\', '/'),
            path => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))), StringComparer.Ordinal);

void SameSnapshot(Dictionary<string, string> before, string root)
{
    var after = Snapshot(root);
    Assert(before.Count == after.Count && before.All(pair => after.TryGetValue(pair.Key, out var hash) && hash == pair.Value),
        "Unexpected file creation, deletion or content change.");
}

void AssertNoPublish(string parent, string target)
{
    Assert(!Directory.Exists(target) && !File.Exists(target), "A rejected request published a target.");
    Assert(!Directory.EnumerateFileSystemEntries(parent).Any(), "A rejected request left owned files or staging directories.");
}

string CreateSourceFixture(string parent)
{
    var root = Path.Combine(parent, "Cehpalon-Engine");
    Directory.CreateDirectory(Path.Combine(root, ".git"));
    Directory.CreateDirectory(Path.Combine(parent, "Cehpalon-Engine-Docs", ".git"));
    Directory.CreateDirectory(Path.Combine(parent, "Cehpalon-Engine-Samples", ".git"));
    foreach (var relative in sourcePaths)
    {
        var target = Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        File.Copy(Path.Combine(engineRoot, relative.Replace('/', Path.DirectorySeparatorChar)), target);
    }
    return root;
}

void UsageWithoutFiles(params string[] arguments)
{
    var parent = Scope();
    var target = Path.Combine(parent, "output");
    var expanded = arguments.Select(value => value == "$output" ? target : value == "$engine" ? engineRoot : value).ToArray();
    var result = Run(expanded);
    Assert(result.Code == 2, "Expected usage/config exit 2; got " + result.Code);
    Assert(!string.IsNullOrWhiteSpace(result.Error), "Rejected usage must provide a diagnostic.");
    AssertNoPublish(parent, target);
}

Check("help-without-filesystem-work", () =>
{
    var before = Snapshot(runRoot);
    var result = Run("--help");
    Assert(result.Code == 0 && result.Output.Contains("new", StringComparison.Ordinal) && result.Output.Contains("validate", StringComparison.Ordinal));
    Assert(result.Error.Length == 0);
    SameSnapshot(before, runRoot);
});
Check("version-without-filesystem-work", () =>
{
    var before = Snapshot(runRoot);
    var result = Run("--version");
    Assert(result.Code == 0 && !string.IsNullOrWhiteSpace(result.Output) && result.Error.Length == 0);
    SameSnapshot(before, runRoot);
});

foreach (var invocation in new (string Name, string[] Arguments)[]
{
    ("no-command", []),
    ("unknown-command", ["launch"]),
    ("help-extra-argument", ["--help", "extra"]),
    ("version-extra-argument", ["--version", "extra"]),
    ("new-missing-options", ["new"]),
    ("new-missing-output-value", ["new", "--name", "Demo", "--output"]),
    ("new-missing-engine-root", ["new", "--name", "Demo", "--output", "$output"]),
    ("new-unknown-option", ["new", "--name", "Demo", "--output", "$output", "--engine-root", "$engine", "--start", "true"]),
    ("new-duplicate-name", ["new", "--name", "Demo", "--name", "Other", "--output", "$output", "--engine-root", "$engine"]),
    ("new-duplicate-output", ["new", "--name", "Demo", "--output", "$output", "--output", "$output", "--engine-root", "$engine"]),
    ("new-duplicate-engine-root", ["new", "--name", "Demo", "--output", "$output", "--engine-root", "$engine", "--engine-root", "$engine"]),
    ("new-duplicate-profile", ["new", "--name", "Demo", "--output", "$output", "--engine-root", "$engine", "--profile", "portable-request-reply", "--profile", "portable-request-reply"]),
    ("new-unsupported-profile", ["new", "--name", "Demo", "--output", "$output", "--engine-root", "$engine", "--profile", "durable-distributed"]),
    ("new-positional-trailer", ["new", "--name", "Demo", "--output", "$output", "--engine-root", "$engine", "extra"]),
    ("validate-missing-config", ["validate"]),
    ("validate-missing-value", ["validate", "--config"]),
    ("validate-unknown-option", ["validate", "--config", "$output", "--unknown", "value"]),
    ("validate-duplicate-config", ["validate", "--config", "$output", "--config", "$output"])
})
{
    Check(invocation.Name, () => UsageWithoutFiles(invocation.Arguments));
}

foreach (var name in new[] { "", "lower", "0Demo", "With-Dash", "With.Space", "With Space", "../Escape", "A/B", "A\\B", "ไทย", "Demo\nInjected", "CON", "PRN", "AUX", "NUL", "COM1", "LPT9", "Com1", new string('A', 65) })
{
    var description = name.Length > 20 ? "length-" + name.Length : name.Replace("\n", "\\n", StringComparison.Ordinal);
    Check("invalid-name-before-publish-" + description, () =>
    {
        var parent = Scope();
        var target = Path.Combine(parent, "output");
        var result = Run(NewArguments(target, name));
        Assert(result.Code == 2, "Invalid name should be usage error, got " + result.Code);
        AssertNoPublish(parent, target);
    });
}

Check("maximum-name-length-supported", () =>
{
    var parent = Scope();
    var target = Path.Combine(parent, "output");
    var result = Run(NewArguments(target, new string('A', 64)));
    Assert(result.Code == 0 && Directory.Exists(target), "64-character name was rejected: " + result.Error);
});

Check("scaffold-does-not-run-build-or-services", () =>
{
    var parent = Scope();
    var target = Path.Combine(parent, "output");
    var result = Run(NewArguments(target));
    Assert(result.Code == 0 && result.Error.Length == 0, "Scaffold failed: " + result.Error);
    var files = Snapshot(target);
    Assert(files.Keys.Order(StringComparer.Ordinal).SequenceEqual(expectedFiles.Order(StringComparer.Ordinal)),
        "Generated file set differs from the bounded nine-file contract: " + string.Join(",", files.Keys));
    Assert(!Directory.EnumerateDirectories(target, "*", SearchOption.AllDirectories).Any(path =>
        new[] { "bin", "obj", ".git", "node_modules" }.Contains(Path.GetFileName(path), StringComparer.OrdinalIgnoreCase)),
        "Generation must not build, restore or initialize other tools.");
    foreach (var path in Directory.EnumerateFiles(target, "*", SearchOption.AllDirectories))
    {
        var bytes = File.ReadAllBytes(path);
        Assert(bytes.Length > 0, "Empty generated file.");
        Assert(!(bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF), "UTF8 BOM is not deterministic template encoding.");
        _ = new UTF8Encoding(false, true).GetString(bytes);
    }
});

Check("same-options-generate-identical-relative-file-bytes", () =>
{
    var parent = Scope();
    var first = Path.Combine(parent, "first");
    var second = Path.Combine(parent, "second");
    Assert(Run(NewArguments(first)).Code == 0);
    Assert(Run([.. NewArguments(second), "--profile", "portable-request-reply"]).Code == 0);
    var expected = Snapshot(first);
    SameSnapshot(expected, second);
});

foreach (var failAfterWrite in new[] { false, true })
{
    for (var writeNumber = 1; writeNumber <= expectedFiles.Length; writeNumber++)
    {
        var failedWrite = writeNumber;
        Check($"write-failure-{failedWrite}-{(failAfterWrite ? "after" : "before")}-cleans-only-owned-stage", () =>
        {
            var parent = Scope();
            var target = Path.Combine(parent, "output");
            var neighbor = Path.Combine(parent, "neighbor.bin");
            File.WriteAllBytes(neighbor, [0, 255, 10, 13, 71]);
            var before = Snapshot(parent);
            var physical = new PhysicalToolingFileSystem();
            var calls = 0;
            var moves = 0;
            var fileSystem = new DelegatingFileSystem(
                (path, bytes) =>
                {
                    calls++;
                    if (calls == failedWrite && !failAfterWrite) throw new IOException("SUPER_SECRET_IO_MESSAGE");
                    physical.WriteAllBytes(path, bytes);
                    if (calls == failedWrite && failAfterWrite) throw new IOException("SUPER_SECRET_IO_MESSAGE");
                },
                (source, destination) => { moves++; physical.MoveDirectory(source, destination); });
            var result = Invoke(NewArguments(target), fileSystem);
            Assert(result.Code == 3, "Injected I/O failure must return exit3.");
            Assert(calls == failedWrite && moves == 0, "Generation continued or published after write failure.");
            Assert(!(result.Output + result.Error).Contains("SUPER_SECRET_IO_MESSAGE", StringComparison.Ordinal), "Unexpected filesystem details leaked.");
            SameSnapshot(before, parent);
            Assert(Directory.EnumerateFileSystemEntries(parent).Count() == 1, "Owned staging directory survived write failure.");
        });
    }
}

Check("publication-collision-preserves-outsider-and-cleans-owned-stage", () =>
{
    var parent = Scope();
    var target = Path.Combine(parent, "output");
    var physical = new PhysicalToolingFileSystem();
    var writes = 0;
    var moves = 0;
    string? staging = null;
    var fileSystem = new DelegatingFileSystem(
        (path, bytes) => { writes++; physical.WriteAllBytes(path, bytes); },
        (source, destination) =>
        {
            moves++;
            staging = source;
            Assert(Snapshot(source).Count == expectedFiles.Length, "Publication attempted before full template was written.");
            Directory.CreateDirectory(destination);
            File.WriteAllBytes(Path.Combine(destination, "outsider.bin"), [1, 255, 13, 10, 0]);
            physical.MoveDirectory(source, destination);
        });
    var result = Invoke(NewArguments(target), fileSystem);
    Assert(result.Code == 3 && writes == expectedFiles.Length && moves == 1);
    Assert(staging is not null && !Directory.Exists(staging), "Owned staging was retained after collision.");
    Assert(File.ReadAllBytes(Path.Combine(target, "outsider.bin")).SequenceEqual(new byte[] { 1, 255, 13, 10, 0 }), "Outsider target was damaged.");
    Assert(Directory.EnumerateFileSystemEntries(target).Count() == 1 && Directory.EnumerateFileSystemEntries(parent).Count() == 1,
        "Collision cleanup removed the outsider or retained generated files.");
});

Check("publication-io-failure-cleans-owned-stage-without-publishing", () =>
{
    var parent = Scope();
    var target = Path.Combine(parent, "output");
    var physical = new PhysicalToolingFileSystem();
    var writes = 0;
    var fileSystem = new DelegatingFileSystem(
        (path, bytes) => { writes++; physical.WriteAllBytes(path, bytes); },
        (_, _) => throw new IOException("SUPER_SECRET_IO_MESSAGE"));
    var result = Invoke(NewArguments(target), fileSystem);
    Assert(result.Code == 3 && writes == expectedFiles.Length);
    Assert(!(result.Output + result.Error).Contains("SUPER_SECRET_IO_MESSAGE", StringComparison.Ordinal));
    AssertNoPublish(parent, target);
});

Check("unexpected-staging-entry-retains-stage-and-outsider-bytes", () =>
{
    var parent = Scope();
    var target = Path.Combine(parent, "output");
    var physical = new PhysicalToolingFileSystem();
    string? stage = null;
    string? producedFile = null;
    byte[]? producedBytes = null;
    var fileSystem = new DelegatingFileSystem(
        (path, bytes) =>
        {
            physical.WriteAllBytes(path, bytes);
            stage = Path.GetDirectoryName(path)!;
            producedFile = path;
            producedBytes = bytes;
            File.WriteAllBytes(Path.Combine(stage, "outsider.bin"), [0, 255, 13, 10, 9]);
            throw new IOException("SUPER_SECRET_IO_MESSAGE");
        },
        (_, _) => throw new InvalidOperationException("Publication must not run after write failure."));
    var result = Invoke(NewArguments(target), fileSystem);
    Assert(result.Code == 3 && stage is not null && Directory.Exists(stage));
    Assert(!Directory.Exists(target));
    Assert(File.ReadAllBytes(Path.Combine(stage!, "outsider.bin")).SequenceEqual(new byte[] { 0, 255, 13, 10, 9 }));
    Assert(File.ReadAllBytes(producedFile!).SequenceEqual(producedBytes!), "Unsafe cleanup partially deleted known files before discovering outsider.");
    Assert(Directory.EnumerateFileSystemEntries(stage!).Count() == 2 && Directory.EnumerateFileSystemEntries(parent).Count() == 1);
    Assert(!(result.Output + result.Error).Contains("SUPER_SECRET_IO_MESSAGE", StringComparison.Ordinal));
    using var error = JsonDocument.Parse(result.Error);
    Assert(error.RootElement.GetProperty("code").GetString() == "path.cleanup", "Unsafe cleanup must be distinct from successful rollback.");
});

Check("preexisting-directory-and-sentinel-remain-unchanged", () =>
{
    var parent = Scope();
    var target = Path.Combine(parent, "output");
    Directory.CreateDirectory(target);
    File.WriteAllBytes(Path.Combine(target, "sentinel.bin"), [0, 255, 10, 13, 1]);
    var before = Snapshot(parent);
    var result = Run(NewArguments(target));
    Assert(result.Code == 3);
    SameSnapshot(before, parent);
    Assert(Directory.EnumerateDirectories(parent).Count() == 1);
});

Check("preexisting-empty-directory-is-not-adopted", () =>
{
    var parent = Scope();
    var target = Path.Combine(parent, "output");
    Directory.CreateDirectory(target);
    Assert(Run(NewArguments(target)).Code == 3);
    Assert(Directory.Exists(target) && !Directory.EnumerateFileSystemEntries(target).Any());
    Assert(Directory.EnumerateFileSystemEntries(parent).Count() == 1);
});

Check("preexisting-file-is-not-overwritten", () =>
{
    var parent = Scope();
    var target = Path.Combine(parent, "output");
    File.WriteAllText(target, "ORIGINAL\r\nBYTES", new UTF8Encoding(false));
    var before = Snapshot(parent);
    Assert(Run(NewArguments(target)).Code == 3);
    SameSnapshot(before, parent);
});

Check("missing-parent-is-not-created", () =>
{
    var parent = Scope();
    var target = Path.Combine(parent, "absent", "output");
    Assert(Run(NewArguments(target)).Code == 3);
    AssertNoPublish(parent, target);
});

Check("missing-engine-root-is-not-created", () =>
{
    var parent = Scope();
    var target = Path.Combine(parent, "output");
    Assert(Run(NewArguments(target, root: Path.Combine(parent, "absent-engine"))).Code == 3);
    AssertNoPublish(parent, target);
});

Check("engine-root-file-is-not-a-project-root", () =>
{
    var parent = Scope();
    var target = Path.Combine(parent, "output");
    var file = Path.Combine(parent, "engine-file");
    File.WriteAllText(file, "sentinel");
    var before = Snapshot(parent);
    Assert(Run(NewArguments(target, root: file)).Code == 3);
    SameSnapshot(before, parent);
});

Check("empty-engine-directory-is-not-accepted", () =>
{
    var parent = Scope();
    var target = Path.Combine(parent, "output");
    var empty = Path.Combine(parent, "empty-engine");
    Directory.CreateDirectory(empty);
    Assert(Run(NewArguments(target, root: empty)).Code == 3);
    Assert(!Directory.Exists(target) && !Directory.EnumerateFileSystemEntries(empty).Any());
    Assert(Directory.EnumerateFileSystemEntries(parent).Count() == 1);
});

Check("new-output-under-engine-src-rejected-without-any-sibling-change", () =>
{
    var parent = Path.Combine(engineRoot, "src");
    var before = Directory.EnumerateFileSystemEntries(parent).Order(StringComparer.Ordinal).ToArray();
    var target = Path.Combine(parent, "ToolingShouldNeverCreate" + Guid.NewGuid().ToString("N"));
    var result = Run(NewArguments(target));
    Assert(result.Code == 3, "An unignored checkout subtree must not be scaffold output.");
    Assert(!Directory.Exists(target) && !File.Exists(target));
    Assert(before.SequenceEqual(Directory.EnumerateFileSystemEntries(parent).Order(StringComparer.Ordinal)), "Rejected output altered the checkout subtree.");
});

Check("new-output-under-own-existing-local-parent-is-allowed", () =>
{
    var parent = Path.Combine(engineRoot, ".local", "tooling-contracts-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(parent);
    var target = Path.Combine(parent, "output");
    var result = Run(NewArguments(target));
    Assert(result.Code == 0, "Ignored .local output should be allowed: " + result.Error);
    Assert(Snapshot(target).Count == expectedFiles.Length);
});

Check("same-named-runner-wrapper-is-not-a-checkout-boundary", () =>
{
    var wrapper = Path.Combine(Scope(), "Cehpalon-Engine");
    Directory.CreateDirectory(wrapper);
    var source = CreateSourceFixture(wrapper);
    var parent = Path.Combine(source, ".local");
    Directory.CreateDirectory(parent);
    var target = Path.Combine(parent, "consumer");
    var result = Run(NewArguments(target, root: source));
    Assert(result.Code == 0, "A same-named wrapper without .git must not hide the actual checkout's .local: " + result.Error);
    Assert(Snapshot(target).Count == expectedFiles.Length);
    Assert(!Directory.Exists(Path.Combine(wrapper, ".git")), "The wrapper must remain an ordinary parent directory.");
});

foreach (var checkoutName in new[] { "Cehpalon-Engine", "Cehpalon-Engine-Docs", "Cehpalon-Engine-Samples" })
{
    Check("canonical-checkout-unignored-descendant-is-not-output-" + checkoutName, () =>
    {
        var programRoot = Scope();
        var source = CreateSourceFixture(programRoot);
        var parent = Path.Combine(programRoot, checkoutName);
        var before = Directory.EnumerateFileSystemEntries(parent).Order(StringComparer.Ordinal).ToArray();
        var target = Path.Combine(parent, "ToolingShouldNeverCreate" + Guid.NewGuid().ToString("N"));
        Assert(Run(NewArguments(target, root: source)).Code == 3);
        Assert(!Directory.Exists(target) && !File.Exists(target));
        Assert(before.SequenceEqual(Directory.EnumerateFileSystemEntries(parent).Order(StringComparer.Ordinal)), "Rejected output altered a sibling checkout.");
    });
}

foreach (var invalidSource in new (string Name, string Path, string Text)[]
{
    ("malformed-sdk-json", "global.json", "{ broken SUPER_SECRET_SOURCE_VALUE"),
    ("scalar-sdk-policy", "global.json", "{\"sdk\":\"SUPER_SECRET_SOURCE_VALUE\"}"),
    ("nonobject-sdk-root", "global.json", "[\"SUPER_SECRET_SOURCE_VALUE\"]"),
    ("numeric-sdk-version", "global.json", "{\"sdk\":{\"version\":123,\"rollForward\":\"disable\",\"allowPrerelease\":true}}"),
    ("wrong-sdk-version", "global.json", "{\"sdk\":{\"version\":\"SUPER_SECRET_SOURCE_VALUE\",\"rollForward\":\"disable\",\"allowPrerelease\":true}}"),
    ("malformed-package-xml", "NuGet.Config", "<configuration>SUPER_SECRET_SOURCE_VALUE"),
    ("unapproved-package-feed", "NuGet.Config", "<configuration><packageSources><clear/><add key=\"secret\" value=\"https://SUPER_SECRET_SOURCE_VALUE.invalid/feed\" protocolVersion=\"3\"/></packageSources></configuration>")
})
{
    Check("invalid-source-" + invalidSource.Name + "-redacted-and-before-output", () =>
    {
        var parent = Scope();
        var source = CreateSourceFixture(parent);
        File.WriteAllText(Path.Combine(source, invalidSource.Path), invalidSource.Text, new UTF8Encoding(false));
        var before = Snapshot(parent);
        var target = Path.Combine(parent, "output");
        var result = Run(NewArguments(target, root: source));
        Assert(result.Code == 3, "Invalid source policy must be structured path/source exit3.");
        Assert(!(result.Output + result.Error).Contains("SUPER_SECRET_SOURCE_VALUE", StringComparison.Ordinal));
        using var error = JsonDocument.Parse(result.Error);
        Assert(error.RootElement.GetProperty("success").ValueKind == JsonValueKind.False);
        Assert(!Directory.Exists(target));
        SameSnapshot(before, parent);
        Assert(Directory.EnumerateDirectories(parent).Count() == 3, "Invalid source created staging/output.");
    });
}

foreach (var metacharacter in new[] { ";", "%", "$", "@" })
{
    Check("msbuild-metacharacter-in-source-path-rejected-" + metacharacter, () =>
    {
        var parent = Scope();
        var fixtureParent = Path.Combine(parent, "source" + metacharacter + "path");
        Directory.CreateDirectory(fixtureParent);
        var source = CreateSourceFixture(fixtureParent);
        var before = Snapshot(parent);
        var target = Path.Combine(parent, "output");
        var result = Run(NewArguments(target, root: source));
        Assert(result.Code == 3, "Source path with MSBuild syntax must be rejected before output.");
        SameSnapshot(before, parent);
        Assert(!Directory.Exists(target) && Directory.EnumerateFileSystemEntries(parent).Count() == 1);
    });
}

foreach (var pathNamespace in new[] { @"\\?\C:\NoIO", @"\\.\NUL" })
{
    foreach (var argument in new[] { "output", "engine-root", "config" })
    {
        Check("device-namespace-rejected-before-io-" + argument + "-" + pathNamespace, () =>
        {
            var parent = Scope();
            var target = Path.Combine(parent, "output");
            var arguments = argument switch
            {
                "output" => NewArguments(pathNamespace),
                "engine-root" => NewArguments(target, root: pathNamespace),
                _ => new[] { "validate", "--config", pathNamespace }
            };
            var result = Run(arguments);
            Assert(result.Code == 3);
            using var error = JsonDocument.Parse(result.Error);
            Assert(error.RootElement.GetProperty("code").GetString() == "path.namespace", "Device path must be rejected lexically before filesystem access.");
            AssertNoPublish(parent, target);
        });
    }
}

if (OperatingSystem.IsWindows())
{
    Check("windows-extended-output-path-cannot-bypass-checkout-boundary", () =>
    {
        var parent = Scope();
        var source = CreateSourceFixture(parent);
        var target = Path.Combine(source, "src", "UnexpectedOutput");
        var before = Snapshot(parent);
        Assert(Run(NewArguments(@"\\?\" + target, root: source)).Code == 3);
        Assert(!Directory.Exists(target));
        SameSnapshot(before, parent);
        Assert(!Directory.EnumerateDirectories(Path.Combine(source, "src")).Any(path => Path.GetFileName(path).StartsWith(".cehpalon-stage-", StringComparison.Ordinal)));
    });
    Check("windows-extended-source-path-is-rejected-before-output", () =>
    {
        var parent = Scope();
        var source = CreateSourceFixture(parent);
        var before = Snapshot(parent);
        var target = Path.Combine(parent, "output");
        Assert(Run(NewArguments(target, root: @"\\?\" + source)).Code == 3);
        Assert(!Directory.Exists(target));
        SameSnapshot(before, parent);
        Assert(Directory.EnumerateDirectories(parent).Count() == 3);
    });
    Check("windows-extended-config-path-is-rejected-without-modification", () =>
    {
        var parent = Scope();
        var target = Path.Combine(parent, "output");
        Assert(Run(NewArguments(target)).Code == 0);
        var before = Snapshot(parent);
        Assert(Run("validate", "--config", @"\\?\" + Path.Combine(target, "appsettings.json")).Code == 3);
        SameSnapshot(before, parent);
    });
}

Check("existing-directory-symlink-is-not-followed-or-removed", () =>
{
    var parent = Scope();
    var external = Path.Combine(parent, "external");
    var target = Path.Combine(parent, "output");
    Directory.CreateDirectory(external);
    File.WriteAllText(Path.Combine(external, "sentinel"), "outside-content");
    Directory.CreateSymbolicLink(target, external);
    var before = Snapshot(external);
    Assert(Run(NewArguments(target)).Code == 3);
    Assert(new DirectoryInfo(target).LinkTarget is not null, "Existing symlink was removed or replaced.");
    SameSnapshot(before, external);
    Assert(Directory.EnumerateFileSystemEntries(parent).Count() == 2);
});

Check("dangling-directory-symlink-is-not-replaced", () =>
{
    var parent = Scope();
    var missing = Path.Combine(parent, "not-created");
    var target = Path.Combine(parent, "output");
    Directory.CreateSymbolicLink(target, missing);
    Assert(Run(NewArguments(target)).Code == 3);
    Assert(new DirectoryInfo(target).LinkTarget is not null, "Dangling symlink was removed or replaced.");
    Assert(!Directory.Exists(missing));
    Assert(Directory.EnumerateFileSystemEntries(parent).Count() == 1);
});

Check("output-parent-symlink-is-not-followed", () =>
{
    var parent = Scope();
    var external = Path.Combine(parent, "external");
    var link = Path.Combine(parent, "linked-parent");
    Directory.CreateDirectory(external);
    File.WriteAllBytes(Path.Combine(external, "sentinel"), [0, 255, 13, 10]);
    Directory.CreateSymbolicLink(link, external);
    var before = Snapshot(external);
    Assert(Run(NewArguments(Path.Combine(link, "output"))).Code == 3);
    Assert(new DirectoryInfo(link).LinkTarget is not null);
    SameSnapshot(before, external);
    Assert(Directory.EnumerateFileSystemEntries(parent).Count() == 2);
});

Check("source-input-symlink-is-not-followed", () =>
{
    var parent = Scope();
    var source = CreateSourceFixture(parent);
    var realInput = Path.Combine(parent, "external-global.json");
    File.Copy(Path.Combine(source, "global.json"), realInput);
    File.Delete(Path.Combine(source, "global.json"));
    File.CreateSymbolicLink(Path.Combine(source, "global.json"), realInput);
    var before = File.ReadAllBytes(realInput);
    var target = Path.Combine(parent, "output");
    Assert(Run(NewArguments(target, root: source)).Code == 3);
    Assert(new FileInfo(Path.Combine(source, "global.json")).LinkTarget is not null);
    Assert(File.ReadAllBytes(realInput).SequenceEqual(before));
    Assert(!Directory.Exists(target) && Directory.EnumerateDirectories(parent).Count() == 3);
});

Check("valid-generated-config-validates-without-changing-files", () =>
{
    var parent = Scope();
    var target = Path.Combine(parent, "output");
    Assert(Run(NewArguments(target)).Code == 0);
    var before = Snapshot(parent);
    var result = Run("validate", "--config", Path.Combine(target, "appsettings.json"));
    Assert(result.Code == 0 && result.Error.Length == 0, "Generated config rejected: " + result.Error);
    SameSnapshot(before, parent);
});

foreach (var setting in new (string Name, string From, string To)[]
{
    ("unsupported-topology", "SingleProcess", "Distributed"),
    ("unsupported-pattern", "RequestReply", "EventSourcing"),
    ("unsupported-architecture", "Modular", "Microservices")
})
{
    Check("generated-config-rejects-" + setting.Name + "-without-mutation", () =>
    {
        var parent = Scope();
        var target = Path.Combine(parent, "output");
        Assert(Run(NewArguments(target)).Code == 0);
        var path = Path.Combine(target, "appsettings.json");
        var original = File.ReadAllText(path);
        Assert(original.Contains(setting.From, StringComparison.Ordinal), "Expected baseline config setting not present.");
        File.WriteAllText(path, original.Replace(setting.From, setting.To, StringComparison.Ordinal), new UTF8Encoding(false));
        var before = Snapshot(parent);
        var result = Run("validate", "--config", path);
        Assert(result.Code == 2, "Unsupported config combination must be exit2.");
        SameSnapshot(before, parent);
    });
}

Check("unknown-module-config-diagnostic-does-not-disclose-module-key", () =>
{
    var parent = Scope();
    var target = Path.Combine(parent, "output");
    Assert(Run(NewArguments(target)).Code == 0);
    var path = Path.Combine(target, "appsettings.json");
    var text = File.ReadAllText(path);
    Assert(text.Contains("\"app\"", StringComparison.Ordinal));
    File.WriteAllText(path, text.Replace("\"app\"", "\"SUPER_SECRET_CONFIG_VALUE\"", StringComparison.Ordinal), new UTF8Encoding(false));
    var before = Snapshot(parent);
    var result = Run("validate", "--config", path);
    Assert(result.Code == 2);
    Assert(!(result.Output + result.Error).Contains("SUPER_SECRET_CONFIG_VALUE", StringComparison.Ordinal), "Unknown module key leaked in diagnostic code/path/message.");
    SameSnapshot(before, parent);
});

Check("missing-config-has-path-exit-without-creation", () =>
{
    var parent = Scope();
    var path = Path.Combine(parent, "missing.json");
    Assert(Run("validate", "--config", path).Code == 3);
    Assert(!Directory.EnumerateFileSystemEntries(parent).Any());
});

Check("directory-config-is-rejected-without-mutation", () =>
{
    var parent = Scope();
    Assert(Run("validate", "--config", parent).Code == 3);
    Assert(!Directory.EnumerateFileSystemEntries(parent).Any());
});

foreach (var invalid in new (string Name, string Text)[]
{
    ("empty", ""),
    ("malformed", "{ not-json SUPER_SECRET_CONFIG_VALUE"),
    ("no-engine-section", "{\"ConnectionStrings\":{\"Secret\":\"SUPER_SECRET_CONFIG_VALUE\"}}"),
    ("scalar-root", "\"SUPER_SECRET_CONFIG_VALUE\""),
    ("array-root", "[\"SUPER_SECRET_CONFIG_VALUE\"]"),
    ("duplicate-engine-sections", "{\"Cehpalon\":{},\"Cehpalon\":{\"secret\":\"SUPER_SECRET_CONFIG_VALUE\"}}")
})
{
    Check("invalid-config-" + invalid.Name + "-preserves-bytes-and-redacts-content", () =>
    {
        var parent = Scope();
        var path = Path.Combine(parent, "config.json");
        File.WriteAllText(path, invalid.Text, new UTF8Encoding(false));
        var before = Snapshot(parent);
        var result = Run("validate", "--config", path);
        Assert(result.Code == 2, "Invalid config must be exit2, got " + result.Code);
        Assert(!(result.Output + result.Error).Contains("SUPER_SECRET_CONFIG_VALUE", StringComparison.Ordinal), "Config content leaked into CLI output.");
        SameSnapshot(before, parent);
    });
}

Check("oversize-config-rejected-without-content-disclosure", () =>
{
    var parent = Scope();
    var path = Path.Combine(parent, "large.json");
    File.WriteAllText(path, "{\"Secret\":\"SUPER_SECRET_CONFIG_VALUE" + new string('x', 1024 * 1024) + "\"}", new UTF8Encoding(false));
    var before = Snapshot(parent);
    var result = Run("validate", "--config", path);
    Assert(result.Code == 2);
    Assert(!(result.Output + result.Error).Contains("SUPER_SECRET_CONFIG_VALUE", StringComparison.Ordinal));
    SameSnapshot(before, parent);
});

Check("invalid-utf8-config-is-rejected-without-modification", () =>
{
    var parent = Scope();
    var path = Path.Combine(parent, "invalid-utf8.json");
    File.WriteAllBytes(path, [0x7B, 0x22, 0xC3, 0x28, 0x22, 0x3A, 0x30, 0x7D]);
    var before = Snapshot(parent);
    Assert(Run("validate", "--config", path).Code == 2);
    SameSnapshot(before, parent);
});

string[] SmallArguments(string target) => [.. NewArguments(target), "--profile", "small-api"];
string[] smallFiles = ["Catalog.cs", "Consumer.csproj", "ContractExport.cs", "FixtureHost.cs", "NuGet.Config", "Program.cs", "README.md", "SelfTest.cs",
    "appsettings.graphql-only.json", "appsettings.graphql.json", "appsettings.json", "appsettings.off.json", "engine-source.json", "global.json"];

Check("small-api-exact-files-determinism-and-profile-specific-validation", () =>
{
    var parent = Scope(); var first = Path.Combine(parent, "first"); var second = Path.Combine(parent, "second");
    Assert(Run(SmallArguments(first)).Code == 0); Assert(Run(SmallArguments(second)).Code == 0);
    Assert(Directory.EnumerateFiles(first).Select(Path.GetFileName).Order(StringComparer.Ordinal).SequenceEqual(smallFiles.Order(StringComparer.Ordinal)));
    SameSnapshot(Snapshot(first), second);
    foreach (var name in new[] { "appsettings.json", "appsettings.graphql.json", "appsettings.graphql-only.json", "appsettings.off.json" })
    {
        var config = Path.Combine(first, name); var before = Snapshot(first);
        var result = Run("validate", "--profile", "small-api", "--config", config);
        Assert(result.Code == 0 && result.Error.Length == 0);
        using var json = JsonDocument.Parse(result.Output);
        Assert(json.RootElement.GetProperty("profile").GetString() == "small-api");
        SameSnapshot(before, first);
    }
    Assert(Run("validate", "--config", Path.Combine(first, "appsettings.json")).Code == 2,
        "Small API config must not be silently accepted by the portable catalog.");
});

foreach (var capability in new[] { "worker", "database", "cache", "broker", "ai", "retrieval" })
{
    Check("small-api-pure-validation-rejects-unsupported-" + capability, () =>
    {
        var parent = Scope(); var target = Path.Combine(parent, "consumer"); Assert(Run(SmallArguments(target)).Code == 0);
        var path = Path.Combine(target, "appsettings.json");
        var config = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(path))!;
        config["Cehpalon"]!["Modules"]![capability] = new System.Text.Json.Nodes.JsonObject { ["Enabled"] = true };
        File.WriteAllText(path, config.ToJsonString()); var before = Snapshot(target);
        var result = Run("validate", "--profile", "small-api", "--config", path);
        Assert(result.Code == 2 && result.Output.Length == 0); SameSnapshot(before, target);
    });
}

for (var position = 1; position <= 14; position++)
foreach (var after in new[] { false, true })
{
    var fault = position; var afterWrite = after;
    Check($"small-api-write-failure-{fault}-{afterWrite}-preserves-neighbor", () =>
    {
        var parent = Scope(); var target = Path.Combine(parent, "consumer"); var neighbor = Path.Combine(parent, "neighbor.txt");
        File.WriteAllText(neighbor, "unrelated bytes"); var before = Snapshot(parent);
        var physical = new PhysicalToolingFileSystem(); var writes = 0;
        var fs = new DelegatingFileSystem((path, bytes) =>
        {
            writes++;
            if (writes == fault && !afterWrite) throw new IOException("SUPER_SECRET_FAILURE");
            physical.WriteAllBytes(path, bytes);
            if (writes == fault && afterWrite) throw new IOException("SUPER_SECRET_FAILURE");
        }, physical.MoveDirectory);
        var result = Invoke(SmallArguments(target), fs);
        Assert(result.Code == 3 && writes == fault && !result.Error.Contains("SUPER_SECRET_FAILURE", StringComparison.Ordinal));
        Assert(!Directory.Exists(target) && !Directory.EnumerateDirectories(parent).Any()); SameSnapshot(before, parent);
    });
}

Check("small-api-publication-collision-keeps-outsider-bytes", () =>
{
    var parent = Scope(); var target = Path.Combine(parent, "consumer"); var physical = new PhysicalToolingFileSystem();
    var fs = new DelegatingFileSystem(physical.WriteAllBytes, (stage, destination) =>
    {
        Directory.CreateDirectory(destination); File.WriteAllText(Path.Combine(destination, "outsider.txt"), "owned by another writer");
        physical.MoveDirectory(stage, destination);
    });
    Assert(Invoke(SmallArguments(target), fs).Code == 3);
    Assert(File.ReadAllText(Path.Combine(target, "outsider.txt")) == "owned by another writer");
    Assert(Directory.EnumerateDirectories(parent).Single() == target && Directory.EnumerateFiles(target).Count() == 1);
});

var output = new
{
    schemaVersion = 1,
    timestampUtc = DateTimeOffset.UtcNow,
    runtime = RuntimeInformation.FrameworkDescription,
    os = RuntimeInformation.OSDescription,
    architecture = RuntimeInformation.ProcessArchitecture.ToString(),
    scope = "Experimental portable CLI contracts: parsing, deterministic file generation, non-destructive path handling and config validation. Not generated-consumer compilation, real transports/providers, deployment qualification, full tooling acceptance or performance proof.",
    fixtureRoot = runRoot,
    passed = checks.Count - failures,
    failed = failures,
    tests = checks
};
var json = JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = true });
var outputArgument = args.SingleOrDefault(value => value.StartsWith("--output=", StringComparison.Ordinal));
if (outputArgument is not null)
{
    var path = Path.GetFullPath(outputArgument[9..]);
    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
    File.WriteAllText(path, json + "\n", new UTF8Encoding(false));
}
Console.WriteLine(json);
return failures == 0 ? 0 : 1;

static string FindEngineRoot()
{
    for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        if (File.Exists(Path.Combine(directory.FullName, "src", "Cehpalon.Engine.Core", "Cehpalon.Engine.Core.csproj")))
            return directory.FullName;
    throw new InvalidOperationException("Cannot locate Engine source root.");
}

sealed record CliResult(int Code, string Output, string Error);

sealed class DelegatingFileSystem(Action<string, byte[]> write, Action<string, string> move) : IToolingFileSystem
{
    public void WriteAllBytes(string path, byte[] bytes) => write(path, bytes);
    public void MoveDirectory(string source, string destination) => move(source, destination);
}
