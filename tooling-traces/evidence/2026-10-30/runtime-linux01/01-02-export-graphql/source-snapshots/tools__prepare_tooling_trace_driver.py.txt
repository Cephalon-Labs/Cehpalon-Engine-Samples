"""Prepare a pinned, explicitly perturbed diagnostic copy; never edits Engine source."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
BASE_REVISION = '55c630fc5d4c47258a1a2b0da4a16ce8bc42b9f7'
DRIVER_SHA256 = '359fc818ecf9851cbc0dd9065cea87d7ede10033943a09df2c88cbfefc41e3c0'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('Pinned diagnostic source anchor count differs: ' + repr(old[:100]))
    return source.replace(old, new, 1)


SUPPORT = r'''using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

// Diagnostic-only observer. Every stage end is captured before this logger runs.
static class DiagnosticSpans
{
    static readonly List<SpanRecord> Records = new();
    static string? path;
    static long sequence, anchorBefore, anchorAfter, utcTicks;
    static int size, caseIndex = -1, pair = -1;
    static string state = "startup", phase = "startup", variant = "none";
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    [DllImport("libc", EntryPoint = "gettid")] static extern int GetTid();
    static int OsThreadId() => OperatingSystem.IsWindows() ? checked((int)GetCurrentThreadId()) : GetTid();
    internal static void Initialize(string output)
    {
        if (File.Exists(output)) throw new IOException("Diagnostic span sidecar must be new.");
        path = output;
        anchorBefore = Stopwatch.GetTimestamp();
        utcTicks = DateTimeOffset.UtcNow.UtcTicks;
        anchorAfter = Stopwatch.GetTimestamp();
    }
    internal static void Case(int operationCount, string caseState, int index, int pairSequence, string rowPhase)
    { size = operationCount; state = caseState; caseIndex = index; pair = pairSequence; phase = rowPhase; variant = "none"; }
    internal static void Variant(string value) => variant = value;
    internal static void Span(string stage, long startTicks, long endTicks)
    {
        if (path is null) return;
        var id = ++sequence;
        // Metadata acquisition and event/sidecar bookkeeping are AFTER body end.
        var tid = OsThreadId();
        var pid = Environment.ProcessId;
        var markerBefore = Stopwatch.GetTimestamp();
        ToolingDiagnosticEvents.Log.Span(id, stage, startTicks, endTicks, Stopwatch.Frequency,
            utcTicks, anchorBefore, anchorAfter, pid, tid, caseIndex, size, state, variant, pair, phase, markerBefore);
        var markerAfter = Stopwatch.GetTimestamp();
        Records.Add(new(id, stage, startTicks, endTicks, Stopwatch.Frequency, utcTicks,
            anchorBefore, anchorAfter, pid, tid, caseIndex, size, state, variant, pair, phase,
            markerBefore, markerAfter));
    }
    internal static void Complete()
    {
        if (path is null) return;
        using var writer = new StreamWriter(new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read), new UTF8Encoding(false));
        var json = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        foreach (var record in Records) writer.WriteLine(JsonSerializer.Serialize(record, json));
    }
    sealed record SpanRecord(long Sequence, string Stage, long StartTicks, long EndTicks, long Frequency,
        long UtcAnchorTicks, long AnchorBeforeTicks, long AnchorAfterTicks, int ProcessId, int OsThreadId,
        int CaseIndex, int Size, string State, string Variant, int PairSequence, string Phase,
        long MarkerBeforeTicks, long MarkerAfterTicks);
}

[EventSource(Name = "Cehpalon-Tooling-Diagnostic")]
sealed class ToolingDiagnosticEvents : EventSource
{
    internal static readonly ToolingDiagnosticEvents Log = new();
    public static class Keywords { public const EventKeywords Diagnostic = (EventKeywords)1; }
    [Event(1, Level = EventLevel.Informational, Keywords = Keywords.Diagnostic)]
    public void Span(long sequence, string stage, long startTicks, long endTicks, long frequency,
        long utcAnchorTicks, long anchorBeforeTicks, long anchorAfterTicks, int processId, int osThreadId,
        int caseIndex, int size, string state, string variant, int pairSequence, string phase, long markerBeforeTicks)
    {
        if (IsEnabled()) WriteEvent(1, sequence, stage, startTicks, endTicks, frequency,
            utcAnchorTicks, anchorBeforeTicks, anchorAfterTicks, processId, osThreadId,
            caseIndex, size, state, variant, pairSequence, phase, markerBeforeTicks);
    }
}
'''


def instrument(original):
    source = original
    source = replace_once(source, '        var report = new Report();',
                          '        DiagnosticSpans.Initialize(output + ".spans.jsonl");\n        var report = new Report();')
    source = replace_once(source, '            foreach (var size in Sizes) report.Preflight.Add(CachePreflight(size));',
                          '            foreach (var size in Sizes) { DiagnosticSpans.Case(size, "cache", -1, -1, "preflight"); report.Preflight.Add(CachePreflight(size)); }')
    source = replace_once(source, '                Context? context = state == "fresh" ? null : new Context(size);',
                          '                DiagnosticSpans.Case(size, state, caseIndex, -1, "seed");\n                Context? context = state == "fresh" ? null : new Context(size);')
    source = replace_once(source, '                    context = state == "fresh" ? new Context(size) : context!;',
                          '                    DiagnosticSpans.Case(size, state, caseIndex, pair, pair < 2 ? "primer" : "measurement");\n                    context = state == "fresh" ? new Context(size) : context!;')
    source = replace_once(source, '                            raw.WriteLine(JsonSerializer.Serialize(new { failedAttempt = report.FailedAttempt }, JournalJson));',
                          '                            var failedWriteStart = Stopwatch.GetTimestamp();\n                            raw.WriteLine(JsonSerializer.Serialize(new { failedAttempt = report.FailedAttempt }, JournalJson));\n                            DiagnosticSpans.Span("journal.persistence.failure", failedWriteStart, Stopwatch.GetTimestamp());')
    source = replace_once(source, '                        raw.WriteLine(JsonSerializer.Serialize(new { phase = pair < 2 ? "primer" : "measurement", row }, JournalJson));',
                          '                        var writeStart = Stopwatch.GetTimestamp();\n                        raw.WriteLine(JsonSerializer.Serialize(new { phase = pair < 2 ? "primer" : "measurement", row }, JournalJson));\n                        DiagnosticSpans.Span("journal.persistence", writeStart, Stopwatch.GetTimestamp());')
    source = replace_once(source, '                foreach (var artifact in new[] { lastGenerator!, lastManual! })',
                          '                DiagnosticSpans.Case(size, state, caseIndex, 16, "postflight");\n                foreach (var artifact in new[] { lastGenerator!, lastManual! })')
    source = replace_once(source, '            JsonSerializer.Serialize(final, report, Json);',
                          '            JsonSerializer.Serialize(final, report, Json);\n            DiagnosticSpans.Complete();')
    source = replace_once(source, '        using var stream = new MemoryStream();\n        using var process = Process.GetCurrentProcess();',
                          '        DiagnosticSpans.Variant(variant);\n        var setupStart = Stopwatch.GetTimestamp();\n        using var stream = new MemoryStream();\n        using var process = Process.GetCurrentProcess();')
    source = replace_once(source, '        var start = Stopwatch.GetTimestamp();\n        Compilation compilation',
                          '        long generatorStart = 0, generatorEnd = 0;\n        var start = Stopwatch.GetTimestamp();\n        Compilation compilation')
    source = replace_once(source, '        if (variant == "generator")\n            context.Driver = context.Driver.RunGeneratorsAndUpdateCompilation(context.Input, out compilation, out generatorDiagnostics);\n        var emitted = compilation.Emit(stream);',
                          '        if (variant == "generator")\n        {\n            generatorStart = Stopwatch.GetTimestamp();\n            context.Driver = context.Driver.RunGeneratorsAndUpdateCompilation(context.Input, out compilation, out generatorDiagnostics);\n            generatorEnd = Stopwatch.GetTimestamp();\n        }\n        var emitStart = Stopwatch.GetTimestamp();\n        var emitted = compilation.Emit(stream);\n        var emitEnd = Stopwatch.GetTimestamp();')
    source = replace_once(source, '        var gc0 = GC.CollectionCount(0) - g0; var gc1 = GC.CollectionCount(1) - g1; var gc2 = GC.CollectionCount(2) - g2;',
                          '        var gc0 = GC.CollectionCount(0) - g0; var gc1 = GC.CollectionCount(1) - g1; var gc2 = GC.CollectionCount(2) - g2;\n        // All observer event writes happen AFTER original metric brackets.\n        DiagnosticSpans.Span("execute.setup", setupStart, start);\n        if (variant == "generator") DiagnosticSpans.Span("generator.run", generatorStart, generatorEnd);\n        DiagnosticSpans.Span("pe.emit", emitStart, emitEnd);\n        DiagnosticSpans.Span("compiler.wall", start, start + wall);')
    source = replace_once(source, '        AssertRegistry(context, artifact.Registry);\n        var load = new AssemblyLoadContext',
                          '        DiagnosticSpans.Variant(artifact.Variant);\n        AssertRegistry(context, artifact.Registry);\n        var runtimeStart = Stopwatch.GetTimestamp();\n        var load = new AssemblyLoadContext')
    source = replace_once(source, '        finally { load.Unload(); }',
                          '        finally { load.Unload(); DiagnosticSpans.Span("runtime.verify", runtimeStart, Stopwatch.GetTimestamp()); }')
    source = replace_once(source, '    static void AssertRegistry(Context context, string source)\n    {',
                          '    static void AssertRegistry(Context context, string source)\n    {\n        var astStart = Stopwatch.GetTimestamp();\n        try { AssertRegistryBody(context, source); }\n        finally { DiagnosticSpans.Span("ast.verify", astStart, Stopwatch.GetTimestamp()); }\n    }\n\n    static void AssertRegistryBody(Context context, string source)\n    {')
    source = replace_once(source, '    internal static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));',
                          '    internal static string Hash(byte[] bytes)\n    {\n        var hashStart = Stopwatch.GetTimestamp();\n        try { return Convert.ToHexStringLower(SHA256.HashData(bytes)); }\n        finally { DiagnosticSpans.Span("hash", hashStart, Stopwatch.GetTimestamp()); }\n    }')
    source = replace_once(source, '        Size = size;\n        var trees',
                          '        var setupStart = Stopwatch.GetTimestamp();\n        Size = size;\n        var trees')
    source = replace_once(source, '        Driver = Runner.Driver(track);',
                          '        Driver = Runner.Driver(track);\n        DiagnosticSpans.Span("fixture.setup", setupStart, Stopwatch.GetTimestamp());')
    source = replace_once(source, '        if (version == Version) throw new InvalidOperationException("Edit fixture must change one operation ID per pair.");',
                          '        var editStart = Stopwatch.GetTimestamp();\n        if (version == Version) throw new InvalidOperationException("Edit fixture must change one operation ID per pair.");')
    source = replace_once(source, '        Manual = Manual.ReplaceSyntaxTree(manualTree, next); manualTree = next;',
                          '        Manual = Manual.ReplaceSyntaxTree(manualTree, next); manualTree = next;\n        DiagnosticSpans.Span("fixture.edit", editStart, Stopwatch.GetTimestamp());')
    source = replace_once(source, '    public string Protocol { get; } = "cehpalon-tooling-components-v1";',
                          '    public string Protocol { get; } = "cehpalon-tooling-diagnostic-spans-v1";\n    public bool Canonical { get; } = false;\n    public bool DiagnosticPerturbed { get; } = true;\n    public string Interpretation { get; } = "Observer-instrumented diagnostic only; extra clocks/events/record buffering perturb process state; no performance acceptance.";')
    source = replace_once(source, '            report.PerformanceStatus = "observed";',
                          '            report.PerformanceStatus = "diagnostic_only_not_acceptance";')
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine-root', required=True)
    parser.add_argument('--output', required=True, help='New project directory under this Samples checkout .local')
    parser.add_argument('--expected-engine-revision', default=BASE_REVISION)
    args = parser.parse_args()
    engine = Path(args.engine_root).resolve()
    output = (ROOT / args.output).resolve()
    if output == ROOT / '.local' or not output.is_relative_to((ROOT / '.local').resolve()):
        raise ValueError('Diagnostic project must be a new directory beneath ignored Samples .local')
    if output.exists():
        raise FileExistsError('Diagnostic project must not overwrite an earlier attempt')
    if re.fullmatch('[0-9a-f]{40}', args.expected_engine_revision) is None:
        raise ValueError('Expected revision must be an exact full Engine SHA')
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=engine, text=True).strip()
    dirty = subprocess.check_output(['git', 'status', '--porcelain'], cwd=engine, text=True).strip()
    if revision != args.expected_engine_revision or dirty:
        raise ValueError('Engine must be clean at the explicitly expected revision')
    original = (engine / 'Benchmarks/Tooling.Components/Program.cs').read_bytes()
    if digest(original) != DRIVER_SHA256:
        raise ValueError('Pinned Engine55 driver content hash differs; do not silently instrument another driver')
    modified = instrument(original.decode('utf-8'))
    project = '''<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net11.0</TargetFramework><Nullable>enable</Nullable><ImplicitUsings>enable</ImplicitUsings><ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile><Deterministic>true</Deterministic><IsPackable>false</IsPackable></PropertyGroup><ItemGroup><ProjectReference Include="CORE"/><ProjectReference Include="GENERATOR"/><PackageReference Include="Microsoft.CodeAnalysis.CSharp" Version="[4.14.0]" PrivateAssets="all"/></ItemGroup></Project>'''
    project = project.replace('CORE', escape((engine / 'src/Cehpalon.Engine.Core/Cehpalon.Engine.Core.csproj').as_posix(), {'"': '&quot;'})).replace('GENERATOR', escape((engine / 'src/Cehpalon.Engine.CodeGeneration/Cehpalon.Engine.CodeGeneration.csproj').as_posix(), {'"': '&quot;'}))
    files = {'Program.cs': modified.encode('utf-8'), 'DiagnosticSupport.cs': SUPPORT.encode('utf-8'),
             'TraceDriver.csproj': project.encode('utf-8'), 'Directory.Build.props': b'<Project/>\n',
             'global.json': (engine / 'global.json').read_bytes(), 'NuGet.Config': (engine / 'NuGet.Config').read_bytes(),
             'source-original.cs.txt': original}
    output.mkdir(parents=True, exist_ok=False)
    for name, content in files.items():
        (output / name).write_bytes(content)
    manifest = {'schema_version': 1, 'mode': 'diagnostic_copy', 'canonical': False, 'performance_status': 'diagnostic_only_not_acceptance',
                'qualification_status': 'not_qualified', 'engine_revision': revision, 'engine_source_unchanged': True,
                'original_driver_sha256': DRIVER_SHA256, 'helper_sha256': digest(Path(__file__).read_bytes()),
                'event_provider': 'Cehpalon-Tooling-Diagnostic', 'event_keywords': '0x1',
                'run_contract': 'dotnet TraceDriver.dll --output=<new-report.json>; sidecar <new-report.json>.spans.jsonl',
                'clock_mapping': 'Span start/end are actual Stopwatch body boundaries; event writes occur later. MarkerBefore/AfterTicks in sidecar bound the logging call; eventTimeRelative minus these timestamps gives an offset interval. UTC anchor has its own before/after bound. Inconsistent mapping must be reported as uncertain.',
                'observer_limits': ['Extra timestamp calls perturb the original wall scope; events, PInvoke native-thread lookup, buffered span records and final sidecar serialization perturb process state.', 'Event/logging work is excluded from each declared stage body and original wall/allocation/CPU/GC brackets; it can affect later process state.', 'Runtime verification includes actual owned handler disposal but excludes the separately tagged AST/logger work.', 'Static metadata reference initialization before Main is visible in runtime trace, not covered by per-row markers.', 'Sidecar is buffered until final report; abrupt process loss can leave incomplete sidecar, so event-only correlations cannot be called complete.'],
                'files': {name: {'bytes': len(content), 'sha256': digest(content)} for name, content in files.items()}}
    (output / 'diagnostic-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8', newline='\n')
    if (engine / 'Benchmarks/Tooling.Components/Program.cs').read_bytes() != original:
        raise ValueError('Engine source changed during diagnostic preparation')
    print(json.dumps({'status': 'prepared', 'canonical': False, 'engine_revision': revision, 'output': str(output), 'files': len(files)}))


if __name__ == '__main__':
    main()
