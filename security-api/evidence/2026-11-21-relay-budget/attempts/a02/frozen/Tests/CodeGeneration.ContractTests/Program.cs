using System.Collections.Immutable;
using System.Globalization;
using System.Reflection;
using System.Runtime.Loader;
using System.Text.Json;
using Cehpalon.Engine.CodeGeneration;
using Cehpalon.Engine.Core;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

var checks = new List<CheckResult>();
var output = args.SingleOrDefault(a => a.StartsWith("--output=", StringComparison.Ordinal))?[9..];
const string imports = "using System; using System.Threading; using System.Threading.Tasks; using Cehpalon.Engine.Core;\n";
var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
    .Append(typeof(OperationAttribute).Assembly.Location).Distinct(StringComparer.Ordinal)
    .Select(path => MetadataReference.CreateFromFile(path)).ToArray();

void Assert(bool value, string message = "Contract assertion failed") { if (!value) throw new Exception(message); }
void Test(string name, Action action)
{
    try { action(); checks.Add(new(name, "Passed", null)); }
    catch (Exception error) { checks.Add(new(name, "Failed", error.ToString())); }
}
string Handler(string name = "Echo", string id = "echo.run", string access = "internal", string extra = "", string request = "string", string response = "string") =>
    imports + $"namespace Fixture {{ [Operation(\"{id}\")] {access} {extra} class {name} : IOperationHandler<{request}, {response}> {{ public ValueTask<OperationResult<{response}>> HandleAsync({request} request, OperationContext context, CancellationToken cancellationToken) => new ValueTask<OperationResult<{response}>>(OperationResult<{response}>.Success(default!)); }} }}";

RunResult Run(string[] sources, CancellationToken token = default)
{
    var parse = new CSharpParseOptions(LanguageVersion.Preview);
    var compilation = CSharpCompilation.Create("Fixture_" + Guid.NewGuid().ToString("N"),
        sources.Select((source, index) => CSharpSyntaxTree.ParseText(source, parse, path: "Input" + index + ".cs")),
        references, new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, nullableContextOptions: NullableContextOptions.Enable));
    GeneratorDriver driver = CSharpGeneratorDriver.Create(new[] { new OperationRegistryGenerator().AsSourceGenerator() }, parseOptions: parse,
        driverOptions:new GeneratorDriverOptions(IncrementalGeneratorOutputKind.None,trackIncrementalGeneratorSteps:true));
    driver = driver.RunGeneratorsAndUpdateCompilation(compilation, out var generated, out var diagnostics, token);
    return new RunResult(driver, generated, diagnostics, compilation);
}
string Text(RunResult result) => string.Join("\n", result.Driver.GetRunResult().GeneratedTrees.Select(tree => tree.GetText().ToString()));
void Valid(RunResult result)
{
    var diagnostics = result.Compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToArray();
    Assert(!result.Diagnostics.Any(d => d.Severity == DiagnosticSeverity.Error), string.Join("\n", result.Diagnostics));
    Assert(diagnostics.Length == 0, string.Join("\n", diagnostics.Select(d => d.ToString())));
}
void Invalid(string source, string code)
{
    var result = Run(new[] { source });
    Assert(result.Diagnostics.Any(d => d.Id == code && d.Severity == DiagnosticSeverity.Error && d.Location.IsInSource), "Expected located " + code + ": " + string.Join("\n", result.Diagnostics));
    Assert(!result.Driver.GetRunResult().GeneratedTrees.Any(), "Invalid candidate must suppress entire registry");
}

Test("valid internal handler generates compileable typed registry", () => { var result = Run(new[] { Handler() }); Valid(result); Assert(Text(result).Contains("builder.Register<string, string>(\"echo.run\", () => factory.Create<global::Fixture.Echo>())", StringComparison.Ordinal)); });
Test("valid public handler compiles", () => Valid(Run(new[] { Handler(access: "public") })));
Test("valid nested internal handler compiles", () => Valid(Run(new[] { imports + "namespace Fixture { internal class Outer { [Operation(\"nested.run\")] internal sealed class Echo : IOperationHandler<int, int> { public ValueTask<OperationResult<int>> HandleAsync(int request, OperationContext context, CancellationToken token) => new(OperationResult<int>.Success(request)); } } }" })));
Test("dependency-injected constructor has no new constraint", () => Valid(Run(new[] { imports + "namespace Fixture { [Operation(\"ctor.run\")] internal sealed class Echo : IOperationHandler<string,string> { public Echo(string dependency) {} public ValueTask<OperationResult<string>> HandleAsync(string request,OperationContext context,CancellationToken token)=>new(OperationResult<string>.Success(request)); } }" })));
Test("attribute alias resolves semantically", () => Valid(Run(new[] { Handler().Replace("[Operation(", "[Alias(", StringComparison.Ordinal).Replace(imports, imports + "using Alias = Cehpalon.Engine.Core.OperationAttribute;\n", StringComparison.Ordinal) })));
Test("partial declaration registers once", () => { var result = Run(new[] { Handler(extra: "partial"), "namespace Fixture { internal partial class Echo {} }" }); Valid(result); Assert(Text(result).Split("builder.Register<", StringSplitOptions.None).Length == 2); });
Test("inherited closed contract compiles", () => Valid(Run(new[] { imports + "namespace Fixture { internal abstract class Base<T> : IOperationHandler<T,string> { public abstract ValueTask<OperationResult<string>> HandleAsync(T request, OperationContext context, CancellationToken token); } [Operation(\"inherited.run\")] internal sealed class Echo : Base<int> { public override ValueTask<OperationResult<string>> HandleAsync(int request, OperationContext context, CancellationToken token) => new(OperationResult<string>.Success(request.ToString())); } }" })));
Test("same inherited interface via diamond remains unambiguous", () => Valid(Run(new[] { imports + "namespace Fixture { internal interface IAlias : IOperationHandler<string,string> {} [Operation(\"diamond.run\")] internal sealed class Echo : IAlias, IOperationHandler<string,string> { public ValueTask<OperationResult<string>> HandleAsync(string request,OperationContext context,CancellationToken token)=>new(OperationResult<string>.Success(request)); } }" })));
Test("keyword type and namespace escaped", () => { var source = imports + "namespace @namespace { internal sealed class @event {} [Operation(\"keyword.run\")] internal class @class : IOperationHandler<@event,@event> { public ValueTask<OperationResult<@event>> HandleAsync(@event request,OperationContext context,CancellationToken token)=>new(OperationResult<@event>.Success(request)); } }"; var result=Run(new[]{source}); Valid(result); Assert(Text(result).Contains("global::@namespace.@class",StringComparison.Ordinal)); });
Test("array and closed generic request types compile", () => Valid(Run(new[] { Handler(request: "System.Collections.Generic.List<int[]>", response: "int[]") })));
Test("nullable annotated request compiles", () => Valid(Run(new[] { Handler(request: "string?", response: "string?") })));
Test("128-byte canonical id accepted", () => Valid(Run(new[] { Handler(id: "a" + new string('z', 127)) })));
foreach (var id in new[] { "", "Upper", "1first", "space id", "unicode.ท", "a" + new string('z',128) })
    Test("invalid id rejected: " + (id.Length > 30 ? "too-long" : id), () => Invalid(Handler(id:id), "CEHGEN001"));
Test("null operation id rejected", () => Invalid(Handler().Replace("\"echo.run\"", "null", StringComparison.Ordinal),"CEHGEN001"));
Test("abstract handler rejected", () => Invalid(Handler(extra:"abstract"),"CEHGEN002"));
Test("generic handler rejected", () => Invalid(Handler(name:"Echo<T>"),"CEHGEN002"));
Test("generic containing type rejected", () => Invalid(imports+"namespace Fixture { internal class Outer<T> { [Operation(\"generic.run\")] internal sealed class Echo : IOperationHandler<int,int> { public ValueTask<OperationResult<int>> HandleAsync(int request,OperationContext context,CancellationToken token)=>new(OperationResult<int>.Success(request)); } } }", "CEHGEN002"));
Test("private nested handler rejected", () => Invalid(imports+"namespace Fixture { internal class Outer { [Operation(\"private.run\")] private class Echo : IOperationHandler<int,int> { public ValueTask<OperationResult<int>> HandleAsync(int request,OperationContext context,CancellationToken token)=>new(OperationResult<int>.Success(request)); } } }", "CEHGEN003"));
Test("protected nested handler rejected", () => Invalid(imports+"namespace Fixture { public class Outer { [Operation(\"protected.run\")] protected class Echo : IOperationHandler<int,int> { public ValueTask<OperationResult<int>> HandleAsync(int request,OperationContext context,CancellationToken token)=>new(OperationResult<int>.Success(request)); } } }", "CEHGEN003"));
Test("file-local handler rejected", () => Invalid(Handler(access:"file"),"CEHGEN003"));
Test("normal-first same-display file-local handler cannot be dropped", () => {var result=Run(new[]{Handler(id:"normal.run"),Handler(id:"file.run",access:"file")});Assert(!result.Input.GetDiagnostics().Any(d=>d.Severity==DiagnosticSeverity.Error),"Peer fixture must be valid input C#");Assert(result.Diagnostics.Any(d=>d.Id=="CEHGEN003"&&d.Location.IsInSource));Assert(result.Driver.GetRunResult().GeneratedTrees.Length==0);});
Test("file-first same-display handler also fails closed", () => {var result=Run(new[]{Handler(id:"file.run",access:"file"),Handler(id:"normal.run")});Assert(!result.Input.GetDiagnostics().Any(d=>d.Severity==DiagnosticSeverity.Error),"Peer fixture must be valid input C#");Assert(result.Diagnostics.Any(d=>d.Id=="CEHGEN003"&&d.Location.IsInSource));Assert(result.Driver.GetRunResult().GeneratedTrees.Length==0);});
Test("file-local request rejected", () => Invalid(imports+"namespace Fixture { file class Request {} [Operation(\"file.request\")] internal class Echo : IOperationHandler<Request,string> { public ValueTask<OperationResult<string>> HandleAsync(Request request,OperationContext context,CancellationToken token)=>new(OperationResult<string>.Success(\"ok\")); } }", "CEHGEN003"));
Test("inaccessible containing type rejected", () => Invalid(imports+"namespace Fixture { internal class Outer { private class Hidden { [Operation(\"hidden.run\")] internal class Echo : IOperationHandler<int,int> { public ValueTask<OperationResult<int>> HandleAsync(int request,OperationContext context,CancellationToken token)=>new(OperationResult<int>.Success(request)); } } } }", "CEHGEN003"));
Test("ambiguous two distinct contracts rejected", () => Invalid(imports+"namespace Fixture { [Operation(\"ambiguous.run\")] internal class Echo : IOperationHandler<int,int>, IOperationHandler<string,string> { public ValueTask<OperationResult<int>> HandleAsync(int request,OperationContext context,CancellationToken token)=>new(OperationResult<int>.Success(request)); public ValueTask<OperationResult<string>> HandleAsync(string request,OperationContext context,CancellationToken token)=>new(OperationResult<string>.Success(request)); } }", "CEHGEN004"));
Test("attribute without handler contract rejected", () => Invalid(imports+"[Operation(\"missing.run\")] internal class Missing {}", "CEHGEN004"));
Test("duplicate ids fail closed including valid candidates", () => { var result=Run(new[]{ Handler("First"), Handler("Second"), Handler("Third","valid.third") }); Assert(result.Diagnostics.Count(d=>d.Id=="CEHGEN005")==2); Assert(result.Driver.GetRunResult().GeneratedTrees.Length==0); });
Test("one invalid candidate suppresses otherwise valid registry", () => {var result=Run(new[]{Handler("Valid"),Handler("Invalid","UPPER")});Assert(result.Diagnostics.Any(d=>d.Id=="CEHGEN001"));Assert(result.Driver.GetRunResult().GeneratedTrees.Length==0);});
Test("reserved generated type collision diagnosed", () => Invalid(Handler()+"namespace Cehpalon.Engine.Generated { internal static class OperationRegistrations {} }", "CEHGEN006"));
Test("reserved generated namespace collision diagnosed before emission", () => Invalid(Handler()+"namespace Cehpalon.Engine.Generated.OperationRegistrations { internal class Existing {} }", "CEHGEN006"));
Test("duplicate attributes across partial declarations fail closed", () => {var result=Run(new[]{Handler(id:"first.run",extra:"partial"),imports+"namespace Fixture { [Operation(\"second.run\")] internal partial class Echo {} }"});Assert(result.Diagnostics.Any(d=>d.Id=="CEHGEN007"&&d.Location.IsInSource));Assert(result.Driver.GetRunResult().GeneratedTrees.Length==0);});
Test("no operation attributes creates no generated code", () => {var result=Run(new[]{"internal class Plain {}"});Valid(result);Assert(result.Driver.GetRunResult().GeneratedTrees.Length==0);});
Test("retained incremental driver caches unchanged candidates", () => {var first=Run(new[]{Handler()});var driver=first.Driver.RunGeneratorsAndUpdateCompilation(first.Input,out var compiled,out var diagnostics);var candidateSteps=driver.GetRunResult().Results[0].TrackedSteps["OperationCandidates"];Assert(candidateSteps.SelectMany(s=>s.Outputs).All(o=>o.Reason==IncrementalStepRunReason.Cached || o.Reason==IncrementalStepRunReason.Unchanged));Assert(Text(first)==string.Join("\n",driver.GetRunResult().GeneratedTrees.Select(t=>t.GetText().ToString())));Assert(!diagnostics.Any(d=>d.Severity==DiagnosticSeverity.Error));});
Test("retained incremental driver refreshes changed operation id", () => {var first=Run(new[]{Handler()});var tree=first.Input.SyntaxTrees.Single();var replacement=CSharpSyntaxTree.ParseText(Handler(id:"changed.run"),(CSharpParseOptions)tree.Options,path:tree.FilePath);var changed=first.Input.ReplaceSyntaxTree(tree,replacement);var driver=first.Driver.RunGeneratorsAndUpdateCompilation(changed,out var compiled,out var diagnostics);var second=new RunResult(driver,compiled,diagnostics,changed);Valid(second);Assert(Text(second).Contains("changed.run",StringComparison.Ordinal));Assert(!Text(second).Contains("echo.run",StringComparison.Ordinal));});
Test("generation order and culture are deterministic", () => { var previous=CultureInfo.CurrentCulture;try {CultureInfo.CurrentCulture=CultureInfo.GetCultureInfo("tr-TR");var first=Run(new[]{Handler("Zed","z.last"),Handler("Alpha","a.first")});CultureInfo.CurrentCulture=CultureInfo.GetCultureInfo("en-US");var second=Run(new[]{Handler("Alpha","a.first"),Handler("Zed","z.last")});Valid(first);Valid(second);Assert(Text(first)==Text(second));Assert(Text(first).IndexOf("a.first",StringComparison.Ordinal)<Text(first).IndexOf("z.last",StringComparison.Ordinal));Assert(!Text(first).Contains('\r'));}finally{CultureInfo.CurrentCulture=previous;} });
Test("multiple duplicate-id groups keep deterministic diagnostic order", () =>
{
    var result = Run(new[] { Handler("Zed", "duplicate.a", extra: "partial"), Handler("Alpha", "duplicate.a"),
        Handler("Beta", "duplicate.b"), Handler("Gamma", "duplicate.b"), Handler("Valid", "valid.run"),
        "namespace Fixture { internal partial class Zed {} }" });
    var duplicates = result.Diagnostics.Where(d => d.Id == "CEHGEN005").ToArray();
    Assert(duplicates.Length == 4);
    Assert(duplicates.Select(d => d.Location.SourceTree!.FilePath).SequenceEqual(new[] { "Input1.cs", "Input0.cs", "Input2.cs", "Input3.cs" }));
    Assert(result.Driver.GetRunResult().GeneratedTrees.Length == 0);
});
Test("partial declaration errors precede semantic duplicate-id deduplication", () =>
{
    var result = Run(new[] { Handler("Peer", "duplicate.run", extra: "partial"),
        imports + "namespace Fixture { [Operation(\"duplicate.run\")] internal partial class Peer {} }", Handler("Other", "duplicate.run") });
    Assert(result.Diagnostics.Count(d => d.Id == "CEHGEN007") == 2, "Each annotated partial declaration must report its duplicate attribute");
    Assert(result.Diagnostics.Count(d => d.Id == "CEHGEN005") == 2, "Each distinct symbol must report the duplicate ID exactly once");
    Assert(result.Diagnostics.Take(2).All(d => d.Id == "CEHGEN007"), "Declaration errors must remain before duplicate-ID diagnostics");
    Assert(result.Driver.GetRunResult().GeneratedTrees.Length == 0);
});
Test("retained driver changes and reverts one id among multiple handlers", () =>
{
    var first = Run(new[] { Handler("First", "first.run"), Handler("Second", "second.run") });
    var tree = first.Input.SyntaxTrees.First();
    var replacement = CSharpSyntaxTree.ParseText(Handler("First", "changed.run"), (CSharpParseOptions)tree.Options, path: tree.FilePath);
    var changed = first.Input.ReplaceSyntaxTree(tree, replacement);
    var driver = first.Driver.RunGeneratorsAndUpdateCompilation(changed, out var compiled, out var diagnostics);
    var second = new RunResult(driver, compiled, diagnostics, changed); Valid(second);
    Assert(Text(second).Contains("changed.run", StringComparison.Ordinal) && Text(second).Contains("second.run", StringComparison.Ordinal));
    var reverted = changed.ReplaceSyntaxTree(replacement, tree);
    driver = driver.RunGeneratorsAndUpdateCompilation(reverted, out compiled, out diagnostics);
    var final = new RunResult(driver, compiled, diagnostics, reverted); Valid(final);
    Assert(Text(first) == Text(final), "Reverted valid inputs must restore exact source bytes");
});
Test("retained driver refreshes inherited contract changed in another tree", () =>
{
    string Base(string type) => imports + "namespace Fixture { internal class Base : IOperationHandler<" + type + "," + type +
        "> { public ValueTask<OperationResult<" + type + ">> HandleAsync(" + type + " request, OperationContext context, CancellationToken token) => new(OperationResult<" + type + ">.Success(request)); } }";
    var first = Run(new[] { imports + "namespace Fixture { [Operation(\"inherited.run\")] internal sealed class Echo : Base {} }", Base("int") });
    var tree = first.Input.SyntaxTrees.Last();
    var replacement = CSharpSyntaxTree.ParseText(Base("string"), (CSharpParseOptions)tree.Options, path: tree.FilePath);
    var changed = first.Input.ReplaceSyntaxTree(tree, replacement);
    var driver = first.Driver.RunGeneratorsAndUpdateCompilation(changed, out var compiled, out var diagnostics);
    var second = new RunResult(driver, compiled, diagnostics, changed); Valid(second);
    Assert(Text(second).Contains("builder.Register<string, string>", StringComparison.Ordinal));
    Assert(!Text(second).Contains("builder.Register<int, int>", StringComparison.Ordinal));
    var reverted = changed.ReplaceSyntaxTree(replacement, tree);
    driver = driver.RunGeneratorsAndUpdateCompilation(reverted, out compiled, out diagnostics);
    var final = new RunResult(driver, compiled, diagnostics, reverted); Valid(final);
    Assert(Text(first) == Text(final));
});
Test("pre-cancelled generator run propagates cancellation", () => {using var source=new CancellationTokenSource();source.Cancel();try {Run(new[]{Handler()},source.Token);throw new Exception("Expected cancellation");}catch(OperationCanceledException){} });
Test("actual emitted registry stays lazy and dispatches via Core", () =>
{
    var source=imports+"namespace Fixture { [Operation(\"echo.run\")] internal sealed class Echo : IOperationHandler<string,string>, IDisposable { public static int Disposed; public ValueTask<OperationResult<string>> HandleAsync(string request, OperationContext context, CancellationToken token)=>new(OperationResult<string>.Success(request+\":\"+context.CorrelationId)); public void Dispose()=>Disposed++; } internal sealed class Factory : IOperationHandlerFactory { public int Calls; public THandler Create<THandler>() where THandler:class { Calls++; if(typeof(THandler)==typeof(Echo)) return (THandler)(object)new Echo(); throw new InvalidOperationException(); } } public static class Entry { public static string Execute() { var builder=new OperationRegistryBuilder(); var factory=new Factory(); Cehpalon.Engine.Generated.OperationRegistrations.RegisterAll(builder,factory); if(factory.Calls!=0) throw new Exception(\"Eager factory\"); var dispatcher=new OperationDispatcher(builder.Build()); var result=dispatcher.DispatchAsync<string,string>(\"echo.run\",\"business\",new OperationContext(\"correlation\")).AsTask().GetAwaiter().GetResult(); if(factory.Calls!=1 || Echo.Disposed!=1) throw new Exception(\"Factory/disposal count\"); return result.Value; } } }";
    var result=Run(new[]{source});Valid(result);
    using var stream=new MemoryStream();var emitted=result.Compilation.Emit(stream);Assert(emitted.Success,string.Join("\n",emitted.Diagnostics));stream.Position=0;
    var context=new AssemblyLoadContext("GeneratedContract_"+Guid.NewGuid(),isCollectible:true);
    try {var assembly=context.LoadFromStream(stream);var entry=assembly.GetType("Fixture.Entry")!.GetMethod("Execute",BindingFlags.Public|BindingFlags.Static)!;Assert((string)entry.Invoke(null,null)! == "business:correlation");}
    finally {context.Unload();}
});

var report=new { observed_at_utc=DateTimeOffset.UtcNow, scope="Build-time codegen and Core fixture contracts only; not real transports, tenancy, benchmark, AOT, supported Windows or hosted CI proof", framework=System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription, roslyn=typeof(CSharpCompilation).Assembly.GetName().Version!.ToString(), passed=checks.Count(c=>c.Status=="Passed"),failed=checks.Count(c=>c.Status=="Failed"),results=checks };
var json=JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true});
if(output is not null){Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);File.WriteAllText(output,json+"\n");}
Console.WriteLine(json);
return report.failed==0?0:1;

record CheckResult(string Name,string Status,string? Detail);
record RunResult(GeneratorDriver Driver,Compilation Compilation,ImmutableArray<Diagnostic> Diagnostics,Compilation Input);
