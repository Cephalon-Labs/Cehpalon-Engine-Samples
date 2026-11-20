using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.CodeGeneration;
using System.Text.Json;

var references=((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator).Append(typeof(OperationAttribute).Assembly.Location).Distinct().Select(p=>MetadataReference.CreateFromFile(p)).ToArray();
const string imports="using Cehpalon.Engine.Core; using System.Threading; using System.Threading.Tasks; ";
string Handler(string id,string access="internal",string modifier="")=>imports+$"namespace Fixture {{ [Operation(\"{id}\")] {access} {modifier} class Echo : IOperationHandler<string,string> {{ public ValueTask<OperationResult<string>> HandleAsync(string r,OperationContext c,CancellationToken t)=>new(OperationResult<string>.Success(r)); }} }}";
object Probe(string name,string[] sources)
{
    var parse=new CSharpParseOptions(LanguageVersion.Preview);
    var input=CSharpCompilation.Create("Peer",sources.Select((s,i)=>CSharpSyntaxTree.ParseText(s,parse,path:$"input{i}.cs")),references,new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary,nullableContextOptions:NullableContextOptions.Enable));
    GeneratorDriver driver=CSharpGeneratorDriver.Create([new OperationRegistryGenerator().AsSourceGenerator()],parseOptions:parse);
    driver=driver.RunGeneratorsAndUpdateCompilation(input,out var output,out var diagnostics);
    return new {name,inputErrors=input.GetDiagnostics().Where(d=>d.Severity==DiagnosticSeverity.Error).Select(d=>d.ToString()).ToArray(),generatorDiagnostics=diagnostics.Select(d=>d.ToString()).ToArray(),trees=driver.GetRunResult().GeneratedTrees.Select(t=>t.ToString()).ToArray(),outputErrors=output.GetDiagnostics().Where(d=>d.Severity==DiagnosticSeverity.Error).Select(d=>d.ToString()).ToArray()};
}
var results=new[]{
    Probe("valid-first normal and file-local handler same displayname",[Handler("normal.run"),Handler("file.run","file")]),
    Probe("file-first same semantic collision reversed",[Handler("file.run","file"),Handler("normal.run")]),
    Probe("file-local alone baseline",[Handler("file.run","file")]),
    Probe("duplicate attribute split across partial declarations",[Handler("first.run","internal","partial"),imports+"namespace Fixture { [Operation(\"second.run\")] internal partial class Echo {} }"]),
    Probe("reserved generated name exists as namespace",[Handler("normal.run"),"namespace Cehpalon.Engine.Generated.OperationRegistrations { internal class Existing {} }"])
};
File.WriteAllText(".local/codegen-peer/results.json",JsonSerializer.Serialize(results,new JsonSerializerOptions{WriteIndented=true})+"\n");
Console.WriteLine(JsonSerializer.Serialize(results,new JsonSerializerOptions{WriteIndented=true}));
