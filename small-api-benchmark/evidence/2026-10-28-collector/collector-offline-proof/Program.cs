using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Text.Json;
using SmallApi.Benchmark;

var output=Path.GetFullPath(args[0]);Directory.CreateDirectory(output);
var checks=new List<object>();var failed=0;
void Check(string name,Action action){try{action();checks.Add(new{name,passed=true});}catch(Exception e){failed++;checks.Add(new{name,passed=false,error=e.ToString()});}}
var driver=typeof(LoadDriver);const BindingFlags flags=BindingFlags.Static|BindingFlags.NonPublic;
var rowType=driver.GetNestedType("Observation",BindingFlags.NonPublic)!;
var store=driver.GetMethod("StoreObservation",flags)!;var coverage=driver.GetMethod("RequireCompleteObservations",flags)!;var persist=driver.GetMethod("PersistObservations",flags)!;
var options=(JsonSerializerOptions)driver.GetField("Json",flags)!.GetValue(null)!;
var preparationType=driver.GetNestedType("PreparationRecord",BindingFlags.NonPublic)!;
var preparationHeaders=driver.GetMethod("ValidatePreparationHeaders",flags)!;
Check("preparation acceptspositive HTTP1.1 withoutconsumingbody",()=>
{
 var content=new UnknownContent();using var response=new HttpResponseMessage(System.Net.HttpStatusCode.OK){Version=System.Net.HttpVersion.Version11,Content=content};response.Headers.TransferEncodingChunked=true;
 preparationHeaders.Invoke(null,[response,Activator.CreateInstance(preparationType,true)]);
 if(content.Serializations!=0)throw new Exception("Header readiness consumed response body.");
});
Check("preparation rejectszerobody ConnectionClose HTTP2 andunframedunknownbody",()=>
{
 foreach(var mode in new[]{"zero","close","http2","unframed"})
 {
  using var response=new HttpResponseMessage(System.Net.HttpStatusCode.OK){Version=mode=="http2"?System.Net.HttpVersion.Version20:System.Net.HttpVersion.Version11,Content=mode=="zero"?new ByteArrayContent([]):mode=="unframed"?new UnknownContent():new ByteArrayContent([1])};
  if(mode=="close")response.Headers.ConnectionClose=true;
  try{preparationHeaders.Invoke(null,[response,Activator.CreateInstance(preparationType,true)]);throw new Exception("Accepted invalid header mode:"+mode);}
  catch(TargetInvocationException e)when(e.InnerException is InvalidOperationException){}
 }
});
object Row(int index)=>Activator.CreateInstance(rowType,[index,index%2==0?"get":"list",1000L+index*10,index%17==0?0L:1001L+index*10,1005L+index*10,index%17==0?0:200,index%17==0?0:100,index%17==0?"offered.dropped":""])!;
void Throws(Action action){try{action();throw new Exception("Expected rejection.");}catch(TargetInvocationException e) when(e.InnerException is InvalidOperationException){}}
var rows=Array.CreateInstance(rowType,128);
Check("concurrent unique indices retained once",()=>{Parallel.For(0,128,index=>store.Invoke(null,[rows,Row(index)]));coverage.Invoke(null,[rows]);});
Check("duplicate index rejected without replacing original",()=>{var before=rows.GetValue(5);Throws(()=>store.Invoke(null,[rows,Row(5)]));if(!ReferenceEquals(before,rows.GetValue(5)))throw new Exception("Duplicate replaced raw evidence.");});
Check("negative and out-of-range indices rejected",()=>{Throws(()=>store.Invoke(null,[rows,Row(-1)]));Throws(()=>store.Invoke(null,[rows,Row(128)]));});
Check("missing observation cannot pass coverage",()=>Throws(()=>coverage.Invoke(null,[Array.CreateInstance(rowType,128)])));
Check("misindexed observation cannot pass coverage",()=>{var wrong=Array.CreateInstance(rowType,2);wrong.SetValue(Row(1),0);wrong.SetValue(Row(0),1);Throws(()=>coverage.Invoke(null,[wrong]));});
var full=Path.Combine(output,"full.jsonl.gz");await (Task)persist.Invoke(null,[full,rows])!;
string[] Read(string path){using var f=File.OpenRead(path);using var gzip=new GZipStream(f,CompressionMode.Decompress);using var r=new StreamReader(gzip);return r.ReadToEnd().Split('\n',StringSplitOptions.RemoveEmptyEntries).Select(line=>line.TrimEnd('\r')).ToArray();}
Check("all128 raw rows retain prior schema and exact field serialization",()=>
{
 var lines=Read(full);if(lines.Length!=129)throw new Exception("Wrong raw count.");using var header=JsonDocument.Parse(lines[0]);
 if(header.RootElement.GetProperty("schema").GetInt32()!=1||header.RootElement.GetProperty("frequency").GetInt64()!=Stopwatch.Frequency)throw new Exception("Header changed.");
 var columns=header.RootElement.GetProperty("columns").EnumerateArray().Select(x=>x.GetString()).ToArray();if(!columns.SequenceEqual(new[]{"index","operation","scheduledTicks","sentTicks","completedTicks","httpStatus","bodyBytes","error"}))throw new Exception("Columns changed.");
 for(var index=0;index<128;index++)
 {
  var row=rows.GetValue(index)!;var values=new[]{"Index","Operation","Scheduled","Sent","Completed","Status","Bytes","Error"}.Select(name=>rowType.GetProperty(name)!.GetValue(row)).ToArray();
  if(lines[index+1]!=JsonSerializer.Serialize(values,options))throw new Exception("Raw fields differ at"+index);
 }
});
var partial=Array.CreateInstance(rowType,128);for(var index=0;index<128;index++)if(index!=42)store.Invoke(null,[partial,Row(index)]);
var partialPath=Path.Combine(output,"partial.jsonl.gz");await (Task)persist.Invoke(null,[partialPath,partial])!;
Check("partial managed-failure evidence retains every observed row without invented missing row",()=>{var lines=Read(partialPath);if(lines.Length!=128||lines.Skip(1).Any(line=>JsonDocument.Parse(line).RootElement[0].GetInt32()==42))throw new Exception("Partial rows lost or fabricated.");Throws(()=>coverage.Invoke(null,[partial]));});
Check("request builder and manifest remain byte-identical to prior180000-offer GraphQL series",()=>
{
 var workload=driver.GetMethod("Build",flags)!.Invoke(null,[180000,"graphql"]);
 var hash=(string)driver.GetMethod("HashManifest",flags)!.Invoke(null,[workload,true])!;
 using var prior=JsonDocument.Parse(File.ReadAllText("D:/Cephalon/Cehpalon-Engine-Samples/.local/benchmark-observation-02/load/graphql/00-engine/driver/load-result.json"));
 if(hash!=prior.RootElement.GetProperty("manifestHash").GetString())throw new Exception("Offered byte manifest changed.");
});
await File.WriteAllTextAsync(Path.Combine(output,"proof.json"),JsonSerializer.Serialize(new{scope="Offline record conservation and serializer/manifest equivalence; no request traffic or performance measurement",passed=checks.Count-failed,failed,checks},new JsonSerializerOptions{WriteIndented=true}));
Console.WriteLine($"Collector offline proof: {checks.Count-failed}/{checks.Count}");return failed==0?0:1;

sealed class UnknownContent:HttpContent
{
 public int Serializations;
 protected override bool TryComputeLength(out long length){length=0;return false;}
 protected override Task SerializeToStreamAsync(Stream stream,System.Net.TransportContext? context){Serializations++;return stream.WriteAsync(new byte[]{1}).AsTask();}
}
