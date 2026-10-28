using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;

namespace SmallApi.Benchmark;

/// <summary>Fixed offered-schedule client. Its CPU allocation must be disjoint from the server.</summary>
public static class LoadDriver
{
    private sealed record Offered(int Index,string Operation,int Id,int Page,int Lane,int Ordinal,int ExpectedRevision,string? Label,byte[] Payload,string Path);
    private sealed record Observation(int Index,string Operation,long Scheduled,long Sent,long Completed,int Status,int Bytes,string Error);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web){WriteIndented=false};
    private const string Seed="cehpalon-small-api-v1:20261027";
    public static async Task<int> RunAsync(string[] args)
    {
        string Arg(string key,string? fallback=null)=>args.FirstOrDefault(x=>x.StartsWith("--"+key+"=",StringComparison.Ordinal))?[(key.Length+3)..]??fallback??throw new ArgumentException(key);
        var output=Path.GetFullPath(Arg("output"));Directory.CreateDirectory(output);
        var transport=Arg("transport");var rate=int.Parse(Arg("rate","1000"));var seconds=int.Parse(Arg("seconds","180"));var warmSeconds=int.Parse(Arg("warmup","60"));
        var warmOnly=Arg("warmup-only","false")=="true";
        if(transport is not("http" or "graphql") || rate<=0 || seconds<=0 || warmSeconds<0) throw new ArgumentException("Invalid load protocol.");
        using var root=X509CertificateLoader.LoadCertificateFromFile(Arg("ca-file"));
        var chain=new X509ChainPolicy{TrustMode=X509ChainTrustMode.CustomRootTrust,RevocationMode=X509RevocationMode.NoCheck};chain.CustomTrustStore.Add(root);
        using var sockets=new SocketsHttpHandler{UseProxy=false,MaxConnectionsPerServer=128,SslOptions=new SslClientAuthenticationOptions{EnabledSslProtocols=SslProtocols.Tls13,CertificateChainPolicy=chain}};
        var tlsConnections=new ConcurrentBag<object>();
        sockets.PlaintextStreamFilter=(context,ct)=>
        {
            if(context.PlaintextStream is not SslStream ssl || ssl.SslProtocol!=SslProtocols.Tls13) throw new InvalidOperationException("Expected an observed TLS1.3 collector connection.");
            tlsConnections.Add(new{protocol=ssl.SslProtocol.ToString(),cipher=ssl.NegotiatedCipherSuite.ToString(),httpVersion=context.NegotiatedHttpVersion.ToString()});
            return ValueTask.FromResult(context.PlaintextStream);
        };
        using var client=new HttpClient(sockets){BaseAddress=new Uri(Arg("url")),Timeout=Timeout.InfiniteTimeSpan};
        var count=checked(rate*seconds);var warmCount=checked(rate*warmSeconds);
        var workload=Build(Math.Max(Math.Max(count,warmCount),checked(rate*2)),transport);
        await using(var file=new FileStream(Path.Combine(output,"offered-manifest.jsonl.gz"),FileMode.CreateNew))
        await using(var gzip=new GZipStream(file,CompressionLevel.Fastest))
        await using(var writer=new StreamWriter(gzip,new UTF8Encoding(false)))
            foreach(var item in workload.Take(warmOnly?warmCount:count)) await writer.WriteLineAsync(JsonSerializer.Serialize(new{item.Index,item.Operation,item.Id,item.Page,item.Lane,item.Ordinal,item.ExpectedRevision,item.Label,payloadSha256=Convert.ToHexStringLower(SHA256.HashData(item.Payload))},Json));
        var manifestHash=HashManifest(workload.Take(warmOnly?warmCount:count));
        var logicalManifestHash=HashManifest(workload.Take(warmOnly?warmCount:count),false);
        Console.WriteLine(JsonSerializer.Serialize(new{stage="manifest-frozen",count=warmOnly?warmCount:count,rate,seconds,warmSeconds,transport,manifestHash,logicalManifestHash}));
        // Establish the collector's HTTP/TLS machinery before imposing an offered schedule.
        // These read-only preparations and the complete capacity preflight are retained, never scored as warmup.
        using(var reset=await client.PostAsync("/__fixture/reset",new StringContent("{}",Encoding.UTF8,"application/json"))) reset.EnsureSuccessStatusCode();
        var preparation=new ConcurrentBag<object>();var noWrites=new ConcurrentDictionary<int,int>();
        async Task Prepare(Offered item)
        {
            var started=Stopwatch.GetTimestamp();var status=0;var byteCount=0;string? failure=null;
            try
            {
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var request=new HttpRequestMessage(HttpMethod.Post,item.Path){Version=HttpVersion.Version11,VersionPolicy=HttpVersionPolicy.RequestVersionExact,Content=new ByteArrayContent(item.Payload)};
            request.Content.Headers.ContentType=new MediaTypeHeaderValue("application/json");
            using var response=await client.SendAsync(request,deadline.Token);var body=await response.Content.ReadAsByteArrayAsync(deadline.Token);
            status=(int)response.StatusCode;byteCount=body.Length;
            response.EnsureSuccessStatusCode();using var document=JsonDocument.Parse(body);var value=document.RootElement;
            if(transport=="graphql")
            {
                if(value.TryGetProperty("errors",out _)) throw new InvalidOperationException("GraphQL collector preparation failed.");
                value=value.GetProperty("data").GetProperty(item.Operation=="get"?"catalogItem":"catalogPage");
            }
            if(!Validate(value,item,noWrites)) throw new InvalidOperationException("Collector preparation business validation failed.");
            }
            catch(Exception error){failure=error.ToString();throw;}
            finally {preparation.Add(new{item.Index,item.Operation,startedTicks=started,completedTicks=Stopwatch.GetTimestamp(),status,bytes=byteCount,error=failure});}
        }
        try
        {
            await Prepare(workload.First(item=>item.Operation=="get"));
            await Prepare(workload.First(item=>item.Operation=="list"));
            await Task.WhenAll(workload.Where(item=>item.Operation=="get").Take(128).Select(Prepare));
        }
        finally
        {
            await File.WriteAllTextAsync(Path.Combine(output,"collector-preparation.json"),JsonSerializer.Serialize(new{requests=preparation.ToArray(),stopwatchFrequency=Stopwatch.Frequency,tlsConnections=tlsConnections.ToArray(),scope="Read-only connection/JIT preparation outside offered schedules"},Json));
        }
        var preflight=await Phase("preflight",rate*2,2);
        var preflightState=ValidateFinal(await State(),workload.Take(rate*2));
        await File.WriteAllTextAsync(Path.Combine(output,"collector-preflight.json"),JsonSerializer.Serialize(new{preflight,state=preflightState},Json));
        if(preflight.errors!=0 || preflight.dropped!=0 || preflight.correct!=rate*2 || !preflightState.passed) throw new InvalidOperationException("Collector preflight failed; retain the whole attempt, do not enter timed warmup/load.");
        using(var reset=await client.PostAsync("/__fixture/reset",new StringContent("{}",Encoding.UTF8,"application/json"))) reset.EnsureSuccessStatusCode();
        var warm=warmCount==0?null:await Phase("warmup",warmCount,warmSeconds);
        if(warmOnly)
        {
            var finalWarm=await State();var validation=ValidateFinal(finalWarm,workload.Take(warmCount));
            await File.WriteAllTextAsync(Path.Combine(output,"warmup-result.json"),JsonSerializer.Serialize(new{transport,rate,warmSeconds,manifestHash,logicalManifestHash,tlsConnections=tlsConnections.ToArray(),warmup=warm,state=validation,finalState=finalWarm},new JsonSerializerOptions(Json){WriteIndented=true}));
            Console.WriteLine(JsonSerializer.Serialize(new{stage="warmup-completed",transport,warm?.correct,warm?.errors,validation.passed}));
            return 0;
        }
        using(var reset=await client.PostAsync("/__fixture/reset",new StringContent("{}",Encoding.UTF8,"application/json"))) reset.EnsureSuccessStatusCode();
        var initial=await State();
        var initialMetrics=await Metrics();
        var measured=await Phase("measured",count,seconds);
        var finalMetrics=await Metrics();
        var final=await State();
        var state=ValidateFinal(final,workload.Take(count));
        var initialValidation=ValidateFinal(initial,[]);
        var report=new{transport,rate,seconds,warmSeconds,manifestHash,logicalManifestHash,stopwatchFrequency=Stopwatch.Frequency,tlsConnections=tlsConnections.ToArray(),initialState=initial,initialValidation,initialMetrics,finalMetrics,finalState=final,warmup=warm,measured,state,
            scope="Fixed open-loop localhost observation; environment qualification is determined by orchestrator, never inferred from numeric budgets."};
        await File.WriteAllTextAsync(Path.Combine(output,"load-result.json"),JsonSerializer.Serialize(report,new JsonSerializerOptions(Json){WriteIndented=true}));
        Console.WriteLine(JsonSerializer.Serialize(new{stage="completed",transport,measured.correct,measured.errors,measured.dropped,statePassed=state.passed}));
        return 0; // Preserve complete runs even when engineering budgets fail; the report is authoritative.

        async Task<JsonElement> State()
        {using var response=await client.GetAsync("/__fixture/state");response.EnsureSuccessStatusCode();return JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync()).RootElement.Clone();}
        async Task<JsonElement> Metrics()
        {using var response=await client.GetAsync("/__fixture/metrics");response.EnsureSuccessStatusCode();return JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync()).RootElement.Clone();}

        async Task<PhaseResult> Phase(string phase,int offeredCount,int duration)
        {
            var rows=Channel.CreateUnbounded<Observation>(new UnboundedChannelOptions{SingleReader=true,SingleWriter=false});
            var observations=new ConcurrentBag<Observation>();var issued=new ConcurrentDictionary<int,int>();
            var lanes=Enumerable.Range(0,32).Select(_=>new SemaphoreSlim(1,1)).ToArray();
            var writing=Task.Run(async()=>
            {
                await using var file=new FileStream(Path.Combine(output,phase+"-requests.jsonl.gz"),FileMode.CreateNew);
                await using var gzip=new GZipStream(file,CompressionLevel.Fastest);
                await using var writer=new StreamWriter(gzip,new UTF8Encoding(false));
                await writer.WriteLineAsync(JsonSerializer.Serialize(new{schema=1,columns=new[]{"index","operation","scheduledTicks","sentTicks","completedTicks","httpStatus","bodyBytes","error"},frequency=Stopwatch.Frequency}));
                await foreach(var row in rows.Reader.ReadAllAsync())
                    await writer.WriteLineAsync(JsonSerializer.Serialize(new object[]{row.Index,row.Operation,row.Scheduled,row.Sent,row.Completed,row.Status,row.Bytes,row.Error}));
            });
            var pending=new HashSet<Task>();var start=Stopwatch.GetTimestamp();var outstanding=0;var nextProgress=start+30*Stopwatch.Frequency;
            for(var i=0;i<offeredCount;i++)
            {
                var scheduled=start+(long)(i*(double)Stopwatch.Frequency/rate);
                while(Stopwatch.GetTimestamp()<scheduled)
                {
                    var remaining=(scheduled-Stopwatch.GetTimestamp())*1000.0/Stopwatch.Frequency;
                    if(remaining>1.5) await Task.Delay(TimeSpan.FromMilliseconds(remaining-0.5)); else Thread.SpinWait(30);
                }
                var item=workload[i];
                if(Volatile.Read(ref outstanding)>=128)
                {Record(new(i,item.Operation,scheduled,0,Stopwatch.GetTimestamp(),0,0,"offered.dropped"));}
                else
                {
                    Interlocked.Increment(ref outstanding);
                    var task=Send(item,scheduled);pending.Add(task);
                    pending.RemoveWhere(t=>t.IsCompleted);
                }
                if(Stopwatch.GetTimestamp()>=nextProgress)
                {Console.WriteLine(JsonSerializer.Serialize(new{stage=phase,offered=i+1,total=offeredCount,outstanding}));nextProgress+=30*Stopwatch.Frequency;}
            }
            await Task.WhenAll(pending);rows.Writer.TryComplete();await writing;
            foreach(var lane in lanes) lane.Dispose();
            var all=observations.OrderBy(x=>x.Index).ToArray();var good=all.Where(x=>x.Error=="").ToArray();
            if(all.Length!=offeredCount || all.Select(x=>x.Index).Distinct().Count()!=offeredCount) throw new InvalidOperationException("Missing/duplicate offered observations.");
            var latencies=all.Select(x=>(x.Completed-x.Scheduled)*1000.0/Stopwatch.Frequency).Order().ToArray();
            var sentLatencies=all.Where(x=>x.Sent>0).Select(x=>(x.Completed-x.Sent)*1000.0/Stopwatch.Frequency).Order().ToArray();
            var floorEnd=start+(long)((duration+1.0)*Stopwatch.Frequency);
            return new(offeredCount,good.Length,all.Count(x=>x.Error!=""),all.Count(x=>x.Error=="offered.dropped"),good.Count(x=>x.Completed<=floorEnd),Percentile(latencies,.95),Percentile(latencies,.99),Percentile(sentLatencies,.95),all.Max(x=>Math.Max(0,x.Sent-x.Scheduled))*1000.0/Stopwatch.Frequency,(all.Max(x=>x.Completed)-start)*1000.0/Stopwatch.Frequency,
                all.Where(x=>x.Error!="").GroupBy(x=>x.Error).ToDictionary(x=>x.Key,x=>x.Count()));

            void Record(Observation row){observations.Add(row);if(!rows.Writer.TryWrite(row)) throw new InvalidOperationException("Raw evidence writer closed early.");}
            async Task Send(Offered item,long scheduled)
            {
                long sent=0;int status=0,bytes=0;string error="";bool locked=false;
                using var deadline=new CancellationTokenSource();
                var remaining=1.0-(Stopwatch.GetTimestamp()-scheduled)/(double)Stopwatch.Frequency;
                deadline.CancelAfter(TimeSpan.FromSeconds(Math.Max(0,remaining)));
                try
                {
                    if(item.Operation=="set"){await lanes[item.Lane].WaitAsync(deadline.Token);locked=true;}
                    using var request=new HttpRequestMessage(HttpMethod.Post,item.Path){Version=HttpVersion.Version11,VersionPolicy=HttpVersionPolicy.RequestVersionExact,Content=new ByteArrayContent(item.Payload)};
                    request.Content.Headers.ContentType=new MediaTypeHeaderValue("application/json");
                    sent=Stopwatch.GetTimestamp();
                    if(item.Operation=="set") issued.AddOrUpdate(item.Id,item.ExpectedRevision+1,(_,old)=>Math.Max(old,item.ExpectedRevision+1));
                    using var response=await client.SendAsync(request,deadline.Token);status=(int)response.StatusCode;
                    var body=await response.Content.ReadAsByteArrayAsync(deadline.Token);bytes=body.Length;
                    if(status!=200) error="http."+status;
                    else
                    {
                        using var document=JsonDocument.Parse(body);var value=document.RootElement;
                        if(transport=="graphql")
                        {
                            if(value.TryGetProperty("errors",out _)) error="graphql.error";
                            else value=value.GetProperty("data").GetProperty(item.Operation switch{"get"=>"catalogItem","list"=>"catalogPage",_=>"setLabel"});
                        }
                        if(error=="" && !Validate(value,item,issued)) error="business.invalid";
                    }
                }
                catch(OperationCanceledException){error="request.timeout";}
                catch(Exception exception){error="client."+exception.GetType().Name;}
                finally
                {
                    if(locked) lanes[item.Lane].Release();
                    Record(new(item.Index,item.Operation,scheduled,sent,Stopwatch.GetTimestamp(),status,bytes,error));Interlocked.Decrement(ref outstanding);
                }
            }
        }
    }

    private sealed record PhaseResult(int offered,int correct,int errors,int dropped,int successfulWithinDrain,double p95Ms,double p99Ms,double sentP95Ms,double maximumQueueMs,double elapsedMs,Dictionary<string,int> errorKinds);
    private static double Percentile(double[] sorted,double p)=>sorted.Length==0?0:sorted[Math.Max(0,(int)Math.Ceiling(p*sorted.Length)-1)];
    private static string HashManifest(IEnumerable<Offered> workload,bool includePayload=true)
    {
        using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach(var item in workload) hash.AppendData(Encoding.UTF8.GetBytes($"{item.Index}:{item.Operation}:{item.Id}:{item.Page}:{item.Lane}:{item.Ordinal}:{item.ExpectedRevision}:{item.Label}:"+(includePayload?Convert.ToHexStringLower(SHA256.HashData(item.Payload)):"")+"\n"));
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }
    private static Offered[] Build(int count,string transport)
    {
        var result=new Offered[count];var writes=0;
        for(var i=0;i<count;i++)
        {
            var hash=SHA256.HashData(Encoding.UTF8.GetBytes(Seed+":"+i));var number=System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(hash);
            var op=i%100<80?"get":i%100<95?"list":"set";var id=1+(int)(number%10000);var page=(int)(number%500);var lane=-1;var ordinal=-1;var expected=0;string? label=null;
            object input;
            if(op=="set") {lane=writes%32;ordinal=writes/32;writes++;id=1+lane+32*(ordinal%312);expected=ordinal/312;label=$"lane-{lane}-write-{ordinal}";input=new{id,expectedRevision=expected,label};}
            else input=op=="get"?new{id}:(object)new{page};
            var field=op switch{"get"=>"catalogItem","list"=>"catalogPage",_=>"setLabel"};var type=op switch{"get"=>"GetItemInput!","list"=>"ListItemsInput!",_=>"SetLabelInput!"};
            var selection=op=="list"?"items { id label revision amountMinorUnits }":"id label revision amountMinorUnits";
            var payload=transport=="http"?JsonSerializer.SerializeToUtf8Bytes(input,Json):JsonSerializer.SerializeToUtf8Bytes(new{query=$"{(op=="set"?"mutation":"query")}($input:{type}){{{field}(input:$input){{{selection}}}}}",variables=new{input}},Json);
            result[i]=new(i,op,id,page,lane,ordinal,expected,label,payload,transport=="http"?"/api/catalog/"+op:"/graphql");
        }
        return result;
    }
    private static bool Validate(JsonElement value,Offered request,ConcurrentDictionary<int,int> issued)
    {
        if(request.Operation=="list")
        {var items=value.GetProperty("items");if(items.GetArrayLength()!=20)return false;for(var i=0;i<20;i++)if(!ValidItem(items[i],1+request.Page*20+i,issued))return false;return true;}
        if(!ValidItem(value,request.Id,issued))return false;
        return request.Operation!="set" || value.GetProperty("revision").GetInt32()==request.ExpectedRevision+1 && value.GetProperty("label").GetString()==request.Label;
    }
    private static bool ValidItem(JsonElement value,int id,ConcurrentDictionary<int,int> issued)
    {
        if(value.GetProperty("id").GetInt32()!=id || value.GetProperty("amountMinorUnits").GetInt64()!=id*17L)return false;
        var revision=value.GetProperty("revision").GetInt32();if(revision<0 || revision>issued.GetValueOrDefault(id))return false;
        var label=revision==0?$"item-{id:D5}":$"lane-{(id-1)%32}-write-{(revision-1)*312+(id-1)/32}";
        return value.GetProperty("label").GetString()==label;
    }
    private sealed record StateValidation(bool passed,string reason);
    private static StateValidation ValidateFinal(JsonElement state,IEnumerable<Offered> workload)
    {
        if(!state.TryGetProperty("records",out var records) || records.GetArrayLength()!=10000)return new(false,"Final state must expose10000 records.");
        var writes=workload.Where(x=>x.Operation=="set").GroupBy(x=>x.Id).ToDictionary(x=>x.Key,x=>x.Last());
        var ids=new HashSet<int>();
        foreach(var item in records.EnumerateArray())
        {
            var id=item.GetProperty("id").GetInt32();
            if(id<1 || id>10000 || !ids.Add(id)) return new(false,"Duplicate/out-of-range final key.");
            var revision=writes.TryGetValue(id,out var last)?last.ExpectedRevision+1:0;
            var label=last is null?$"item-{id:D5}":last.Label;
            if(item.GetProperty("revision").GetInt32()!=revision || item.GetProperty("label").GetString()!=label || item.GetProperty("amountMinorUnits").GetInt64()!=id*17L)return new(false,"Final planned update/state mismatch.");
        }
        return new(true,"");
    }
}
