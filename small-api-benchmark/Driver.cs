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

namespace SmallApi.Benchmark;

/// <summary>Fixed offered-schedule client. Its CPU allocation must be disjoint from the server.</summary>
public static class LoadDriver
{
    private sealed record Offered(int Index,string Operation,int Id,int Page,int Lane,int Ordinal,int ExpectedRevision,string? Label,byte[] Payload,string Path);
    private sealed record Observation(int Index,string Operation,long Scheduled,long Sent,long Completed,int Status,int Bytes,string Error);
    private sealed record TlsConnection(long ConnectionId,string Pool,string Protocol,string Cipher,string HttpVersion,long ConnectedTicks,long StopwatchFrequency,int? PreparationIndex);
    private static readonly HttpRequestOptionsKey<long> ConnectionIdOption=new("cehpalon.fixture.connection-id");
    private static readonly HttpRequestOptionsKey<int> PreparationIndexOption=new("cehpalon.fixture.preparation-index");
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web){WriteIndented=false};
    private const string Seed="cehpalon-small-api-v1:20261027";
    public static async Task<int> RunAsync(string[] args)
    {
        string Arg(string key,string? fallback=null)=>args.FirstOrDefault(x=>x.StartsWith("--"+key+"=",StringComparison.Ordinal))?[(key.Length+3)..]??fallback??throw new ArgumentException(key);
        var output=Path.GetFullPath(Arg("output"));Directory.CreateDirectory(output);
        var transport=Arg("transport");var rate=int.Parse(Arg("rate","1000"));var seconds=int.Parse(Arg("seconds","180"));var warmSeconds=int.Parse(Arg("warmup","60"));
        var warmOnly=Arg("warmup-only","false")=="true";
        var preflightOnly=Arg("preflight-only","false")=="true";
        if(warmOnly && preflightOnly)throw new ArgumentException("Select either warmup-only or preflight-only.");
        if(transport is not("http" or "graphql") || rate<=0 || seconds<=0 || warmSeconds<0) throw new ArgumentException("Invalid load protocol.");
        using var root=X509CertificateLoader.LoadCertificateFromFile(Arg("ca-file"));
        var chain=new X509ChainPolicy{TrustMode=X509ChainTrustMode.CustomRootTrust,RevocationMode=X509RevocationMode.NoCheck};chain.CustomTrustStore.Add(root);
        var tlsConnections=new ConcurrentBag<TlsConnection>();long connectionSequence=0;
        SocketsHttpHandler CreateSockets(string pool)
        {
            var handler=new SocketsHttpHandler{UseProxy=false,MaxConnectionsPerServer=128,SslOptions=new SslClientAuthenticationOptions{EnabledSslProtocols=SslProtocols.Tls13,CertificateChainPolicy=chain}};
            handler.PlaintextStreamFilter=(context,ct)=>
            {
                if(context.PlaintextStream is not SslStream ssl || ssl.SslProtocol!=SslProtocols.Tls13 || context.NegotiatedHttpVersion!=HttpVersion.Version11)throw new InvalidOperationException("Expected an observed TLS1.3/HTTP1.1 collector connection.");
                var id=Interlocked.Increment(ref connectionSequence);
                context.InitialRequestMessage.Options.Set(ConnectionIdOption,id);
                int? preparationIndex=context.InitialRequestMessage.Options.TryGetValue(PreparationIndexOption,out var index)?index:null;
                tlsConnections.Add(new(id,pool,ssl.SslProtocol.ToString(),ssl.NegotiatedCipherSuite.ToString(),context.NegotiatedHttpVersion.ToString(),Stopwatch.GetTimestamp(),Stopwatch.Frequency,preparationIndex));
                return ValueTask.FromResult(context.PlaintextStream);
            };
            return handler;
        }
        TlsConnection[] SnapshotTls()=>tlsConnections.OrderBy(x=>x.ConnectionId).ToArray();
        using var sockets=CreateSockets("load");using var controlSockets=CreateSockets("control");
        using var client=new HttpClient(sockets){BaseAddress=new Uri(Arg("url")),Timeout=Timeout.InfiniteTimeSpan};
        using var controlClient=new HttpClient(controlSockets){BaseAddress=client.BaseAddress,Timeout=Timeout.InfiniteTimeSpan};
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
        var preparation=new ConcurrentBag<PreparationRecord>();var noWrites=new ConcurrentDictionary<int,int>();var barrier=new BarrierProof();
        var enteredPhases=new List<string>();
        JsonElement measuredFinalMetrics=default;
        var preparationStarted=Stopwatch.GetTimestamp();var preparationBefore=ClientMetrics();
        using var preparationDeadline=new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var release=new TaskCompletionSource<long>(TaskCreationOptions.RunContinuationsAsynchronously);Task[] heldTasks=[];
        Exception? preparationFailure=null;
        HttpRequestMessage PreparationRequest(Offered item,int preparationIndex)
        {
            var request=new HttpRequestMessage(HttpMethod.Post,item.Path){Version=HttpVersion.Version11,VersionPolicy=HttpVersionPolicy.RequestVersionExact,Content=new ByteArrayContent(item.Payload)};
            request.Content.Headers.ContentType=new MediaTypeHeaderValue("application/json");request.Options.Set(PreparationIndexOption,preparationIndex);return request;
        }
        async Task ReadAndValidate(HttpResponseMessage response,Offered item,PreparationRecord row,CancellationToken ct)
        {
            row.BodyReadStartedTicks=Stopwatch.GetTimestamp();
            var body=await response.Content.ReadAsByteArrayAsync(ct);row.Bytes=body.Length;row.BodyCompletedTicks=Stopwatch.GetTimestamp();
            if(body.Length==0)throw new InvalidOperationException("Preparation body must be nonempty.");
            using var document=JsonDocument.Parse(body);var value=document.RootElement;
            if(transport=="graphql")
            {
                if(value.TryGetProperty("errors",out _))throw new InvalidOperationException("GraphQL collector preparation failed.");
                value=value.GetProperty("data").GetProperty(item.Operation=="get"?"catalogItem":"catalogPage");
            }
            if(!Validate(value,item,noWrites))throw new InvalidOperationException("Collector preparation business validation failed.");
            row.Passed=true;
        }
        async Task WarmRead(Offered item,int preparationIndex)
        {
            var row=new PreparationRecord{PreparationIndex=preparationIndex,Index=item.Index,Operation=item.Operation,Pool="control",Stage="warm-read",StartedTicks=Stopwatch.GetTimestamp()};preparation.Add(row);
            try
            {
                using var request=PreparationRequest(item,preparationIndex);
                using var response=await controlClient.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,preparationDeadline.Token);
                ValidatePreparationHeaders(response,row);
                row.ConnectionId=request.Options.TryGetValue(ConnectionIdOption,out var id)?id:null;
                await ReadAndValidate(response,item,row,preparationDeadline.Token);
            }
            catch(Exception error){row.Error=error.ToString();throw;}
            finally{row.CompletedTicks=Stopwatch.GetTimestamp();}
        }
        async Task HoldRead(Offered item,int preparationIndex,TaskCompletionSource headers)
        {
            var row=new PreparationRecord{PreparationIndex=preparationIndex,Index=item.Index,Operation=item.Operation,Pool="load",Stage="held-load",StartedTicks=Stopwatch.GetTimestamp()};preparation.Add(row);
            try
            {
                using var request=PreparationRequest(item,preparationIndex);
                using var response=await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,preparationDeadline.Token);
                ValidatePreparationHeaders(response,row);
                row.ConnectionId=request.Options.TryGetValue(ConnectionIdOption,out var id)?id:null;
                if(row.ConnectionId is null)throw new InvalidOperationException("A held response did not identify its new physical load connection.");
                headers.TrySetResult();
                await release.Task.WaitAsync(preparationDeadline.Token);
                await ReadAndValidate(response,item,row,preparationDeadline.Token);
            }
            catch(Exception error){row.Error=error.ToString();headers.TrySetException(error);throw;}
            finally{row.CompletedTicks=Stopwatch.GetTimestamp();}
        }
        void ReleaseHeld()
        {
            barrier.ReleasedTicks??=Stopwatch.GetTimestamp();release.TrySetResult(barrier.ReleasedTicks.Value);
        }
        try
        {
            using(var reset=await controlClient.PostAsync("/__fixture/reset",new StringContent("{}",Encoding.UTF8,"application/json"),preparationDeadline.Token))reset.EnsureSuccessStatusCode();
            await WarmRead(workload.First(item=>item.Operation=="get"),0);
            await WarmRead(workload.First(item=>item.Operation=="list"),1);
            var selected=workload.Where(item=>item.Operation=="get").Take(128).ToArray();
            if(selected.Length!=128)throw new InvalidOperationException("The frozen manifest must contain128 read-only preparation inputs.");
            var headers=Enumerable.Range(0,128).Select(_=>new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)).ToArray();
            barrier.StartedTicks=Stopwatch.GetTimestamp();
            heldTasks=selected.Select((item,index)=>HoldRead(item,index+2,headers[index])).ToArray();
            await Task.WhenAll(headers.Select(signal=>signal.Task)).WaitAsync(preparationDeadline.Token);
            barrier.AllHeadersReadyTicks=Stopwatch.GetTimestamp();
            var held=preparation.Where(row=>row.Stage=="held-load").OrderBy(row=>row.PreparationIndex).ToArray();
            var physical=SnapshotTls().Where(connection=>connection.Pool=="load").ToArray();
            barrier.HeldResponses=held.Length;barrier.TlsConnectionsAtBarrier=physical.Length;
            barrier.DistinctConnectionIds=held.Where(row=>row.ConnectionId is not null).Select(row=>row.ConnectionId!.Value).Distinct().Order().ToArray();
            barrier.DistinctConnectionCount=barrier.DistinctConnectionIds.Length;barrier.LoadTlsConnectionIdsAtBarrier=physical.Select(connection=>connection.ConnectionId).Order().ToArray();
            if(held.Length!=128 || physical.Length!=128 || barrier.DistinctConnectionCount!=128 || !barrier.DistinctConnectionIds.SequenceEqual(barrier.LoadTlsConnectionIdsAtBarrier) || held.Any(row=>row.HeadersReadyTicks is null || row.BodyReadStartedTicks is not null || row.CompletedTicks is not null))
                throw new InvalidOperationException("Physical connection readiness barrier did not hold128 distinct live HTTP1.1 responses before body consumption.");
            ReleaseHeld();await Task.WhenAll(heldTasks);
            preparationDeadline.Token.ThrowIfCancellationRequested();
            if(Stopwatch.GetElapsedTime(preparationStarted)>TimeSpan.FromSeconds(30))throw new TimeoutException("Shared30-second preparation deadline elapsed.");
            barrier.NonemptyHttp11Responses=held.Count(row=>row.Passed && row.HttpVersion=="1.1" && row.Bytes>0);
            barrier.CompletedTicks=Stopwatch.GetTimestamp();
            barrier.Passed=barrier.NonemptyHttp11Responses==128;
            if(!barrier.Passed)throw new InvalidOperationException("Not all held response bodies validated before preflight.");
        }
        catch(Exception error)
        {
            preparationFailure=error;preparationDeadline.Cancel();ReleaseHeld();
            try{await Task.WhenAll(heldTasks);}
            catch(Exception cleanupFailure){preparationFailure=new AggregateException("Preparation and joined held-request cleanup failed.",preparationFailure,cleanupFailure);}
        }
        finally
        {
            ReleaseHeld();barrier.CompletedTicks??=Stopwatch.GetTimestamp();
            await WriteEvidence(Path.Combine(output,"collector-preparation.json"),new
            {
                schemaVersion=1,status=preparationFailure is null?"passed":"preparation-failed",plannedReadOnlyRequests=130,
                readOnlyRequests=preparation.Count,successfulReadOnlyRequests=preparation.Count(row=>row.Passed),
                requests=preparation.OrderBy(row=>row.PreparationIndex).ToArray(),barrier,clientBefore=preparationBefore,clientAfter=ClientMetrics(),
                preparationStartedTicks=preparationStarted,preparationCompletedTicks=Stopwatch.GetTimestamp(),
                stopwatchFrequency=Stopwatch.Frequency,tlsConnections=SnapshotTls(),error=preparationFailure?.ToString(),
                scope="Two verified control-pool reads plus128 held load-pool responses; all bodies released only after physical TLS readiness, outside offered schedules and startup measurement"
            });
        }
        var preparationSummary=new{readOnlyRequests=preparation.Count,successfulReadOnlyRequests=preparation.Count(row=>row.Passed),barrier};
        if(preparationFailure is not null)
        {
            await WriteCollectorFailure("preparation-failed","preparation",preparationFailure.ToString(),"collector-preparation.json");
            return 1;
        }
        PhaseResult preflight;StateValidation preflightState;
        try
        {
            preflight=await Phase("preflight",rate*2,2);
            preflightState=ValidateFinal(await State(),workload.Take(rate*2));
        }
        catch(Exception error)
        {
            await WriteCollectorFailure("collector-phase-failed","preflight",error.ToString(),"preflight-evidence-accounting.json");return 1;
        }
        var preflightPassed=preflight.errors==0 && preflight.dropped==0 && preflight.correct==rate*2 && preflightState.passed;
        await WriteEvidence(Path.Combine(output,"collector-preflight.json"),new{schemaVersion=1,status=preflightPassed?"passed":"collector-preflight-failed",preflight,state=preflightState,preparation=preparationSummary,tlsConnections=SnapshotTls(),telemetryFile="preflight-evidence-accounting.json",enteredPhases=enteredPhases.ToArray(),warmupEntered=false,measuredEntered=false});
        if(preflightOnly)
            await WriteEvidence(Path.Combine(output,"preflight-result.json"),new{schemaVersion=1,mode="preflight-only",transport,rate,offeredCount=rate*2,seconds=2,plannedManifestOffers=warmOnly?warmCount:count,status=preflightPassed?"passed":"collector-preflight-failed",preparation=preparationSummary,preflight,state=preflightState,tlsConnections=SnapshotTls(),telemetryFile="preflight-evidence-accounting.json",enteredPhases=enteredPhases.ToArray(),warmupEntered=false,measuredEntered=false});
        if(!preflightPassed)
        {
            await WriteCollectorFailure("collector-preflight-failed","preflight","Collector capacity/state preflight failed; timed warmup and measurement were not entered.","preflight-evidence-accounting.json",preflight);return 1;
        }
        if(preflightOnly)
        {
            Console.WriteLine(JsonSerializer.Serialize(new{stage="preflight-only-completed",transport,rate,preflight.offered,preflight.correct,preflight.errors,preflight.dropped,preflightState.passed}));return 0;
        }
        try
        {
            await ResetControl();
            var warm=warmCount==0?null:await Phase("warmup",warmCount,warmSeconds);
            if(warmOnly)
            {
                var finalWarm=await State();var validation=ValidateFinal(finalWarm,workload.Take(warmCount));
                await File.WriteAllTextAsync(Path.Combine(output,"warmup-result.json"),JsonSerializer.Serialize(new{transport,rate,warmSeconds,manifestHash,logicalManifestHash,preparation=preparationSummary,tlsConnections=SnapshotTls(),warmup=warm,state=validation,finalState=finalWarm},new JsonSerializerOptions(Json){WriteIndented=true}));
                Console.WriteLine(JsonSerializer.Serialize(new{stage="warmup-completed",transport,warm?.correct,warm?.errors,validation.passed}));
                return 0;
            }
            await ResetControl();
            var initial=await State();
            var initialMetrics=await Metrics();
            var measured=await Phase("measured",count,seconds);
            if(measuredFinalMetrics.ValueKind!=JsonValueKind.Object)throw new InvalidOperationException("Measured completion metrics were not captured before evidence persistence.");
            var finalMetrics=measuredFinalMetrics;
            var final=await State();
            var state=ValidateFinal(final,workload.Take(count));
            var initialValidation=ValidateFinal(initial,[]);
            var report=new{transport,rate,seconds,warmSeconds,manifestHash,logicalManifestHash,stopwatchFrequency=Stopwatch.Frequency,preparation=preparationSummary,tlsConnections=SnapshotTls(),initialState=initial,initialValidation,initialMetrics,finalMetrics,finalState=final,warmup=warm,measured,state,
                collectorEvidence=new{storage="Preallocated indexed reference slots; Observation records still allocate per offered row; all rows persisted after joining the phase",serverMetricsBracket="Initial metrics before Phase; final metrics immediately after measured request join, before raw JSON/gzip persistence. This explicitly corrects the prior flush-inclusive metrics bracket.",clientMetricsBracket="Snapshots before schedule origin and immediately after request join, excluding completion-metrics control request and raw persistence",tlsTimestampBoundary="connectedTicks is PlaintextStreamFilter after the TLS handshake, not TCP connection start; phase accounting has the matching Stopwatch clock",crashBoundary="Managed phase failures flush observed rows before failing; abrupt process termination may lose the in-memory phase and invalidates the attempt"},
                scope="Fixed open-loop localhost observation; environment qualification is determined by orchestrator, never inferred from numeric budgets."};
            await File.WriteAllTextAsync(Path.Combine(output,"load-result.json"),JsonSerializer.Serialize(report,new JsonSerializerOptions(Json){WriteIndented=true}));
            Console.WriteLine(JsonSerializer.Serialize(new{stage="completed",transport,measured.correct,measured.errors,measured.dropped,statePassed=state.passed}));
            return 0; // Preserve complete runs even when engineering budgets fail; the report is authoritative.
        }
        catch(Exception error)
        {
            var phase=enteredPhases.LastOrDefault()??"continuation";
            await WriteCollectorFailure("collector-phase-failed",phase,error.ToString(),phase+"-evidence-accounting.json");return 1;
        }

        async Task ResetControl()
        {using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(10));using var response=await controlClient.PostAsync("/__fixture/reset",new StringContent("{}",Encoding.UTF8,"application/json"),deadline.Token);response.EnsureSuccessStatusCode();}
        async Task<JsonElement> State()
        {using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(10));using var response=await controlClient.GetAsync("/__fixture/state",deadline.Token);response.EnsureSuccessStatusCode();return JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(deadline.Token)).RootElement.Clone();}
        async Task<JsonElement> Metrics()
        {using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(10));using var response=await controlClient.GetAsync("/__fixture/metrics",deadline.Token);response.EnsureSuccessStatusCode();return JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(deadline.Token)).RootElement.Clone();}
        async Task WriteCollectorFailure(string status,string stage,string error,string telemetryFile,PhaseResult? counts=null)
        {
            var path=Path.Combine(output,"collector-failure.json");
            if(File.Exists(path))return;
            await WriteEvidence(path,new{schemaVersion=1,status,stage,transport,rate,error,stopwatchFrequency=Stopwatch.Frequency,telemetryFile,preparationFile="collector-preparation.json",reportFile=stage=="preflight"?"collector-preflight.json":null,counts,enteredPhases=enteredPhases.ToArray(),warmupEntered=enteredPhases.Contains("warmup"),measuredEntered=enteredPhases.Contains("measured"),tlsConnections=SnapshotTls(),client=ClientMetrics(),observedTicks=Stopwatch.GetTimestamp()});
        }

        async Task<PhaseResult> Phase(string phase,int offeredCount,int duration)
        {
            enteredPhases.Add(phase);
            // Allocate outside the offered interval. Compression/JSON work runs only after
            // all requests finish, rather than competing with HTTP continuations in the pool.
            var observations=new Observation?[offeredCount];var issued=new ConcurrentDictionary<int,int>();
            var lanes=Enumerable.Range(0,32).Select(_=>new SemaphoreSlim(1,1)).ToArray();
            var tlsBefore=SnapshotTls();var clientBefore=ClientMetrics();
            var pending=new HashSet<Task>();var start=Stopwatch.GetTimestamp();var outstanding=0;var nextProgress=start+30*Stopwatch.Frequency;
            Exception? phaseFailure=null;
            try
            {
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
                        pending.RemoveWhere(t=>t.IsCompletedSuccessfully);
                    }
                    if(Stopwatch.GetTimestamp()>=nextProgress)
                    {Console.WriteLine(JsonSerializer.Serialize(new{stage=phase,offered=i+1,total=offeredCount,outstanding}));nextProgress+=30*Stopwatch.Frequency;}
                }
            }
            catch(Exception error){phaseFailure=error;}
            finally
            {
                try{await Task.WhenAll(pending);}
                catch(Exception error){phaseFailure=phaseFailure is null?error:new AggregateException(phaseFailure,error);}
                var requestsCompleted=Stopwatch.GetTimestamp();
                ClientMetricsSnapshot? clientAfter=null;
                try{clientAfter=ClientMetrics();}
                catch(Exception error){phaseFailure=phaseFailure is null?error:new AggregateException(phaseFailure,error);}
                var tlsAfter=SnapshotTls();
                long? completionMetricsStarted=null,completionMetricsCompleted=null;
                if(phase=="measured")
                {
                    completionMetricsStarted=Stopwatch.GetTimestamp();
                    try{measuredFinalMetrics=await Metrics();}
                    catch(Exception error){phaseFailure=phaseFailure is null?error:new AggregateException(phaseFailure,error);}
                    finally{completionMetricsCompleted=Stopwatch.GetTimestamp();}
                }
                var persistenceStarted=Stopwatch.GetTimestamp();
                try
                {
                    await PersistObservations(Path.Combine(output,phase+"-requests.jsonl.gz"),observations);
                    await File.WriteAllTextAsync(Path.Combine(output,phase+"-evidence-accounting.json"),JsonSerializer.Serialize(new
                    {
                        telemetrySchemaVersion=1,phase,offeredCount,observedCount=observations.Count(row=>row is not null),phaseStartedTicks=start,requestsCompletedTicks=requestsCompleted,
                        clientBefore,clientAfter,completionMetricsStartedTicks=completionMetricsStarted,completionMetricsCompletedTicks=completionMetricsCompleted,
                        tlsConnectionsBefore=tlsBefore,tlsConnectionsAfter=tlsAfter,newTlsConnectionIds=tlsAfter.Select(connection=>connection.ConnectionId).Except(tlsBefore.Select(connection=>connection.ConnectionId)).Order().ToArray(),
                        persistenceStartedTicks=persistenceStarted,persistenceCompletedTicks=Stopwatch.GetTimestamp(),
                        stopwatchFrequency=Stopwatch.Frequency,phaseFailure=phaseFailure?.ToString(),
                        serverMetricsBracket=phase=="measured"?"Final server metrics captured after request join and before this flush; latency timestamps still stop before Record":"No completion server-metrics query for this phase; only the measured phase captures that boundary",
                        clientMetricsBracket="Before schedule origin to after request join; completion-metrics request and raw persistence excluded"
                    },Json));
                }
                catch(Exception persistenceFailure)
                {throw phaseFailure is null?new InvalidOperationException("Raw evidence persistence failed.",persistenceFailure):new AggregateException("Phase execution and raw evidence persistence failed.",phaseFailure,persistenceFailure);}
                finally{foreach(var lane in lanes)lane.Dispose();}
            }
            if(phaseFailure is not null)
            {await WriteCollectorFailure("collector-phase-failed",phase,phaseFailure.ToString(),phase+"-evidence-accounting.json");throw new InvalidOperationException("Collector phase failed; retained all observed rows and accounting.",phaseFailure);}
            RequireCompleteObservations(observations);
            var all=observations.Select(row=>row!).ToArray();var good=all.Where(x=>x.Error=="").ToArray();
            var latencies=all.Select(x=>(x.Completed-x.Scheduled)*1000.0/Stopwatch.Frequency).Order().ToArray();
            var sentLatencies=all.Where(x=>x.Sent>0).Select(x=>(x.Completed-x.Sent)*1000.0/Stopwatch.Frequency).Order().ToArray();
            var floorEnd=start+(long)((duration+1.0)*Stopwatch.Frequency);
            return new(offeredCount,good.Length,all.Count(x=>x.Error!=""),all.Count(x=>x.Error=="offered.dropped"),good.Count(x=>x.Completed<=floorEnd),Percentile(latencies,.95),Percentile(latencies,.99),Percentile(sentLatencies,.95),all.Max(x=>Math.Max(0,x.Sent-x.Scheduled))*1000.0/Stopwatch.Frequency,(all.Max(x=>x.Completed)-start)*1000.0/Stopwatch.Frequency,
                all.Where(x=>x.Error!="").GroupBy(x=>x.Error).ToDictionary(x=>x.Key,x=>x.Count()));

            void Record(Observation row)=>StoreObservation(observations,row);
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
                    try{Record(new(item.Index,item.Operation,scheduled,sent,Stopwatch.GetTimestamp(),status,bytes,error));}
                    finally{Interlocked.Decrement(ref outstanding);}
                }
            }
        }
    }

    private sealed class PreparationRecord
    {
        public int PreparationIndex{get;init;}public int Index{get;init;}public string Operation{get;init;}="";
        public string Stage{get;init;}="";public string Pool{get;init;}="";
        public long StartedTicks{get;init;}public long? HeadersReadyTicks{get;set;}public long? BodyReadStartedTicks{get;set;}
        public long? BodyCompletedTicks{get;set;}public long? CompletedTicks{get;set;}public long? ConnectionId{get;set;}
        public int Status{get;set;}public int Bytes{get;set;}public string? Error{get;set;}public bool Passed{get;set;}
        public string? HttpVersion{get;set;}public long? ContentLength{get;set;}public bool Chunked{get;set;}public bool ConnectionClose{get;set;}
    }
    private sealed class BarrierProof
    {
        public int TargetConnections=>128;public string PoolScope=>"load";public int HeldResponses{get;set;}
        public int NonemptyHttp11Responses{get;set;}public int TlsConnectionsAtBarrier{get;set;}public int DistinctConnectionCount{get;set;}
        public long[] DistinctConnectionIds{get;set;}=[];public long[] LoadTlsConnectionIdsAtBarrier{get;set;}=[];
        public long StartedTicks{get;set;}public long? AllHeadersReadyTicks{get;set;}public long? ReleasedTicks{get;set;}
        public long? CompletedTicks{get;set;}public int DeadlineSeconds=>30;public bool Passed{get;set;}
    }
    private static void ValidatePreparationHeaders(HttpResponseMessage response,PreparationRecord row)
    {
        row.Status=(int)response.StatusCode;row.HttpVersion=response.Version.ToString();row.ContentLength=response.Content.Headers.ContentLength;
        row.Chunked=response.Headers.TransferEncodingChunked==true;row.ConnectionClose=response.Headers.ConnectionClose==true;row.HeadersReadyTicks=Stopwatch.GetTimestamp();
        response.EnsureSuccessStatusCode();
        if(row.Status!=200 || response.Version!=HttpVersion.Version11 || row.ConnectionClose || row.ContentLength==0 || row.ContentLength is null && !row.Chunked)
            throw new InvalidOperationException("Preparation requires200/nonempty-framed HTTP1.1 keep-alive responses.");
    }
    private static async Task WriteEvidence(string path,object value)
    {
        await using var stream=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None);
        await JsonSerializer.SerializeAsync(stream,value,Json);
    }

    private sealed record ClientMetricsSnapshot(long ObservedTicks,double CpuMilliseconds,long AllocatedBytesApproximate,int Gc0,int Gc1,int Gc2,int ThreadPoolThreads,long ThreadPoolPendingWorkItems,long ThreadPoolCompletedWorkItems);
    private static ClientMetricsSnapshot ClientMetrics()
    {
        using var process=Process.GetCurrentProcess();
        return new(Stopwatch.GetTimestamp(),process.TotalProcessorTime.TotalMilliseconds,GC.GetTotalAllocatedBytes(false),
            GC.CollectionCount(0),GC.CollectionCount(1),GC.CollectionCount(2),ThreadPool.ThreadCount,ThreadPool.PendingWorkItemCount,ThreadPool.CompletedWorkItemCount);
    }

    private static void StoreObservation(Observation?[] observations,Observation row)
    {
        if((uint)row.Index>=(uint)observations.Length)throw new InvalidOperationException("Offered observation index is out of range.");
        if(Interlocked.CompareExchange(ref observations[row.Index],row,null) is not null)throw new InvalidOperationException("Duplicate offered observation index.");
    }
    private static void RequireCompleteObservations(Observation?[] observations)
    {
        for(var index=0;index<observations.Length;index++)
            if(observations[index] is not { } row || row.Index!=index)throw new InvalidOperationException("Missing/misindexed offered observation.");
    }
    private static async Task PersistObservations(string path,Observation?[] observations)
    {
        await using var file=new FileStream(path,FileMode.CreateNew);
        await using var gzip=new GZipStream(file,CompressionLevel.Fastest);
        await using var writer=new StreamWriter(gzip,new UTF8Encoding(false));
        await writer.WriteLineAsync(JsonSerializer.Serialize(new{schema=1,columns=new[]{"index","operation","scheduledTicks","sentTicks","completedTicks","httpStatus","bodyBytes","error"},frequency=Stopwatch.Frequency}));
        foreach(var row in observations)
            if(row is not null)await writer.WriteLineAsync(JsonSerializer.Serialize(new object[]{row.Index,row.Operation,row.Scheduled,row.Sent,row.Completed,row.Status,row.Bytes,row.Error}));
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
