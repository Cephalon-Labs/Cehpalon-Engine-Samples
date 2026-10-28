using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Encodings.Web;
using System.Text.Json;
using Cehpalon.Engine.Composition;
using Cehpalon.Engine.Transports.Http;
using Cehpalon.Engine.Transports.GraphQL;
using HotChocolate.AspNetCore;
using HotChocolate.Types;
using HotChocolate.Execution.Configuration;
using HotChocolate.Execution.Instrumentation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Options;

namespace SmallApi.Benchmark;

public sealed class Probes
{
    public int HostFactories,ApiFactories,GraphQLFactories,GraphQLServices,ForbiddenFactories,EndpointCount,GraphQLDiagnosticConstructors,GraphQLExecutorInitializations,GraphQLSchemasReady;
}

public sealed class BenchmarkHost:IAsyncDisposable
{
    public CatalogStore Store {get;}=new();
    public Probes Probes {get;}=new();
    public WebApplication Application {get;private set;}=null!;
    public Uri Address=>new(Application.Urls.Single());
    public string Variant {get;private set;}="";
    public string Transport {get;private set;}="";
    private TlsFixture? tls;
    private ActivationLease? lease;
    private IAsyncDisposable? nativeResource;
    private bool disposed;
    private StartupTrace? startupTrace;
    private int firstBusinessRequest;
    public static string Config(bool api,bool graphql,bool worker=false)=>JsonSerializer.Serialize(new{Cehpalon=new{SchemaVersion=1,Architecture="Modular",Topology="SingleProcess",Pattern="RequestReply",Modules=new{api=new{Enabled=api},graphql=new{Enabled=graphql},worker=new{Enabled=worker}}}});
    public static CompositionCompilation ValidateConfiguration(string configuration)=>CompositionCompiler.Compile(configuration,[new("host",ModuleRole.Support),new("api",ModuleRole.EntryPoint,["host"]),new("graphql",ModuleRole.EntryPoint,["host"]),new("worker",ModuleRole.EntryPoint),new("database",ModuleRole.EntryPoint),new("cache",ModuleRole.EntryPoint),new("broker",ModuleRole.EntryPoint),new("ai",ModuleRole.EntryPoint),new("retrieval",ModuleRole.EntryPoint)]);
    public static async Task<BenchmarkHost> StartAsync(string variant,string transport,bool tls=true,string? fixtureDirectory=null,StartupTrace? startupTrace=null)
    {
        if(variant is not("baseline" or "engine") || transport is not("http" or "graphql"))throw new ArgumentException("Unknown benchmark variant/transport.");
        startupTrace?.Mark("host.construct.begin");
        var host=new BenchmarkHost{Variant=variant,Transport=transport,startupTrace=startupTrace};
        startupTrace?.Mark("host.construct.end");
        if(tls)host.tls=new(fixtureDirectory,startupTrace);
        try{await host.Start();return host;}catch{await host.DisposeAsync();throw;}
    }
    private async Task Start()
    {
        startupTrace?.Mark("composition.begin");
        var plan=Variant=="engine"?ValidateConfiguration(Config(true,Transport=="graphql")).Plan!:null;
        startupTrace?.Mark("composition.end");
        async ValueTask<IAsyncDisposable> StartNative(CancellationToken ct)
        {
            Probes.HostFactories++;
            startupTrace?.Mark("builder.begin");
            var builder=WebApplication.CreateSlimBuilder(new WebApplicationOptions{Args=[],EnvironmentName="Production"});builder.Logging.ClearProviders();
            startupTrace?.Mark("builder.end");
            startupTrace?.Mark("services.begin");
            builder.WebHost.ConfigureKestrel(options=>options.Listen(IPAddress.Loopback,0,listen=>
            {
                listen.Protocols=HttpProtocols.Http1;
                if(tls is not null)listen.UseHttps(https=>{https.ServerCertificate=tls.Server;https.SslProtocols=SslProtocols.Tls13;});
            }));
            builder.Services.AddAuthentication("public-fixture").AddScheme<AuthenticationSchemeOptions,PublicFixtureAuthentication>("public-fixture",_=>{});builder.Services.AddAuthorization();
            var dispatch=new Dispatch(Store,Variant=="engine");
            builder.Services.AddSingleton<ITransportOperationDispatcher>(dispatch);
            if(Transport=="graphql")
            {
                Probes.GraphQLFactories++;
                IRequestExecutorBuilder graphql;
                if(Variant=="engine")graphql=builder.Services.AddCehpalonGraphQL(new GraphQLOperationCatalog.Builder().AddQuery("catalogItem",Bindings.Get).AddQuery("catalogPage",Bindings.List).AddMutation("setLabel",Bindings.Set).Build());
                else
                {
                    builder.Services.AddHttpContextAccessor();
                    graphql=builder.Services.AddGraphQLServer().AddQueryType(new ObjectType(d=>{d.Name("Query");Wire.QueryField(d,"catalogItem",Bindings.Get,dispatch);Wire.QueryField(d,"catalogPage",Bindings.List,dispatch);}))
                        .AddMutationType(new ObjectType(d=>{d.Name("Mutation");Wire.QueryField(d,"setLabel",Bindings.Set,dispatch);}))
                        .DisableIntrospection(true).AddMaxExecutionDepthRule(8).ModifyOptions(o=>{o.EnableDefer=false;o.EnableStream=false;})
                        .ModifyRequestOptions(o=>o.IncludeExceptionDetails=false).ModifyCostOptions(o=>{o.MaxFieldCost=1000;o.MaxTypeCost=1000;o.EnforceCostLimits=true;});
                }
                graphql.AddDiagnosticEventListener(_=>new LifecycleDiagnostic(Probes));
            }
            Probes.GraphQLServices=builder.Services.Count(s=>(s.ServiceType.FullName??"").StartsWith("HotChocolate.",StringComparison.Ordinal));
            startupTrace?.Mark("services.end");
            startupTrace?.Mark("app.build.begin");
            var app=builder.Build();Application=app;
            startupTrace?.Mark("app.build.end");
            try
            {
                startupTrace?.Mark("routes.begin");
                if(startupTrace is not null)app.Use(async(http,next)=>
                {
                    if((http.Request.Path=="/api/catalog/get" || http.Request.Path=="/graphql") && Interlocked.CompareExchange(ref firstBusinessRequest,1,0)==0)
                    {
                        startupTrace.Mark("first.business.request.begin");
                        try{await next(http);}finally{startupTrace.Mark("first.business.response.end");}
                    }
                    else await next(http);
                });
                app.UseAuthentication();app.UseAuthorization();
                app.MapGet("/health",()=>Results.Ok(new{status="ok"}));
                app.MapPost("/__fixture/reset",()=>{if(Store.Factories!=Store.Disposals)return Results.Conflict();Reset();return Results.Ok(new{stateHash=Store.StateHash()});});
                app.MapGet("/__fixture/state",()=>Results.Json(State(),Wire.Json));
                app.MapGet("/__fixture/metrics",()=>Results.Json(Metrics(),Wire.Json));
                app.MapPost("/__fixture/delay",(bool enabled)=>{EnableDelay(enabled);return Results.Ok();});
                Probes.ApiFactories++;
                if(Variant=="engine")
                {app.MapOperation("/api/catalog/get",Bindings.Get);app.MapOperation("/api/catalog/list",Bindings.List);app.MapOperation("/api/catalog/set",Bindings.Set);}
                else
                {Wire.Map(app,"/api/catalog/get",Bindings.Get,dispatch);Wire.Map(app,"/api/catalog/list",Bindings.List,dispatch);Wire.Map(app,"/api/catalog/set",Bindings.Set,dispatch);}
                if(Transport=="graphql")
                {
                    if(Variant=="engine")app.MapCehpalonGraphQL("/graphql");
                    else
                    {
                        var endpoint=app.MapGraphQLHttp("/graphql").WithOptions(o=>{o.EnableGetRequests=false;o.EnableSchemaRequests=false;o.EnableMultipartRequests=false;o.Batching=AllowedBatching.None;});
                        endpoint.Add(b=>{var next=b.RequestDelegate!;b.RequestDelegate=http=>Wire.GuardGraphQL(http,next);});
                    }
                }
                Probes.EndpointCount=((IEndpointRouteBuilder)app).DataSources.SelectMany(d=>d.Endpoints).Count();
                startupTrace?.Mark("routes.end");
                startupTrace?.Mark("app.start.begin");
                await app.StartAsync(ct);
                startupTrace?.Mark("app.start.end");
                return new AppResource(app);
            }
            catch{await app.DisposeAsync();throw;}
        }
        var registrations=new List<ModuleRegistration>{new("host",StartNative),new("api",_=>ValueTask.FromResult<IAsyncDisposable>(new Empty())),new("graphql",_=>ValueTask.FromResult<IAsyncDisposable>(new Empty()))};
        foreach(var name in new[]{"worker","database","cache","broker","ai","retrieval"})registrations.Add(new(name,_=>{Probes.ForbiddenFactories++;throw new InvalidOperationException("Forbidden activation: "+name);}));
        if(Variant=="engine")lease=await PlanActivator.ActivateAsync(plan!,registrations);
        else nativeResource=await StartNative(CancellationToken.None);
    }
    public void Reset(){if(Store.Factories!=Store.Disposals)throw new InvalidOperationException("Reset requires no active handlers.");Store.Reset();}
    public void EnableDelay(bool enabled)=>Store.DelayWrites=enabled;
    public HttpClient Client()=>tls?.Client(Address)??new HttpClient{BaseAddress=Address,Timeout=TimeSpan.FromSeconds(10)};
    public object Ready()
    {
        startupTrace?.Mark("readiness.hash.begin");var stateHash=Store.StateHash();startupTrace?.Mark("readiness.hash.end");
        return new{address=Address.ToString(),rootCaDerBase64=tls is null?null:Convert.ToBase64String(tls.Root.Export(X509ContentType.Cert)),tlsProtocol=tls is null?"None":"Tls13",variant=Variant,transport=Transport,processId=Environment.ProcessId,datasetId="cehpalon-small-api-v1",stateHash};
    }
    public object Metrics()
    {
        var allocated=GC.GetTotalAllocatedBytes(true);var gc0=GC.CollectionCount(0);var gc1=GC.CollectionCount(1);var gc2=GC.CollectionCount(2);
        using var process=Process.GetCurrentProcess();
        return new{totalAllocatedBytes=allocated,cpuMilliseconds=process.TotalProcessorTime.TotalMilliseconds,workingSetBytes=process.WorkingSet64,gc0,gc1,gc2,
            factories=Store.Factories,constructors=Store.Constructors,disposals=Store.Disposals,reads=Store.Reads,writes=Store.Writes};
    }
    public object State()
    {
        var metrics=Metrics();return new{variant=Variant,transport=Transport,records=Store.Snapshot(),stateHash=Store.StateHash(),factories=Store.Factories,constructors=Store.Constructors,disposals=Store.Disposals,reads=Store.Reads,writes=Store.Writes,metrics,probes=Probes};
    }
    public async ValueTask DisposeAsync(){if(disposed)return;disposed=true;try{if(lease is not null)await lease.DisposeAsync();if(nativeResource is not null)await nativeResource.DisposeAsync();}finally{tls?.Dispose();}}
    private sealed class Empty:IAsyncDisposable{public ValueTask DisposeAsync()=>ValueTask.CompletedTask;}
    private sealed class AppResource(WebApplication app):IAsyncDisposable{public async ValueTask DisposeAsync(){using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));await app.StopAsync(timeout.Token);await app.DisposeAsync();}}
}

public sealed class LifecycleDiagnostic:ExecutionDiagnosticEventListener
{
    private readonly Probes probes;
    public LifecycleDiagnostic(Probes probes){this.probes=probes;Interlocked.Increment(ref probes.GraphQLDiagnosticConstructors);}
    public override void ExecutorCreated(string name,HotChocolate.Execution.IRequestExecutor executor)
    {Interlocked.Increment(ref probes.GraphQLExecutorInitializations);if(executor.Schema is not null)Interlocked.Increment(ref probes.GraphQLSchemasReady);}
}

public sealed class PublicFixtureAuthentication(IOptionsMonitor<AuthenticationSchemeOptions> options,ILoggerFactory logger,UrlEncoder encoder):AuthenticationHandler<AuthenticationSchemeOptions>(options,logger,encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()=>Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub","public-synthetic-fixture")],Scheme.Name)),Scheme.Name)));
}

public sealed class TlsFixture:IDisposable
{
    private readonly RSA? rootKey,leafKey;
    private readonly byte[]? generatedPfx;
    public X509Certificate2 Root{get;}
    public X509Certificate2 Server{get;}
    public TlsFixture(string? fixtureDirectory=null,StartupTrace? startupTrace=null)
    {
        if(fixtureDirectory is not null)
        {
            startupTrace?.Mark("tls.root.load.begin");
            Root=X509CertificateLoader.LoadCertificate(File.ReadAllBytes(Path.Combine(fixtureDirectory,"root-ca.der")));
            startupTrace?.Mark("tls.root.load.end");
            startupTrace?.Mark("tls.pkcs12.load.begin");
            Server=X509CertificateLoader.LoadPkcs12FromFile(Path.Combine(fixtureDirectory,"server.pfx"),null,OperatingSystem.IsWindows()?X509KeyStorageFlags.UserKeySet:X509KeyStorageFlags.EphemeralKeySet);
            startupTrace?.Mark("tls.pkcs12.load.end");
            return;
        }
        startupTrace?.Mark("tls.generate.begin");
        rootKey=RSA.Create(2048);leafKey=RSA.Create(2048);
        var now=DateTimeOffset.UtcNow;var ca=new CertificateRequest("CN=Cehpalon benchmark fixture CA",rootKey,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        ca.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));ca.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign|X509KeyUsageFlags.CrlSign,true));Root=ca.CreateSelfSigned(now.AddMinutes(-5),now.AddHours(49));
        var leaf=new CertificateRequest("CN=localhost",leafKey,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);leaf.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));leaf.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature,true));leaf.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection{new("1.3.6.1.5.5.7.3.1")},true));var san=new SubjectAlternativeNameBuilder();san.AddDnsName("localhost");san.AddIpAddress(IPAddress.Loopback);leaf.CertificateExtensions.Add(san.Build());
        using var publicLeaf=leaf.Create(Root,now.AddMinutes(-2),now.AddHours(48),RandomNumberGenerator.GetBytes(16));using var keyed=publicLeaf.CopyWithPrivateKey(leafKey);generatedPfx=keyed.Export(X509ContentType.Pfx);Server=X509CertificateLoader.LoadPkcs12(generatedPfx,null,OperatingSystem.IsWindows()?X509KeyStorageFlags.UserKeySet:X509KeyStorageFlags.EphemeralKeySet);
        startupTrace?.Mark("tls.generate.end");
    }
    public byte[] ExportPrivateFixture()=>generatedPfx is null?throw new InvalidOperationException("Only a newly generated fixture can export its private key."):(byte[])generatedPfx.Clone();
    public HttpClient Client(Uri address)
    {var chain=new X509ChainPolicy{TrustMode=X509ChainTrustMode.CustomRootTrust,RevocationMode=X509RevocationMode.NoCheck};chain.CustomTrustStore.Add(Root);return new(new SocketsHttpHandler{UseProxy=false,SslOptions=new SslClientAuthenticationOptions{EnabledSslProtocols=SslProtocols.Tls13,CertificateChainPolicy=chain}}){BaseAddress=address,Timeout=TimeSpan.FromSeconds(10)};}
    public void Dispose(){Server.Dispose();Root.Dispose();rootKey?.Dispose();leafKey?.Dispose();if(generatedPfx is not null)CryptographicOperations.ZeroMemory(generatedPfx);}
}

/// <summary>Opt-in diagnostic marks only; disabled in acceptance measurements.</summary>
public sealed class StartupTrace:IDisposable
{
    private readonly string path;
    private readonly object gate=new();
    private readonly List<(string Stage,long Timestamp)> marks=[];
    public StartupTrace(string path,long managedEntryTimestamp)
    {
        this.path=Path.GetFullPath(path);if(File.Exists(this.path))throw new IOException("Startup trace output must be new.");
        marks.Add(("managed.entry",managedEntryTimestamp));
    }
    public void Mark(string stage){var timestamp=Stopwatch.GetTimestamp();lock(gate)marks.Add((stage,timestamp));}
    public void Dispose()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        object[] records;lock(gate)records=marks.Select(m=>(object)new{stage=m.Stage,timestamp=m.Timestamp,elapsedMilliseconds=Stopwatch.GetElapsedTime(marks[0].Timestamp,m.Timestamp).TotalMilliseconds}).ToArray();
        using var file=new FileStream(path,FileMode.CreateNew,FileAccess.Write);
        JsonSerializer.Serialize(file,new{scope="Opt-in diagnostic instrumentation, not acceptance or throughput timing",processId=Environment.ProcessId,stopwatchFrequency=Stopwatch.Frequency,marks=records},Wire.Json);
    }
}
