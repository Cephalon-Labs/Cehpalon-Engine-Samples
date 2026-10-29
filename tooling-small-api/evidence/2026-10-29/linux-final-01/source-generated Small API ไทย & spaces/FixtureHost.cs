using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Cehpalon.Engine.Composition;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;
using Cehpalon.Engine.Transports.Http;
using Cehpalon.Engine.Transports.GraphQL;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.IdentityModel.Tokens;

namespace PortableConsumers.Generated;

public sealed class JwtFixture : IDisposable
{
    public const string Issuer="urn:cehpalon:small-api-fixture", Audience="cehpalon-small-api-fixture";
    private readonly RSA key=RSA.Create(2048);
    public SecurityKey PublicKey => new RsaSecurityKey(key.ExportParameters(false));
    public string Token(string subject="alice",string issuer=Issuer,string audience=Audience,bool expired=false,bool duplicateSubject=false,string type="at+jwt")
    {
        var now=DateTime.UtcNow;
        var claims=new List<Claim>{new("sub",subject)};
        if(duplicateSubject) claims.Add(new("sub","mallory"));
        var token=new JwtSecurityToken(issuer,audience,claims,now.AddMinutes(-5),expired?now.AddMinutes(-1):now.AddMinutes(5),new SigningCredentials(new RsaSecurityKey(key),SecurityAlgorithms.RsaSha256));
        token.Header["typ"]=type;
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    public static bool ExactClaims(ClaimsPrincipal principal)
    {
        if(One(principal,"iss")!=Issuer || One(principal,"sub") is not {Length:>0 and <=256} subject
            || !long.TryParse(One(principal,"nbf"),NumberStyles.None,CultureInfo.InvariantCulture,out var start)
            || !long.TryParse(One(principal,"exp"),NumberStyles.None,CultureInfo.InvariantCulture,out var end)) return false;
        try { _=new IdentitySnapshot(new(Issuer,subject),JwtBearerDefaults.AuthenticationScheme,DateTimeOffset.FromUnixTimeSeconds(start),DateTimeOffset.FromUnixTimeSeconds(end)); return true; }
        catch(ArgumentException) { return false; }
    }
    public static string? One(ClaimsPrincipal principal,string type) { var values=principal.FindAll(type).Take(2).ToArray(); return values.Length==1?values[0].Value:null; }
    public void Dispose()=>key.Dispose();
}

public sealed class ValidatedIdentity(HttpContext http) : IIdentitySource
{
    public async ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var auth=await http.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme);
        ct.ThrowIfCancellationRequested();
        if(!auth.Succeeded || auth.Principal is null || !JwtFixture.ExactClaims(auth.Principal)) return null;
        return new(new(JwtFixture.Issuer,JwtFixture.One(auth.Principal,"sub")!),JwtBearerDefaults.AuthenticationScheme,
            DateTimeOffset.FromUnixTimeSeconds(long.Parse(JwtFixture.One(auth.Principal,"nbf")!,CultureInfo.InvariantCulture)),
            DateTimeOffset.FromUnixTimeSeconds(long.Parse(JwtFixture.One(auth.Principal,"exp")!,CultureInfo.InvariantCulture)));
    }
}

public sealed class SampleDispatcher(CatalogStore store) : ITransportOperationDispatcher
{
    public ValueTask<OperationResult<TResponse>> DispatchAsync<TRequest,TResponse>(HttpContext http,string id,TRequest request,OperationContext context,CancellationToken ct)
    {
        CatalogHandler Factory() { Interlocked.Increment(ref store.Factories); Interlocked.Increment(ref store.Constructors); return new(store); }
        var registry=new TenantOperationRegistryBuilder()
            .Register<GetItem,Item>("catalog.get","catalog.get","catalog",r=>r with{},r=>new(new(r.Tenant),"catalog"),Factory)
            .Register<ListItems,ItemPage>("catalog.list","catalog.list","catalog",r=>r with{},r=>new(new(r.Tenant),"catalog"),Factory)
            .Register<SetLabel,Item>("catalog.set","catalog.set","catalog",r=>r with{},r=>new(new(r.Tenant),"catalog"),Factory).Build();
        var services=new TenantSecurityServices(new ValidatedIdentity(http),new IdentityTrustPolicy([JwtFixture.Issuer],[JwtBearerDefaults.AuthenticationScheme]),new Memberships(store),store,TimeSpan.FromSeconds(30),store.MissingPolicy?null:new CatalogPolicy());
        var tenant=new TenantOperationDispatcher(registry,services);
        var core=new OperationRegistryBuilder();
        Cehpalon.Engine.Generated.OperationRegistrations.RegisterAll(core,new GatewayFactory(tenant));
        return new OperationDispatcher(core.Build()).DispatchAsync<TRequest,TResponse>(id,request,context,ct);
    }
}

public sealed class TlsFixture : IDisposable
{
    private readonly RSA rootKey=RSA.Create(2048),leafKey=RSA.Create(2048);
    public X509Certificate2 Root {get;}
    public X509Certificate2 Server {get;}
    public TlsFixture()
    {
        var now=DateTimeOffset.UtcNow;
        var ca=new CertificateRequest("CN=Cehpalon Small API fixture CA",rootKey,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        ca.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));
        ca.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign|X509KeyUsageFlags.CrlSign,true));
        Root=ca.CreateSelfSigned(now.AddMinutes(-5),now.AddHours(2));
        var leaf=new CertificateRequest("CN=localhost",leafKey,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        leaf.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));
        leaf.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature,true));
        leaf.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection{new("1.3.6.1.5.5.7.3.1")},true));
        var san=new SubjectAlternativeNameBuilder();san.AddDnsName("localhost");san.AddIpAddress(IPAddress.Loopback);leaf.CertificateExtensions.Add(san.Build());
        using var cert=leaf.Create(Root,now.AddMinutes(-2),now.AddHours(1),RandomNumberGenerator.GetBytes(16));
        using var keyed=cert.CopyWithPrivateKey(leafKey);
        Server=X509CertificateLoader.LoadPkcs12(keyed.Export(X509ContentType.Pfx),null,OperatingSystem.IsWindows()?X509KeyStorageFlags.UserKeySet:X509KeyStorageFlags.EphemeralKeySet);
    }
    public HttpClient Client(Uri address,string? wrongHost=null)
    {
        var chain=new X509ChainPolicy{TrustMode=X509ChainTrustMode.CustomRootTrust,RevocationMode=X509RevocationMode.NoCheck};chain.CustomTrustStore.Add(Root);
        var handler=new SocketsHttpHandler{UseProxy=false,SslOptions=new SslClientAuthenticationOptions{CertificateChainPolicy=chain}};
        if(wrongHost is not null) handler.ConnectCallback=async(_,ct)=>{var socket=new Socket(SocketType.Stream,ProtocolType.Tcp);await socket.ConnectAsync(IPAddress.Loopback,address.Port,ct);return new NetworkStream(socket,true);};
        return new(handler){BaseAddress=wrongHost is null?address:new Uri($"https://{wrongHost}:{address.Port}"),Timeout=TimeSpan.FromSeconds(10)};
    }
    public void Dispose(){Server.Dispose();Root.Dispose();leafKey.Dispose();rootKey.Dispose();}
}

public sealed class ActivationCounters
{
    public int HostFactories,HostDisposals,ApiFactories,GraphQLFactories,ForbiddenFactories,GraphQLServices,Endpoints;
}

public sealed class FixtureHost : IAsyncDisposable
{
    private CatalogStore? store;
    public CatalogStore Store => store ?? throw new InvalidOperationException("Catalog module has not activated.");
    public ActivationCounters Counters {get;}=new();
    public WebApplication? Application {get;private set;}
    public Uri Address=>new(Application!.Urls.Single());
    private ActivationLease? lease;
    public static string Config(bool api,bool graphql,bool worker=false)=>System.Text.Json.JsonSerializer.Serialize(new{Cehpalon=new{SchemaVersion=1,Architecture="Modular",Topology="SingleProcess",Pattern="RequestReply",Modules=new{api=new{Enabled=api},graphql=new{Enabled=graphql},worker=new{Enabled=worker}}}});
    public Task Start(string configuration,TlsFixture tls,JwtFixture jwt) => Start(configuration,tls.Server,jwt.PublicKey);
    public static ActivationPlan Compile(string configuration)
    {
        var descriptors=new List<ModuleDescriptor>{new("host",ModuleRole.Support),new("api",ModuleRole.EntryPoint,["host"]),new("graphql",ModuleRole.EntryPoint,["host"])};
        foreach(var name in new[]{"worker","database","cache","broker","ai","retrieval"}) descriptors.Add(new(name,ModuleRole.EntryPoint));
        var result=CompositionCompiler.Compile(configuration,descriptors);
        if(!result.IsSuccess) throw new ArgumentException("Invalid composition: "+string.Join(',',result.Diagnostics.Select(d=>d.Code)));
        var plan=result.Plan!;
        if(plan.ActivationOrder.Any(x=>x is not("host" or "api" or "graphql"))) throw new ArgumentException("Unsupported sample capability.");
        return plan;
    }
    public async Task Start(string configuration,X509Certificate2 certificate,SecurityKey publicKey)
    {
        var plan=Compile(configuration);
        var enabled=plan.ActivationOrder.ToHashSet(StringComparer.Ordinal);
        var registrations=new List<ModuleRegistration>();
        registrations.Add(new("host",async ct=>
        {
            Interlocked.Increment(ref Counters.HostFactories);
            store=new();
            var builder=WebApplication.CreateSlimBuilder(new WebApplicationOptions{Args=[],EnvironmentName="Production"});
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(k=>k.Listen(IPAddress.Loopback,0,l=>{l.Protocols=HttpProtocols.Http1;l.UseHttps(certificate);}));
            builder.Services.AddSingleton<ITransportOperationDispatcher>(new SampleDispatcher(Store));
            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o=>
            {
                o.MapInboundClaims=false;o.IncludeErrorDetails=false;
                o.TokenValidationParameters=new(){ValidateIssuerSigningKey=true,IssuerSigningKey=publicKey,ValidateIssuer=true,ValidIssuer=JwtFixture.Issuer,ValidateAudience=true,ValidAudience=JwtFixture.Audience,
                    ValidateLifetime=true,RequireExpirationTime=true,RequireSignedTokens=true,ClockSkew=TimeSpan.Zero,ValidAlgorithms=[SecurityAlgorithms.RsaSha256],ValidTypes=["at+jwt"]};
                o.Events=new JwtBearerEvents{OnTokenValidated=c=>{if(c.Principal is null || !JwtFixture.ExactClaims(c.Principal)) c.Fail("Invalid fixture identity.");return Task.CompletedTask;}};
            });
            builder.Services.AddAuthorization();
            if(enabled.Contains("graphql"))
            {
                Counters.GraphQLFactories++;
                var catalog=new GraphQLOperationCatalog.Builder().AddQuery("catalogItem",Bindings.Get).AddQuery("catalogPage",Bindings.List).AddMutation("setLabel",Bindings.Set).Build();
                builder.Services.AddCehpalonGraphQL(catalog);
            }
            Counters.GraphQLServices=builder.Services.Count(s=>(s.ServiceType.FullName??"").StartsWith("HotChocolate.",StringComparison.Ordinal));
            var app=builder.Build();Application=app;
            try
            {
                app.UseAuthentication();app.UseAuthorization();
                app.MapGet("/health",()=>Results.Ok(new{status="ok"}));
                if(enabled.Contains("api"))
                {
                    Counters.ApiFactories++;
                    app.MapOperation("/api/catalog/get",Bindings.Get);app.MapOperation("/api/catalog/list",Bindings.List);app.MapOperation("/api/catalog/set",Bindings.Set);
                }
                if(enabled.Contains("graphql")) app.MapCehpalonGraphQL("/graphql");
                Counters.Endpoints=((Microsoft.AspNetCore.Routing.IEndpointRouteBuilder)app).DataSources.SelectMany(x=>x.Endpoints).Count();
                await app.StartAsync(ct);
                return new HostResource(app,Counters);
            }
            catch {await app.DisposeAsync();Application=null;throw;}
        }));
        registrations.Add(new("api",_=>ValueTask.FromResult<IAsyncDisposable>(new NoResource())));
        registrations.Add(new("graphql",_=>ValueTask.FromResult<IAsyncDisposable>(new NoResource())));
        foreach(var name in new[]{"worker","database","cache","broker","ai","retrieval"}) registrations.Add(new(name,_=>{Counters.ForbiddenFactories++;throw new InvalidOperationException("Disabled module activated: "+name);}));
        lease=await PlanActivator.ActivateAsync(plan,registrations);
    }
    public async ValueTask DisposeAsync() {if(lease is not null) await lease.DisposeAsync();}
    private sealed class NoResource:IAsyncDisposable {public ValueTask DisposeAsync()=>ValueTask.CompletedTask;}
    private sealed class HostResource(WebApplication app,ActivationCounters counters):IAsyncDisposable
    {public async ValueTask DisposeAsync(){using var ct=new CancellationTokenSource(TimeSpan.FromSeconds(5));try{await app.StopAsync(ct.Token);}finally{await app.DisposeAsync();Interlocked.Increment(ref counters.HostDisposals);}}}
}
