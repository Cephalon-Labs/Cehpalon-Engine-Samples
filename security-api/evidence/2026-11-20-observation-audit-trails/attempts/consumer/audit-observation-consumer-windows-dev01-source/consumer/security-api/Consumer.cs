using System.Globalization;
using System.Net;
using Cehpalon.Engine.Authorization;
using Cehpalon.Engine.Composition;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Identity.AspNetCore;
using Cehpalon.Engine.Identity.JwtBearer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using Cehpalon.Engine.Tenancy;
using Cehpalon.Engine.Transports.Http;
using Cehpalon.Engine.Transports.GraphQL;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.IdentityModel.Tokens;

namespace SecurityApi;

public sealed record DocumentRequest(string Tenant,string ResourceId);
public sealed record SwitchRequest(string Tenant);
public sealed record SwitchResult(string Tenant);
public sealed record ReadSetRequest(string ResourceId,string[]? Tenants=null);
public sealed record ReadSetResult(DocumentResult[] Results);
public sealed record HistoryRequest(string Tenant,int Limit=50,string? Cursor=null);
public sealed record DocumentResult(string Tenant,int Revision);
public sealed record HistoryResult(string Tenant,int Count,string[] Outcomes,string? NextCursor);

public static class Bindings
{
    public static readonly OperationBinding<EntityMutationRequest,EntityMutationResult> CreateEntity=new("entity.create",ValidateEntity);
    public static readonly OperationBinding<EntityMutationRequest,EntityMutationResult> UpdateEntity=new("entity.update",ValidateEntity);
    public static readonly OperationBinding<EntityMutationRequest,EntityMutationResult> DeleteEntity=new("entity.delete",ValidateEntity);
    public static readonly OperationBinding<TrailHistoryRequest,TrailHistoryResult> TrailHistory=new("trail.history",r=>Tenant(r.Tenant)&&r.Limit is >=1 and <=200&&(r.Cursor is null||int.TryParse(r.Cursor,NumberStyles.None,CultureInfo.InvariantCulture,out var n)&&n>=0)?null:Invalid());
    private static OperationError? ValidateEntity(EntityMutationRequest r)=>Tenant(r.Tenant)&&(r.EntityId is "shared" or "created")&&(r.Title is {Length:>0 and <=128})&&(r.Amount is >=0 and <=1000000)&&(r.Secret is {Length:>0 and <=128})?null:Invalid();
    public static readonly OperationBinding<SwitchRequest,SwitchResult> Switch=new("tenant.select",r=>Tenant(r.Tenant)?null:Invalid());
    public static readonly OperationBinding<ReadSetRequest,ReadSetResult> ReadSet=new("document.read_all",r=>r.ResourceId=="shared"&&(r.Tenants is null||r.Tenants.Length is >0 and <=64&&r.Tenants.All(Tenant)&&r.Tenants.Distinct(StringComparer.Ordinal).Count()==r.Tenants.Length)?null:Invalid());
    public static readonly OperationBinding<DocumentRequest,DocumentResult> Read=new("document.read",Validate);
    public static readonly OperationBinding<DocumentRequest,DocumentResult> Rbac=new("document.rbac",Validate);
    public static readonly OperationBinding<DocumentRequest,DocumentResult> Abac=new("document.abac",Validate);
    public static readonly OperationBinding<DocumentRequest,DocumentResult> Update=new("document.update",Validate);
    public static readonly OperationBinding<HistoryRequest,HistoryResult> History=new("history.read",r=>Tenant(r.Tenant)&&r.Limit is >=1 and <=200&&(r.Cursor is null||int.TryParse(r.Cursor,NumberStyles.None,CultureInfo.InvariantCulture,out var n)&&n>=0)?null:Invalid());
    private static OperationError? Validate(DocumentRequest r)=>Tenant(r.Tenant)&&r.ResourceId=="shared"?null:Invalid();
    private static bool Tenant(string value)=>value is "A" or "B";
    private static OperationError Invalid()=>new("request.invalid","Invalid input.");
}

// Controlled authority fixture; never read roles/department/tenant membership from the request.
public sealed class Authority : ITenantMembershipSource,IResourceScopeSource,IAuthorizationFactsSource,ITenantReadSetSource
{
    public bool ReaderRevoked;public volatile bool RevokeB;public ObservationFixture? Observation;
    private DateTimeOffset Now=>Observation?.Clock.GetUtcNow()??DateTimeOffset.UtcNow;
    public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot identity,TenantId tenant,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();Observation?.At("membership",tenant.Value);var subject=identity.Principal.Subject;
        var allowed=((subject is "alice" or "no-role" or "wrong-department" or "auditor" or "limited-reporter")&&tenant.Value=="A" || subject=="bob"&&tenant.Value=="B" || subject is "switcher" or "reporter" && tenant.Value is "A" or "B" || subject=="trail-reader"&&tenant.Value=="A" || subject=="trail-reader-b"&&tenant.Value=="B")&&!(RevokeB&&tenant.Value=="B");
        return ValueTask.FromResult<TenantMembershipSnapshot?>(allowed?new(identity.Principal,tenant,true,Now.AddMinutes(-5),Now.AddMinutes(5),"m1"):null);
    }
    public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId tenant,string kind,string id,CancellationToken token)
    {token.ThrowIfCancellationRequested();Observation?.At("resource",tenant.Value);return ValueTask.FromResult<ResourceScopeSnapshot?>(new(tenant,kind,id,"r1"));}
    public ValueTask<AuthorizationFacts?> ResolveAsync(TenantAccessRequest r,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();Observation?.At("policy",r.Tenant.Value);var subject=r.Identity.Principal.Subject;
        string[] roles=subject is "trail-reader" or "trail-reader-b"?["trail-reader"]:subject=="auditor"?["auditor"]:subject=="no-role"||ReaderRevoked?[]:["reader","member"];
        return ValueTask.FromResult<AuthorizationFacts?>(new(r.Identity.Principal,r.Tenant,r.Membership.Version,r.Resource.Kind,r.Resource.ResourceId,r.Resource.Version,
            Now.AddMinutes(-1),Now.AddMinutes(1),roles,
            new([new("department",subject=="wrong-department"?"sales":"finance")]),new([new("department","finance")]),new([new("network","private")])));
    }
    public ValueTask<TenantReadSetSnapshot?> ResolveAsync(TenantReadSetRequest request,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();Observation?.At("grant",null);var subject=request.Identity.Principal.Subject;
        if(request.OperationId!="document.read_all"||subject is not("reporter" or "limited-reporter"))return ValueTask.FromResult<TenantReadSetSnapshot?>(null);
        TenantId[] tenants=subject=="reporter"?[new("A"),new("B")]:[new("A")];
        return ValueTask.FromResult<TenantReadSetSnapshot?>(new(request.Identity.Principal,request.OperationId,request.ResourceKind,request.ResourceId,tenants,
            Now.AddMinutes(-1),Now.AddMinutes(1),"read-set-v1"));
    }
    public static AccessRule[] Rules()=>[
        new("tenant.select","select","tenant",["member"]),
        new("document.read_all","read","document",["reader"],[AttributePredicate.Match(AttributeScope.Subject,"department",AttributeScope.Resource,"department")]),
        new("document.read","read","document",["reader"],[AttributePredicate.Match(AttributeScope.Subject,"department",AttributeScope.Resource,"department"),AttributePredicate.EqualTo(AttributeScope.Environment,"network","private")]),
        new("document.rbac","read","document",["reader"]),
        new("document.abac","read","document",allAttributes:[AttributePredicate.Match(AttributeScope.Subject,"department",AttributeScope.Resource,"department")]),
        new("document.update","write","document",["reader"],[AttributePredicate.Match(AttributeScope.Subject,"department",AttributeScope.Resource,"department")]),
        new("history.read","read","audit-history",["auditor"]),
        new("entity.create","create","entity",["reader"]),new("entity.update","update","entity",["reader"]),new("entity.delete","delete","entity",["reader"]),
        new("trail.history","read","audit-trail",["trail-reader"])
    ];
}

// Bounded fixture store. Production consumers supply durable append/history implementations.
public sealed class MemoryAuditStore:ITenantAuditSink,ITenantAuditHistorySource
{
    private readonly object gate=new();private readonly List<TenantAuditEvent> events=[];
    public ObservationFixture? Observation;public bool Fail;public Action<TenantAuditEvent>? AppendHook;public int Count{get{lock(gate)return events.Count;}}
    public TenantAuditEvent[] Snapshot(){lock(gate)return events.ToArray();}
    public ValueTask AppendAsync(TenantAuditEvent entry,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();lock(gate)
        {
            if(Fail||events.Count>=1024)throw new IOException("Fixture audit unavailable.");
            if(events.Any(e=>e.InvocationId==entry.InvocationId&&e.Stage==entry.Stage))throw new InvalidOperationException("Duplicate fixture audit record.");
            AppendHook?.Invoke(entry);if(entry.Stage==TenantAuditStage.Authorization)Observation?.At("audit",entry.AuthorizedTenant?.Value);events.Add(entry);
        }
        return ValueTask.CompletedTask;
    }
    public ValueTask<TenantAuditHistoryPage> ReadAsync(TenantId tenant,int limit,string? cursor,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();var offset=cursor is null?0:int.Parse(cursor,NumberStyles.None,CultureInfo.InvariantCulture);
        lock(gate)
        {
            var rows=events.Where(e=>tenant.Equals(e.AuthorizedTenant)).ToArray();var page=rows.Skip(offset).Take(limit).ToArray();
            var next=offset+page.Length;return ValueTask.FromResult(new TenantAuditHistoryPage(page,next<rows.Length?next.ToString(CultureInfo.InvariantCulture):null));
        }
    }
}

public sealed class BusinessState
{
    public ObservationFixture? Observation;public int Factories,Disposals;public Action<TenantId>? ReadSetHook;public Func<TenantId,CancellationToken,Task>? ReadSetGate;public Func<TenantId,CancellationToken,Task>? DocumentGate;private readonly Dictionary<string,int> revisions=new(StringComparer.Ordinal);
    public int Revision(string tenant){lock(revisions)return revisions.TryGetValue(tenant,out var value)?value:0;}
    public DocumentResult Read(TenantOperationContext context,bool write)
    {
        context.DemandAccess(context.Tenant,"document","shared",write?"write":"read");
        lock(revisions){revisions.TryGetValue(context.Tenant.Value,out var revision);if(write)revisions[context.Tenant.Value]=++revision;Observation?.RecordEffect(context.Tenant.Value);return new(context.Tenant.Value,revision);}
    }
}
public sealed class DocumentHandler(BusinessState state):ITenantOperationHandler<DocumentRequest,DocumentResult>,IDisposable
{
    private string? tenant;
    public async ValueTask<OperationResult<DocumentResult>> HandleAsync(DocumentRequest request,TenantOperationContext context,CancellationToken token)
    {
        tenant=request.Tenant;if(state.DocumentGate is not null)await state.DocumentGate(context.Tenant,token);token.ThrowIfCancellationRequested();
        if(state.Observation?.RejectBusiness==true){state.Observation.At("business-rejected",tenant);return OperationResult<DocumentResult>.Failure(new("fixture.rejected","Controlled business rejection."));}
        var result=state.Read(context,context.Action=="write");state.Observation?.At("after-handler",tenant);return OperationResult<DocumentResult>.Success(result);
    }
    public void Dispose(){Interlocked.Increment(ref state.Disposals);state.Observation?.At("cleanup",tenant);if(state.Observation?.FailCleanup==true)throw new IOException("Controlled cleanup failure.");}
}
public sealed class HistoryHandler(TenantAuditHistoryReader reader,BusinessState state):ITenantOperationHandler<HistoryRequest,HistoryResult>,IDisposable
{
    public async ValueTask<OperationResult<HistoryResult>> HandleAsync(HistoryRequest request,TenantOperationContext context,CancellationToken token)
    {var page=await reader.ReadAsync(context,request.Limit,request.Cursor,token);return OperationResult<HistoryResult>.Success(new(context.Tenant.Value,page.Entries.Count,page.Entries.Select(e=>e.Outcome.ToString()).ToArray(),page.NextCursor));}
    public void Dispose()=>Interlocked.Increment(ref state.Disposals);
}

[Operation("document.read")]
public sealed class ReadGateway(TenantOperationDispatcher dispatcher):IOperationHandler<DocumentRequest,DocumentResult>
{public ValueTask<OperationResult<DocumentResult>> HandleAsync(DocumentRequest r,OperationContext c,CancellationToken t)=>dispatcher.DispatchAsync<DocumentRequest,DocumentResult>("document.read",r,c,t);}
[Operation("document.rbac")]
public sealed class RbacGateway(TenantOperationDispatcher dispatcher):IOperationHandler<DocumentRequest,DocumentResult>
{public ValueTask<OperationResult<DocumentResult>> HandleAsync(DocumentRequest r,OperationContext c,CancellationToken t)=>dispatcher.DispatchAsync<DocumentRequest,DocumentResult>("document.rbac",r,c,t);}
[Operation("document.abac")]
public sealed class AbacGateway(TenantOperationDispatcher dispatcher):IOperationHandler<DocumentRequest,DocumentResult>
{public ValueTask<OperationResult<DocumentResult>> HandleAsync(DocumentRequest r,OperationContext c,CancellationToken t)=>dispatcher.DispatchAsync<DocumentRequest,DocumentResult>("document.abac",r,c,t);}
[Operation("document.update")]
public sealed class UpdateGateway(TenantOperationDispatcher dispatcher):IOperationHandler<DocumentRequest,DocumentResult>
{public ValueTask<OperationResult<DocumentResult>> HandleAsync(DocumentRequest r,OperationContext c,CancellationToken t)=>dispatcher.DispatchAsync<DocumentRequest,DocumentResult>("document.update",r,c,t);}
[Operation("history.read")]
public sealed class HistoryGateway(TenantOperationDispatcher dispatcher):IOperationHandler<HistoryRequest,HistoryResult>
{public ValueTask<OperationResult<HistoryResult>> HandleAsync(HistoryRequest r,OperationContext c,CancellationToken t)=>dispatcher.DispatchAsync<HistoryRequest,HistoryResult>("history.read",r,c,t);}
public sealed class Gateways(TenantOperationDispatcher dispatcher,TenantReadSetDispatcher readSetDispatcher,BusinessState state):IOperationHandlerFactory
{
    public THandler Create<THandler>() where THandler:class=>(THandler)(object)(typeof(THandler)==typeof(ReadGateway)?new ReadGateway(dispatcher):
        typeof(THandler)==typeof(RbacGateway)?new RbacGateway(dispatcher):typeof(THandler)==typeof(AbacGateway)?new AbacGateway(dispatcher):
        typeof(THandler)==typeof(SwitchGateway)?new SwitchGateway(dispatcher):typeof(THandler)==typeof(ReadSetGateway)?new ReadSetGateway(readSetDispatcher,state):typeof(THandler)==typeof(UpdateGateway)?new UpdateGateway(dispatcher):typeof(THandler)==typeof(HistoryGateway)?new HistoryGateway(dispatcher):
        typeof(THandler)==typeof(EntityCreateGateway)?new EntityCreateGateway(dispatcher):typeof(THandler)==typeof(EntityUpdateGateway)?new EntityUpdateGateway(dispatcher):
        typeof(THandler)==typeof(EntityDeleteGateway)?new EntityDeleteGateway(dispatcher):typeof(THandler)==typeof(TrailHistoryGateway)?new TrailHistoryGateway(dispatcher):throw new InvalidOperationException("Unknown generated gateway."));
}

public sealed class Bridge(Host host):ITransportOperationDispatcher
{
    public ValueTask<OperationResult<TResponse>> DispatchAsync<TRequest,TResponse>(HttpContext http,string id,TRequest request,OperationContext context,CancellationToken token)
    {
        DocumentHandler Factory(){Interlocked.Increment(ref host.Business.Factories);return new(host.Business);}
        var builder=new TenantOperationRegistryBuilder().RegisterTenantSelection();
        foreach(var op in new[]{"document.read","document.rbac","document.abac","document.update"})
            builder.Register<DocumentRequest,DocumentResult>(op,op=="document.update"?"write":"read","document",r=>r with{},r=>new(new(r.Tenant),r.ResourceId),Factory);
        if(host.Audit is not null)builder.Register<HistoryRequest,HistoryResult>("history.read","read","audit-history",r=>r with{},r=>new(new(r.Tenant),"tenant"),()=>{Interlocked.Increment(ref host.Business.Factories);return new HistoryHandler(new(host.Audit),host.Business);});
        var trailProfile=host.TrailProfile;
        if(trailProfile is not null)
        {
            foreach(var operation in new[]{("entity.create","create"),("entity.update","update"),("entity.delete","delete")})
                builder.Register<EntityMutationRequest,EntityMutationResult>(operation.Item1,operation.Item2,"entity",r=>r with{},r=>new(new(r.Tenant),r.EntityId),()=>{Interlocked.Increment(ref trailProfile.MutationFactories);return new EntityMutationHandler(trailProfile,host.Trail,host.Observation);});
            if(host.Trail is not null)builder.Register<TrailHistoryRequest,TrailHistoryResult>("trail.history","read","audit-trail",r=>r with{},r=>new(new(r.Tenant),"tenant"),()=>{Interlocked.Increment(ref trailProfile.HistoryFactories);return new TrailHistoryHandler(trailProfile);});
        }
        var accessor=new FixedContextAccessor(http);
        IIdentitySource identitySource;
        if(host.CookieAuthentication)
        {
            IAuthenticatedTicketIdentityMapper mapper=new TicketPropertyIdentityMapper(JwtFixture.Issuer);
            if(host.Sessions is not null)mapper=new SessionBoundTicketIdentityMapper(mapper);
            identitySource=new AspNetCoreIdentitySource(accessor,host.IdentityScheme,mapper,host.Observation?.Clock);
        }
        else identitySource=host.Sessions is null?new AspNetCoreJwtIdentitySource(accessor,host.IdentityScheme)
            :new AspNetCoreJwtIdentitySource(accessor,host.IdentityScheme,host.Observation?.Clock,"sid");
        if(host.Sessions is not null)
        {
            if(host.Observation?.InnerLifetime is { } innerLifetime)identitySource=new SessionValidatingIdentitySource(identitySource,host.Sessions,innerLifetime,host.Observation.Clock);
            identitySource=new SessionValidatingIdentitySource(identitySource,host.Sessions,host.Observation?.Lifetime??TimeSpan.FromSeconds(30),host.Observation?.Clock);
        }
        var services=new TenantSecurityServices(identitySource,
            new([JwtFixture.Issuer],[host.IdentityScheme]),host.Authority!,host.Authority!,TimeSpan.FromSeconds(30),host.Policy,timeProvider:host.Observation?.Clock,audit:host.Audit is null?null:new(host.Audit));
        var dispatcher=new TenantOperationDispatcher(builder.Build(),services);var core=new OperationRegistryBuilder();
        Cehpalon.Engine.Generated.OperationRegistrations.RegisterAll(core,new Gateways(dispatcher,new(services,host.Authority!),host.Business));
        return new OperationDispatcher(core.Build()).DispatchAsync<TRequest,TResponse>(id,request,context,token);
    }
    // This request-owned adapter must not mutate ASP.NET's ambient static AsyncLocal holder.
    private sealed class FixedContextAccessor(HttpContext context):IHttpContextAccessor
    {public HttpContext? HttpContext{get;set;}=context;}
}

public sealed class Host:IAsyncDisposable
{
    public WebApplication? App;private ActivationLease? lease;
    public Authority? Authority;public RoleAttributeAccessPolicy? Policy;public MemoryAuditStore? Audit;
    public readonly BusinessState Business=new();public int SecurityFactories,AuditFactories,HostFactories,GraphQLServices,AuthenticationServices,KeyProviderCalls,DecryptionKeyProviderCalls,KeyRingProviderCalls,SessionFactoryCalls,SessionAuthenticationCallbacks;
    public AuditTrailFixture? TrailProfile{get;private set;}public TenantChangeAuditRecorder? Trail{get;private set;}public int TrailModuleFactories;
    public ObservationFixture? Observation{get;private set;}
    public IIdentitySessionStatusSource? Sessions{get;private set;}
    public string IdentityScheme{get;private set;}="Bearer";public bool CookieAuthentication{get;private set;}
    public Uri Address=>new(App!.Urls.Single());
    public async Task Start(TlsFixture tls,JwtFixture jwt,bool api=true,bool graphql=true,bool security=true,bool audit=true,bool publicEndpoint=false,JwtProfileFixture? jwtProfile=null,bool cookieAuthentication=false,JweFixture? jweProfile=null,KeyRingFixture? keyRingProfile=null,SessionFixture? sessionProfile=null,ObservationFixture? observationProfile=null,AuditTrailFixture? trailProfile=null)
    {
        if((jweProfile is not null?1:0)+(jwtProfile is not null?1:0)+(cookieAuthentication?1:0)+(keyRingProfile is not null?1:0)>1)throw new ArgumentException("Select exactly one fixture authentication profile.");
        TrailProfile=trailProfile;var trailEnabled=trailProfile is not null&&trailProfile.Mode!=TenantChangeAuditMode.Disabled;Observation=observationProfile;Business.Observation=observationProfile;CookieAuthentication=cookieAuthentication;IdentityScheme=cookieAuthentication?"fixture-cookie":"Bearer";
        var config=System.Text.Json.JsonSerializer.Serialize(new{Cehpalon=new{SchemaVersion=1,Architecture="Modular",Topology="SingleProcess",Pattern="RequestReply",Modules=new{
            api=new{Enabled=api},graphql=new{Enabled=graphql},security=new{Enabled=security},audit=new{Enabled=audit},trail=new{Enabled=trailEnabled},@public=new{Enabled=publicEndpoint}}}});
        var hostDependencies=new List<string>();if(api||graphql)hostDependencies.Add("security");if(audit)hostDependencies.Add("audit");if(trailEnabled)hostDependencies.Add("trail");
        var compiled=CompositionCompiler.Compile(config,[new("host",ModuleRole.Support,hostDependencies),new("api",ModuleRole.EntryPoint,["host","security"]),new("graphql",ModuleRole.EntryPoint,["host","security"]),
            new("public",ModuleRole.EntryPoint,["host"]),new("security",ModuleRole.Support),new("audit",ModuleRole.Support),new("trail",ModuleRole.Support,["security"])]);
        if(!compiled.IsSuccess)throw new ArgumentException("Invalid security composition.");
        lease=await PlanActivator.ActivateAsync(compiled.Plan!,[
            new("security",_=>{SecurityFactories++;if(sessionProfile is not null){SessionFactoryCalls++;Sessions=sessionProfile.Create();}Authority=new(){Observation=observationProfile};Policy=new(SecurityApi.Authority.Rules(),Authority,observationProfile?.Clock);return ValueTask.FromResult<IAsyncDisposable>(new Empty());}),
            new("trail",_=>{TrailModuleFactories++;Trail=TenantChangeAuditRecorder.Activate(trailProfile!.Policy,trailProfile.CreateSink,timeProvider:observationProfile?.Clock);return ValueTask.FromResult<IAsyncDisposable>(new Empty());}),
            new("audit",_=>{AuditFactories++;Audit=new(){Observation=observationProfile};return ValueTask.FromResult<IAsyncDisposable>(new Empty());}),
            new("api",_=>ValueTask.FromResult<IAsyncDisposable>(new Empty())),new("graphql",_=>ValueTask.FromResult<IAsyncDisposable>(new Empty())),new("public",_=>ValueTask.FromResult<IAsyncDisposable>(new Empty())),
            new("host",async token=>
            {
                HostFactories++;var builder=WebApplication.CreateSlimBuilder(new WebApplicationOptions{Args=[],EnvironmentName="Production"});builder.Logging.ClearProviders();
                builder.WebHost.ConfigureKestrel(k=>k.Listen(IPAddress.Loopback,0,l=>{l.Protocols=HttpProtocols.Http1;l.UseHttps(tls.Server);}));
                if(security)
                {
                    builder.Services.AddSingleton<ITransportOperationDispatcher>(new Bridge(this));
                    if(cookieAuthentication)
                    {
                        builder.Services.AddAuthentication(IdentityScheme).AddCookie(IdentityScheme,o=>{
                            o.Cookie.Name="cehpalon.fixture";o.Cookie.SecurePolicy=CookieSecurePolicy.Always;o.SlidingExpiration=false;
                            o.Events.OnRedirectToLogin=c=>{c.Response.StatusCode=StatusCodes.Status401Unauthorized;return Task.CompletedTask;};
                            o.Events.OnRedirectToAccessDenied=c=>{c.Response.StatusCode=StatusCodes.Status403Forbidden;return Task.CompletedTask;};});
                        builder.Services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
                    }
                    else
                    {
                        var settings=keyRingProfile?.Settings??jweProfile?.Settings??jwtProfile?.Settings??new JwtProfileSettings{Scheme=IdentityScheme,Issuer=JwtFixture.Issuer,Audience=JwtFixture.Audience,Algorithm="RS256",KeySource=JwtKeySource.PublicJwks};
                        var configBytes=System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new{Authentication=settings});
                        builder.Configuration.AddJsonStream(new MemoryStream(configBytes));
                        var profile=JwtAuthenticationProfile.FromConfiguration(builder.Configuration.GetSection("Authentication"));
                        var authentication=builder.Services.AddAuthentication(IdentityScheme);
                        if(keyRingProfile is not null)authentication.AddCehpalonJwtBearerKeyRing(()=>{KeyRingProviderCalls++;return keyRingProfile.CreateRing(profile);});
                        else if(profile.KeySource==JwtKeySource.PublicJwks)authentication.AddCehpalonJwtBearer(profile,
                            publicJwks:()=>{KeyProviderCalls++;return jwtProfile is null?jwt.PublicJwks():jwtProfile.PublicJwks();},
                            decryptionKeys:jweProfile is null?null:()=>{DecryptionKeyProviderCalls++;return [jweProfile.DecryptionKey];});
                        else authentication.AddCehpalonJwtBearer(profile,providedKeys:()=>{KeyProviderCalls++;return [jwtProfile!.VerificationKey];});
                    }
                    if(sessionProfile is not null&&!cookieAuthentication)builder.Services.PostConfigure<JwtBearerOptions>(IdentityScheme,options=>
                    {
                        var previous=options.Events.OnTokenValidated;
                        options.Events.OnTokenValidated=async context=>{Interlocked.Increment(ref SessionAuthenticationCallbacks);await previous(context);};
                    });
                    builder.Services.AddAuthorization();
                }
                if(graphql)
                {
                    var catalog=new GraphQLOperationCatalog.Builder().AddQuery("readSet",Bindings.ReadSet).AddQuery("document",Bindings.Read).AddQuery("rbac",Bindings.Rbac).AddQuery("abac",Bindings.Abac).AddMutation("updateDocument",Bindings.Update).AddMutation("selectTenant",Bindings.Switch);
                    if(audit)catalog.AddQuery("history",Bindings.History);
                    if(trailProfile is not null){catalog.AddMutation("createEntity",Bindings.CreateEntity).AddMutation("updateEntity",Bindings.UpdateEntity).AddMutation("deleteEntity",Bindings.DeleteEntity);if(trailEnabled)catalog.AddQuery("trailHistory",Bindings.TrailHistory);}
                    builder.Services.AddCehpalonGraphQL(catalog.Build());
                }
                GraphQLServices=builder.Services.Count(s=>(s.ServiceType.FullName??"").StartsWith("HotChocolate.",StringComparison.Ordinal));
                AuthenticationServices=builder.Services.Count(s=>(s.ServiceType.FullName??"").StartsWith("Microsoft.AspNetCore.Authentication.",StringComparison.Ordinal));
                var app=builder.Build();App=app;
                try
                {
                    if(security){app.UseAuthentication();app.UseAuthorization();}
                    if(publicEndpoint)app.MapGet("/health",()=>Results.Ok(new{status="ok"}));
                    if(api){app.MapOperation("/tenant/select",Bindings.Switch);app.MapOperation("/document/read-all",Bindings.ReadSet);app.MapOperation("/document/read",Bindings.Read);app.MapOperation("/document/rbac",Bindings.Rbac);app.MapOperation("/document/abac",Bindings.Abac);app.MapOperation("/document/update",Bindings.Update);if(audit)app.MapOperation("/history",Bindings.History);}
                    if(api&&trailProfile is not null){app.MapOperation("/entity/create",Bindings.CreateEntity);app.MapOperation("/entity/update",Bindings.UpdateEntity);app.MapOperation("/entity/delete",Bindings.DeleteEntity);if(trailEnabled)app.MapOperation("/trail/history",Bindings.TrailHistory);}
                    if(graphql)app.MapCehpalonGraphQL();await app.StartAsync(token);return new HostLease(app);
                }
                catch{await app.DisposeAsync();throw;}
            })]);
    }
    // Fixture-only cookie creation uses the real handler ticket format and an ephemeral provider.
    // No login endpoint, password flow, persisted key ring or account-management claim is introduced.
    public string FixtureCookie(string subject="alice",bool expired=false,string? sessionId=null)
    {
        if(!CookieAuthentication)throw new InvalidOperationException("Cookie fixture is not selected.");
        var now=DateTimeOffset.UtcNow;
        var properties=new AuthenticationProperties{IssuedUtc=now.AddMinutes(-5),ExpiresUtc=expired?now.AddMinutes(-1):now.AddMinutes(5)};
        var claims=new List<Claim>{new(ClaimTypes.NameIdentifier,subject)};if(sessionId is not null)claims.Add(new("sid",sessionId));
        var principal=new ClaimsPrincipal(new ClaimsIdentity(claims,IdentityScheme));
        var format=App!.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(IdentityScheme).TicketDataFormat;
        return "cehpalon.fixture="+format.Protect(new AuthenticationTicket(principal,properties,IdentityScheme));
    }
    public async ValueTask DisposeAsync(){if(lease is not null)await lease.DisposeAsync();}
    private sealed class Empty:IAsyncDisposable{public ValueTask DisposeAsync()=>ValueTask.CompletedTask;}
    private sealed class HostLease(WebApplication app):IAsyncDisposable{public async ValueTask DisposeAsync(){await app.StopAsync();await app.DisposeAsync();}}
}
