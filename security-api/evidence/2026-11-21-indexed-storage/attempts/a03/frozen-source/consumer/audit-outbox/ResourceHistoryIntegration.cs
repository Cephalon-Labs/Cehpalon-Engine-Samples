using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;

namespace AuditOutbox;

public sealed record ResourceHistoryRequest(string Tenant,TenantChangeAuditResourceQuery Query);
public sealed record ResourceHistoryResult(string Tenant,TenantChangeAuditResourcePage Page);
public sealed class ResourceHistoryAuthority(TimeProvider clock):IIdentitySource,ITenantMembershipSource,IResourceScopeSource,ITenantAccessPolicy
{
    public bool Active=true,AllowHistory=true,AllowB;public string GrantedOperation="trail.resource-history",GrantedAction="read",GrantedKind="audit-trail";public int IdentityLookups,PolicyLookups;
    public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken token)
    {token.ThrowIfCancellationRequested();Interlocked.Increment(ref IdentityLookups);var now=clock.GetUtcNow();return ValueTask.FromResult<IdentitySnapshot?>(Active?new(new("owned-resource-history-authority","resource-history-service"),"fixture-service",now.AddMinutes(-1),now.AddMinutes(1)):null);}
    public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot identity,TenantId tenant,CancellationToken token)
    {token.ThrowIfCancellationRequested();var now=clock.GetUtcNow();return ValueTask.FromResult<TenantMembershipSnapshot?>(tenant.Value=="A"||AllowB&&tenant.Value=="B"?new(identity.Principal,tenant,true,now.AddMinutes(-1),now.AddMinutes(1),"resource-history-membership"):null);}
    public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId tenant,string kind,string id,CancellationToken token)
    {token.ThrowIfCancellationRequested();return ValueTask.FromResult<ResourceScopeSnapshot?>(new(tenant,kind,id,"resource-history-grant"));}
    public ValueTask<bool> IsAllowedAsync(TenantAccessRequest request,CancellationToken token)
    {token.ThrowIfCancellationRequested();Interlocked.Increment(ref PolicyLookups);return ValueTask.FromResult(AllowHistory&&request.OperationId==GrantedOperation&&request.Action==GrantedAction&&request.Resource.Kind==GrantedKind&&request.Resource.ResourceId=="tenant");}
}
// Existing mutation hosts retain Composition. This is generated Core + checked tenant query dispatch only.
public sealed class ResourceHistoryHost
{
    public ResourceHistoryAuthority Authority{get;}public int GatewayFactories,HandlerFactories,ReaderResults;public TenantOperationContext? RetainedContext;
    private readonly TenantChangeAuditResourceHistoryReader reader;private readonly OperationDispatcher dispatcher;
    public static ResourceHistoryHost? Activate(TenantChangeAuditPolicy policy,Func<ITenantChangeAuditResourceHistorySource>? sourceFactory=null,TimeProvider? clock=null)
    {var reader=TenantChangeAuditResourceHistoryReader.Activate(policy,sourceFactory);return reader is null?null:new(reader,clock:clock);}
    public ResourceHistoryHost(TenantChangeAuditResourceHistoryReader reader,string action="read",string kind="audit-trail",TimeProvider? clock=null)
    {
        this.reader=reader;clock??=TimeProvider.System;Authority=new(clock){GrantedAction=action,GrantedKind=kind};var registry=new TenantOperationRegistryBuilder().Register<ResourceHistoryRequest,ResourceHistoryResult>("trail.resource-history",action,kind,r=>r with{},r=>new(new(r.Tenant),"tenant"),()=>{Interlocked.Increment(ref HandlerFactories);return new Handler(this);}).Build();
        var security=new TenantSecurityServices(Authority,new(["owned-resource-history-authority"],["fixture-service"]),Authority,Authority,TimeSpan.FromSeconds(30),Authority,clock);var tenant=new TenantOperationDispatcher(registry,security);var core=new OperationRegistryBuilder();Cehpalon.Engine.Generated.OperationRegistrations.RegisterAll(core,new Factory(this,tenant));dispatcher=new(core.Build());
    }
    public ValueTask<OperationResult<ResourceHistoryResult>> Run(TenantChangeAuditResourceQuery query,string tenant="A",CancellationToken token=default)=>dispatcher.DispatchAsync<ResourceHistoryRequest,ResourceHistoryResult>("trail.resource-history",new(tenant,query),new("owned-resource-history"),token);
    private sealed class Handler(ResourceHistoryHost owner):ITenantOperationHandler<ResourceHistoryRequest,ResourceHistoryResult>
    {
        public async ValueTask<OperationResult<ResourceHistoryResult>> HandleAsync(ResourceHistoryRequest request,TenantOperationContext context,CancellationToken token)
        {owner.RetainedContext=context;var page=await owner.reader.ReadAsync(context,request.Query,token);Interlocked.Increment(ref owner.ReaderResults);return OperationResult<ResourceHistoryResult>.Success(new(context.Tenant.Value,page));}
    }
    private sealed class Factory(ResourceHistoryHost owner,TenantOperationDispatcher tenant):IOperationHandlerFactory
    {
        public THandler Create<THandler>() where THandler:class
        {if(typeof(THandler)!=typeof(ResourceHistoryGateway))throw new InvalidOperationException("Only selected resource history gateway may be created.");Interlocked.Increment(ref owner.GatewayFactories);return(THandler)(object)new ResourceHistoryGateway(tenant);}
    }
}
[Operation("trail.resource-history")]
public sealed class ResourceHistoryGateway(TenantOperationDispatcher dispatcher):IOperationHandler<ResourceHistoryRequest,ResourceHistoryResult>
{
    public ValueTask<OperationResult<ResourceHistoryResult>> HandleAsync(ResourceHistoryRequest request,OperationContext context,CancellationToken token)=>dispatcher.DispatchAsync<ResourceHistoryRequest,ResourceHistoryResult>("trail.resource-history",request,context,token);
}
