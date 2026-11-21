using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;

namespace AuditOutbox;

public sealed record LookupRequest(string Tenant,Guid ReceiptId);
public sealed record LookupResult(string Tenant,TenantChangeAuditRecord? Record);
public sealed class LookupAuthority(TimeProvider clock):IIdentitySource,ITenantMembershipSource,IResourceScopeSource,ITenantAccessPolicy
{
    public bool Active=true,AllowLookup=true,AllowB;public string GrantedOperation="trail.lookup",GrantedAction="read",GrantedKind="audit-trail";public int IdentityLookups,PolicyLookups;
    public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken token)
    {token.ThrowIfCancellationRequested();Interlocked.Increment(ref IdentityLookups);var now=clock.GetUtcNow();return ValueTask.FromResult<IdentitySnapshot?>(Active?new(new("owned-lookup-authority","audit-lookup-service"),"fixture-service",now.AddMinutes(-1),now.AddMinutes(1)):null);}
    public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot identity,TenantId tenant,CancellationToken token)
    {token.ThrowIfCancellationRequested();var now=clock.GetUtcNow();return ValueTask.FromResult<TenantMembershipSnapshot?>(tenant.Value=="A"||AllowB&&tenant.Value=="B"?new(identity.Principal,tenant,true,now.AddMinutes(-1),now.AddMinutes(1),"lookup-membership"):null);}
    public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId tenant,string kind,string id,CancellationToken token)
    {token.ThrowIfCancellationRequested();return ValueTask.FromResult<ResourceScopeSnapshot?>(new(tenant,kind,id,"lookup-resource"));}
    public ValueTask<bool> IsAllowedAsync(TenantAccessRequest request,CancellationToken token)
    {token.ThrowIfCancellationRequested();Interlocked.Increment(ref PolicyLookups);return ValueTask.FromResult(AllowLookup&&request.OperationId==GrantedOperation&&request.Action==GrantedAction&&request.Resource.Kind==GrantedKind&&request.Resource.ResourceId=="tenant");}
}
// Its extra operation grant is sample policy. The portable reader requires a live audit-trail/tenant/read scope.
public sealed class LookupHost
{
    public LookupAuthority Authority{get;}public int GatewayFactories,HandlerFactories,ReaderResults;public TenantOperationContext? RetainedContext;
    private readonly TenantChangeAuditLookupReader reader;private readonly OperationDispatcher dispatcher;
    public static LookupHost? Activate(TenantChangeAuditPolicy policy,Func<ITenantChangeAuditLookupSource>? sourceFactory=null,TimeProvider? clock=null)
    {var reader=TenantChangeAuditLookupReader.Activate(policy,sourceFactory);return reader is null?null:new(reader,clock:clock);}
    public LookupHost(TenantChangeAuditLookupReader reader,string action="read",string kind="audit-trail",TimeProvider? clock=null)
    {
        this.reader=reader;clock??=TimeProvider.System;Authority=new(clock){GrantedAction=action,GrantedKind=kind};
        var registry=new TenantOperationRegistryBuilder().Register<LookupRequest,LookupResult>("trail.lookup",action,kind,r=>r with{},r=>new(new(r.Tenant),"tenant"),()=>{Interlocked.Increment(ref HandlerFactories);return new Handler(this);}).Build();
        var security=new TenantSecurityServices(Authority,new(["owned-lookup-authority"],["fixture-service"]),Authority,Authority,TimeSpan.FromSeconds(30),Authority,clock);var tenant=new TenantOperationDispatcher(registry,security);var core=new OperationRegistryBuilder();
        Cehpalon.Engine.Generated.OperationRegistrations.RegisterAll(core,new Factory(this,tenant));dispatcher=new(core.Build());
    }
    public ValueTask<OperationResult<LookupResult>> Run(Guid receiptId,string tenant="A",CancellationToken token=default)
        =>dispatcher.DispatchAsync<LookupRequest,LookupResult>("trail.lookup",new(tenant,receiptId),new("owned-lookup"),token);
    private sealed class Handler(LookupHost owner):ITenantOperationHandler<LookupRequest,LookupResult>
    {
        public async ValueTask<OperationResult<LookupResult>> HandleAsync(LookupRequest request,TenantOperationContext context,CancellationToken token)
        {owner.RetainedContext=context;var record=await owner.reader.FindAsync(context,request.ReceiptId,token);Interlocked.Increment(ref owner.ReaderResults);return OperationResult<LookupResult>.Success(new(context.Tenant.Value,record));}
    }
    private sealed class Factory(LookupHost owner,TenantOperationDispatcher tenant):IOperationHandlerFactory
    {
        public THandler Create<THandler>() where THandler:class
        {if(typeof(THandler)!=typeof(LookupGateway))throw new InvalidOperationException("Only selected lookup gateway may be created.");Interlocked.Increment(ref owner.GatewayFactories);return(THandler)(object)new LookupGateway(tenant);}
    }
}
[Operation("trail.lookup")]
public sealed class LookupGateway(TenantOperationDispatcher dispatcher):IOperationHandler<LookupRequest,LookupResult>
{
    public ValueTask<OperationResult<LookupResult>> HandleAsync(LookupRequest request,OperationContext context,CancellationToken token)
        =>dispatcher.DispatchAsync<LookupRequest,LookupResult>("trail.lookup",request,context,token);
}
