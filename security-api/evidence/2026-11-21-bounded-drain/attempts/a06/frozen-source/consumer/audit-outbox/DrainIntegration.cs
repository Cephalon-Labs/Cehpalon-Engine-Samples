using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;

namespace AuditOutbox;

public sealed record DrainRequest(string Tenant,int MaximumBatches=16,int MaximumRecords=2048,int MaximumPerBatch=128);

// A separately granted service operation; ordinary relay/status grants do not activate this handler.
public sealed class DrainAuthority(TimeProvider clock):IIdentitySource,ITenantMembershipSource,IResourceScopeSource,ITenantAccessPolicy
{
    public bool Active=true,AllowDrain=true,AllowB;public string GrantedOperation="outbox.drain";public int IdentityLookups,PolicyLookups;
    public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken token)
    {token.ThrowIfCancellationRequested();IdentityLookups++;var now=clock.GetUtcNow();return ValueTask.FromResult<IdentitySnapshot?>(Active?new(new("owned-drain-authority","audit-drain-service"),"fixture-service",now.AddMinutes(-1),now.AddMinutes(1)):null);}
    public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot identity,TenantId tenant,CancellationToken token)
    {token.ThrowIfCancellationRequested();var now=clock.GetUtcNow();return ValueTask.FromResult<TenantMembershipSnapshot?>(tenant.Value=="A"||AllowB&&tenant.Value=="B"?new(identity.Principal,tenant,true,now.AddMinutes(-1),now.AddMinutes(1),"drain-membership"):null);}
    public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId tenant,string kind,string id,CancellationToken token)
    {token.ThrowIfCancellationRequested();return ValueTask.FromResult<ResourceScopeSnapshot?>(new(tenant,kind,id,"drain-resource"));}
    public ValueTask<bool> IsAllowedAsync(TenantAccessRequest request,CancellationToken token)
    {token.ThrowIfCancellationRequested();PolicyLookups++;return ValueTask.FromResult(AllowDrain&&request.OperationId==GrantedOperation&&request.Action=="relay"&&request.Resource.Kind=="audit-outbox"&&request.Resource.ResourceId=="tenant");}
}
public sealed class DrainHost
{
    public DrainAuthority Authority{get;}public int HandlerFactories,GatewayFactories;public TenantOperationContext? RetainedContext;public TenantChangeAuditOutboxDrainException? LastException;
    private readonly TenantChangeAuditOutboxRelay relay;private readonly OperationDispatcher dispatcher;
    public static DrainHost? Activate(bool enabled,Func<TenantChangeAuditOutboxRelay>? relayFactory=null,TimeProvider? clock=null)
    {if(!enabled)return null;ArgumentNullException.ThrowIfNull(relayFactory);return new(relayFactory(),clock);}
    public DrainHost(TenantChangeAuditOutboxRelay relay,TimeProvider? clock=null)
    {
        this.relay=relay??throw new ArgumentNullException(nameof(relay));clock??=TimeProvider.System;Authority=new(clock);
        var registry=new TenantOperationRegistryBuilder().Register<DrainRequest,TenantChangeAuditOutboxDrainResult>("outbox.drain","relay","audit-outbox",r=>r with{},r=>new(new(r.Tenant),"tenant"),()=>{HandlerFactories++;return new Handler(this);}).Build();
        var security=new TenantSecurityServices(Authority,new(["owned-drain-authority"],["fixture-service"]),Authority,Authority,TimeSpan.FromSeconds(30),Authority,clock);
        var tenant=new TenantOperationDispatcher(registry,security);var core=new OperationRegistryBuilder();
        Cehpalon.Engine.Generated.OperationRegistrations.RegisterAll(core,new Factory(this,tenant));dispatcher=new(core.Build());
    }
    public ValueTask<OperationResult<TenantChangeAuditOutboxDrainResult>> Run(string tenant="A",int batches=16,int records=2048,int perBatch=128,CancellationToken token=default)
        =>dispatcher.DispatchAsync<DrainRequest,TenantChangeAuditOutboxDrainResult>("outbox.drain",new(tenant,batches,records,perBatch),new("owned-drain"),token);
    private sealed class Handler(DrainHost owner):ITenantOperationHandler<DrainRequest,TenantChangeAuditOutboxDrainResult>
    {
        public async ValueTask<OperationResult<TenantChangeAuditOutboxDrainResult>> HandleAsync(DrainRequest request,TenantOperationContext context,CancellationToken token)
        {
            owner.RetainedContext=context;
            try{return OperationResult<TenantChangeAuditOutboxDrainResult>.Success(await owner.relay.DrainAsync(context,request.MaximumBatches,request.MaximumRecords,request.MaximumPerBatch,token));}
            catch(TenantChangeAuditOutboxDrainException error){owner.LastException=error;throw;}
        }
    }
    private sealed class Factory(DrainHost owner,TenantOperationDispatcher tenant):IOperationHandlerFactory
    {
        public THandler Create<THandler>() where THandler:class
        {if(typeof(THandler)!=typeof(DrainGateway))throw new InvalidOperationException("Only the selected drain gateway may be created.");owner.GatewayFactories++;return(THandler)(object)new DrainGateway(tenant);}
    }
}
[Operation("outbox.drain")]
public sealed class DrainGateway(TenantOperationDispatcher dispatcher):IOperationHandler<DrainRequest,TenantChangeAuditOutboxDrainResult>
{
    public ValueTask<OperationResult<TenantChangeAuditOutboxDrainResult>> HandleAsync(DrainRequest request,OperationContext context,CancellationToken token)
        =>dispatcher.DispatchAsync<DrainRequest,TenantChangeAuditOutboxDrainResult>("outbox.drain",request,context,token);
}
