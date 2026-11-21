extern alias securityapi;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;
using securityapi::SecurityApi;

namespace AuditOutbox;

public sealed class OutboxIntegration(PostgresStore store,TenantChangeAuditPolicy policy):IEntityTrailIntegration
{
    private readonly TenantChangeAuditPolicy capturePolicy=policy;
    public int Activations,ProviderFactories,HandlerFactories,Mutations,Values,Results;
    public bool ThrowAfterMutation,WrongReceipt,WrongSessionTenant,ThrowValues;
    public Func<TenantOperationContext,Task>? AfterMutation;
    public CancellationTokenSource? CallerCancellation;
    public TenantChangeAuditTransactionException? LastException;
    public TenantChangeAuditOutboxExecutor<DomainSession>? Executor;
    public TenantOperationContext? RetainedWriterContext;
    public static TenantChangeAuditPolicy Policy(TenantChangeAuditMode mode)=>new(mode,[new("entity.update","update","entity",[new("title"),new("amount"),new("secret",true)])]);
    public void Activate(TenantOperationRegistry registry)
    {
        Activations++;Executor=TenantChangeAuditOutboxExecutor<DomainSession>.ActivateValidated(capturePolicy,registry,["entity.update"],()=>{ProviderFactories++;return store;});
    }
    public ITenantOperationHandler<EntityMutationRequest,EntityMutationResult> CreateHandler(){HandlerFactories++;return new Handler(this,store);}
    public TenantChangeAuditPolicy HistoryPolicy=policy;
    public ITenantOperationHandler<TrailHistoryRequest,TrailHistoryResult> CreateHistoryHandler()=>new PgHistoryHandler(store,HistoryPolicy);
    private sealed class Handler(OutboxIntegration owner,PostgresStore store):ITenantOperationHandler<EntityMutationRequest,EntityMutationResult>
    {
        public async ValueTask<OperationResult<EntityMutationResult>> HandleAsync(EntityMutationRequest request,TenantOperationContext context,CancellationToken token)
        {
            context.DemandAccess(new(request.Tenant),"entity",request.EntityId,context.Action);token.ThrowIfCancellationRequested();
            if(context.OperationId!="entity.update")return OperationResult<EntityMutationResult>.Failure(new("sample.update_only","This provider proof supports updates only."));
            owner.RetainedWriterContext=context;
            using var linked=owner.CallerCancellation is null?null:CancellationTokenSource.CreateLinkedTokenSource(token,owner.CallerCancellation.Token);
            var callerToken=linked?.Token??token;
            try
            {
                if(owner.Executor is null)
                {
                    await using var tx=await store.BeginAsync(context.Tenant,token);
                    var row=await tx.Session.Change(context.Tenant,request.EntityId,request.Title,request.Amount,request.Secret,token);await tx.CommitAsync(token);
                    return OperationResult<EntityMutationResult>.Success(new(context.Tenant.Value,request.EntityId,row.After.Revision.ToString()));
                }
                var result=await owner.Executor.ExecuteAsync<EntityMutationResult>(context,async(session,ct)=>
                {
                    var row=await session.Change(owner.WrongSessionTenant?new("B"):context.Tenant,request.EntityId,request.Title,request.Amount,request.Secret,ct);
                    owner.Mutations++;if(owner.AfterMutation is not null)await owner.AfterMutation(context);
                    if(owner.ThrowAfterMutation)throw new IOException("Controlled callback failure after SQL mutation.");
                    var receipt=new TenantChangeReceipt(Guid.NewGuid(),context.Identity.Principal,context.Identity.AuthenticationScheme,context.Tenant,context.OperationId,context.Action,
                        context.Resource.Kind,context.Resource.ResourceId,owner.WrongReceipt?"wrong-authorization-version":context.Resource.Version,TenantChangeKind.Update,
                        row.Before.Revision.ToString(),row.After.Revision.ToString(),DateTimeOffset.UtcNow);
                    TenantChangeState State(DomainRow d)=>new([new("title",TenantChangeValue.Text(d.Title)),new("amount",TenantChangeValue.Number(d.Amount)),new("secret",TenantChangeValue.Text(d.Secret))]);
                    return new(receipt,new(context.Tenant.Value,request.EntityId,row.After.Revision.ToString()),()=>{owner.Values++;if(owner.ThrowValues)throw new IOException("Controlled state projection failure.");return new(State(row.Before),State(row.After));});
                },callerToken);
                owner.Results++;return OperationResult<EntityMutationResult>.Success(result);
            }
            catch(TenantChangeAuditTransactionException error)
            {
                owner.LastException=error;return OperationResult<EntityMutationResult>.Failure(new("audit_outbox."+error.Outcome.ToString().ToLowerInvariant(),"The audit transaction did not release a successful result; inspect its recorded outcome before retrying."));
            }
        }
    }
}

public sealed class PgHistoryHandler(PostgresStore store,TenantChangeAuditPolicy policy):ITenantOperationHandler<TrailHistoryRequest,TrailHistoryResult>
{
    public async ValueTask<OperationResult<TrailHistoryResult>> HandleAsync(TrailHistoryRequest request,TenantOperationContext context,CancellationToken token)
    {
        var page=await new TenantChangeAuditHistoryReader(store,policy).ReadAsync(context,request.Limit,request.Cursor,token);
        TrailValueResult Value(TenantChangeValue value)=>new(value.Kind.ToString(),value.TextValue,value.DecimalValue?.ToString(System.Globalization.CultureInfo.InvariantCulture),value.BooleanValue);
        var rows=page.Entries.Select(r=>new TrailChangeResult(r.Receipt.ReceiptId.ToString("D"),r.RecordedAtUtc.ToString("O"),r.Receipt.ReportedAtUtc?.ToString("O"),r.Receipt.Principal.Issuer,r.Receipt.Principal.Subject,r.Receipt.AuthenticationScheme,r.Receipt.Tenant.Value,r.Receipt.OperationId,r.Receipt.Action,r.Receipt.ResourceId,
            r.Receipt.AuthorizationResourceVersion,r.Receipt.BeforeEntityVersion,r.Receipt.AfterEntityVersion,r.Receipt.Kind.ToString(),r.Mode.ToString(),r.CapturedMode.ToString(),r.Fields.Select(f=>new TrailFieldResult(f.Name,Value(f.Before),Value(f.After),f.WasChanged)).ToArray())).ToArray();
        return OperationResult<TrailHistoryResult>.Success(new(context.Tenant.Value,rows,page.NextCursor));
    }
}

public sealed record RelayRequest(string Tenant,int Maximum=128);
public sealed record RelayResult(int Acknowledged);

// The relay's configured authority is resolved afresh for every dispatch, not copied from the writer.
public sealed class RelayAuthority:IIdentitySource,ITenantMembershipSource,IResourceScopeSource,ITenantAccessPolicy
{
    public bool Active=true,AllowRelay=true,AllowB;public int IdentityLookups,PolicyLookups;
    public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken token)
    {token.ThrowIfCancellationRequested();IdentityLookups++;return ValueTask.FromResult<IdentitySnapshot?>(Active?new(new("owned-relay-authority","audit-relay-service"),"fixture-service",DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddMinutes(1)):null);}
    public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot identity,TenantId tenant,CancellationToken token)
    {token.ThrowIfCancellationRequested();return ValueTask.FromResult<TenantMembershipSnapshot?>(tenant.Value=="A"||AllowB&&tenant.Value=="B"?new(identity.Principal,tenant,true,DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddMinutes(1),"relay-membership"):null);}
    public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId tenant,string kind,string id,CancellationToken token)
    {token.ThrowIfCancellationRequested();return ValueTask.FromResult<ResourceScopeSnapshot?>(new(tenant,kind,id,"relay-resource"));}
    public ValueTask<bool> IsAllowedAsync(TenantAccessRequest request,CancellationToken token)
    {token.ThrowIfCancellationRequested();PolicyLookups++;return ValueTask.FromResult(AllowRelay&&request.OperationId=="outbox.relay"&&request.Action=="relay"&&request.Resource.Kind=="audit-outbox"&&request.Resource.ResourceId=="tenant");}
}
public sealed class RelayHost
{
    public RelayAuthority Authority{get;}=new();public TenantOperationContext? RetainedContext;public TenantChangeAuditOutboxRelayException? LastException;
    public TenantChangeAuditOutboxRelay? Relay;private readonly OperationDispatcher dispatcher;
    public RelayHost(TenantChangeAuditOutboxRelay? relay)
    {
        Relay=relay;var registry=new TenantOperationRegistryBuilder().Register<RelayRequest,RelayResult>("outbox.relay","relay","audit-outbox",r=>r with{},r=>new(new(r.Tenant),"tenant"),()=>new Handler(this)).Build();
        var security=new TenantSecurityServices(Authority,new(["owned-relay-authority"],["fixture-service"]),Authority,Authority,TimeSpan.FromSeconds(30),Authority);
        var tenant=new TenantOperationDispatcher(registry,security);var core=new OperationRegistryBuilder();
        Cehpalon.Engine.Generated.OperationRegistrations.RegisterAll(core,new Factory(tenant));dispatcher=new(core.Build());
    }
    public ValueTask<OperationResult<RelayResult>> Run(string tenant="A",int maximum=128,CancellationToken token=default)
        =>dispatcher.DispatchAsync<RelayRequest,RelayResult>("outbox.relay",new(tenant,maximum),new("owned-relay"),token);
    private sealed class Handler(RelayHost owner):ITenantOperationHandler<RelayRequest,RelayResult>
    {
        public async ValueTask<OperationResult<RelayResult>> HandleAsync(RelayRequest request,TenantOperationContext context,CancellationToken token)
        {
            owner.RetainedContext=context;
            try{return OperationResult<RelayResult>.Success(new(owner.Relay is null?0:await owner.Relay.RelayAsync(context,request.Maximum,token)));}
            catch(TenantChangeAuditOutboxRelayException error){owner.LastException=error;throw;}
        }
    }
    private sealed class Factory(TenantOperationDispatcher dispatcher):IOperationHandlerFactory
    {
        public THandler Create<THandler>() where THandler:class
            =>(THandler)(object)(typeof(THandler)==typeof(RelayGateway)?(object)new RelayGateway(dispatcher):typeof(THandler)==typeof(StatusGateway)?new StatusGateway(dispatcher):throw new InvalidOperationException("Unknown generated gateway."));
    }
}
[Operation("outbox.relay")]
public sealed class RelayGateway(TenantOperationDispatcher dispatcher):IOperationHandler<RelayRequest,RelayResult>
{
    public ValueTask<OperationResult<RelayResult>> HandleAsync(RelayRequest request,OperationContext context,CancellationToken token)
        =>dispatcher.DispatchAsync<RelayRequest,RelayResult>("outbox.relay",request,context,token);
}
