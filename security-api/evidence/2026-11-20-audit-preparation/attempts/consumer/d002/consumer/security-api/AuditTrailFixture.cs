using System.Globalization;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;

namespace SecurityApi;

public sealed record EntityMutationRequest(string Tenant,string EntityId,string Title,decimal Amount,string Secret);
public sealed record EntityMutationResult(string Tenant,string EntityId,string? EntityVersion);
public sealed record TrailHistoryRequest(string Tenant,int Limit=50,string? Cursor=null);
public sealed record TrailValueResult(string Kind,string? Text,string? Number,bool? Boolean);
public sealed record TrailFieldResult(string Name,TrailValueResult Before,TrailValueResult After,bool WasChanged);
public sealed record TrailChangeResult(string ReceiptId,string RecordedAtUtc,string? ReportedAtUtc,string PrincipalIssuer,string PrincipalSubject,string AuthenticationScheme,string Tenant,string OperationId,string Action,string EntityId,string AuthorizationResourceVersion,string? BeforeEntityVersion,string? AfterEntityVersion,string Kind,string Mode,string CapturedMode,TrailFieldResult[] Fields);
public sealed record TrailHistoryResult(string Tenant,TrailChangeResult[] Entries,string? NextCursor);

/// <summary>Plain per-project control/business fixture, distinct from the optional audit sink it creates.</summary>
public sealed class AuditTrailFixture
{
    private readonly object gate=new();private readonly Dictionary<(string Tenant,string Entity),DomainEntity> entities=[];
    public AuditTrailFixture(TenantChangeAuditMode mode)
    {
        Mode=mode;Policy=BuildPolicy(mode);HistoryPolicy=Policy;
        entities.Add(("A","shared"),new("initial-A",1m,"domain-secret-A",0));entities.Add(("B","shared"),new("initial-B",1m,"domain-secret-B",0));
    }
    public TenantChangeAuditMode Mode{get;}
    public TenantChangeAuditPolicy Policy{get;}
    public TenantChangeAuditPolicy HistoryPolicy{get;set;}
    public MemoryTrailStore? Store{get;private set;}
    public int FactoryCalls,ProviderConstructors,ValueFactoryCalls,MutationFactories,MutationDisposals,HistoryFactories,HistoryDisposals,AppendCalls;
    public Func<TenantChangeAuditRecord,CancellationToken,Task>? AppendGate;
    public bool FailSinkCreation,FailValues,WrongReceiptVersion;
    public static TenantChangeAuditPolicy BuildPolicy(TenantChangeAuditMode mode,bool titleOnly=false,bool redactTitle=false,bool noRules=false)
    {
        TenantChangeFieldRule[] fields=titleOnly?[new("title",redactTitle)]:[new("title"),new("amount"),new("enabled"),new("category"),new("notes"),new("secret",true)];
        return new(mode,noRules?[]:[new("entity.create","create","entity",fields),new("entity.update","update","entity",fields),new("entity.delete","delete","entity",fields)]);
    }
    public ITenantChangeAuditSink CreateSink()
    {
        Interlocked.Increment(ref FactoryCalls);if(FailSinkCreation)throw new IOException("Controlled trail sink startup failure.");
        if(Store is not null)throw new InvalidOperationException("Trail sink may activate only once.");return Store=new(this);
    }
    public int Revision(string tenant,string entity="shared"){lock(gate)return entities.TryGetValue((tenant,entity),out var value)?value.Revision:-1;}
    public string? Title(string tenant,string entity="shared"){lock(gate)return entities.TryGetValue((tenant,entity),out var value)?value.Title:null;}
    public (DomainEntity? Before,DomainEntity? After) Mutate(string tenant,string entity,string action,string title,decimal amount,string secret)
    {
        lock(gate)
        {
            entities.TryGetValue((tenant,entity),out var before);
            if(action=="create"&&before is not null||action!="create"&&before is null)throw new InvalidOperationException("Controlled domain entity precondition failed.");
            DomainEntity? after=action=="delete"?null:new(title,amount,secret,(before?.Revision??0)+1);
            if(after is null)entities.Remove((tenant,entity));else entities[(tenant,entity)]=after;
            return(before,after);
        }
    }
    public TenantChangeStates Values(DomainEntity? before,DomainEntity? after)
    {
        Interlocked.Increment(ref ValueFactoryCalls);if(FailValues)throw new InvalidOperationException("Field-value factory should remain lazy for this mode.");
        TenantChangeState State(DomainEntity? value)=>value is null?TenantChangeState.Empty:new(new Dictionary<string,TenantChangeValue>(StringComparer.Ordinal){
            ["title"]=TenantChangeValue.Text(value.Title),["amount"]=TenantChangeValue.Number(value.Amount),["enabled"]=TenantChangeValue.Boolean(true),
            ["category"]=TenantChangeValue.Text("stable"),["notes"]=TenantChangeValue.Null,["secret"]=TenantChangeValue.Text(value.Secret),["internal"]=TenantChangeValue.Text("unallowlisted-domain-internal")});
        return new(State(before),State(after));
    }
    public sealed record DomainEntity(string Title,decimal Amount,string Secret,int Revision){public string Version=>"entity-v"+Revision.ToString(CultureInfo.InvariantCulture);}
    public sealed class MemoryTrailStore:ITenantChangeAuditSink,ITenantChangeAuditHistorySource
    {
        private readonly object gate=new();private readonly List<TenantChangeAuditRecord> rows=[];public bool Fail,LeakForeignHistory;
        private readonly AuditTrailFixture owner;
        public MemoryTrailStore(AuditTrailFixture owner){this.owner=owner;Interlocked.Increment(ref owner.ProviderConstructors);}
        public TenantChangeAuditRecord[] Snapshot(){lock(gate)return rows.ToArray();}
        public async ValueTask AppendAsync(TenantChangeAuditRecord record,CancellationToken token)
        {
            Interlocked.Increment(ref owner.AppendCalls);if(owner.AppendGate is not null)await owner.AppendGate(record,token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();lock(gate){if(Fail)throw new IOException("Controlled trail persistence failure.");if(rows.Count>=256||rows.Any(r=>r.Receipt.ReceiptId==record.Receipt.ReceiptId))throw new InvalidOperationException("Bounded fixture trail storage rejected append.");rows.Add(record);}
        }
        public ValueTask<TenantChangeAuditPage> ReadAsync(TenantId tenant,int limit,string? cursor,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();var offset=cursor is null?0:int.Parse(cursor,NumberStyles.None,CultureInfo.InvariantCulture);
            lock(gate){var selected=rows.Where(r=>LeakForeignHistory||r.Receipt.Tenant.Equals(tenant)).ToArray();var page=selected.Skip(offset).Take(limit).ToArray();var next=offset+page.Length;return ValueTask.FromResult(new TenantChangeAuditPage(page,next<selected.Length?next.ToString(CultureInfo.InvariantCulture):null));}
        }
    }
}

public sealed class EntityMutationHandler(AuditTrailFixture fixture,TenantChangeAuditRecorder? recorder,ObservationFixture? observation,AuditPreparationFixture? preparationProfile=null):ITenantOperationHandler<EntityMutationRequest,EntityMutationResult>,IDisposable
{
    public async ValueTask<OperationResult<EntityMutationResult>> HandleAsync(EntityMutationRequest request,TenantOperationContext context,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();context.DemandAccess(new(request.Tenant),"entity",request.EntityId,context.Action);
        TenantChangeAuditPreparation? prepared=null;
        if(preparationProfile is not null&&recorder is not null)
        {
            if(preparationProfile.BeforePrepare is not null)await preparationProfile.BeforePrepare(context,token).ConfigureAwait(false);
            Interlocked.Increment(ref preparationProfile.PrepareCalls);
            prepared=(preparationProfile.RecorderOverride??recorder).Prepare(context,token);
            preparationProfile.Captured=prepared;
        }
        var changed=fixture.Mutate(request.Tenant,request.EntityId,context.Action,request.Title,request.Amount,request.Secret);
        observation?.At("after-domain-mutation",request.Tenant);
        if(recorder is not null)
        {
            var kind=context.Action=="create"?TenantChangeKind.Create:context.Action=="delete"?TenantChangeKind.Delete:TenantChangeKind.Update;
            var receipt=new TenantChangeReceipt(Guid.NewGuid(),context.Identity.Principal,context.Identity.AuthenticationScheme,context.Tenant,context.OperationId,context.Action,
                context.Resource.Kind,context.Resource.ResourceId,fixture.WrongReceiptVersion?"incorrect-authorization-version":context.Resource.Version,kind,
                changed.Before?.Version,changed.After?.Version,(observation?.Clock??TimeProvider.System).GetUtcNow());
            try
            {
                if(prepared is not null)await preparationProfile!.Complete(prepared,receipt,()=>fixture.Values(changed.Before,changed.After),fixture,token);
                else await recorder.RecordAsync(context,receipt,()=>fixture.Values(changed.Before,changed.After),token);
            }
            catch(TenantChangeAuditWriteException error) when(error.MayHaveCommitted)
            {return OperationResult<EntityMutationResult>.Failure(new("audit_trail.write_failed_may_have_committed","The domain change may have committed while audit persistence failed."));}
        }
        if(preparationProfile?.Completion==PreparationCompletion.Deferred)
            return OperationResult<EntityMutationResult>.Failure(new("audit_preparation.deferred_fixture","The fixture deliberately deferred completion beyond its checked scope."));
        return OperationResult<EntityMutationResult>.Success(new(request.Tenant,request.EntityId,changed.After?.Version));
    }
    public void Dispose()=>Interlocked.Increment(ref fixture.MutationDisposals);
}
public sealed class TrailHistoryHandler(AuditTrailFixture fixture):ITenantOperationHandler<TrailHistoryRequest,TrailHistoryResult>,IDisposable
{
    public async ValueTask<OperationResult<TrailHistoryResult>> HandleAsync(TrailHistoryRequest request,TenantOperationContext context,CancellationToken token)
    {
        var page=await new TenantChangeAuditHistoryReader(fixture.Store!,fixture.HistoryPolicy).ReadAsync(context,request.Limit,request.Cursor,token);
        TrailValueResult Value(TenantChangeValue value)=>new(value.Kind.ToString(),value.TextValue,value.DecimalValue?.ToString(CultureInfo.InvariantCulture),value.BooleanValue);
        var rows=page.Entries.Select(r=>new TrailChangeResult(r.Receipt.ReceiptId.ToString("D"),r.RecordedAtUtc.ToString("O",CultureInfo.InvariantCulture),r.Receipt.ReportedAtUtc?.ToString("O",CultureInfo.InvariantCulture),r.Receipt.Principal.Issuer,r.Receipt.Principal.Subject,r.Receipt.AuthenticationScheme,r.Receipt.Tenant.Value,r.Receipt.OperationId,r.Receipt.Action,r.Receipt.ResourceId,
            r.Receipt.AuthorizationResourceVersion,r.Receipt.BeforeEntityVersion,r.Receipt.AfterEntityVersion,r.Receipt.Kind.ToString(),r.Mode.ToString(),r.CapturedMode.ToString(),
            r.Fields.Select(f=>new TrailFieldResult(f.Name,Value(f.Before),Value(f.After),f.WasChanged)).ToArray())).ToArray();
        return OperationResult<TrailHistoryResult>.Success(new(context.Tenant.Value,rows,page.NextCursor));
    }
    public void Dispose()=>Interlocked.Increment(ref fixture.HistoryDisposals);
}
[Operation("entity.create")]
public sealed class EntityCreateGateway(TenantOperationDispatcher dispatcher):IOperationHandler<EntityMutationRequest,EntityMutationResult>
{public ValueTask<OperationResult<EntityMutationResult>> HandleAsync(EntityMutationRequest r,OperationContext c,CancellationToken t)=>dispatcher.DispatchAsync<EntityMutationRequest,EntityMutationResult>("entity.create",r,c,t);}
[Operation("entity.update")]
public sealed class EntityUpdateGateway(TenantOperationDispatcher dispatcher):IOperationHandler<EntityMutationRequest,EntityMutationResult>
{public ValueTask<OperationResult<EntityMutationResult>> HandleAsync(EntityMutationRequest r,OperationContext c,CancellationToken t)=>dispatcher.DispatchAsync<EntityMutationRequest,EntityMutationResult>("entity.update",r,c,t);}
[Operation("entity.delete")]
public sealed class EntityDeleteGateway(TenantOperationDispatcher dispatcher):IOperationHandler<EntityMutationRequest,EntityMutationResult>
{public ValueTask<OperationResult<EntityMutationResult>> HandleAsync(EntityMutationRequest r,OperationContext c,CancellationToken t)=>dispatcher.DispatchAsync<EntityMutationRequest,EntityMutationResult>("entity.delete",r,c,t);}
[Operation("trail.history")]
public sealed class TrailHistoryGateway(TenantOperationDispatcher dispatcher):IOperationHandler<TrailHistoryRequest,TrailHistoryResult>
{public ValueTask<OperationResult<TrailHistoryResult>> HandleAsync(TrailHistoryRequest r,OperationContext c,CancellationToken t)=>dispatcher.DispatchAsync<TrailHistoryRequest,TrailHistoryResult>("trail.history",r,c,t);}
public sealed record AuditTrailSummary(string Protection,string Mode,int SinkFactoryCalls,int SinkConstructors,int ValueFactoryCalls,int Records,int MutationFactories,int HistoryFactories);
