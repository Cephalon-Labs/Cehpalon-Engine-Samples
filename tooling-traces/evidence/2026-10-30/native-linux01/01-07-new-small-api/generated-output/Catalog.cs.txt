using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;
using Cehpalon.Engine.Transports.Http;

namespace PortableConsumers.Generated;

public sealed record GetItem(string Tenant, int Id);
public sealed record ListItems(string Tenant, int Page);
public sealed record SetLabel(string Tenant, int Id, int ExpectedRevision, string Label);
public sealed record Item(string Tenant, int Id, string Label, int Revision, long AmountMinorUnits);
public sealed record ItemPage(Item[] Items);

public static class Bindings
{
    public static readonly OperationBinding<GetItem,Item> Get = new("catalog.get", r => Tenant(r.Tenant) && r.Id > 0 ? null : Invalid());
    public static readonly OperationBinding<ListItems,ItemPage> List = new("catalog.list", r => Tenant(r.Tenant) && r.Page is >= 0 and < 500 ? null : Invalid());
    public static readonly OperationBinding<SetLabel,Item> Set = new("catalog.set", r => Tenant(r.Tenant) && r.Id > 0 && r.ExpectedRevision >= 0 && Label(r.Label) ? null : Invalid());
    private static OperationError Invalid() => new("validation.failed", "Validation failed.");
    private static bool Tenant(string? value) => value is "tenant-a" or "tenant-b";
    private static bool Label(string? value)
    {
        if (value is null || value.Length > 128 || value.Any(char.IsControl)) return false;
        var scalars = 0;
        for (var i=0;i<value.Length;i++)
        {
            if (char.IsLowSurrogate(value[i])) return false;
            if (char.IsHighSurrogate(value[i]) && (++i >= value.Length || !char.IsLowSurrogate(value[i]))) return false;
            if (++scalars > 64) return false;
        }
        return true;
    }
}

// Synthetic, bounded in-memory data port. This is not a provider/RLS proof.
public sealed class CatalogStore : IResourceScopeSource
{
    private readonly object gate = new();
    private readonly Dictionary<(string Tenant,int Id),Item> items = new();
    public int Factories, Constructors, Reads, Writes, Disposals;
    public bool WrongOwner, Revoked, MissingPolicy, DelayWrites;
    public TaskCompletionSource WriteEntered = NewSignal(), CancelObserved = NewSignal();
    public static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    public CatalogStore()
    {
        foreach (var tenant in new[]{"tenant-a","tenant-b"})
            for(var id=1;id<=10000;id++) items.Add((tenant,id),new(tenant,id,$"item-{id:D5}",0,id*17L));
    }
    public int Count => items.Count;
    public int Work => Factories + Constructors + Reads + Writes;
    public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId tenant,string kind,string id,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return ValueTask.FromResult<ResourceScopeSnapshot?>(kind=="catalog" && id=="catalog" && tenant.Value is "tenant-a" or "tenant-b"
            ? new(WrongOwner ? new("tenant-b") : tenant,kind,id,"catalog-v1") : null);
    }
    private void Demand(string tenant,string action,TenantOperationContext context) => context.DemandAccess(new(tenant),"catalog","catalog",action);
    public OperationResult<Item> Get(GetItem request,TenantOperationContext context)
    {
        Demand(request.Tenant,"catalog.get",context);
        lock(gate) { Reads++; return items.TryGetValue((context.Tenant.Value,request.Id),out var item) ? OperationResult<Item>.Success(item) : OperationResult<Item>.Failure(new("resource.not_found","Item not found.")); }
    }
    public OperationResult<ItemPage> List(ListItems request,TenantOperationContext context)
    {
        Demand(request.Tenant,"catalog.list",context);
        lock(gate) { Reads++; return OperationResult<ItemPage>.Success(new(Enumerable.Range(1+request.Page*20,20).Select(id=>items[(context.Tenant.Value,id)]).ToArray())); }
    }
    public async ValueTask<OperationResult<Item>> Set(SetLabel request,TenantOperationContext context,CancellationToken ct)
    {
        Demand(request.Tenant,"catalog.set",context);
        if (DelayWrites)
        {
            WriteEntered.TrySetResult();
            try { await Task.Delay(TimeSpan.FromSeconds(5),ct); }
            catch(OperationCanceledException) { CancelObserved.TrySetResult(); throw; }
        }
        ct.ThrowIfCancellationRequested();
        Demand(request.Tenant,"catalog.set",context);
        lock(gate)
        {
            ct.ThrowIfCancellationRequested();
            if(!items.TryGetValue((context.Tenant.Value,request.Id),out var item)) return OperationResult<Item>.Failure(new("resource.not_found","Item not found."));
            if(item.Revision!=request.ExpectedRevision) return OperationResult<Item>.Failure(new("resource.conflict","Revision conflict."));
            var updated=item with {Label=request.Label,Revision=item.Revision+1};
            items[(context.Tenant.Value,request.Id)]=updated; Writes++; return OperationResult<Item>.Success(updated);
        }
    }
}

public sealed class CatalogHandler(CatalogStore store) : ITenantOperationHandler<GetItem,Item>,ITenantOperationHandler<ListItems,ItemPage>,ITenantOperationHandler<SetLabel,Item>,IDisposable
{
    public ValueTask<OperationResult<Item>> HandleAsync(GetItem r,TenantOperationContext c,CancellationToken ct) { ct.ThrowIfCancellationRequested(); return ValueTask.FromResult(store.Get(r,c)); }
    public ValueTask<OperationResult<ItemPage>> HandleAsync(ListItems r,TenantOperationContext c,CancellationToken ct) { ct.ThrowIfCancellationRequested(); return ValueTask.FromResult(store.List(r,c)); }
    public ValueTask<OperationResult<Item>> HandleAsync(SetLabel r,TenantOperationContext c,CancellationToken ct) => store.Set(r,c,ct);
    public void Dispose() => Interlocked.Increment(ref store.Disposals);
}

// Code generation registers stateless Core gateways lazily; every protected call
// still passes through the same TenantOperationDispatcher.
[Operation("catalog.get")]
public sealed class GetGateway(TenantOperationDispatcher tenant) : IOperationHandler<GetItem,Item>
{ public ValueTask<OperationResult<Item>> HandleAsync(GetItem r,OperationContext c,CancellationToken ct) => tenant.DispatchAsync<GetItem,Item>("catalog.get",r,c,ct); }
[Operation("catalog.list")]
public sealed class ListGateway(TenantOperationDispatcher tenant) : IOperationHandler<ListItems,ItemPage>
{ public ValueTask<OperationResult<ItemPage>> HandleAsync(ListItems r,OperationContext c,CancellationToken ct) => tenant.DispatchAsync<ListItems,ItemPage>("catalog.list",r,c,ct); }
[Operation("catalog.set")]
public sealed class SetGateway(TenantOperationDispatcher tenant) : IOperationHandler<SetLabel,Item>
{ public ValueTask<OperationResult<Item>> HandleAsync(SetLabel r,OperationContext c,CancellationToken ct) => tenant.DispatchAsync<SetLabel,Item>("catalog.set",r,c,ct); }

public sealed class GatewayFactory(TenantOperationDispatcher tenant) : IOperationHandlerFactory
{
    public THandler Create<THandler>() where THandler:class => typeof(THandler)==typeof(GetGateway) ? (THandler)(object)new GetGateway(tenant)
        : typeof(THandler)==typeof(ListGateway) ? (THandler)(object)new ListGateway(tenant)
        : typeof(THandler)==typeof(SetGateway) ? (THandler)(object)new SetGateway(tenant) : throw new InvalidOperationException("Unknown generated gateway.");
}

public sealed class Memberships(CatalogStore store) : ITenantMembershipSource
{
    public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot identity,TenantId tenant,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); var now=DateTimeOffset.UtcNow;
        var allowed=identity.Principal.Issuer==JwtFixture.Issuer && ((identity.Principal.Subject=="alice" && tenant.Value=="tenant-a") || (identity.Principal.Subject=="bob" && tenant.Value=="tenant-b"));
        return ValueTask.FromResult<TenantMembershipSnapshot?>(allowed ? new(identity.Principal,tenant,!store.Revoked,now.AddMinutes(-1),now.AddMinutes(5),"membership-v1") : null);
    }
}
public sealed class CatalogPolicy : ITenantAccessPolicy
{
    public ValueTask<bool> IsAllowedAsync(TenantAccessRequest request,CancellationToken ct)
    { ct.ThrowIfCancellationRequested(); return ValueTask.FromResult(request.OperationId==request.Action && request.OperationId is "catalog.get" or "catalog.list" or "catalog.set"); }
}
