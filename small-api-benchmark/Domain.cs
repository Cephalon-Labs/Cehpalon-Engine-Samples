using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Transports.Http;

namespace SmallApi.Benchmark;

public sealed record GetItem(int Id);
public sealed record ListItems(int Page);
public sealed record SetLabel(int Id,int ExpectedRevision,string Label);
public sealed record Item(int Id,string Label,int Revision,long AmountMinorUnits);
public sealed record ItemPage(Item[] Items);

public static class Bindings
{
    public static readonly OperationBinding<GetItem,Item> Get=new("catalog.get",r=>r.Id>0?null:Invalid());
    public static readonly OperationBinding<ListItems,ItemPage> List=new("catalog.list",r=>r.Page is >=0 and <500?null:Invalid());
    public static readonly OperationBinding<SetLabel,Item> Set=new("catalog.set",r=>r.Id>0 && r.ExpectedRevision>=0 && Label(r.Label)?null:Invalid());
    public static OperationError Invalid()=>new("validation.failed","Request validation failed.");
    private static bool Label(string? value)
    {
        if(value is null || value.Length>128 || value.Any(char.IsControl)) return false;
        var count=0;
        for(var i=0;i<value.Length;i++)
        {
            if(char.IsLowSurrogate(value[i]))return false;
            if(char.IsHighSurrogate(value[i]) && (++i>=value.Length || !char.IsLowSurrogate(value[i])))return false;
            if(++count>64)return false;
        }
        return true;
    }
}

public sealed class CatalogStore
{
    private readonly object gate=new();
    private readonly Item[] items=new Item[10000];
    public long Factories,Constructors,Disposals,Reads,Writes;
    public volatile bool DelayWrites;
    public TaskCompletionSource DelayEntered {get;private set;}=Signal();
    public TaskCompletionSource CancelObserved {get;private set;}=Signal();
    public long CancellationObservedTimestamp {get;private set;}
    public long DelayEnteredTimestamp {get;private set;}
    public CatalogStore()=>Reset();
    private static TaskCompletionSource Signal()=>new(TaskCreationOptions.RunContinuationsAsynchronously);
    public void ResetCancellationSignals(){DelayEntered=Signal();CancelObserved=Signal();CancellationObservedTimestamp=0;DelayEnteredTimestamp=0;}
    public void Reset()
    {
        lock(gate)
        {
            for(var id=1;id<=10000;id++)items[id-1]=new(id,$"item-{id:D5}",0,id*17L);
            Factories=Constructors=Disposals=Reads=Writes=0;DelayWrites=false;ResetCancellationSignals();
        }
    }
    public Item[] Snapshot(){lock(gate)return (Item[])items.Clone();}
    public string StateHash()=>Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(Snapshot(),Wire.Json))).ToLowerInvariant();
    public OperationResult<Item> Get(GetItem request,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();lock(gate)
        {Reads++;return request.Id<=10000?OperationResult<Item>.Success(items[request.Id-1]):OperationResult<Item>.Failure(new("resource.not_found","Item not found."));}
    }
    public OperationResult<ItemPage> List(ListItems request,CancellationToken ct)
    {ct.ThrowIfCancellationRequested();lock(gate){Reads++;return OperationResult<ItemPage>.Success(new(items.Skip(request.Page*20).Take(20).ToArray()));}}
    public async ValueTask<OperationResult<Item>> Set(SetLabel request,CancellationToken ct)
    {
        if(DelayWrites)
        {
            DelayEnteredTimestamp=Stopwatch.GetTimestamp();DelayEntered.TrySetResult();
            try{await Task.Delay(TimeSpan.FromSeconds(5),ct);}
            catch(OperationCanceledException){CancellationObservedTimestamp=Stopwatch.GetTimestamp();CancelObserved.TrySetResult();throw;}
        }
        ct.ThrowIfCancellationRequested();lock(gate)
        {
            ct.ThrowIfCancellationRequested();
            if(request.Id>10000)return OperationResult<Item>.Failure(new("resource.not_found","Item not found."));
            var item=items[request.Id-1];
            if(item.Revision!=request.ExpectedRevision)return OperationResult<Item>.Failure(new("resource.conflict","Revision conflict."));
            var updated=item with{Label=request.Label,Revision=item.Revision+1};items[request.Id-1]=updated;Writes++;return OperationResult<Item>.Success(updated);
        }
    }
}

[Operation("catalog.get")]
public sealed class GetHandler(CatalogStore store):IOperationHandler<GetItem,Item>,IDisposable
{public ValueTask<OperationResult<Item>> HandleAsync(GetItem r,OperationContext c,CancellationToken ct)=>ValueTask.FromResult(store.Get(r,ct));public void Dispose()=>Interlocked.Increment(ref store.Disposals);}
[Operation("catalog.list")]
public sealed class ListHandler(CatalogStore store):IOperationHandler<ListItems,ItemPage>,IDisposable
{public ValueTask<OperationResult<ItemPage>> HandleAsync(ListItems r,OperationContext c,CancellationToken ct)=>ValueTask.FromResult(store.List(r,ct));public void Dispose()=>Interlocked.Increment(ref store.Disposals);}
[Operation("catalog.set")]
public sealed class SetHandler(CatalogStore store):IOperationHandler<SetLabel,Item>,IDisposable
{public ValueTask<OperationResult<Item>> HandleAsync(SetLabel r,OperationContext c,CancellationToken ct)=>store.Set(r,ct);public void Dispose()=>Interlocked.Increment(ref store.Disposals);}

public sealed class HandlerFactory(CatalogStore store):IOperationHandlerFactory
{
    public THandler Create<THandler>()where THandler:class
    {
        Interlocked.Increment(ref store.Factories);Interlocked.Increment(ref store.Constructors);
        return typeof(THandler)==typeof(GetHandler)?(THandler)(object)new GetHandler(store):typeof(THandler)==typeof(ListHandler)?(THandler)(object)new ListHandler(store):typeof(THandler)==typeof(SetHandler)?(THandler)(object)new SetHandler(store):throw new InvalidOperationException("Unknown fixture handler.");
    }
}

public sealed class Dispatch(CatalogStore store,bool engine):ITransportOperationDispatcher
{
    private readonly HandlerFactory factory=new(store);
    private readonly OperationDispatcher? dispatcher=engine?Build(new HandlerFactory(store)):null;
    private static OperationDispatcher Build(HandlerFactory factory){var builder=new OperationRegistryBuilder();Cehpalon.Engine.Generated.OperationRegistrations.RegisterAll(builder,factory);return new(builder.Build());}
    public ValueTask<OperationResult<TResponse>> DispatchAsync<TRequest,TResponse>(HttpContext http,string id,TRequest request,OperationContext context,CancellationToken ct)
    {
        if(engine)
        {
            return dispatcher!.DispatchAsync<TRequest,TResponse>(id,request,context,ct);
        }
        return Direct<TRequest,TResponse>(id,request,context,ct);
    }
    private async ValueTask<OperationResult<TResponse>> Direct<TRequest,TResponse>(string id,TRequest request,OperationContext context,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if(id=="catalog.get" && request is GetItem get){using var handler=factory.Create<GetHandler>();return (OperationResult<TResponse>)(object)await handler.HandleAsync(get,context,ct);}
        if(id=="catalog.list" && request is ListItems list){using var handler=factory.Create<ListHandler>();return (OperationResult<TResponse>)(object)await handler.HandleAsync(list,context,ct);}
        if(id=="catalog.set" && request is SetLabel set){using var handler=factory.Create<SetHandler>();return (OperationResult<TResponse>)(object)await handler.HandleAsync(set,context,ct);}
        throw new InvalidOperationException("Unknown direct fixture operation.");
    }
}
