using Cehpalon.Engine.Core;
using Cehpalon.Engine.Tenancy;

namespace SecurityApi;

[Operation("tenant.select")]
public sealed class SwitchGateway(TenantOperationDispatcher dispatcher):IOperationHandler<SwitchRequest,SwitchResult>
{
    public async ValueTask<OperationResult<SwitchResult>> HandleAsync(SwitchRequest request,OperationContext context,CancellationToken token)
    {
        var result=await dispatcher.DispatchAsync<TenantSelectionRequest,TenantSelectionResult>("tenant.select",new(new(request.Tenant)),context,token);
        return result.IsSuccess?OperationResult<SwitchResult>.Success(new(result.Value.Tenant.Value)):OperationResult<SwitchResult>.Failure(result.Error);
    }
}

[Operation("document.read_all")]
public sealed class ReadSetGateway(TenantReadSetDispatcher dispatcher,BusinessState state):IOperationHandler<ReadSetRequest,ReadSetResult>
{
    public async ValueTask<OperationResult<ReadSetResult>> HandleAsync(ReadSetRequest request,OperationContext context,CancellationToken token)
    {
        var operation=new TenantReadSetOperation<ReadSetRequest,DocumentResult>("document.read_all","document",r=>r with{Tenants=r.Tenants?.ToArray()},r=>r.ResourceId,
            ()=>{Interlocked.Increment(ref state.Factories);return new ReadSetHandler(state);});
        var result=await dispatcher.DispatchAsync(operation,request,context,request.Tenants?.Select(t=>new TenantId(t)),token);
        return result.IsSuccess?OperationResult<ReadSetResult>.Success(new(result.Value.Results.Select(v=>v.Value).ToArray())):OperationResult<ReadSetResult>.Failure(result.Error);
    }
}

// Explicit trusted read capability. No write dispatcher or mutation binding is used here.
public sealed class ReadSetHandler(BusinessState state):ITenantOperationHandler<ReadSetRequest,DocumentResult>,IDisposable
{
    public async ValueTask<OperationResult<DocumentResult>> HandleAsync(ReadSetRequest request,TenantOperationContext context,CancellationToken token)
    {
        if(state.ReadSetGate is not null)await state.ReadSetGate(context.Tenant,token);
        token.ThrowIfCancellationRequested();var result=state.Read(context,false);state.ReadSetHook?.Invoke(context.Tenant);
        return OperationResult<DocumentResult>.Success(result);
    }
    public void Dispose()=>Interlocked.Increment(ref state.Disposals);
}
