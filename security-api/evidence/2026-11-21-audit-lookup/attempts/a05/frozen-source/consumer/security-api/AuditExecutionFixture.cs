using Cehpalon.Engine.Core;
using Cehpalon.Engine.Tenancy;

namespace SecurityApi;

/// <summary>Owned consumer controls. None of these switches are taken from request metadata.</summary>
public sealed class AuditExecutionFixture
{
    public int HelperCalls,MutationCalls,ResultsReturned,PossibleCommitFailures;
    public ExecutionFault Fault;
    public CancellationTokenSource? MutationCancellation;
    public Func<TenantOperationContext,CancellationToken,Task>? BeforeExecute;
    public Func<CancellationToken,Task>? AfterMutation;
    public bool MutationSawCancellation;
    public readonly TaskCompletionSource Finished=new(TaskCreationOptions.RunContinuationsAsynchronously);
}
public enum ExecutionFault { None,ThrowAfterMutation,CancelAfterMutation,NullOutcome,WrongReceipt }
public sealed record ExecutionSummary(string Protection,string Mode,int Helpers,int Mutations,int Results,int Appends,int Values,int Records);

/// <summary>Explicit project integration: invoke the helper and await it before publishing success.</summary>
public sealed class AuditExecutionHandler(AuditTrailFixture fixture,TenantChangeAuditRecorder? recorder,AuditExecutionFixture execution,
    AuditPreparationFixture preparation,ObservationFixture? observation):ITenantOperationHandler<EntityMutationRequest,EntityMutationResult>,IDisposable
{
    public async ValueTask<OperationResult<EntityMutationResult>> HandleAsync(EntityMutationRequest request,TenantOperationContext context,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();context.DemandAccess(new(request.Tenant),"entity",request.EntityId,context.Action);
        if(recorder is null)
        {
            var changed=fixture.Mutate(request.Tenant,request.EntityId,context.Action,request.Title,request.Amount,request.Secret);
            return OperationResult<EntityMutationResult>.Success(new(request.Tenant,request.EntityId,changed.After?.Version));
        }
        using var linked=execution.MutationCancellation is null?null:CancellationTokenSource.CreateLinkedTokenSource(token,execution.MutationCancellation.Token);
        var mutationToken=linked?.Token??token;
        if(execution.BeforeExecute is not null)await execution.BeforeExecute(context,mutationToken).ConfigureAwait(false);
        Interlocked.Increment(ref execution.HelperCalls);
        try
        {
            var result=await (preparation.RecorderOverride??recorder).ExecuteAsync<EntityMutationResult>(context,async ct=>
            {
                Interlocked.Increment(ref execution.MutationCalls);ct.ThrowIfCancellationRequested();
                var changed=fixture.Mutate(request.Tenant,request.EntityId,context.Action,request.Title,request.Amount,request.Secret);
                observation?.At("after-domain-mutation",request.Tenant);
                if(execution.AfterMutation is not null)await execution.AfterMutation(ct).ConfigureAwait(false);
                execution.MutationSawCancellation=ct.IsCancellationRequested;
                if(execution.Fault==ExecutionFault.ThrowAfterMutation)throw new IOException("Controlled private callback failure after domain change.");
                if(execution.Fault==ExecutionFault.CancelAfterMutation)throw new OperationCanceledException(ct);
                if(execution.Fault==ExecutionFault.NullOutcome)return null!;
                var kind=context.Action=="create"?TenantChangeKind.Create:context.Action=="delete"?TenantChangeKind.Delete:TenantChangeKind.Update;
                var receipt=new TenantChangeReceipt(Guid.NewGuid(),context.Identity.Principal,context.Identity.AuthenticationScheme,context.Tenant,context.OperationId,context.Action,
                    context.Resource.Kind,context.Resource.ResourceId,execution.Fault==ExecutionFault.WrongReceipt?"incorrect-authorization-version":context.Resource.Version,kind,
                    changed.Before?.Version,changed.After?.Version,(observation?.Clock??TimeProvider.System).GetUtcNow());
                return new TenantChangeAuditMutation<EntityMutationResult>(receipt,new(request.Tenant,request.EntityId,changed.After?.Version),()=>fixture.Values(changed.Before,changed.After));
            },mutationToken).ConfigureAwait(false);
            Interlocked.Increment(ref execution.ResultsReturned);
            return OperationResult<EntityMutationResult>.Success(result);
        }
        catch(TenantChangeAuditWriteException error) when(error.MayHaveCommitted)
        {
            Interlocked.Increment(ref execution.PossibleCommitFailures);
            return OperationResult<EntityMutationResult>.Failure(new("audit_trail.write_failed_may_have_committed","The domain change may have committed while required audit completion failed."));
        }
        finally{execution.Finished.TrySetResult();}
    }
    public void Dispose()=>Interlocked.Increment(ref fixture.MutationDisposals);
}
