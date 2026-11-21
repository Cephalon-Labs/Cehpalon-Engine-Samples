using Cehpalon.Engine.Tenancy;

namespace SecurityApi;

/// <summary>Owned test controls, not a recorder/provider and never selected by request metadata.</summary>
public sealed class AuditPreparationFixture
{
    public string PolicyFault="none",RequiredFault="none";
    public bool SameBuilderAlternative,DispatchAlternative;
    public PreparationCompletion Completion;
    public int PrepareCalls,RequiredEnumerations,CompletionFailures;
    public TenantChangeAuditPreparation? Captured;
    public TenantChangeAuditRecorder? RecorderOverride;
    public Func<TenantOperationContext,CancellationToken,Task>? BeforePrepare;
    public TenantChangeReceipt? CapturedReceipt;
    public TenantChangeAuditPolicy Policy(AuditTrailFixture fixture)
    {
        var rules=fixture.Policy.Rules.ToList();
        if(PolicyFault=="missing")rules.RemoveAll(r=>r.OperationId=="entity.update");
        else if(PolicyFault=="unknown")rules.Add(new("entity.unknown","update","entity"));
        else if(PolicyFault=="action"||PolicyFault=="kind")
        {var index=rules.FindIndex(r=>r.OperationId=="entity.update");var old=rules[index];rules[index]=new(old.OperationId,PolicyFault=="action"?"write":old.Action,PolicyFault=="kind"?"different-kind":old.ResourceKind,old.Fields);}
        return new(fixture.Mode,rules);
    }
    public IEnumerable<string> RequiredOperations()
    {
        Interlocked.Increment(ref RequiredEnumerations);
        if(RequiredFault=="poison")throw new InvalidOperationException("Disabled required enumeration must stay unused.");
        if(RequiredFault=="infinite"){while(true)yield return "entity.update";}
        yield return "entity.create";yield return "entity.update";yield return "entity.delete";
        if(RequiredFault=="missing")yield return "entity.unregistered";
        if(RequiredFault=="duplicate")yield return "entity.update";
    }
    public async Task Complete(TenantChangeAuditPreparation preparation,TenantChangeReceipt receipt,Func<TenantChangeStates> values,AuditTrailFixture fixture,CancellationToken token)
    {
        CapturedReceipt=receipt;
        if(Completion==PreparationCompletion.Deferred)return;
        if(Completion==PreparationCompletion.Normal){await preparation.CompleteAsync(receipt,values,token);return;}
        if(Completion==PreparationCompletion.Concurrent)
        {
            var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var release=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            fixture.AppendGate=async(_,ct)=>{entered.TrySetResult();await release.Task.WaitAsync(ct);};
            var first=Task.Run(async()=>await preparation.CompleteAsync(receipt,values,token));
            TenantChangeAuditWriteException? loser=null;
            try
            {
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
                try{await Task.Run(async()=>await preparation.CompleteAsync(receipt,values,token));}
                catch(TenantChangeAuditWriteException error){loser=error;Interlocked.Increment(ref CompletionFailures);}
            }
            finally{release.TrySetResult();}
            await first;
            if(loser is null)throw new InvalidOperationException("Concurrent completion unexpectedly repeated.");
            throw loser;
        }
        if(Completion==PreparationCompletion.Replay)
        {await preparation.CompleteAsync(receipt,values,token);try{await preparation.CompleteAsync(receipt,values,token);}catch(TenantChangeAuditWriteException){Interlocked.Increment(ref CompletionFailures);throw;}return;}
        try
        {
            if(Completion==PreparationCompletion.NullFirst)await preparation.CompleteAsync(null!,values,token);
            else if(Completion==PreparationCompletion.CancelledFirst){using var cancelled=new CancellationTokenSource();cancelled.Cancel();await preparation.CompleteAsync(receipt,values,cancelled.Token);}
            else await preparation.CompleteAsync(receipt,values,token);
        }
        catch(TenantChangeAuditWriteException){Interlocked.Increment(ref CompletionFailures);}
        try{await preparation.CompleteAsync(receipt,values,token);}
        catch(TenantChangeAuditWriteException){Interlocked.Increment(ref CompletionFailures);throw;}
        throw new InvalidOperationException("Failed preparation was unexpectedly reusable.");
    }
}
public enum PreparationCompletion { Normal,Replay,Concurrent,FailedFirst,NullFirst,CancelledFirst,Deferred }
public sealed record PreparationSummary(string Protection,string Mode,int PrepareCalls,int Appends,int Values,int Records,int MutationFactories,int HistoryFactories);
