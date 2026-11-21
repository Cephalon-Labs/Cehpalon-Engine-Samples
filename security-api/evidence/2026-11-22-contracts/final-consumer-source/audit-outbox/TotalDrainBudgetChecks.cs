extern alias securityapi;
using System.Net.Http.Json;
using Cehpalon.Engine.Tenancy;
using Npgsql;
using securityapi::SecurityApi;
using Host=securityapi::SecurityApi.Host;

namespace AuditOutbox;

// Only tagged SQL Lock controls below establish actual backend cancellation.
// Other held/faulted phases are explicit wrappers with external watchdog/unblock/join ownership.
public static class TotalDrainBudgetChecks
{
    private static readonly TimeSpan Short=TimeSpan.FromSeconds(2);
    private static void Require(bool value){if(!value)throw new InvalidOperationException("Total drain budget consumer assertion failed.");}
    private static TaskCompletionSource Signal()=>new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static async Task<Exception> Failure(Func<Task> action){try{await action();}catch(Exception error){return error;}throw new InvalidOperationException("Expected total drain failure.");}
    private static async Task Join(Task task){try{await task;}catch(Exception){}}
    private static TenantChangeAuditOutboxRelay Relay(Adapter source,TimeSpan? perBatch=null)=>TenantChangeAuditOutboxRelay.ActivateWithBudget(true,perBatch,()=>source,()=>source,TimeSpan.FromSeconds(30))!;
    private static TenantChangeAuditOutboxDrainException Progress(Exception error,int started=1,int completed=0,int completedAck=0,int interrupted=0,bool mayHaveDelivered=false)
    {
        Require(error is TenantChangeAuditOutboxDrainException);var value=(TenantChangeAuditOutboxDrainException)error;
        Require(value.Tenant.Value=="A"&&value.StartedBatches==started&&value.CompletedBatches==completed&&value.CompletedAcknowledgedCount==completedAck&&value.InterruptedAcknowledgedCount==interrupted&&value.AcknowledgedCount==completedAck+interrupted&&value.MayHaveDelivered==mayHaveDelivered&&ReferenceEquals(value.PrimaryFailure,value.InnerException));return value;
    }
    private static TenantChangeAuditOutboxRelayException Child(TenantChangeAuditOutboxDrainException error)
    {Require(error.PrimaryFailure is TenantChangeAuditOutboxRelayException);return(TenantChangeAuditOutboxRelayException)error.PrimaryFailure;}
    private static void TimeoutKind(Exception? error,string kind)=>Require(error is TimeoutException&&error.Message.Contains(kind+" budget",StringComparison.Ordinal));
    private static async Task Recover(PostgresStore store,Adapter source,TenantChangeAuditOutboxRelay relay)
    {
        source.ClaimOverride=null;source.SinkOverride=null;source.AckOverride=null;source.AfterRelease=null;var host=new DrainHost(relay);host.Authority.AllowDrain=false;var claims=source.Claims;
        Require(!(await host.RunWithTotalBudget(TimeSpan.FromSeconds(10))).IsSuccess&&source.Claims==claims);host.Authority.AllowDrain=true;Require((await host.RunWithTotalBudget(TimeSpan.FromSeconds(10))).IsSuccess&&host.Authority.IdentityLookups==2&&(await store.Counts())==(1,1,1));
    }
    private static async Task<Exception> Held(DrainHost host,TimeSpan timeout,Pause pause,CancellationTokenSource caller,Func<Task,Task>? inspect=null,int perBatch=128,Pause? alsoRelease=null)
    {
        var pending=host.RunWithTotalBudget(timeout,perBatch:perBatch,token:caller.Token).AsTask();
        try{if(inspect is not null)await inspect(pending);return await Failure(()=>pending).WaitAsync(TimeSpan.FromSeconds(20));}
        finally{caller.Cancel();pause.Release();alsoRelease?.Release();await Join(pending);}
    }
    public static async Task Run(Func<string,Func<Task>,Task> outer,Func<Task<PostgresStore>> createStore,Func<PostgresStore,Task> mutate,string connection,Action<object> observe)
    {
        var stores=new List<PostgresStore>();
        async Task<PostgresStore> Store(){var value=await createStore();stores.Add(value);return value;}
        async Task Check(string name,Func<Task> action)=>await outer(name,async()=>{stores.Clear();await action();Require(stores.All(s=>s.StatusReads==0&&s.HistoryReads==0));});
        await Check("total drain disabled selection creates no host factory or SQL",()=>
        {
            var store=new PostgresStore(connection,"ao_"+Guid.NewGuid().ToString("N"));var factories=0;Require(DrainHost.Activate(false,()=>{factories++;throw new InvalidOperationException();}) is null&&factories==0&&store.Connections==0);return Task.CompletedTask;
        });
        await Check("total drain exact bounds reject before claim and one minute is accepted",async()=>
        {
            var store=await Store();var source=new Adapter(store);var host=new DrainHost(Relay(source));foreach(var value in new[]{TimeSpan.Zero,TimeSpan.FromTicks(-1),TimeSpan.FromMinutes(1).Add(TimeSpan.FromTicks(1))})Require(await Failure(()=>host.RunWithTotalBudget(value).AsTask()) is ArgumentOutOfRangeException);
            Require(source.Claims==0);var result=await host.RunWithTotalBudget(TimeSpan.FromMinutes(1));Require(result.IsSuccess&&result.Value.AcknowledgedCount==0&&result.Value.StopReason==TenantChangeAuditOutboxDrainStopReason.NoProgress&&source.Claims==1&&source.Tokens.Single().CanBeCanceled);
        });
        await Check("legacy and explicit null total budget preserve actual PostgreSQL caller work tokens",async()=>
        {
            foreach(var legacy in new[]{true,false})
            {
                var store=await Store();await mutate(store);var source=new Adapter(store);var host=new DrainHost(Relay(source));using var caller=new CancellationTokenSource();var result=legacy?await host.Run(token:caller.Token):await host.RunWithTotalBudget(null,token:caller.Token);
                Require(result.IsSuccess&&result.Value.AcknowledgedCount==1&&source.Tokens.All(t=>t==caller.Token)&&source.SinkToken==caller.Token&&source.AckToken==caller.Token&&source.IndependentRelease&&(await store.Counts())==(1,1,1));
            }
        });
        await Check("legacy and null total budget retain exact unrelated claim wrapper cancellation",async()=>
        {
            foreach(var legacy in new[]{true,false})
            {
                var store=await Store();var source=new Adapter(store);using var caller=new CancellationTokenSource();using var other=new CancellationTokenSource();other.Cancel();var original=new OperationCanceledException(other.Token);source.ClaimOverride=(_,_,_,_)=>throw original;var host=new DrainHost(Relay(source));
                var error=Progress(await Failure(()=>legacy?host.Run(token:caller.Token).AsTask():host.RunWithTotalBudget(null,token:caller.Token).AsTask()));Require(ReferenceEquals(error.PrimaryFailure,original)&&source.Tokens.Single()==caller.Token&&source.Releases==0);
            }
        });
        await Check("total budget cancels actual table-blocked PostgreSQL Claim and quiesces before reuse",async()=>
        {
            var store=await Store();await mutate(store);var probe=new SqlProbe(connection,store.Schema);var source=new Adapter(probe.Provider);var relay=Relay(source);using var caller=new CancellationTokenSource();var blocker=await probe.HoldTable("audit_outbox");var pending=new DrainHost(relay).RunWithTotalBudget(TimeSpan.FromSeconds(5),token:caller.Token).AsTask();int pid=0;
            try{pid=await probe.Observe("audit_outbox","WITH selected",pending,source);var error=Progress(await Failure(()=>pending).WaitAsync(TimeSpan.FromSeconds(15)));TimeoutKind(error.PrimaryFailure,"drain");Require(source.Releases==0&&probe.Provider.SinkCalls==0&&await probe.Quiescent(pid));}
            finally{caller.Cancel();await blocker.DisposeAsync();await Join(pending);}
            Require(await probe.Quiescent(pid));await Recover(store,source,relay);observe(new{phase="claim",actual_postgres_lock_before_expiry=true,backend_pid=pid,owned_task_joined=true,backend_quiescent=true,fresh_reuse=true});
        });
        await Check("total budget cancels actual table-blocked PostgreSQL sink and releases its known lease",async()=>
        {
            var store=await Store();await mutate(store);var probe=new SqlProbe(connection,store.Schema);var source=new Adapter(probe.Provider);SqlLock? blocker=null;var locked=Signal();source.ClaimOverride=async(tenant,maximum,duration,token)=>{var lease=await probe.Provider.ClaimAsync(tenant,maximum,duration,token);blocker=await probe.HoldTable("audit_sink");locked.TrySetResult();return lease;};var relay=Relay(source);using var caller=new CancellationTokenSource();var pending=new DrainHost(relay).RunWithTotalBudget(TimeSpan.FromSeconds(5),token:caller.Token).AsTask();int pid=0;
            try{await locked.Task.WaitAsync(TimeSpan.FromSeconds(10));pid=await probe.Observe("audit_sink","INSERT INTO",pending,source);var error=Progress(await Failure(()=>pending).WaitAsync(TimeSpan.FromSeconds(15)),mayHaveDelivered:true);TimeoutKind(Child(error).PrimaryFailure,"drain");Require(source.IndependentRelease&&source.Releases==1&&await probe.Quiescent(pid));}
            finally{caller.Cancel();if(blocker is not null)await blocker.DisposeAsync();await Join(pending);}
            Require((await store.Counts())==(1,0,0));await Recover(store,source,relay);observe(new{phase="sink",actual_postgres_lock_before_expiry=true,backend_pid=pid,owned_task_joined=true,backend_quiescent=true,independent_release=true});
        });
        await Check("total budget cancels actual row-blocked PostgreSQL acknowledgement with deduplicated replay",async()=>
        {
            var store=await Store();await mutate(store);var original=(await store.Payloads()).Single();var probe=new SqlProbe(connection,store.Schema);var source=new Adapter(probe.Provider);SqlLock? blocker=null;var locked=Signal();source.SinkOverride=async(record,token)=>{await probe.Provider.AppendOnceAsync(record,token);blocker=await probe.HoldRow();locked.TrySetResult();};var relay=Relay(source);using var caller=new CancellationTokenSource();var pending=new DrainHost(relay).RunWithTotalBudget(TimeSpan.FromSeconds(5),token:caller.Token).AsTask();int pid=0;
            try{await locked.Task.WaitAsync(TimeSpan.FromSeconds(10));pid=await probe.Observe("audit_outbox","SET delivered=true",pending,source);await source.ReleaseEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));Require(source.IndependentRelease);await blocker!.DisposeAsync();var error=Progress(await Failure(()=>pending).WaitAsync(TimeSpan.FromSeconds(10)),mayHaveDelivered:true);TimeoutKind(Child(error).PrimaryFailure,"drain");Require(await probe.Quiescent(pid)&&(await store.Counts())==(1,0,1));}
            finally{caller.Cancel();if(blocker is not null)await blocker.DisposeAsync();await Join(pending);}
            await Recover(store,source,relay);Require(probe.Provider.SinkCalls==2&&(await store.Payloads("audit_sink")).Single()==original);observe(new{phase="acknowledge",actual_postgres_lock_before_expiry=true,backend_pid=pid,owned_task_joined=true,backend_quiescent=true,independent_release=true,replay_deduplicated=true});
        });
        await Check("one total work token spans successful first batch and blocked next claim",async()=>
        {
            var store=await Store();await mutate(store);await mutate(store);var source=new Adapter(store);var pause=new Pause();source.ClaimOverride=async(tenant,maximum,duration,token)=>{if(source.Claims==2){await pause.Wait(token);Require(token.IsCancellationRequested);token.ThrowIfCancellationRequested();}return await store.ClaimAsync(tenant,maximum,duration,token);};using var caller=new CancellationTokenSource();var error=Progress(await Held(new(Relay(source)),Short,pause,caller,perBatch:1),2,1,1,0,true);TimeoutKind(error.PrimaryFailure,"drain");Require(source.Tokens.Count==2&&source.Tokens[0]==source.Tokens[1]&&source.Releases==1&&(await store.Counts())==(2,1,1));observe(new{phase="multiple_batches",shared_total_work_token=true,completed_batches=1,completed_acknowledged=1,failed_second_claim=true,no_retry=true});
        });
        await Check("total configured claim wrapper caller cancellation retains original caller token",async()=>
        {
            var store=await Store();var source=new Adapter(store);var pause=new Pause();source.ClaimOverride=async(_,_,_,token)=>{await pause.Wait(token);Require(token.IsCancellationRequested);token.ThrowIfCancellationRequested();return null;};using var caller=new CancellationTokenSource();var error=Progress(await Held(new(Relay(source)),TimeSpan.FromSeconds(10),pause,caller,async _=>{await pause.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));caller.Cancel();}));
            Require(error.PrimaryFailure is OperationCanceledException cancelled&&cancelled.CancellationToken==caller.Token&&source.Releases==0&&store.Claims==0);
        });
        await Check("total configured sink wrapper caller cancellation releases independently",async()=>
        {
            var store=await Store();await mutate(store);var source=new Adapter(store);var pause=new Pause();source.SinkOverride=async(_,token)=>{await pause.Wait(token);Require(token.IsCancellationRequested);token.ThrowIfCancellationRequested();};using var caller=new CancellationTokenSource();var error=Progress(await Held(new(Relay(source)),TimeSpan.FromSeconds(10),pause,caller,async _=>{await pause.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));caller.Cancel();}),mayHaveDelivered:true);
            Require(Child(error).PrimaryFailure is OperationCanceledException cancelled&&cancelled.CancellationToken==caller.Token&&source.IndependentRelease&&store.SinkCalls==0);
        });
        await Check("caller and total signals observed before selection choose original caller token",async()=>
        {
            var store=await Store();await mutate(store);var source=new Adapter(store);var pause=new Pause();source.SinkOverride=async(_,token)=>{await pause.Wait(token,true);Require(token.IsCancellationRequested);token.ThrowIfCancellationRequested();};using var caller=new CancellationTokenSource();var error=Progress(await Held(new(Relay(source)),Short,pause,caller,async _=>{await pause.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(10));caller.Cancel();pause.Release();}),mayHaveDelivered:true);
            Require(Child(error).PrimaryFailure is OperationCanceledException cancelled&&cancelled.CancellationToken==caller.Token&&source.IndependentRelease);observe(new{phase="both_signals",total_observed_before_caller=true,both_before_primary_selection=true,original_caller_token=true});
        });
        await Check("shorter per-batch timer remains selected under a longer total budget",async()=>
        {
            var store=await Store();await mutate(store);var source=new Adapter(store);var pause=new Pause();source.SinkOverride=async(_,token)=>{await pause.Wait(token);token.ThrowIfCancellationRequested();};using var caller=new CancellationTokenSource();var error=Progress(await Held(new(Relay(source,TimeSpan.FromSeconds(1))),TimeSpan.FromSeconds(10),pause,caller),mayHaveDelivered:true);TimeoutKind(Child(error).PrimaryFailure,"relay");Require(source.IndependentRelease);
        });
        await Check("shorter total timer is selected before a longer per-batch budget",async()=>
        {
            var store=await Store();await mutate(store);var source=new Adapter(store);var pause=new Pause();source.SinkOverride=async(_,token)=>{await pause.Wait(token);token.ThrowIfCancellationRequested();};using var caller=new CancellationTokenSource();var error=Progress(await Held(new(Relay(source,TimeSpan.FromSeconds(10))),Short,pause,caller),mayHaveDelivered:true);TimeoutKind(Child(error).PrimaryFailure,"drain");Require(source.IndependentRelease);
        });
        await Check("uncooperative sink wrapper after actual SQL is joined before total failure and replay deduplicates",async()=>
        {
            var store=await Store();await mutate(store);var original=(await store.Payloads()).Single();var source=new Adapter(store);var pause=new Pause();source.SinkOverride=async(record,token)=>{await store.AppendOnceAsync(record,token);await pause.Wait(token,true);};var relay=Relay(source);using var caller=new CancellationTokenSource();var error=Progress(await Held(new(relay),Short,pause,caller,async pending=>{await pause.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(10));Require(!pending.IsCompleted&&(await store.Counts())==(1,0,1));pause.Release();}),mayHaveDelivered:true);
            TimeoutKind(Child(error).PrimaryFailure,"drain");Require(source.IndependentRelease);await Recover(store,source,relay);Require(store.SinkCalls==2&&(await store.Payloads("audit_sink")).Single()==original);observe(new{phase="late_sink",physical_sink_committed=true,held_after_total_signal=true,owned_task_joined=true,fresh_replay_deduplicated=true});
        });
        await Check("late actual acknowledgement retains interrupted count after total expiry",async()=>
        {
            var store=await Store();await mutate(store);var source=new Adapter(store);var pause=new Pause();source.AckOverride=async(lease,id,token)=>{Require(await store.AcknowledgeAsync(lease,id,token));await pause.Wait(token);return true;};using var caller=new CancellationTokenSource();var error=Progress(await Held(new(Relay(source)),Short,pause,caller),interrupted:1,mayHaveDelivered:true);
            TimeoutKind(Child(error).PrimaryFailure,"drain");Require(source.IndependentRelease&&(await store.Counts())==(1,1,1));observe(new{phase="late_acknowledgement",completed_batches=0,interrupted_acknowledged=1,actual_delivered=1});
        });
        await Check("total expiry during awaited cleanup withholds child return but retains actual acknowledgement",async()=>
        {
            var store=await Store();await mutate(store);var source=new Adapter(store);var pause=new Pause();source.AfterRelease=async(_,releaseToken)=>{await pause.Wait(source.Tokens[0]);Require(!releaseToken.IsCancellationRequested);};using var caller=new CancellationTokenSource();var error=Progress(await Held(new(Relay(source)),Short,pause,caller),interrupted:1,mayHaveDelivered:true);
            TimeoutKind(Child(error).PrimaryFailure,"drain");Require(Child(error).ReleaseFailure is null&&source.IndependentRelease&&(await store.Counts())==(1,1,1));observe(new{phase="cleanup_expiry",completed_batches=0,interrupted_acknowledged=1,physical_release_before_expiry=true,independent_release_token=true});
        });
        await Check("unrelated sink cancellation is selected before later total expiry during release",async()=>
        {
            var store=await Store();await mutate(store);var preparedLease=await store.ClaimAsync(new("A"),1,TimeSpan.FromSeconds(30),default)??throw new InvalidOperationException();var source=new Adapter(store);var pause=new Pause();using var other=new CancellationTokenSource();using var caller=new CancellationTokenSource();other.Cancel();var original=new OperationCanceledException("Controlled unrelated sink wrapper cancellation.",other.Token);
            // The real owned lease is prepared before this timer; this particular claim is an explicit immediate wrapper.
            source.ClaimOverride=(_,_,_,_)=>ValueTask.FromResult<TenantChangeAuditOutboxLease?>(preparedLease);source.SinkOverride=(_,token)=>{Require(!caller.IsCancellationRequested&&!token.IsCancellationRequested);throw original;};source.AfterRelease=async(_,releaseToken)=>{await pause.Wait(source.Tokens[0]);Require(!releaseToken.IsCancellationRequested);};var error=Progress(await Held(new(Relay(source)),TimeSpan.FromSeconds(4),pause,caller),mayHaveDelivered:true);
            Require(ReferenceEquals(Child(error).PrimaryFailure,original)&&Child(error).ReleaseFailure is null&&source.Tokens[0].IsCancellationRequested&&source.IndependentRelease);observe(new{phase="early_unrelated_cancellation",exact_original_primary=true,total_signal_only_during_release=true,not_reclassified=true});
        });
        await Check("per-batch timeout selected before caller cancellation during release stays per-batch",async()=>
        {
            var store=await Store();await mutate(store);var source=new Adapter(store);var sinkPause=new Pause();var cleanupPause=new Pause();using var caller=new CancellationTokenSource();source.SinkOverride=async(_,token)=>{await sinkPause.Wait(token);token.ThrowIfCancellationRequested();};source.AfterRelease=async(_,releaseToken)=>{await cleanupPause.Wait(caller.Token);Require(!releaseToken.IsCancellationRequested);};
            var error=Progress(await Held(new(Relay(source,TimeSpan.FromSeconds(1))),TimeSpan.FromSeconds(10),sinkPause,caller,async _=>{await source.ReleaseEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));caller.Cancel();},alsoRelease:cleanupPause),mayHaveDelivered:true);TimeoutKind(Child(error).PrimaryFailure,"relay");Require(source.IndependentRelease&&Child(error).ReleaseFailure is null);observe(new{phase="early_per_batch_timeout",caller_signal_only_after_release_entry=true,selected_timeout_retained=true});
        });
        await Check("total timeout selected before caller cancellation during release stays total",async()=>
        {
            var store=await Store();await mutate(store);var source=new Adapter(store);var sinkPause=new Pause();var cleanupPause=new Pause();using var caller=new CancellationTokenSource();source.SinkOverride=async(_,token)=>{await sinkPause.Wait(token);token.ThrowIfCancellationRequested();};source.AfterRelease=async(_,releaseToken)=>{await cleanupPause.Wait(caller.Token);Require(!releaseToken.IsCancellationRequested);};
            var error=Progress(await Held(new(Relay(source)),Short,sinkPause,caller,async _=>{await source.ReleaseEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));caller.Cancel();},alsoRelease:cleanupPause),mayHaveDelivered:true);TimeoutKind(Child(error).PrimaryFailure,"drain");Require(source.IndependentRelease&&Child(error).ReleaseFailure is null);observe(new{phase="early_total_timeout",caller_signal_only_after_release_entry=true,selected_timeout_retained=true});
        });
        await Check("release-only cancellation after total expiry remains exact cleanup failure",async()=>
        {
            var store=await Store();await mutate(store);var source=new Adapter(store);var pause=new Pause();using var other=new CancellationTokenSource();other.Cancel();var original=new OperationCanceledException("Controlled release-only wrapper cancellation.",other.Token);source.AfterRelease=async(_,releaseToken)=>{await pause.Wait(source.Tokens[0]);Require(!releaseToken.IsCancellationRequested);throw original;};using var caller=new CancellationTokenSource();var error=Progress(await Held(new(Relay(source)),Short,pause,caller),interrupted:1,mayHaveDelivered:true);
            Require(Child(error).PrimaryFailure is null&&ReferenceEquals(Child(error).ReleaseFailure,original)&&source.IndependentRelease&&(await store.Counts())==(1,1,1));observe(new{phase="release_only_cancellation",exact_release_failure=true,primary_remains_null=true,total_expired=true,interrupted_acknowledged=1});
        });
        await Check("unrelated sink fault after total signal retains original fault reference",async()=>
        {
            var store=await Store();await mutate(store);var source=new Adapter(store);var pause=new Pause();var original=new IOException("Controlled unrelated sink wrapper fault.");source.SinkOverride=async(_,token)=>{await pause.Wait(token);throw original;};using var caller=new CancellationTokenSource();var error=Progress(await Held(new(Relay(source)),Short,pause,caller),mayHaveDelivered:true);Require(ReferenceEquals(Child(error).PrimaryFailure,original)&&source.IndependentRelease);
        });
        await Check("foreign partial relay exception after total expiry stays original without borrowed progress",async()=>
        {
            var store=await Store();await mutate(store);var foreign=await ForeignFailure(store);var source=new Adapter(store);var pause=new Pause();source.ClaimOverride=async(_,_,_,token)=>{await pause.Wait(token);throw foreign;};using var caller=new CancellationTokenSource();var error=Progress(await Held(new(Relay(source)),Short,pause,caller));
            Require(ReferenceEquals(error.PrimaryFailure,foreign)&&foreign.AcknowledgedCount==1&&foreign.MayHaveDelivered&&source.Releases==0&&(await store.Counts())==(1,0,0)&&(await store.Counts("B"))==(2,1,2));observe(new{phase="foreign_claim",prior_error_tenant="B",prior_error_acknowledged=1,current_acknowledged=0,current_may_have_delivered=false,exact_foreign_primary=true,total_expired=true});
        });
        await Check("total opt-in retains exact tenant and fresh operation authority",async()=>
        {
            var store=await Store();await mutate(store);var source=new Adapter(store);var host=new DrainHost(Relay(source));Require(!(await host.RunWithTotalBudget(Short,"B")).IsSuccess&&source.Claims==0);host.Authority.AllowB=true;Require(!(await host.RunWithTotalBudget(Short,"C")).IsSuccess&&source.Claims==0);var b=await host.RunWithTotalBudget(Short,"B");Require(b.IsSuccess&&b.Value.AcknowledgedCount==0&&source.Claims==1&&(await store.Counts())==(1,0,0));host.Authority.AllowDrain=false;Require(!(await host.RunWithTotalBudget(Short)).IsSuccess&&source.Claims==1);host.Authority.AllowDrain=true;Require((await host.RunWithTotalBudget(Short)).IsSuccess&&host.Authority.IdentityLookups==5&&(await store.Counts())==(1,1,1));
        });
        await Check("total opt-in rejects pre-caller and disposed checked scopes before further claim",async()=>
        {
            var store=await Store();await mutate(store);var source=new Adapter(store);var relay=Relay(source);var host=new DrainHost(relay);using var caller=new CancellationTokenSource();caller.Cancel();var cancelled=await Failure(()=>host.RunWithTotalBudget(Short,token:caller.Token).AsTask());Require(cancelled is OperationCanceledException oce&&oce.CancellationToken==caller.Token&&source.Claims==0);
            Require((await host.RunWithTotalBudget(Short)).IsSuccess);var claims=source.Claims;Require(await Failure(()=>relay.DrainWithBudgetAsync(host.RetainedContext!,Short).AsTask()) is TenantAccessDeniedException&&source.Claims==claims);
        });
    }
    private static async Task<TenantChangeAuditOutboxRelayException> ForeignFailure(PostgresStore store)
    {
        for(var i=0;i<2;i++)
        {
            var integration=new OutboxIntegration(store,OutboxIntegration.Policy(TenantChangeAuditMode.ChangedFields));using var tls=new TlsFixture();using var jwt=new JwtFixture();await using var host=new Host();await host.Start(tls,jwt,trailProfile:new(TenantChangeAuditMode.ChangedFields),trailIntegration:integration);
            using var client=tls.Client(host.Address);using var request=new HttpRequestMessage(HttpMethod.Post,"/entity/update"){Content=JsonContent.Create(new EntityMutationRequest("B","shared","total-drain",5,"private-total"))};request.Headers.Authorization=new("Bearer",jwt.Token("bob"));using var response=await client.SendAsync(request);Require(response.IsSuccessStatusCode);
        }
        var source=new Adapter(store);var fault=new IOException("Controlled foreign B second acknowledgement failure.");source.AckOverride=async(lease,id,token)=>{if(source.Acks==2)throw fault;return await store.AcknowledgeAsync(lease,id,token);};var hostRelay=new RelayHost(Relay(source));hostRelay.Authority.AllowB=true;var error=await Failure(()=>hostRelay.Run("B",2).AsTask());Require(error is TenantChangeAuditOutboxRelayException foreign&&foreign.AcknowledgedCount==1&&foreign.MayHaveDelivered&&ReferenceEquals(foreign.PrimaryFailure,fault));return(TenantChangeAuditOutboxRelayException)error;
    }
    private sealed class Pause
    {
        public TaskCompletionSource Entered{get;}=Signal();public TaskCompletionSource Cancelled{get;}=Signal();private readonly TaskCompletionSource exit=Signal();
        public async Task Wait(CancellationToken token,bool holdAfterCancellation=false)
        {using var registration=token.Register(()=>{Cancelled.TrySetResult();if(!holdAfterCancellation)exit.TrySetResult();});Entered.TrySetResult();await exit.Task;}
        public void Release()=>exit.TrySetResult();
    }
    private sealed class Adapter(PostgresStore store):ITenantChangeAuditOutboxSource,ITenantChangeAuditIdempotentSink
    {
        public Func<TenantId,int,TimeSpan,CancellationToken,ValueTask<TenantChangeAuditOutboxLease?>>? ClaimOverride;
        public Func<TenantChangeAuditRecord,CancellationToken,ValueTask>? SinkOverride;
        public Func<TenantChangeAuditOutboxLease,Guid,CancellationToken,ValueTask<bool>>? AckOverride;
        public Func<TenantChangeAuditOutboxLease,CancellationToken,Task>? AfterRelease;
        public int Claims,Acks,Releases;public List<CancellationToken> Tokens{get;}=[];public CancellationToken SinkToken,AckToken;public bool IndependentRelease;public TaskCompletionSource ReleaseEntered{get;}=Signal();
        public async ValueTask<TenantChangeAuditOutboxLease?> ClaimAsync(TenantId tenant,int maximum,TimeSpan duration,CancellationToken token)
        {Claims++;Tokens.Add(token);return ClaimOverride is null?await store.ClaimAsync(tenant,maximum,duration,token):await ClaimOverride(tenant,maximum,duration,token);}
        public async ValueTask AppendOnceAsync(TenantChangeAuditRecord record,CancellationToken token)
        {SinkToken=token;if(SinkOverride is null)await store.AppendOnceAsync(record,token);else await SinkOverride(record,token);}
        public async ValueTask<bool> AcknowledgeAsync(TenantChangeAuditOutboxLease lease,Guid id,CancellationToken token)
        {Acks++;AckToken=token;return AckOverride is null?await store.AcknowledgeAsync(lease,id,token):await AckOverride(lease,id,token);}
        public async ValueTask ReleaseAsync(TenantChangeAuditOutboxLease lease,CancellationToken token)
        {Releases++;IndependentRelease=token.CanBeCanceled&&!token.IsCancellationRequested&&token!=Tokens.Last();ReleaseEntered.TrySetResult();await store.ReleaseAsync(lease,token);if(AfterRelease is not null)await AfterRelease(lease,token);}
    }
    private sealed class SqlLock(NpgsqlConnection connection,NpgsqlTransaction transaction):IAsyncDisposable
    {
        private int disposed;
        public async ValueTask DisposeAsync(){if(Interlocked.Exchange(ref disposed,1)!=0)return;try{await transaction.RollbackAsync();}finally{await transaction.DisposeAsync();await connection.DisposeAsync();}}
    }
    private sealed class SqlProbe
    {
        private readonly string connection,schema;private readonly string tag="owned-total-drain-"+Guid.NewGuid().ToString("N");public PostgresStore Provider{get;}
        public SqlProbe(string connection,string schema){this.connection=connection;this.schema=schema;Provider=new(new NpgsqlConnectionStringBuilder(connection){ApplicationName=tag}.ConnectionString,schema);}
        private async Task<NpgsqlConnection> Open(){var c=new NpgsqlConnection(connection);try{await c.OpenAsync();return c;}catch{await c.DisposeAsync();throw;}}
        private async Task<SqlLock> Hold(string sql){var c=await Open();var tx=await c.BeginTransactionAsync();try{await using var command=new NpgsqlCommand(sql,c,tx);await command.ExecuteNonQueryAsync();return new(c,tx);}catch{await tx.DisposeAsync();await c.DisposeAsync();throw;}}
        public Task<SqlLock> HoldTable(string table){Require(table is "audit_outbox" or "audit_sink");return Hold($"LOCK TABLE {schema}.{table} IN ACCESS EXCLUSIVE MODE");}
        public Task<SqlLock> HoldRow()=>Hold($"SELECT receipt FROM {schema}.audit_outbox WHERE tenant='A' AND NOT delivered FOR UPDATE");
        public async Task<int> Observe(string table,string fragment,Task pending,Adapter source)
        {
            await using var c=await Open();for(var i=0;i<100;i++)
            {
                await using var command=new NpgsqlCommand("SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE $2 AND query LIKE $3",c);command.Parameters.AddWithValue(tag);command.Parameters.AddWithValue("%"+schema+"."+table+"%");command.Parameters.AddWithValue("%"+fragment+"%");var result=await command.ExecuteScalarAsync();
                if(result is int pid){Require(!pending.IsCompleted&&!source.Tokens[0].IsCancellationRequested);return pid;}Require(!pending.IsCompleted);await Task.Delay(20);
            }
            throw new InvalidOperationException("Actual owned SQL Lock wait not observed before total expiry.");
        }
        public async Task<bool> Quiescent(int pid){Require(pid>0);await using var c=await Open();await using var command=new NpgsqlCommand("SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND application_name=$2 AND (state='active' OR wait_event_type='Lock'))",c);command.Parameters.AddWithValue(pid);command.Parameters.AddWithValue(tag);return(bool)(await command.ExecuteScalarAsync())!;}
    }
}
