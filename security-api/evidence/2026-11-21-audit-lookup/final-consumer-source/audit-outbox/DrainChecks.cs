extern alias securityapi;
using System.Net.Http.Json;
using Cehpalon.Engine.Tenancy;
using securityapi::SecurityApi;
using Host=securityapi::SecurityApi.Host;

namespace AuditOutbox;

// SQL remains the original PostgresStore. Fault/wait/clock controls below are explicit fixture wrappers.
public static class DrainChecks
{
    private static void Require(bool value){if(!value)throw new InvalidOperationException("Bounded drain consumer assertion failed.");}
    private static async Task<Exception> Failure(Func<Task> action)
    {try{await action();}catch(Exception error){return error;}throw new InvalidOperationException("Expected bounded drain failure.");}
    private static async Task Join(Task task){try{await task;}catch(Exception){}}
    private static TenantChangeAuditOutboxRelay Relay(Adapter source,TimeSpan? budget=null,TimeProvider? clock=null)
        =>TenantChangeAuditOutboxRelay.ActivateWithBudget(true,budget,()=>source,()=>source,TimeSpan.FromSeconds(30),clock)!;
    private static TenantChangeAuditOutboxDrainException Progress(Exception error,int started,int completed,int completedAck,int interrupted,bool mayHaveDelivered)
    {
        Require(error is TenantChangeAuditOutboxDrainException);var value=(TenantChangeAuditOutboxDrainException)error;
        Require(value.Tenant.Value=="A"&&value.StartedBatches==started&&value.CompletedBatches==completed&&value.CompletedAcknowledgedCount==completedAck&&value.InterruptedAcknowledgedCount==interrupted&&value.AcknowledgedCount==completedAck+interrupted&&value.MayHaveDelivered==mayHaveDelivered&&ReferenceEquals(value.PrimaryFailure,value.InnerException));return value;
    }
    private static async Task<TenantChangeAuditOutboxDrainResult> Read(DrainHost host,string tenant="A",int batches=16,int records=2048,int perBatch=128)
    {var result=await host.Run(tenant,batches,records,perBatch);Require(result.IsSuccess);return result.Value;}
    private static void Result(TenantChangeAuditOutboxDrainResult value,int batches,int acknowledged,TenantChangeAuditOutboxDrainStopReason reason,string tenant="A")
        =>Require(value.Tenant.Value==tenant&&value.CompletedBatches==batches&&value.AcknowledgedCount==acknowledged&&value.StopReason==reason);
    private static async Task Recover(PostgresStore store,Adapter source,TenantChangeAuditOutboxRelay relay,int total)
    {
        source.ClaimOverride=null;source.SinkOverride=null;source.AckOverride=null;source.AfterRelease=null;
        var fresh=new DrainHost(relay);fresh.Authority.AllowDrain=false;var claims=source.Claims;Require(!(await fresh.Run()).IsSuccess&&source.Claims==claims);fresh.Authority.AllowDrain=true;await Read(fresh);
        Require(fresh.Authority.IdentityLookups==2&&(await store.Counts())==(total,total,total));
    }
    public static async Task Run(Func<string,Func<Task>,Task> outerCheck,Func<Task<PostgresStore>> createStore,Func<PostgresStore,Task> mutate,string connection,Action<object> observe)
    {
        var owned=new List<PostgresStore>();
        async Task<PostgresStore> Store(){var store=await createStore();owned.Add(store);return store;}
        async Task Check(string name,Func<Task> action)=>await outerCheck(name,async()=>{owned.Clear();await action();Require(owned.All(s=>s.StatusReads==0&&s.HistoryReads==0));});
        async Task Seed(PostgresStore store,int count){for(var i=0;i<count;i++)await mutate(store);}
        await Check("drain disabled selection skips poisoned factories and all SQL",()=>
        {
            var store=new PostgresStore(connection,"ao_"+Guid.NewGuid().ToString("N"));var factories=0;
            Require(DrainHost.Activate(false,()=>{factories++;throw new InvalidOperationException();}) is null&&TenantChangeAuditOutboxRelay.ActivateWithBudget(false,TimeSpan.Zero,()=>{factories++;throw new InvalidOperationException();}) is null&&factories==0&&store.Connections==0&&store.StatusReads==0&&store.HistoryReads==0);return Task.CompletedTask;
        });
        await Check("generated drain registration is typed and lazy before selected dispatch",()=>
        {
            var store=new PostgresStore(connection,"ao_"+Guid.NewGuid().ToString("N"));var source=new Adapter(store);var host=new DrainHost(Relay(source));Require(host.GatewayFactories==0&&host.HandlerFactories==0&&source.Claims==0&&store.Connections==0);return Task.CompletedTask;
        });
        await Check("drain bounds and pre-caller cancellation reject before provider claim",async()=>
        {
            var store=await Store();var source=new Adapter(store);var host=new DrainHost(Relay(source));
            foreach(var bounds in new[]{(0,1,1),(17,1,1),(1,0,1),(1,2049,1),(1,1,0),(1,1,129)})Require(await Failure(()=>host.Run(batches:bounds.Item1,records:bounds.Item2,perBatch:bounds.Item3).AsTask()) is ArgumentOutOfRangeException);
            using var cancelled=new CancellationTokenSource();cancelled.Cancel();var error=await Failure(()=>host.Run(token:cancelled.Token).AsTask());Require(error is OperationCanceledException oce&&oce.CancellationToken==cancelled.Token&&source.Claims==0&&store.SinkCalls==0&&store.Releases==0);
        });
        await Check("default actual PostgreSQL drain returns acknowledgement progress then NoProgress",async()=>
        {
            var store=await Store();await Seed(store,3);var source=new Adapter(store);var host=new DrainHost(Relay(source));Result(await Read(host),2,3,TenantChangeAuditOutboxDrainStopReason.NoProgress);Require(source.Requests.SequenceEqual(new[]{128,128})&&source.Releases==1&&(await store.Counts())==(3,3,3));
        });
        await Check("actual PostgreSQL remaining record cap reduces final requested batch",async()=>
        {
            var store=await Store();await Seed(store,5);var source=new Adapter(store);var relay=Relay(source);Result(await Read(new(relay),records:3,perBatch:2),2,3,TenantChangeAuditOutboxDrainStopReason.RecordLimit);Require(source.Requests.SequenceEqual(new[]{2,1})&&(await store.Counts())==(5,3,3));await Recover(store,source,relay,5);
        });
        await Check("actual PostgreSQL batch cap stops without claiming a third batch",async()=>
        {
            var store=await Store();await Seed(store,5);var source=new Adapter(store);Result(await Read(new(Relay(source)),batches:2,records:8,perBatch:2),2,4,TenantChangeAuditOutboxDrainStopReason.BatchLimit);Require(source.Requests.SequenceEqual(new[]{2,2})&&source.Releases==2&&(await store.Counts())==(5,4,4));
        });
        await Check("record limit takes precedence when actual record and batch limits tie",async()=>
        {
            var store=await Store();await Seed(store,2);var source=new Adapter(store);Result(await Read(new(Relay(source)),batches:1,records:2,perBatch:2),1,2,TenantChangeAuditOutboxDrainStopReason.RecordLimit);Require(source.Claims==1&&source.Releases==1&&(await store.Counts())==(2,2,2));
        });
        await Check("positive underfilled actual batch continues to independently produced PostgreSQL work",async()=>
        {
            var store=await Store();await Seed(store,1);var source=new Adapter(store);var produced=false;
            source.AfterRelease=async(_,_)=>{if(source.Releases==1){await Task.Run(()=>mutate(store));produced=true;}};var host=new DrainHost(Relay(source));Result(await Read(host,perBatch:3),3,2,TenantChangeAuditOutboxDrainStopReason.NoProgress);
            Require(produced&&source.Requests.SequenceEqual(new[]{3,3,3})&&source.Releases==2&&host.Authority.IdentityLookups==1&&(await store.Counts())==(2,2,2));observe(new{case_name="underfill",positive_underfilled_batches=2,independently_scheduled_writer_joined=true,acknowledged=2});
        });
        await Check("active PostgreSQL claims yield NoProgress while pending rows still exist",async()=>
        {
            var store=await Store();await Seed(store,3);var held=await store.ClaimAsync(new("A"),3,TimeSpan.FromSeconds(30),default)??throw new InvalidOperationException();var source=new Adapter(store);var relay=Relay(source);
            try{Result(await Read(new(relay)),1,0,TenantChangeAuditOutboxDrainStopReason.NoProgress);Require(source.Claims==1&&source.Releases==0&&(await store.Counts())==(3,0,0));}finally{await store.ReleaseAsync(held,default);}
            await Recover(store,source,relay,3);observe(new{case_name="active_claim",no_progress_with_pending=3,claim_released_before_fresh_manual_replay=true});
        });
        await Check("first poison sink stops actual drain without automatic retry",async()=>
        {
            var store=await Store();await Seed(store,2);var source=new Adapter(store);var relay=Relay(source);store.Fault=ProviderFault.Sink;var error=Progress(await Failure(()=>new DrainHost(relay).Run().AsTask()),1,0,0,0,true);
            Require(error.PrimaryFailure is TenantChangeAuditOutboxRelayException child&&child.PrimaryFailure is IOException&&source.Claims==1&&source.Releases==1&&(await store.Counts())==(2,0,0));store.Fault=ProviderFault.None;await Recover(store,source,relay,2);
        });
        await Check("later poison preserves earlier actual batch and stops before further claims",async()=>
        {
            var store=await Store();await Seed(store,3);var source=new Adapter(store);var poison=new IOException("Controlled second sink wrapper fault.");source.SinkOverride=async(record,token)=>{if(source.Sinks==2)throw poison;await store.AppendOnceAsync(record,token);};var relay=Relay(source);
            var error=Progress(await Failure(()=>new DrainHost(relay).Run(perBatch:1).AsTask()),2,1,1,0,true);Require(error.PrimaryFailure is TenantChangeAuditOutboxRelayException child&&ReferenceEquals(child.PrimaryFailure,poison)&&source.Claims==2&&source.Releases==2&&(await store.Counts())==(3,1,1));await Recover(store,source,relay,3);
        });
        await Check("mid-batch acknowledgement fault retains interrupted progress and deduplicates fresh replay",async()=>
        {
            var store=await Store();await Seed(store,3);var source=new Adapter(store);var poison=new IOException("Controlled second acknowledgement wrapper fault.");source.AckOverride=async(lease,id,token)=>{if(source.Acks==2)throw poison;return await store.AcknowledgeAsync(lease,id,token);};var relay=Relay(source);
            var error=Progress(await Failure(()=>new DrainHost(relay).Run(perBatch:3).AsTask()),1,0,0,1,true);Require(error.PrimaryFailure is TenantChangeAuditOutboxRelayException child&&ReferenceEquals(child.PrimaryFailure,poison)&&source.Claims==1&&source.Releases==1&&(await store.Counts())==(3,1,2));await Recover(store,source,relay,3);Require(store.SinkCalls==4);
        });
        await Check("lost acknowledgement wrapper after actual commit remains uncertain rather than counted",async()=>
        {
            var store=await Store();await Seed(store,2);var source=new Adapter(store);var lost=new IOException("Controlled lost acknowledgement after physical SQL update.");source.AckOverride=async(lease,id,token)=>{Require(await store.AcknowledgeAsync(lease,id,token));throw lost;};var relay=Relay(source);
            var error=Progress(await Failure(()=>new DrainHost(relay).Run().AsTask()),1,0,0,0,true);Require(error.PrimaryFailure is TenantChangeAuditOutboxRelayException child&&ReferenceEquals(child.PrimaryFailure,lost)&&source.Claims==1&&source.Releases==1&&(await store.Counts())==(2,1,1));await Recover(store,source,relay,2);
        });
        await Check("physical release then cleanup wrapper fault preserves acknowledgement without outer release",async()=>
        {
            var store=await Store();await Seed(store,2);var source=new Adapter(store);var cleanup=new IOException("Controlled post-release wrapper fault.");source.AfterRelease=(_,_)=>throw cleanup;var relay=Relay(source);
            var error=Progress(await Failure(()=>new DrainHost(relay).Run().AsTask()),1,0,0,2,true);Require(error.PrimaryFailure is TenantChangeAuditOutboxRelayException child&&child.PrimaryFailure is null&&ReferenceEquals(child.ReleaseFailure,cleanup)&&source.Claims==1&&source.Releases==1&&(await store.Counts())==(2,2,2));await Recover(store,source,relay,2);
        });
        await Check("each drain batch retains its own cooperative budget and a failed next claim is not retried",async()=>
        {
            var store=await Store();await Seed(store,2);var source=new Adapter(store);var signal=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);using var caller=new CancellationTokenSource();
            source.ClaimOverride=async(tenant,maximum,duration,token)=>{if(source.Claims==2){using var registration=token.Register(()=>signal.TrySetResult());await signal.Task;Require(token.IsCancellationRequested);token.ThrowIfCancellationRequested();}return await store.ClaimAsync(tenant,maximum,duration,token);};var relay=Relay(source,TimeSpan.FromSeconds(2));var pending=new DrainHost(relay).Run(perBatch:1,token:caller.Token).AsTask();
            try{var error=Progress(await Failure(()=>pending).WaitAsync(TimeSpan.FromSeconds(15)),2,1,1,0,true);Require(error.PrimaryFailure is TimeoutException&&source.Claims==2&&source.Releases==1&&(await store.Counts())==(2,1,1));}
            finally{signal.TrySetResult();caller.Cancel();await Join(pending);}
            await Recover(store,source,relay,2);
        });
        await Check("deterministic final lease clock callback cancels after relay return and retains completed batch",async()=>
        {
            var store=await Store();await Seed(store,1);var source=new Adapter(store);var relayClock=new FixtureClock();using var caller=new CancellationTokenSource();source.AfterRelease=(_,_)=>{relayClock.AfterNextUtcRead=caller.Cancel;return Task.CompletedTask;};var relay=Relay(source,clock:relayClock);
            var error=Progress(await Failure(()=>new DrainHost(relay).Run(perBatch:1,token:caller.Token).AsTask()),1,1,1,0,true);Require(error.PrimaryFailure is OperationCanceledException cancelled&&cancelled.CancellationToken==caller.Token&&source.Claims==1&&source.Releases==1&&(await store.Counts())==(1,1,1));observe(new{case_name="post_count_caller",control="relay final lease clock callback after final caller/scope guards",completed_batches=1,completed_acknowledged=1,interrupted_acknowledged=0});
        });
        await Check("deterministic final lease clock callback expires scope after relay return and retains completed batch",async()=>
        {
            var store=await Store();await Seed(store,1);var source=new Adapter(store);var relayClock=new FixtureClock();var authorityClock=new FixtureClock();source.AfterRelease=(_,_)=>{relayClock.AfterNextUtcRead=()=>authorityClock.Advance(TimeSpan.FromMinutes(1));return Task.CompletedTask;};var host=new DrainHost(Relay(source,clock:relayClock),authorityClock);
            var error=Progress(await Failure(()=>host.Run(perBatch:1).AsTask()),1,1,1,0,true);Require(error.PrimaryFailure is TenantAccessDeniedException&&source.Claims==1&&source.Releases==1&&(await store.Counts())==(1,1,1));observe(new{case_name="post_count_scope",control="relay final lease clock callback after final checked-scope guard",completed_batches=1,completed_acknowledged=1,interrupted_acknowledged=0});
        });
        await Check("drain exact tenant grant does not grant arbitrary tenant or another queue",async()=>
        {
            var store=await Store();await Seed(store,1);var source=new Adapter(store);var host=new DrainHost(Relay(source));Require(!(await host.Run("B")).IsSuccess&&source.Claims==0);host.Authority.AllowB=true;Require(!(await host.Run("C")).IsSuccess&&source.Claims==0);Result(await Read(host,"B"),1,0,TenantChangeAuditOutboxDrainStopReason.NoProgress,"B");Require((await store.Counts())==(1,0,0));await Read(host);Require((await store.Counts())==(1,1,1));
        });
        await Check("one fresh drain identity lookup covers scope rechecks and later revocation is fresh",async()=>
        {
            var store=await Store();await Seed(store,3);var source=new Adapter(store);var host=new DrainHost(Relay(source));Result(await Read(host,perBatch:1),4,3,TenantChangeAuditOutboxDrainStopReason.NoProgress);Require(host.Authority.IdentityLookups==1&&host.Authority.PolicyLookups==1&&source.Claims==4);host.Authority.Active=false;Require(!(await host.Run()).IsSuccess&&source.Claims==4&&host.Authority.IdentityLookups==2);
        });
        await Check("ordinary relay operation grant does not grant generated drain operation",async()=>
        {
            var store=await Store();await Seed(store,1);var source=new Adapter(store);var host=new DrainHost(Relay(source));host.Authority.GrantedOperation="outbox.relay";Require(!(await host.Run()).IsSuccess&&source.Claims==0&&host.HandlerFactories==0);host.Authority.GrantedOperation="outbox.drain";await Read(host);Require(host.Authority.IdentityLookups==2&&(await store.Counts())==(1,1,1));
        });
        await Check("retained disposed drain context cannot start a second provider batch",async()=>
        {
            var store=await Store();await Seed(store,1);var source=new Adapter(store);var relay=Relay(source);var host=new DrainHost(relay);await Read(host);var claims=source.Claims;Require(await Failure(()=>relay.DrainAsync(host.RetainedContext!).AsTask()) is TenantAccessDeniedException&&source.Claims==claims);
        });
        await Check("foreign tenant prior partial relay exception in claim cannot donate interrupted progress",async()=>
        {
            var store=await Store();await Seed(store,2);var foreign=await PriorForeignFailure(store);var source=new Adapter(store);source.ClaimOverride=async(tenant,maximum,duration,token)=>{if(source.Claims==2)throw foreign;return await store.ClaimAsync(tenant,maximum,duration,token);};
            var error=Progress(await Failure(()=>new DrainHost(Relay(source)).Run(perBatch:1).AsTask()),2,1,1,0,true);Require(ReferenceEquals(error.PrimaryFailure,foreign)&&foreign.AcknowledgedCount==1&&source.Claims==2&&source.Releases==1&&(await store.Counts())==(2,1,1)&&(await store.Counts("B"))==(2,1,2));observe(new{case_name="foreign_claim",prior_error_tenant="B",prior_error_acknowledged=1,current_completed_acknowledged=1,current_interrupted_acknowledged=0,exact_foreign_failure_reference_retained=true});
        });
        await Check("foreign relay exception inside current sink counts only the current owned invocation",async()=>
        {
            var store=await Store();await Seed(store,1);var foreign=await PriorForeignFailure(store);var source=new Adapter(store);source.SinkOverride=(_,_)=>throw foreign;
            var error=Progress(await Failure(()=>new DrainHost(Relay(source)).Run().AsTask()),1,0,0,0,true);Require(error.PrimaryFailure is TenantChangeAuditOutboxRelayException current&&!ReferenceEquals(current,foreign)&&ReferenceEquals(current.PrimaryFailure,foreign)&&current.AcknowledgedCount==0&&source.Claims==1&&source.Releases==1&&(await store.Counts())==(1,0,0)&&(await store.Counts("B"))==(2,1,2));observe(new{case_name="foreign_sink",prior_error_tenant="B",prior_error_acknowledged=1,current_completed_acknowledged=0,current_interrupted_acknowledged=0,current_owned_relay_failure_wraps_exact_foreign_error=true});
        });
        await Check("live writer context cannot enter drain before PostgreSQL claim",async()=>
        {
            var store=await Store();var source=new Adapter(store);var relay=Relay(source);var denied=false;
            await MutateTenant(store,"A",async context=>{try{await relay.DrainAsync(context);}catch(TenantAccessDeniedException){denied=true;}});Require(denied&&source.Claims==0&&(await store.Counts())==(1,0,0));
        });
    }
    private static async Task<TenantChangeAuditOutboxRelayException> PriorForeignFailure(PostgresStore store)
    {
        await MutateTenant(store,"B");await MutateTenant(store,"B");var foreignSource=new Adapter(store);var fault=new IOException("Controlled foreign-tenant second acknowledgement wrapper failure.");foreignSource.AckOverride=async(lease,id,token)=>{if(foreignSource.Acks==2)throw fault;return await store.AcknowledgeAsync(lease,id,token);};var host=new RelayHost(Relay(foreignSource));host.Authority.AllowB=true;var error=await Failure(()=>host.Run("B",2).AsTask());Require(error is TenantChangeAuditOutboxRelayException foreign&&foreign.AcknowledgedCount==1&&foreign.MayHaveDelivered&&ReferenceEquals(foreign.PrimaryFailure,fault)&&(await store.Counts("B"))==(2,1,2));return(TenantChangeAuditOutboxRelayException)error;
    }
    private static async Task MutateTenant(PostgresStore store,string tenant,Func<TenantOperationContext,Task>? afterMutation=null)
    {
        var integration=new OutboxIntegration(store,OutboxIntegration.Policy(TenantChangeAuditMode.ChangedFields)){AfterMutation=afterMutation};using var tls=new TlsFixture();using var jwt=new JwtFixture();await using var host=new Host();await host.Start(tls,jwt,trailProfile:new(TenantChangeAuditMode.ChangedFields),trailIntegration:integration);
        using var client=tls.Client(host.Address);using var request=new HttpRequestMessage(HttpMethod.Post,"/entity/update"){Content=JsonContent.Create(new EntityMutationRequest(tenant,"shared","bounded-drain",4,"private-drain"))};request.Headers.Authorization=new("Bearer",jwt.Token(tenant=="B"?"bob":"alice"));using var response=await client.SendAsync(request);Require(response.IsSuccessStatusCode);
    }
    private sealed class Adapter(PostgresStore store):ITenantChangeAuditOutboxSource,ITenantChangeAuditIdempotentSink
    {
        public Func<TenantId,int,TimeSpan,CancellationToken,ValueTask<TenantChangeAuditOutboxLease?>>? ClaimOverride;
        public Func<TenantChangeAuditRecord,CancellationToken,ValueTask>? SinkOverride;
        public Func<TenantChangeAuditOutboxLease,Guid,CancellationToken,ValueTask<bool>>? AckOverride;
        public Func<TenantChangeAuditOutboxLease,CancellationToken,Task>? AfterRelease;
        public int Claims,Sinks,Acks,Releases;public List<int> Requests{get;}=[];
        public async ValueTask<TenantChangeAuditOutboxLease?> ClaimAsync(TenantId tenant,int maximum,TimeSpan duration,CancellationToken token)
        {Claims++;Requests.Add(maximum);return ClaimOverride is null?await store.ClaimAsync(tenant,maximum,duration,token):await ClaimOverride(tenant,maximum,duration,token);}
        public async ValueTask AppendOnceAsync(TenantChangeAuditRecord record,CancellationToken token)
        {Sinks++;if(SinkOverride is null)await store.AppendOnceAsync(record,token);else await SinkOverride(record,token);}
        public async ValueTask<bool> AcknowledgeAsync(TenantChangeAuditOutboxLease lease,Guid id,CancellationToken token)
        {Acks++;return AckOverride is null?await store.AcknowledgeAsync(lease,id,token):await AckOverride(lease,id,token);}
        public async ValueTask ReleaseAsync(TenantChangeAuditOutboxLease lease,CancellationToken token)
        {Releases++;await store.ReleaseAsync(lease,token);if(AfterRelease is not null)await AfterRelease(lease,token);}
    }
    // This is a deterministic guard-order fixture, not a physical timer/latency observation.
    private sealed class FixtureClock:TimeProvider
    {
        private DateTimeOffset now=DateTimeOffset.UtcNow;private long timestamp;public Action? AfterNextUtcRead;
        public override long TimestampFrequency=>TimeSpan.TicksPerSecond;
        public override DateTimeOffset GetUtcNow(){var result=now;var callback=AfterNextUtcRead;AfterNextUtcRead=null;callback?.Invoke();return result;}
        public override long GetTimestamp()=>timestamp;
        public void Advance(TimeSpan duration){now+=duration;timestamp+=duration.Ticks;}
    }
}
