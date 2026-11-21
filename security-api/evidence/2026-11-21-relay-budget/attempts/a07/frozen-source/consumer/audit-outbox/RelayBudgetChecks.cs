extern alias securityapi;
using System.Net.Http.Json;
using Cehpalon.Engine.Tenancy;
using Npgsql;
using securityapi::SecurityApi;
using Host=securityapi::SecurityApi.Host;

namespace AuditOutbox;

// Delegate waits/faults are wrappers. Only tagged Lock cases establish actual PG SQL cancellation.
public static class RelayBudgetChecks
{
    private static readonly TimeSpan Budget=TimeSpan.FromSeconds(2);
    private static void Require(bool value){if(!value)throw new InvalidOperationException("Relay budget consumer assertion failed.");}
    private static TaskCompletionSource Signal()=>new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static async Task Cancelled(CancellationToken token)
    {try{await Task.Delay(Timeout.InfiniteTimeSpan,token);}catch(OperationCanceledException) when(token.IsCancellationRequested){}}
    private static async Task<Exception> Failure(Task task)
    {try{await task;}catch(Exception error){return error;}throw new InvalidOperationException("Expected relay failure.");}
    private static async Task Join(Task task){try{await task;}catch(Exception){}}
    private static TenantChangeAuditOutboxRelay Relay(Adapter adapter,TimeSpan? timeout)
        =>TenantChangeAuditOutboxRelay.ActivateWithBudget(true,timeout,()=>adapter,()=>adapter,TimeSpan.FromSeconds(30))!;
    private static async Task FreshReplay(PostgresStore store,Adapter adapter,TenantChangeAuditOutboxRelay relay)
    {
        adapter.ClaimOverride=null;adapter.SinkOverride=null;adapter.AckOverride=null;adapter.ReleaseOverride=null;
        var host=new RelayHost(relay);host.Authority.AllowRelay=false;var claims=adapter.Claims;
        Require(!(await host.Run()).IsSuccess&&adapter.Claims==claims);
        host.Authority.AllowRelay=true;var result=await host.Run();
        Require(result.IsSuccess&&result.Value.Acknowledged==1&&host.Authority.IdentityLookups==2&&(await store.Counts())==(1,1,1));
    }
    public static async Task Run(Func<string,Func<Task>,Task> check,Func<Task<PostgresStore>> createStore,Func<PostgresStore,Task> mutate,string connection,Action<object> observe)
    {
        await check("relay budget disabled skips invalid bounds and poisoned factories",()=>
        {
            var calls=0;var relay=TenantChangeAuditOutboxRelay.ActivateWithBudget(false,TimeSpan.FromSeconds(-1),()=>{calls++;throw new InvalidOperationException();},()=>{calls++;throw new InvalidOperationException();},TimeSpan.Zero);
            Require(relay is null&&calls==0);return Task.CompletedTask;
        });
        await check("relay budget enabled invalid bounds fail before provider factories",()=>
        {
            foreach(var timeout in new[]{TimeSpan.Zero,TimeSpan.FromTicks(-1),TimeSpan.FromMinutes(1).Add(TimeSpan.FromTicks(1))})
            {
                var calls=0;var denied=false;try{TenantChangeAuditOutboxRelay.ActivateWithBudget(true,timeout,()=>{calls++;throw new InvalidOperationException();},()=>{calls++;throw new InvalidOperationException();});}catch(ArgumentOutOfRangeException){denied=true;}
                Require(denied&&calls==0);
            }
            return Task.CompletedTask;
        });
        foreach(var legacy in new[]{true,false})
        await check(legacy?"legacy relay actual PostgreSQL success keeps caller work token":"null relay budget actual PostgreSQL success keeps caller work token",async()=>
        {
            var store=await createStore();await mutate(store);var adapter=new Adapter(store);using var caller=new CancellationTokenSource();
            var relay=legacy?TenantChangeAuditOutboxRelay.Activate(true,()=>adapter,()=>adapter,TimeSpan.FromSeconds(30))!:Relay(adapter,null);
            var result=await new RelayHost(relay).Run(token:caller.Token);
            Require(result.IsSuccess&&result.Value.Acknowledged==1&&adapter.ClaimToken==caller.Token&&adapter.SinkToken==caller.Token&&adapter.AckToken==caller.Token&&adapter.ReleaseWasIndependent&&(await store.Counts())==(1,1,1));
        });
        await check("configured relay budget actual PostgreSQL success links work but not release",async()=>
        {
            var store=await createStore();await mutate(store);var adapter=new Adapter(store);using var caller=new CancellationTokenSource();var result=await new RelayHost(Relay(adapter,TimeSpan.FromSeconds(10))).Run(token:caller.Token);
            Require(result.IsSuccess&&result.Value.Acknowledged==1&&adapter.ClaimToken!=caller.Token&&adapter.ClaimToken.CanBeCanceled&&adapter.SinkToken==adapter.ClaimToken&&adapter.AckToken==adapter.ClaimToken&&adapter.ReleaseWasIndependent&&(await store.Counts())==(1,1,1));
        });
        await check("configured relay pre-caller cancellation never claims or publishes",async()=>
        {
            var store=await createStore();await mutate(store);var adapter=new Adapter(store);using var caller=new CancellationTokenSource();caller.Cancel();Exception? error=null;try{await new RelayHost(Relay(adapter,Budget)).Run(token:caller.Token);}catch(OperationCanceledException observed){error=observed;}
            Require(error is OperationCanceledException cancelled&&cancelled.CancellationToken==caller.Token&&adapter.Claims==0&&store.Claims==0&&store.SinkCalls==0&&(await store.Counts())==(1,0,0));
        });
        await check("relay budget cancels actual table-lock-blocked PostgreSQL Claim before reuse",async()=>
        {
            var store=await createStore();await mutate(store);var probe=new SqlProbe(connection,store.Schema);var adapter=new Adapter(probe.Provider);using var caller=new CancellationTokenSource();var relay=Relay(adapter,TimeSpan.FromSeconds(5));
            var blocker=await probe.HoldTableLock();Task? pending=null;int pid=0;
            try
            {
                pending=new RelayHost(relay).Run(token:caller.Token).AsTask();pid=await probe.ObserveLock("WITH selected",pending,adapter);
                Require(!adapter.ClaimToken.IsCancellationRequested);var error=await Failure(pending).WaitAsync(TimeSpan.FromSeconds(15));
                Require(error is TimeoutException&&adapter.Releases==0&&probe.Provider.SinkCalls==0&&probe.Provider.Acks==0&&await probe.Quiescent(pid));
            }
            finally{caller.Cancel();await blocker.DisposeAsync();if(pending is not null)await Join(pending);}
            Require(await probe.Quiescent(pid));await FreshReplay(store,adapter,relay);
            observe(new{phase="claim",kind="actual PostgreSQL provider SQL",lock_wait_observed_before_expiry=true,backend_pid=pid,task_joined=true,backend_quiescent=true,reused_with_fresh_authority=true});
        });
        await check("relay budget cancels actual row-lock-blocked PostgreSQL Ack then independently releases and deduplicates",async()=>
        {
            var store=await createStore();await mutate(store);var original=(await store.Payloads()).Single();var probe=new SqlProbe(connection,store.Schema);var adapter=new Adapter(probe.Provider);using var caller=new CancellationTokenSource();var relay=Relay(adapter,TimeSpan.FromSeconds(5));SqlLock? blocker=null;var locked=Signal();
            adapter.SinkOverride=async(record,token)=>{await probe.Provider.AppendOnceAsync(record,token);blocker=await probe.HoldRowLock();locked.TrySetResult();};
            var pending=new RelayHost(relay).Run(token:caller.Token).AsTask();int pid=0;
            try
            {
                await locked.Task.WaitAsync(TimeSpan.FromSeconds(10));pid=await probe.ObserveLock("SET delivered=true",pending,adapter);Require(!adapter.AckToken.IsCancellationRequested);
                await adapter.ReleaseEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));Require(adapter.ClaimToken.IsCancellationRequested&&adapter.ReleaseWasIndependent);
                await blocker!.DisposeAsync();var error=await Failure(pending).WaitAsync(TimeSpan.FromSeconds(10));
                Require(error is TenantChangeAuditOutboxRelayException failure&&failure.PrimaryFailure is TimeoutException&&failure.AcknowledgedCount==0&&failure.MayHaveDelivered&&failure.ReleaseFailure is null&&await probe.Quiescent(pid)&&(await store.Counts())==(1,0,1));
            }
            finally{caller.Cancel();if(blocker is not null)await blocker.DisposeAsync();await Join(pending);}
            await FreshReplay(store,adapter,relay);Require(probe.Provider.SinkCalls==2&&(await store.Payloads("audit_sink")).Single()==original&&await probe.Quiescent(pid));
            observe(new{phase="acknowledge",kind="actual PostgreSQL provider SQL",lock_wait_observed_before_expiry=true,backend_pid=pid,task_joined=true,backend_quiescent=true,independent_release=true,fresh_replay_deduplicated=true});
        });
        await check("late claim wrapper returns known actual PostgreSQL lease and is released without publish",async()=>
        {
            var store=await createStore();await mutate(store);var adapter=new Adapter(store);
            adapter.ClaimOverride=async(tenant,maximum,duration,token)=>{var lease=await store.ClaimAsync(tenant,maximum,duration,token);Require(lease is not null);await Cancelled(token);return lease;};
            var relay=Relay(adapter,Budget);var error=await Failure(new RelayHost(relay).Run().AsTask());
            Require(error is TenantChangeAuditOutboxRelayException failure&&failure.PrimaryFailure is TimeoutException&&!failure.MayHaveDelivered&&failure.AcknowledgedCount==0&&adapter.ReleaseWasIndependent&&store.Releases==1&&store.SinkCalls==0);
            await FreshReplay(store,adapter,relay);
        });
        await check("late null claim wrapper cannot return successful zero after budget expiry",async()=>
        {
            var store=await createStore();var adapter=new Adapter(store);adapter.ClaimOverride=async(tenant,maximum,duration,token)=>{Require(await store.ClaimAsync(tenant,maximum,duration,token) is null);await Cancelled(token);return null;};
            var error=await Failure(new RelayHost(Relay(adapter,Budget)).Run().AsTask());Require(error is TimeoutException&&store.Claims==1&&adapter.Releases==0&&store.SinkCalls==0&&(await store.Counts())==(0,0,0));
        });
        await check("cooperative sink wrapper cancellation before SQL preserves pending row for manual replay",async()=>
        {
            var store=await createStore();await mutate(store);var adapter=new Adapter(store);adapter.SinkOverride=async(_,token)=>{await Cancelled(token);token.ThrowIfCancellationRequested();};var relay=Relay(adapter,Budget);
            var error=await Failure(new RelayHost(relay).Run().AsTask());Require(error is TenantChangeAuditOutboxRelayException failure&&failure.PrimaryFailure is TimeoutException&&failure.MayHaveDelivered&&failure.AcknowledgedCount==0&&adapter.ReleaseWasIndependent&&store.SinkCalls==0&&(await store.Counts())==(1,0,0));
            await FreshReplay(store,adapter,relay);
        });
        await check("uncooperative sink wrapper after actual SQL is awaited then late success rejected with replay fences",async()=>
        {
            var store=await createStore();await mutate(store);var original=(await store.Payloads()).Single();var adapter=new Adapter(store);var expired=Signal();var finish=Signal();using var caller=new CancellationTokenSource();
            adapter.SinkOverride=async(record,token)=>{await store.AppendOnceAsync(record,token);await Cancelled(token);expired.TrySetResult();await finish.Task;};var relay=Relay(adapter,Budget);var pending=new RelayHost(relay).Run(token:caller.Token).AsTask();
            try
            {
                await expired.Task.WaitAsync(TimeSpan.FromSeconds(10));Require(!pending.IsCompleted&&(await store.Counts())==(1,0,1));finish.TrySetResult();var error=await Failure(pending);
                Require(error is TenantChangeAuditOutboxRelayException failure&&failure.PrimaryFailure is TimeoutException&&failure.MayHaveDelivered&&failure.AcknowledgedCount==0&&adapter.ReleaseWasIndependent);
            }
            finally{finish.TrySetResult();caller.Cancel();await Join(pending);}
            var old=adapter.LastClaim!;var replacement=await store.ClaimAsync(new("A"),1,TimeSpan.FromSeconds(30),default)??throw new InvalidOperationException();
            Require(old.LeaseId!=replacement.LeaseId&&!await store.AcknowledgeAsync(old,old.Records[0].Receipt.ReceiptId,default));await store.ReleaseAsync(old,default);Require(await store.ClaimAsync(new("A"),1,TimeSpan.FromSeconds(30),default) is null);await store.ReleaseAsync(replacement,default);
            await FreshReplay(store,adapter,relay);Require(store.SinkCalls==2&&(await store.Payloads("audit_sink")).Single()==original);
        });
        await check("configured sink wrapper caller cancellation preserves original caller token",async()=>
        {
            var store=await createStore();await mutate(store);var adapter=new Adapter(store);var entered=Signal();using var caller=new CancellationTokenSource();adapter.SinkOverride=async(_,token)=>{entered.TrySetResult();await Cancelled(token);token.ThrowIfCancellationRequested();};
            var pending=new RelayHost(Relay(adapter,TimeSpan.FromSeconds(10))).Run(token:caller.Token).AsTask();try{await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));caller.Cancel();var error=await Failure(pending);Require(error is TenantChangeAuditOutboxRelayException failure&&failure.PrimaryFailure is OperationCanceledException cancelled&&cancelled.CancellationToken==caller.Token&&adapter.ReleaseWasIndependent&&store.SinkCalls==0);}finally{caller.Cancel();await Join(pending);}
        });
        await check("dual-signal sink wrapper classifies observed caller first with original token",async()=>
        {
            var store=await createStore();await mutate(store);var adapter=new Adapter(store);var expired=Signal();var finish=Signal();using var caller=new CancellationTokenSource();adapter.SinkOverride=async(_,token)=>{await Cancelled(token);expired.TrySetResult();await finish.Task;token.ThrowIfCancellationRequested();};
            var pending=new RelayHost(Relay(adapter,Budget)).Run(token:caller.Token).AsTask();try{await expired.Task.WaitAsync(TimeSpan.FromSeconds(10));caller.Cancel();finish.TrySetResult();var error=await Failure(pending);Require(error is TenantChangeAuditOutboxRelayException failure&&failure.PrimaryFailure is OperationCanceledException cancelled&&cancelled.CancellationToken==caller.Token&&adapter.ReleaseWasIndependent);}finally{caller.Cancel();finish.TrySetResult();await Join(pending);}
        });
        await check("unrelated sink wrapper fault stays original after private expiry",async()=>
        {
            var store=await createStore();await mutate(store);var adapter=new Adapter(store);var original=new IOException("Controlled unrelated sink wrapper fault.");adapter.SinkOverride=async(_,token)=>{await Cancelled(token);throw original;};var error=await Failure(new RelayHost(Relay(adapter,Budget)).Run().AsTask());
            Require(error is TenantChangeAuditOutboxRelayException failure&&ReferenceEquals(failure.PrimaryFailure,original)&&failure.MayHaveDelivered&&failure.ReleaseFailure is null&&adapter.ReleaseWasIndependent);
        });
        await check("unrelated claim wrapper cancellation remains original when neither configured signal requested",async()=>
        {
            var store=await createStore();var adapter=new Adapter(store);using var other=new CancellationTokenSource();other.Cancel();var original=new OperationCanceledException(other.Token);adapter.ClaimOverride=(_,_,_,_)=>throw original;
            var error=await Failure(new RelayHost(Relay(adapter,TimeSpan.FromSeconds(10))).Run().AsTask());Require(ReferenceEquals(error,original)&&!adapter.ClaimToken.IsCancellationRequested&&store.Claims==0&&adapter.Releases==0);
        });
        foreach(var legacy in new[]{true,false})
        await check(legacy?"legacy claim wrapper retains original unrelated cancellation and caller token":"null-budget claim wrapper retains original unrelated cancellation and caller token",async()=>
        {
            var store=await createStore();var adapter=new Adapter(store);using var caller=new CancellationTokenSource();using var other=new CancellationTokenSource();other.Cancel();var original=new OperationCanceledException(other.Token);adapter.ClaimOverride=(_,_,_,_)=>throw original;
            var relay=legacy?TenantChangeAuditOutboxRelay.Activate(true,()=>adapter,()=>adapter,TimeSpan.FromSeconds(30))!:Relay(adapter,null);var error=await Failure(new RelayHost(relay).Run(token:caller.Token).AsTask());Require(ReferenceEquals(error,original)&&adapter.ClaimToken==caller.Token&&store.Claims==0&&adapter.Releases==0);
        });
        await check("configured relay exact tenant grant and fresh permission remain mandatory before claim",async()=>
        {
            var store=await createStore();await mutate(store);var adapter=new Adapter(store);var host=new RelayHost(Relay(adapter,TimeSpan.FromSeconds(10)));
            Require(!(await host.Run("B")).IsSuccess&&adapter.Claims==0);host.Authority.AllowB=true;Require(!(await host.Run("C")).IsSuccess&&adapter.Claims==0);
            var b=await host.Run("B");Require(b.IsSuccess&&b.Value.Acknowledged==0&&adapter.Claims==1&&(await store.Counts())==(1,0,0)&&(await store.Counts("B"))==(0,0,0));
            host.Authority.AllowRelay=false;Require(!(await host.Run()).IsSuccess&&adapter.Claims==1);host.Authority.AllowRelay=true;Require((await host.Run()).IsSuccess&&host.Authority.IdentityLookups==5&&(await store.Counts())==(1,1,1));
        });
        await check("configured relay denies a live writer scope before PostgreSQL claim",async()=>
        {
            var store=await createStore();var adapter=new Adapter(store);var relay=Relay(adapter,Budget);var denied=false;var integration=new OutboxIntegration(store,OutboxIntegration.Policy(TenantChangeAuditMode.ChangedFields));
            integration.AfterMutation=async context=>{try{await relay.RelayAsync(context);}catch(TenantAccessDeniedException){denied=true;}};
            using var tls=new TlsFixture();using var jwt=new JwtFixture();await using var host=new Host();await host.Start(tls,jwt,trailProfile:new(TenantChangeAuditMode.ChangedFields),trailIntegration:integration);
            using var client=tls.Client(host.Address);using var request=new HttpRequestMessage(HttpMethod.Post,"/entity/update"){Content=JsonContent.Create(new EntityMutationRequest("A","shared","relay-budget",3,"private-budget"))};request.Headers.Authorization=new("Bearer",jwt.Token());using var response=await client.SendAsync(request);
            Require(response.IsSuccessStatusCode&&denied&&adapter.Claims==0&&store.Claims==0&&(await store.Counts())==(1,0,0));
        });
        await check("configured relay denies retained disposed relay scope before a second claim",async()=>
        {
            var store=await createStore();await mutate(store);var adapter=new Adapter(store);var relay=Relay(adapter,Budget);var host=new RelayHost(relay);Require((await host.Run()).IsSuccess);var error=await Failure(relay.RelayAsync(host.RetainedContext!).AsTask());Require(error is TenantAccessDeniedException&&adapter.Claims==1&&(await store.Counts())==(1,1,1));
        });
        await check("late acknowledgement wrapper retains actual PostgreSQL commit and acknowledged count",async()=>
        {
            var store=await createStore();await mutate(store);var adapter=new Adapter(store);adapter.AckOverride=async(lease,receipt,token)=>{Require(await store.AcknowledgeAsync(lease,receipt,token));await Cancelled(token);return true;};
            var relay=Relay(adapter,Budget);var error=await Failure(new RelayHost(relay).Run().AsTask());Require(error is TenantChangeAuditOutboxRelayException failure&&failure.PrimaryFailure is TimeoutException&&failure.ReleaseFailure is null&&failure.MayHaveDelivered&&failure.AcknowledgedCount==1&&adapter.ReleaseWasIndependent&&(await store.Counts())==(1,1,1));
            adapter.AckOverride=null;var result=await new RelayHost(relay).Run();Require(result.IsSuccess&&result.Value.Acknowledged==0&&store.SinkCalls==1);
        });
        await check("private timeout and release wrapper fault remain independently reported after physical release",async()=>
        {
            var store=await createStore();await mutate(store);var adapter=new Adapter(store);var cleanup=new IOException("Controlled release wrapper fault after actual release.");adapter.SinkOverride=async(_,token)=>{await Cancelled(token);token.ThrowIfCancellationRequested();};adapter.ReleaseOverride=async(lease,token)=>{await store.ReleaseAsync(lease,token);throw cleanup;};
            var error=await Failure(new RelayHost(Relay(adapter,Budget)).Run().AsTask());Require(error is TenantChangeAuditOutboxRelayException failure&&failure.PrimaryFailure is TimeoutException&&ReferenceEquals(failure.ReleaseFailure,cleanup)&&adapter.ReleaseWasIndependent&&(await store.Counts())==(1,0,0));
        });
        await check("private expiry during release wrapper withholds success but retains actual acknowledgement count",async()=>
        {
            var store=await createStore();await mutate(store);var adapter=new Adapter(store);adapter.ReleaseOverride=async(lease,token)=>{await Cancelled(adapter.ClaimToken);Require(!token.IsCancellationRequested);await store.ReleaseAsync(lease,token);};
            var relay=Relay(adapter,Budget);var error=await Failure(new RelayHost(relay).Run().AsTask());Require(error is TenantChangeAuditOutboxRelayException failure&&failure.PrimaryFailure is TimeoutException&&failure.ReleaseFailure is null&&failure.MayHaveDelivered&&failure.AcknowledgedCount==1&&adapter.ReleaseWasIndependent&&(await store.Counts())==(1,1,1));
            adapter.ReleaseOverride=null;var result=await new RelayHost(relay).Run();Require(result.IsSuccess&&result.Value.Acknowledged==0&&store.SinkCalls==1);
        });
    }
    private sealed class Adapter(PostgresStore store):ITenantChangeAuditOutboxSource,ITenantChangeAuditIdempotentSink
    {
        public Func<TenantId,int,TimeSpan,CancellationToken,ValueTask<TenantChangeAuditOutboxLease?>>? ClaimOverride;
        public Func<TenantChangeAuditRecord,CancellationToken,ValueTask>? SinkOverride;
        public Func<TenantChangeAuditOutboxLease,Guid,CancellationToken,ValueTask<bool>>? AckOverride;
        public Func<TenantChangeAuditOutboxLease,CancellationToken,ValueTask>? ReleaseOverride;
        public int Claims,Releases;public CancellationToken ClaimToken,SinkToken,AckToken;public bool ReleaseWasIndependent;public TenantChangeAuditOutboxLease? LastClaim;public TaskCompletionSource ReleaseEntered{get;}=Signal();
        public async ValueTask<TenantChangeAuditOutboxLease?> ClaimAsync(TenantId tenant,int maximum,TimeSpan duration,CancellationToken token)
        {Claims++;ClaimToken=token;return LastClaim=ClaimOverride is null?await store.ClaimAsync(tenant,maximum,duration,token):await ClaimOverride(tenant,maximum,duration,token);}
        public async ValueTask AppendOnceAsync(TenantChangeAuditRecord record,CancellationToken token)
        {SinkToken=token;if(SinkOverride is null)await store.AppendOnceAsync(record,token);else await SinkOverride(record,token);}
        public async ValueTask<bool> AcknowledgeAsync(TenantChangeAuditOutboxLease lease,Guid receiptId,CancellationToken token)
        {AckToken=token;return AckOverride is null?await store.AcknowledgeAsync(lease,receiptId,token):await AckOverride(lease,receiptId,token);}
        public async ValueTask ReleaseAsync(TenantChangeAuditOutboxLease lease,CancellationToken token)
        {Releases++;ReleaseWasIndependent=token.CanBeCanceled&&!token.IsCancellationRequested&&token!=ClaimToken;ReleaseEntered.TrySetResult();if(ReleaseOverride is null)await store.ReleaseAsync(lease,token);else await ReleaseOverride(lease,token);}
    }
    private sealed class SqlLock(NpgsqlConnection connection,NpgsqlTransaction transaction):IAsyncDisposable
    {
        private int disposed;
        public async ValueTask DisposeAsync(){if(Interlocked.Exchange(ref disposed,1)!=0)return;try{await transaction.RollbackAsync();}finally{await transaction.DisposeAsync();await connection.DisposeAsync();}}
    }
    private sealed class SqlProbe
    {
        private readonly string connection,schema;private readonly string tag="owned-relay-budget-"+Guid.NewGuid().ToString("N");public PostgresStore Provider{get;}
        public SqlProbe(string connection,string schema)
        {this.connection=connection;this.schema=schema;Provider=new(new NpgsqlConnectionStringBuilder(connection){ApplicationName=tag}.ConnectionString,schema);}
        private async Task<NpgsqlConnection> Open(){var c=new NpgsqlConnection(connection);try{await c.OpenAsync();return c;}catch{await c.DisposeAsync();throw;}}
        private async Task<SqlLock> Hold(string sql)
        {var c=await Open();var tx=await c.BeginTransactionAsync();try{await using var command=new NpgsqlCommand(sql,c,tx);await command.ExecuteNonQueryAsync();return new(c,tx);}catch{await tx.DisposeAsync();await c.DisposeAsync();throw;}}
        public Task<SqlLock> HoldTableLock()=>Hold($"LOCK TABLE {schema}.audit_outbox IN ACCESS EXCLUSIVE MODE");
        public Task<SqlLock> HoldRowLock()=>Hold($"SELECT receipt FROM {schema}.audit_outbox WHERE tenant='A' AND NOT delivered FOR UPDATE");
        public async Task<int> ObserveLock(string fragment,Task pending,Adapter adapter)
        {
            await using var c=await Open();
            for(var i=0;i<100;i++)
            {
                await using var command=new NpgsqlCommand("SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE $2 AND query LIKE $3",c);command.Parameters.AddWithValue(tag);command.Parameters.AddWithValue("%"+schema+".audit_outbox%");command.Parameters.AddWithValue("%"+fragment+"%");var result=await command.ExecuteScalarAsync();
                if(result is int pid){Require(!pending.IsCompleted&&!adapter.ClaimToken.IsCancellationRequested);return pid;}
                Require(!pending.IsCompleted);await Task.Delay(20);
            }
            throw new InvalidOperationException("Actual owned provider Lock wait was not observed before budget expiry.");
        }
        public async Task<bool> Quiescent(int pid)
        {
            Require(pid>0);await using var c=await Open();await using var command=new NpgsqlCommand("SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND application_name=$2 AND (state='active' OR wait_event_type='Lock'))",c);command.Parameters.AddWithValue(pid);command.Parameters.AddWithValue(tag);return (bool)(await command.ExecuteScalarAsync())!;
        }
    }
}
