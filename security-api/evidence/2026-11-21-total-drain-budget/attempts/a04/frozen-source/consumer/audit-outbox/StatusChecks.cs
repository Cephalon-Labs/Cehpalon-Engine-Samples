extern alias securityapi;
using System.Text.Json;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;
using securityapi::SecurityApi;

namespace AuditOutbox;

public sealed record StatusRequest(string Tenant);
public sealed class StatusAuthority:IIdentitySource,ITenantMembershipSource,IResourceScopeSource,ITenantAccessPolicy
{
    public bool Active=true,AllowInspect=true,AllowB;
    public int IdentityLookups,PolicyLookups;
    public string GrantedAction="inspect",GrantedKind="audit-outbox";
    public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken token)
    {token.ThrowIfCancellationRequested();Interlocked.Increment(ref IdentityLookups);return ValueTask.FromResult<IdentitySnapshot?>(Active?new(new("owned-status-authority","audit-status-service"),"fixture-service",DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddMinutes(1)):null);}
    public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot identity,TenantId tenant,CancellationToken token)
    {token.ThrowIfCancellationRequested();return ValueTask.FromResult<TenantMembershipSnapshot?>(tenant.Value=="A"||(AllowB&&tenant.Value=="B")?new(identity.Principal,tenant,true,DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddMinutes(1),"status-membership"):null);}
    public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId tenant,string kind,string id,CancellationToken token)
    {token.ThrowIfCancellationRequested();return ValueTask.FromResult<ResourceScopeSnapshot?>(new(tenant,kind,id,"status-resource"));}
    public ValueTask<bool> IsAllowedAsync(TenantAccessRequest request,CancellationToken token)
    {token.ThrowIfCancellationRequested();Interlocked.Increment(ref PolicyLookups);return ValueTask.FromResult(AllowInspect&&request.OperationId=="outbox.status"&&request.Action==GrantedAction&&request.Resource.Kind==GrantedKind&&request.Resource.ResourceId=="tenant");}
}
public sealed class StatusHost
{
    public StatusAuthority Authority{get;}=new();
    public TenantOperationContext? RetainedContext;
    public int HandlerFactories;
    private readonly OperationDispatcher dispatcher;
    public StatusHost(TenantChangeAuditOutboxStatusReader reader,string action="inspect",string kind="audit-outbox")
    {
        Authority.GrantedAction=action;Authority.GrantedKind=kind;
        var registry=new TenantOperationRegistryBuilder().Register<StatusRequest,TenantChangeAuditOutboxStatus>("outbox.status",action,kind,r=>r with{},r=>new(new(r.Tenant),"tenant"),()=>{Interlocked.Increment(ref HandlerFactories);return new Handler(this,reader);}).Build();
        var security=new TenantSecurityServices(Authority,new(["owned-status-authority"],["fixture-service"]),Authority,Authority,TimeSpan.FromSeconds(30),Authority);
        var tenant=new TenantOperationDispatcher(registry,security);var core=new OperationRegistryBuilder();
        Cehpalon.Engine.Generated.OperationRegistrations.RegisterAll(core,new Factory(tenant));dispatcher=new(core.Build());
    }
    public ValueTask<OperationResult<TenantChangeAuditOutboxStatus>> Run(string tenant="A",CancellationToken token=default)
        =>dispatcher.DispatchAsync<StatusRequest,TenantChangeAuditOutboxStatus>("outbox.status",new(tenant),new("owned-status"),token);
    private sealed class Handler(StatusHost host,TenantChangeAuditOutboxStatusReader reader):ITenantOperationHandler<StatusRequest,TenantChangeAuditOutboxStatus>
    {
        public async ValueTask<OperationResult<TenantChangeAuditOutboxStatus>> HandleAsync(StatusRequest request,TenantOperationContext context,CancellationToken token)
        {host.RetainedContext=context;return OperationResult<TenantChangeAuditOutboxStatus>.Success(await reader.ReadAsync(context,token));}
    }
    private sealed class Factory(TenantOperationDispatcher dispatcher):IOperationHandlerFactory
    {
        public THandler Create<THandler>() where THandler:class
            =>(THandler)(object)(typeof(THandler)==typeof(StatusGateway)?(object)new StatusGateway(dispatcher):typeof(THandler)==typeof(RelayGateway)?new RelayGateway(dispatcher):throw new InvalidOperationException("Unknown generated gateway."));
    }
}
[Operation("outbox.status")]
public sealed class StatusGateway(TenantOperationDispatcher dispatcher):IOperationHandler<StatusRequest,TenantChangeAuditOutboxStatus>
{
    public ValueTask<OperationResult<TenantChangeAuditOutboxStatus>> HandleAsync(StatusRequest request,OperationContext context,CancellationToken token)
        =>dispatcher.DispatchAsync<StatusRequest,TenantChangeAuditOutboxStatus>("outbox.status",request,context,token);
}

public static class StatusChecks
{
    public static async Task Run(Func<string,Func<Task>,Task> check,Func<Task<PostgresStore>> createStore,Func<PostgresStore,Task> mutate)
    {
        void Require(bool value){if(!value)throw new InvalidOperationException("PostgreSQL outbox status assertion failed.");}
        TenantChangeAuditOutboxStatusReader Reader(PostgresStore store,TimeSpan? timeout=null)=>TenantChangeAuditOutboxStatusReader.Activate(true,()=>store,timeout)!;
        async Task<TenantChangeAuditOutboxStatus> Read(StatusHost host,string tenant="A")
        {var result=await host.Run(tenant);Require(result.IsSuccess);return result.Value;}
        void Counts(TenantChangeAuditOutboxStatus value,long pending,long available,long claimed,long expired,long delivered)
        {Require(value.Pending==pending&&value.Available==available&&value.Claimed==claimed&&value.ExpiredClaims==expired&&value.Delivered==delivered&&value.Pending-value.Available==value.Claimed&&value.ExpiredClaims<=value.Available&&(value.OldestPendingAtUtc is null)==(value.Pending==0));}
        (int Begins,int Stages,int Commits,int Rollbacks,int Claims,int Acks,int Releases,int SinkCalls) Effects(PostgresStore s)=>(s.Begins,s.Stages,s.Commits,s.Rollbacks,s.Claims,s.Acks,s.Releases,s.SinkCalls);

        await check("status disabled activation skips provider factory and all database work",async()=>
        {
            var factories=0;var store=await createStore();var connections=store.Connections;
            Require(TenantChangeAuditOutboxStatusReader.Activate(false,()=>{factories++;return store;},TimeSpan.Zero) is null&&factories==0&&store.StatusReads==0&&store.Connections==connections);
        });
        await check("status empty tenant has coherent zero counts and no oldest pending timestamp",async()=>
        {var store=await createStore();var status=await Read(new(Reader(store)));Counts(status,0,0,0,0,0);Require(status.Tenant.Value=="A"&&status.ObservedAtUtc.Offset==TimeSpan.Zero&&store.StatusReads==1);});
        await check("status reports database enqueue time and does not expose payload receipt or principal",async()=>
        {
            var store=await createStore();await mutate(store);var status=await Read(new(Reader(store)));Counts(status,1,1,0,0,0);Require(status.OldestPendingAtUtc<=status.ObservedAtUtc&&status.OldestPendingAtUtc==(await store.PendingEnqueueTimes()).Single().Enqueued);
            var json=JsonSerializer.Serialize(status);Require(!json.Contains("private-",StringComparison.Ordinal)&&!json.Contains("changed",StringComparison.Ordinal)&&!json.Contains("Receipt",StringComparison.Ordinal)&&!json.Contains("Principal",StringComparison.Ordinal));
        });
        await check("status observation has no claim acknowledgement release sink or domain side effects",async()=>
        {
            var store=await createStore();await mutate(store);var effects=Effects(store);var row=await store.Row();var original=await store.Payloads();var host=new StatusHost(Reader(store));Counts(await Read(host),1,1,0,0,0);Counts(await Read(host),1,1,0,0,0);
            Require(Effects(store)==effects&&(await store.Row())==row&&(await store.Payloads()).SequenceEqual(original)&&store.StatusReads==2);
        });
        await check("status active claim is pending but unavailable until release",async()=>
        {
            var store=await createStore();await mutate(store);var lease=await store.ClaimAsync(new("A"),1,TimeSpan.FromSeconds(30),default)??throw new InvalidOperationException();var host=new StatusHost(Reader(store));Counts(await Read(host),1,0,1,0,0);await store.ReleaseAsync(lease,default);Counts(await Read(host),1,1,0,0,0);
        });
        await check("status expired claim is counted as available and does not auto release",async()=>
        {
            var store=await createStore();await mutate(store);var lease=await store.ClaimAsync(new("A"),1,TimeSpan.FromSeconds(30),default)??throw new InvalidOperationException();await store.ExpireLease(lease);var releases=store.Releases;Counts(await Read(new(Reader(store))),1,1,0,1,0);Require(store.Releases==releases&&!await store.AcknowledgeAsync(lease,lease.Records[0].Receipt.ReceiptId,default));
        });
        await check("status delivered rows are separate from pending and oldest pending becomes null",async()=>
        {
            var store=await createStore();await mutate(store);var relay=new RelayHost(TenantChangeAuditOutboxRelay.Activate(true,()=>store,()=>store));Require((await relay.Run()).IsSuccess);Counts(await Read(new(Reader(store))),0,0,0,0,1);
        });
        await check("status mixed available active and expired rows share one statement clock",async()=>
        {
            var store=await createStore();await mutate(store);await mutate(store);await mutate(store);var lease=await store.ClaimAsync(new("A"),2,TimeSpan.FromSeconds(30),default)??throw new InvalidOperationException();await store.ExpireClaimReceipt(lease,lease.Records[0].Receipt.ReceiptId);
            Counts(await Read(new(Reader(store))),3,2,1,1,0);await store.ReleaseAsync(lease,default);Counts(await Read(new(Reader(store))),3,3,0,0,0);
        });
        await check("status oldest pending timestamp moves to the next physical queued row after acknowledgement",async()=>
        {
            var store=await createStore();await mutate(store);await mutate(store);var physical=await store.PendingEnqueueTimes();Require(physical.Length==2);var host=new StatusHost(Reader(store));var before=await Read(host);Require(before.OldestPendingAtUtc==physical[0].Enqueued);
            var lease=await store.ClaimAsync(new("A"),2,TimeSpan.FromSeconds(30),default)??throw new InvalidOperationException();var first=lease.Records.Single(x=>x.Receipt.ReceiptId==physical[0].Receipt);await store.AppendOnceAsync(first,default);Require(await store.AcknowledgeAsync(lease,first.Receipt.ReceiptId,default));await store.ReleaseAsync(lease,default);
            var after=await Read(host);Counts(after,1,1,0,0,1);Require(after.OldestPendingAtUtc==physical[1].Enqueued&&(await store.PendingEnqueueTimes()).Single().Enqueued==after.OldestPendingAtUtc);
        });
        await check("status delivered means provider acknowledgement not merely sink presence after ack uncertainty",async()=>
        {
            var store=await createStore();await mutate(store);store.Fault=ProviderFault.Ack;var relay=TenantChangeAuditOutboxRelay.Activate(true,()=>store,()=>store)!;var failed=false;try{await new RelayHost(relay).Run();}catch(TenantChangeAuditOutboxRelayException){failed=true;}Require(failed&&(await store.Counts()).Sink==1);var effects=Effects(store);Counts(await Read(new(Reader(store))),1,1,0,0,0);Require(Effects(store)==effects);
            store.Fault=ProviderFault.None;Require((await new RelayHost(relay).Run()).IsSuccess);Counts(await Read(new(Reader(store))),0,0,0,0,1);Require((await store.Counts()).Sink==1);
        });
        await check("status normal service cannot inspect tenant B before membership grant",async()=>
        {
            var store=await createStore();await mutate(store);var host=new StatusHost(Reader(store));Require(!(await host.Run("B")).IsSuccess&&store.StatusReads==0&&host.HandlerFactories==0);host.Authority.AllowB=true;Counts(await Read(host,"B"),0,0,0,0,0);Require(store.StatusReads==1&&host.Authority.IdentityLookups==2);
        });
        await check("status tenant B grant does not grant arbitrary tenant C",async()=>
        {var store=await createStore();var host=new StatusHost(Reader(store));host.Authority.AllowB=true;Require(!(await host.Run("C")).IsSuccess&&store.StatusReads==0&&host.HandlerFactories==0);});
        await check("status facade rejects a provider-reported owner different from the requested tenant",async()=>
        {var store=await createStore();await mutate(store);store.StatusOwnerOverride=new("B");var host=new StatusHost(Reader(store));Require(!(await host.Run()).IsSuccess&&store.StatusReads==1);store.StatusOwnerOverride=null;Counts(await Read(host),1,1,0,0,0);});
        await check("status authorization is checked afresh after inspect permission revocation",async()=>
        {var store=await createStore();var host=new StatusHost(Reader(store));await Read(host);host.Authority.AllowInspect=false;Require(!(await host.Run()).IsSuccess&&store.StatusReads==1&&host.Authority.IdentityLookups==2&&host.Authority.PolicyLookups==2);});
        foreach(var scope in new[]{("relay","audit-outbox"),("read","audit-trail")})
        await check("live "+scope.Item1+" permission does not grant status inspection",async()=>
        {
            var store=await createStore();var host=new StatusHost(Reader(store),scope.Item1,scope.Item2);Require(!(await host.Run()).IsSuccess&&store.StatusReads==0);
        });
        await check("retained status request context cannot be reused after its checked dispatch ends",async()=>
        {
            var store=await createStore();var reader=Reader(store);var host=new StatusHost(reader);await Read(host);var denied=false;try{await reader.ReadAsync(host.RetainedContext!);}catch(TenantAccessDeniedException){denied=true;}Require(denied&&store.StatusReads==1);
        });
        await check("live writer context cannot inspect status while its transaction is still uncommitted",async()=>
        {
            var store=await createStore();var reader=Reader(store);var denied=false;var integration=new OutboxIntegration(store,OutboxIntegration.Policy(TenantChangeAuditMode.ChangedFields));
            integration.AfterMutation=async context=>{try{await reader.ReadAsync(context);}catch(TenantAccessDeniedException){denied=true;}};
            using var tls=new TlsFixture();using var jwt=new JwtFixture();await using var host=new Host();await host.Start(tls,jwt,trailProfile:new(TenantChangeAuditMode.ChangedFields),trailIntegration:integration);
            using var client=tls.Client(host.Address);using var request=new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Post,"/entity/update"){Content=System.Net.Http.Json.JsonContent.Create(new EntityMutationRequest("A","shared","writer",3,"private-writer"))};request.Headers.Authorization=new("Bearer",jwt.Token());using var response=await client.SendAsync(request);Require(response.IsSuccessStatusCode&&denied&&store.StatusReads==0&&(await store.Row()).Revision==1);
        });
        await check("status pre-cancellation does no provider status query",async()=>
        {
            var store=await createStore();var host=new StatusHost(Reader(store));using var cancelled=new CancellationTokenSource();cancelled.Cancel();var observed=false;try{await host.Run(token:cancelled.Token);}catch(OperationCanceledException){observed=true;}Require(observed&&store.StatusReads==0);
        });
        await check("status cancellation after SQL completion withholds the result without data changes",async()=>
        {
            var store=await createStore();await mutate(store);using var cancelled=new CancellationTokenSource();store.AfterStatusQuery=_=>{cancelled.Cancel();return Task.CompletedTask;};var host=new StatusHost(Reader(store));var effects=Effects(store);var observed=false;try{await host.Run(token:cancelled.Token);}catch(OperationCanceledException){observed=true;}Require(observed&&store.StatusReads==1&&Effects(store)==effects&&(await store.Row()).Revision==1);
        });
        await check("status actual lock-blocked PostgreSQL query receives caller cancellation and cleans its connection",async()=>
        {
            var store=await createStore();await mutate(store);var effects=Effects(store);var host=new StatusHost(Reader(store,TimeSpan.FromSeconds(20)));using var cancelled=new CancellationTokenSource();
            await using(var blocker=await store.HoldStatusTableLock())
            {
                var pending=host.Run(token:cancelled.Token).AsTask();var blocked=false;
                try{for(var i=0;i<100;i++){if(store.LastStatusBackendPid!=0&&await store.StatusQueryIsLockBlocked()){blocked=true;break;}await Task.Delay(20);}Require(blocked);cancelled.Cancel();var observed=false;try{await pending;}catch(OperationCanceledException){observed=true;}Require(observed);}finally{cancelled.Cancel();try{await pending;}catch(OperationCanceledException){}}
            }
            var cancelledBackend=store.LastStatusBackendPid;Require(await store.StatusBackendQuiescent(cancelledBackend));Counts(await Read(new(Reader(store))),1,1,0,0,0);Require(Effects(store)==effects&&store.StatusReads==2);
        });
        await check("status snapshots remain coherent while independently scheduled claim workers release and reacquire rows",async()=>
        {
            var store=await createStore();for(var i=0;i<4;i++)await mutate(store);var reader=Reader(store,TimeSpan.FromSeconds(20));var claims=await Task.WhenAll(Enumerable.Range(0,2).Select(_=>Task.Run(async()=>await store.ClaimAsync(new("A"),1,TimeSpan.FromSeconds(30),default))));Require(claims.All(x=>x is not null));Counts(await Read(new(reader)),4,2,2,0,0);
            var start=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var workers=claims.Select(held=>Task.Run(async()=>{await start.Task;await store.ReleaseAsync(held!,default);for(var i=0;i<2;i++){var lease=await store.ClaimAsync(new("A"),1,TimeSpan.FromSeconds(30),default);if(lease is not null)await store.ReleaseAsync(lease,default);}})).ToArray();
            var observers=Enumerable.Range(0,4).Select(_=>Task.Run(async()=>{await start.Task;var host=new StatusHost(reader);for(var i=0;i<3;i++){var value=await Read(host);Require(value.Pending==4&&value.Available+value.Claimed==4&&value.ExpiredClaims==0&&value.Delivered==0);}})).ToArray();start.TrySetResult();await Task.WhenAll(workers.Concat(observers));Counts(await Read(new(reader)),4,4,0,0,0);Require(store.Acks==0&&store.SinkCalls==0);
        });
        await check("independently scheduled status reads preserve tenant partition and do not perform relay work",async()=>
        {
            var store=await createStore();await mutate(store);var reader=Reader(store);var a=new StatusHost(reader);var b=new StatusHost(reader);b.Authority.AllowB=true;var start=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var effects=Effects(store);
            var workers=Enumerable.Range(0,8).Select(i=>Task.Run(async()=>{await start.Task;return await Read(i%2==0?a:b,i%2==0?"A":"B");})).ToArray();start.TrySetResult();var snapshots=await Task.WhenAll(workers);
            Require(snapshots.Count(x=>x.Tenant.Value=="A"&&x.Pending==1)==4&&snapshots.Count(x=>x.Tenant.Value=="B"&&x.Pending==0)==4&&store.StatusReads==8&&Effects(store)==effects);
        });
    }
}
