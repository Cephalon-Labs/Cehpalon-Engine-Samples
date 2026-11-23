extern alias securityapi;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using AuditOutbox;
using Cehpalon.Engine.Tenancy;
using securityapi::SecurityApi;
using Host=securityapi::SecurityApi.Host;

const string usage="PostgreSQL audit/outbox fixture setup:\n  --connection-file=<private-file> --schema=<owned-schema> --output=<new-report.json>\nNo arguments show this setup guide only; no PostgreSQL test was executed. See audit-outbox/README.md for the owned provider workflow.";
if(args.Length==0 || args.Length==1 && args[0] is "--help" or "-h") {Console.WriteLine(usage);return 0;}
if(args.Any(x=>x.StartsWith("--export-audit-contracts",StringComparison.Ordinal)))return await AuditReadContractExport.RunCommandAsync(args);
if(args.Any(x=>x.StartsWith("--verify-audit-contracts",StringComparison.Ordinal)))return await ResourceTransportChecks.RunContractCommandAsync(args);
if(args[0]=="--measure-audit-history")return await ResourceTransportChecks.RunHistoryMeasurementAsync(args);
var arguments=new Dictionary<string,string>(StringComparer.Ordinal);
foreach(var argument in args)
{
    var pair=argument.Split('=',2);
    if(pair.Length!=2 || pair[0] is not ("--connection-file" or "--schema" or "--output") || string.IsNullOrWhiteSpace(pair[1]) || !arguments.TryAdd(pair[0],pair[1]))
    {Console.Error.WriteLine(usage);return 2;}
}
if(arguments.Count!=3) {Console.Error.WriteLine(usage);return 2;}
string output,connection;
try
{
    output=Path.GetFullPath(arguments["--output"]);
    if(File.Exists(output) || Directory.Exists(output)) {Console.Error.WriteLine("Use a fresh output path.");return 2;}
    connection=File.ReadAllText(arguments["--connection-file"]).Trim();
}
catch(Exception error) when(error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
{Console.Error.WriteLine("Report or private connection file could not be opened. "+usage);return 2;}
var prefix=arguments["--schema"];
var checks=new List<object>();var passed=0;var failed=0;var schemas=new List<string>();
void Require(bool value){if(!value)throw new InvalidOperationException("PostgreSQL outbox proof assertion failed.");}
async Task Check(string name,Func<Task> action){try{await action();passed++;checks.Add(new{name,passed=true});}catch(Exception error){failed++;checks.Add(new{name,passed=false,error_type=error.GetType().FullName,error=error.Message});}}
async Task<PostgresStore> Store(string? fixedSchema=null){var schema=fixedSchema??"ao_"+Guid.NewGuid().ToString("N");var store=new PostgresStore(connection,schema);if(fixedSchema is null)await store.Initialize();schemas.Add(schema);return store;}
using var tls=new TlsFixture();using var jwt=new JwtFixture();
async Task<(HttpStatusCode Status,string Body)> Change(Host host,string tenant="A",bool graphql=false,string title="changed",string secret="private-new-secret",string subject="alice")
{
    using var client=tls.Client(host.Address);using var message=new HttpRequestMessage(HttpMethod.Post,graphql?"/graphql":"/entity/update");message.Headers.Authorization=new AuthenticationHeaderValue("Bearer",jwt.Token(subject));
    message.Content=graphql?JsonContent.Create(new{query="mutation { updateEntity(input: { tenant: \""+tenant+"\", entityId: \"shared\", title: \""+title+"\", amount: 9, secret: \""+secret+"\" }) { tenant entityId entityVersion } }"}):JsonContent.Create(new EntityMutationRequest(tenant,"shared",title,9m,secret));
    using var response=await client.SendAsync(message);return(response.StatusCode,await response.Content.ReadAsStringAsync());
}
async Task<(Host Host,OutboxIntegration Integration)> Start(PostgresStore store,TenantChangeAuditMode mode=TenantChangeAuditMode.ChangedFields,bool cookie=false)
{
    var integration=new OutboxIntegration(store,OutboxIntegration.Policy(mode));var host=new Host();await host.Start(tls,jwt,trailProfile:new(mode),trailIntegration:integration,cookieAuthentication:cookie);return(host,integration);
}
async Task<bool> RelayFails(RelayHost host){try{return !(await host.Run()).IsSuccess;}catch(TenantChangeAuditOutboxRelayException){return true;}}
TenantChangeAuditOutboxRelay Relay(PostgresStore store)=>TenantChangeAuditOutboxRelay.Activate(true,()=>store,()=>store,TimeSpan.FromSeconds(30))!;

if(arguments.TryGetValue("--phase",out var phase)&&phase=="restart-read")
{
    var store=await Store(prefix);await Check("separate process after owned server restart retains domain and pending outbox",async()=>{Require((await store.Row()).Revision==1&&(await store.Counts())==(1,0,0));});
    await Check("fresh service authority can relay persisted pending row after writer process exited",async()=>{var host=new RelayHost(Relay(store));Require((await host.Run()).IsSuccess&&(await store.Counts())==(1,1,1));});
    await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{passed,failed,checks,schemas,settings=JsonDocument.Parse(await store.VersionSettings()).RootElement,scope="Separate reopened process/server restart control, not power-loss certification"},new JsonSerializerOptions{WriteIndented=true}));return failed==0?0:1;
}
if(arguments.TryGetValue("--phase",out phase)&&phase=="restart-write")
{
    var store=new PostgresStore(connection,prefix);await store.Initialize();schemas.Add(prefix);await using var host=(await Start(store)).Host;
    await Check("writer process commits same-transaction domain and outbox before exit",async()=>{Require((await Change(host)).Status==HttpStatusCode.OK&&(await store.Row()).Revision==1&&(await store.Counts())==(1,0,0));});
    await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{passed,failed,checks,schemas,scope="Owned process exit before separate server restart/read"},new JsonSerializerOptions{WriteIndented=true}));return failed==0?0:1;
}

await Check("disabled transaction and relay activation performs no provider factories",()=>
{
    var factories=0;var executor=TenantChangeAuditOutboxExecutor<DomainSession>.ActivateValidated(new(TenantChangeAuditMode.Disabled),null,null,()=>{factories++;throw new InvalidOperationException();});
    var relay=TenantChangeAuditOutboxRelay.Activate(false,()=>{factories++;throw new InvalidOperationException();},()=>{factories++;throw new InvalidOperationException();});Require(executor is null&&relay is null&&factories==0);return Task.CompletedTask;
});
await Check("all host modules disabled skips trusted integration activation handler and SQL acquisition",async()=>
{
    var store=new PostgresStore(connection,"ao_"+Guid.NewGuid().ToString("N"));var integration=new OutboxIntegration(store,OutboxIntegration.Policy(TenantChangeAuditMode.ChangedFields));await using var host=new Host();
    await host.Start(tls,jwt,false,false,false,false,trailProfile:new(TenantChangeAuditMode.Disabled),trailIntegration:integration);Require(host.App is null&&integration.Activations==0&&integration.ProviderFactories==0&&integration.HandlerFactories==0&&store.Connections==0&&store.Begins==0);
});
foreach(var mode in new[]{TenantChangeAuditMode.Disabled,TenantChangeAuditMode.MetadataOnly,TenantChangeAuditMode.ChangedFields,TenantChangeAuditMode.BeforeAfterSnapshots})
await Check("project-selected transaction trail mode "+mode,async()=>
{
    var store=await Store();var setup=await Start(store,mode);await using var host=setup.Host;var result=await Change(host);Require(result.Status==HttpStatusCode.OK&&(await store.Row()).Revision==1);
    var counts=await store.Counts();Require(counts==(mode==TenantChangeAuditMode.Disabled?0:1,0,0));Require(setup.Integration.ProviderFactories==(mode==TenantChangeAuditMode.Disabled?0:1)&&setup.Integration.Values==(mode is TenantChangeAuditMode.Disabled or TenantChangeAuditMode.MetadataOnly?0:1));
    foreach(var raw in await store.Payloads()){Require(!raw.Contains("private-new-secret",StringComparison.Ordinal)&&!raw.Contains("private-domain-A",StringComparison.Ordinal));var record=PayloadCodec.Decode(raw);Require(record.Mode==mode&&record.CapturedMode==mode&&PayloadCodec.Encode(record)==raw);}
});
foreach(var graphql in new[]{false,true})
await Check("actual "+(graphql?"GraphQL":"HTTP")+" generated gateway commits domain and outbox atomically",async()=>
{
    var store=await Store();var setup=await Start(store);await using var host=setup.Host;var hidden=false;
    setup.Integration.AfterMutation=async _=>{Require((await store.Row()).Revision==0&&(await store.Counts())==(0,0,0));hidden=true;};
    var result=await Change(host,graphql:graphql);Require(result.Status==HttpStatusCode.OK&&hidden&&setup.Integration.Results==1&&store.Commits==1&&store.Rollbacks==0&&(await store.Counts())==(1,0,0));
});
await Check("cross-tenant HTTP request fails before provider begin or SQL mutation",async()=>
{
    var store=await Store();var setup=await Start(store);await using var host=setup.Host;var result=await Change(host,"B");Require(result.Status!=HttpStatusCode.OK&&store.Begins==0&&setup.Integration.Mutations==0&&(await store.Row("B")).Revision==0&&(await store.Counts("B"))==(0,0,0));
});
await Check("provider domain session rejects cross-tenant use inside a valid writer",async()=>
{
    var store=await Store();var setup=await Start(store);await using var host=setup.Host;setup.Integration.WrongSessionTenant=true;await Change(host);Require(setup.Integration.LastException?.Outcome==TenantChangeAuditTransactionOutcome.RolledBack&&(await store.Row()).Revision==0&&(await store.Row("B")).Revision==0&&(await store.Counts())==(0,0,0));
});
foreach(var fault in new[]{"callback","stage","receipt","values","rollback","commit-before","commit-after","dispose"})
await Check("real provider fault preserves transaction outcome "+fault,async()=>
{
    var store=await Store();var setup=await Start(store);await using var host=setup.Host;
    switch(fault){case "callback":setup.Integration.ThrowAfterMutation=true;break;case "stage":store.Fault=ProviderFault.StageAfterInsert;break;case "receipt":setup.Integration.WrongReceipt=true;break;case "values":setup.Integration.ThrowValues=true;break;case "rollback":setup.Integration.ThrowAfterMutation=true;store.Fault=ProviderFault.Rollback;break;case "commit-before":store.Fault=ProviderFault.CommitBefore;break;case "commit-after":store.Fault=ProviderFault.CommitAfter;break;case "dispose":store.Fault=ProviderFault.Dispose;break;}
    var result=await Change(host);Require(result.Status!=HttpStatusCode.OK&&setup.Integration.Results==0);var error=setup.Integration.LastException??throw new InvalidOperationException("Missing explicit transaction outcome.");
    var committed=fault is "commit-after" or "dispose";var expected=fault is "commit-before" or "commit-after"?TenantChangeAuditTransactionOutcome.CommitUnknown:fault=="rollback"?TenantChangeAuditTransactionOutcome.RollbackUnknown:fault=="dispose"?TenantChangeAuditTransactionOutcome.Committed:TenantChangeAuditTransactionOutcome.RolledBack;
    Require(error.Outcome==expected&&error.MayHaveCommitted==(expected!=TenantChangeAuditTransactionOutcome.RolledBack));Require((await store.Row()).Revision==(committed?1:0)&&(await store.Counts())==(committed?1:0,0,0));
    Require(store.Rollbacks==(fault is "commit-before" or "commit-after" or "dispose"?0:1)&&store.Disposals==1);
    if(fault=="rollback")Require(error.PrimaryFailure is not null&&error.RollbackFailure is not null);if(fault=="dispose")Require(error.DisposalFailure is not null);
});
await Check("retained transaction session cannot autocommit or acquire connection after disposal",async()=>
{
    var store=await Store();var setup=await Start(store);await using var host=setup.Host;Require((await Change(host)).Status==HttpStatusCode.OK);var before=store.Connections;var denied=false;
    try{await store.RetainedSession!.Change(new("A"),"shared","late",3,"private-late");}catch(InvalidOperationException){denied=true;}Require(denied&&store.Connections==before&&(await store.Row()).Revision==1&&(await store.Counts())==(1,0,0));
});
await Check("committed outbox is independent from unavailable final sink",async()=>
{
    var store=await Store();var setup=await Start(store);await using var host=setup.Host;store.Fault=ProviderFault.Sink;Require((await Change(host)).Status==HttpStatusCode.OK&&(await store.Counts())==(1,0,0));var relay=new RelayHost(Relay(store));Require(await RelayFails(relay)&&relay.LastException?.MayHaveDelivered==true&&(await store.Row()).Revision==1&&(await store.Counts())==(1,0,0));
});
await Check("fresh relay permission is required and writer context cannot relay after disposal",async()=>
{
    var store=await Store();var setup=await Start(store);await using var host=setup.Host;Require((await Change(host)).Status==HttpStatusCode.OK);var relay=Relay(store);var denied=false;try{await relay.RelayAsync(setup.Integration.RetainedWriterContext!);}catch(TenantAccessDeniedException){denied=true;}Require(denied&&store.Claims==0);
    var service=new RelayHost(relay);service.Authority.AllowRelay=false;Require(!(await service.Run()).IsSuccess&&store.Claims==0);service.Authority.AllowRelay=true;Require((await service.Run()).IsSuccess&&service.Authority.IdentityLookups==2&&(await store.Counts())==(1,1,1));
});
await Check("relay cross-tenant denial occurs before provider claim",async()=>
{
    var store=await Store();var setup=await Start(store);await using var host=setup.Host;Require((await Change(host)).Status==HttpStatusCode.OK);var relay=new RelayHost(Relay(store));Require(!(await relay.Run("B")).IsSuccess&&store.Claims==0&&(await store.Counts())==(1,0,0));relay.Authority.AllowB=true;Require(!(await relay.Run("C")).IsSuccess&&store.Claims==0);
});
await Check("successful relay persists physically redacted payload and acknowledges one row",async()=>
{
    var store=await Store();var setup=await Start(store);await using var host=setup.Host;Require((await Change(host)).Status==HttpStatusCode.OK);var service=new RelayHost(Relay(store));var result=await service.Run();Require(result.IsSuccess&&result.Value.Acknowledged==1&&(await store.Counts())==(1,1,1));var raw=(await store.Payloads("audit_sink")).Single();Require(!raw.Contains("private-new-secret",StringComparison.Ordinal)&&PayloadCodec.Encode(PayloadCodec.Decode(raw))==raw&&PayloadCodec.Decode(raw).Fields.Single(f=>f.Name=="secret").Before.Kind==TenantChangeValueKind.Redacted);
});
await Check("sink success followed by acknowledgement loss replays same payload idempotently",async()=>
{
    var store=await Store();var setup=await Start(store);await using var host=setup.Host;Require((await Change(host)).Status==HttpStatusCode.OK);var original=(await store.Payloads()).Single();store.Fault=ProviderFault.Ack;var service=new RelayHost(Relay(store));Require(await RelayFails(service)&&service.LastException?.AcknowledgedCount==0&&(await store.Counts())==(1,0,1));store.Fault=ProviderFault.None;
    Require((await new RelayHost(Relay(store)).Run()).IsSuccess&&(await store.Counts())==(1,1,1)&&store.SinkCalls==2&&(await store.Payloads("audit_sink")).Single()==original);
});
await Check("idempotent sink rejects conflicting payload without overwriting stored value",async()=>
{
    var store=await Store();var setup=await Start(store);await using var host=setup.Host;await Change(host);var record=PayloadCodec.Decode((await store.Payloads()).Single());await store.AppendOnceAsync(record,default);var conflicting=new TenantChangeAuditRecord(record.Receipt,record.RecordedAtUtc.AddTicks(1),record.Mode,record.Fields);var denied=false;try{await store.AppendOnceAsync(conflicting,default);}catch(InvalidOperationException){denied=true;}Require(denied&&(await store.Payloads("audit_sink")).Single()==PayloadCodec.Encode(record));
});
await Check("sink receipt identity includes tenant and does not deduplicate a different tenant",async()=>
{
    var store=await Store();var setup=await Start(store);await using var host=setup.Host;await Change(host);var record=PayloadCodec.Decode((await store.Payloads()).Single());await store.AppendOnceAsync(record,default);var b=new TenantChangeAuditRecord(PostgresStore.ReplaceTenant(record.Receipt,new("B")),record.RecordedAtUtc,record.Mode,record.Fields);await store.AppendOnceAsync(b,default);Require((await store.Counts()).Sink==1&&(await store.Counts("B")).Sink==1);
});
await Check("stale provider acknowledgement and release cannot steal a replacement lease",async()=>
{
    var store=await Store();var setup=await Start(store);await using var host=setup.Host;await Change(host);var first=await store.ClaimAsync(new("A"),1,TimeSpan.FromSeconds(30),default)??throw new InvalidOperationException();await store.ReleaseAsync(first,default);var second=await store.ClaimAsync(new("A"),1,TimeSpan.FromSeconds(30),default)??throw new InvalidOperationException();Require(first.LeaseId!=second.LeaseId&&!await store.AcknowledgeAsync(first,first.Records[0].Receipt.ReceiptId,default));await store.ReleaseAsync(first,default);Require(await store.ClaimAsync(new("A"),1,TimeSpan.FromSeconds(30),default) is null);Require(await store.AcknowledgeAsync(second,second.Records[0].Receipt.ReceiptId,default));
});
await Check("concurrent provider claims hold disjoint fenced rows",async()=>
{
    var store=await Store();var setup=await Start(store);await using var host=setup.Host;await Change(host,title:"one");await Change(host,title:"two");var start=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var tasks=Enumerable.Range(0,2).Select(_=>Task.Run(async()=>{await start.Task;return await store.ClaimAsync(new("A"),1,TimeSpan.FromSeconds(30),default);})).ToArray();start.TrySetResult();var leases=await Task.WhenAll(tasks);Require(leases.All(x=>x is not null)&&leases[0]!.Records[0].Receipt.ReceiptId!=leases[1]!.Records[0].Receipt.ReceiptId);foreach(var lease in leases)await store.ReleaseAsync(lease!,default);
});
await Check("authoritative provider expiry rejects an expired acknowledgement",async()=>
{
    var store=await Store();var setup=await Start(store);await using var host=setup.Host;await Change(host);store.ShortLease=true;var lease=await store.ClaimAsync(new("A"),1,TimeSpan.FromSeconds(30),default)??throw new InvalidOperationException();await Task.Delay(250);Require(!await store.AcknowledgeAsync(lease,lease.Records[0].Receipt.ReceiptId,default));store.ShortLease=false;Require(await store.ClaimAsync(new("A"),1,TimeSpan.FromSeconds(30),default) is not null);
});
await Check("retained relay context cannot claim a second batch after dispatch ends",async()=>
{
    var store=await Store();var setup=await Start(store);await using var host=setup.Host;await Change(host);var relay=Relay(store);var service=new RelayHost(relay);Require((await service.Run()).IsSuccess);var calls=store.Claims;var denied=false;try{await relay.RelayAsync(service.RetainedContext!);}catch(TenantAccessDeniedException){denied=true;}Require(denied&&store.Claims==calls);
});

await Check("actual final-sink history stays empty until relay then uses distinct read permission",async()=>
{
    var store=await Store();var setup=await Start(store);await using var host=setup.Host;Require((await Change(host)).Status==HttpStatusCode.OK);
    async Task<(HttpStatusCode Status,JsonElement Body)> History(string tenant="A",string subject="trail-reader")
    {
        using var client=tls.Client(host.Address);using var request=new HttpRequestMessage(HttpMethod.Post,"/trail/history"){Content=JsonContent.Create(new TrailHistoryRequest(tenant))};request.Headers.Authorization=new("Bearer",jwt.Token(subject));using var response=await client.SendAsync(request);return(response.StatusCode,JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement);
    }
    var pending=await History();Require(pending.Status==HttpStatusCode.OK&&pending.Body.GetProperty("entries").GetArrayLength()==0);
    var reads=store.HistoryReads;Require((await History(subject:"auditor")).Status!=HttpStatusCode.OK&&(await History("B")).Status!=HttpStatusCode.OK&&store.HistoryReads==reads);
    Require((await new RelayHost(Relay(store)).Run()).IsSuccess);var delivered=await History();Require(delivered.Status==HttpStatusCode.OK&&delivered.Body.GetProperty("entries").GetArrayLength()==1&&!delivered.Body.GetRawText().Contains("private-new-secret",StringComparison.Ordinal));
    setup.Integration.HistoryPolicy=new(TenantChangeAuditMode.MetadataOnly);var hidden=await History();Require(hidden.Body.GetProperty("entries")[0].GetProperty("fields").GetArrayLength()==0);
});
await Check("unsupported create action rejects before outbox provider begins",async()=>
{
    var store=await Store();var setup=await Start(store);await using var host=setup.Host;using var client=tls.Client(host.Address);using var request=new HttpRequestMessage(HttpMethod.Post,"/entity/create"){Content=JsonContent.Create(new EntityMutationRequest("A","created","unsupported",1,"private-new-secret"))};request.Headers.Authorization=new("Bearer",jwt.Token());using var response=await client.SendAsync(request);Require(response.StatusCode!=HttpStatusCode.OK&&store.Begins==0&&store.Stages==0);
});
foreach(var afterCommit in new[]{false,true})
await Check("caller cancellation reports actual transaction phase "+(afterCommit?"committed":"rolled back"),async()=>
{
    var store=await Store();var setup=await Start(store);await using var host=setup.Host;using var cancel=new CancellationTokenSource();setup.Integration.CallerCancellation=cancel;
    if(afterCommit)store.AfterCommit=cancel.Cancel;else setup.Integration.AfterMutation=_=>{cancel.Cancel();return Task.CompletedTask;};
    Require((await Change(host)).Status!=HttpStatusCode.OK&&setup.Integration.Results==0);Require(setup.Integration.LastException?.Outcome==(afterCommit?TenantChangeAuditTransactionOutcome.Committed:TenantChangeAuditTransactionOutcome.RolledBack));Require((await store.Row()).Revision==(afterCommit?1:0)&&(await store.Counts())==(afterCommit?1:0,0,0));
});

var priorOutboxPassed=passed;var priorOutboxFailed=failed;
await StatusChecks.Run(Check,()=>Store(),async store=>{var setup=await Start(store);await using var host=setup.Host;Require((await Change(host)).Status==HttpStatusCode.OK);});
var statusPassed=passed-priorOutboxPassed;var statusFailed=failed-priorOutboxFailed;
var beforeRelayBudgetPassed=passed;var beforeRelayBudgetFailed=failed;var relayBudgetObservations=new List<object>();
await RelayBudgetChecks.Run(Check,()=>Store(),async store=>{var setup=await Start(store);await using var host=setup.Host;Require((await Change(host)).Status==HttpStatusCode.OK);},connection,relayBudgetObservations.Add);
var relayBudgetPassed=passed-beforeRelayBudgetPassed;var relayBudgetFailed=failed-beforeRelayBudgetFailed;
var beforeDrainPassed=passed;var beforeDrainFailed=failed;var drainObservations=new List<object>();
await DrainChecks.Run(Check,()=>Store(),async store=>{var setup=await Start(store);await using var host=setup.Host;Require((await Change(host)).Status==HttpStatusCode.OK);},connection,drainObservations.Add);
var drainPassed=passed-beforeDrainPassed;var drainFailed=failed-beforeDrainFailed;
var beforeTotalDrainPassed=passed;var beforeTotalDrainFailed=failed;var totalDrainObservations=new List<object>();
await TotalDrainBudgetChecks.Run(Check,()=>Store(),async store=>{var setup=await Start(store);await using var host=setup.Host;Require((await Change(host)).Status==HttpStatusCode.OK);},connection,totalDrainObservations.Add);
var totalDrainPassed=passed-beforeTotalDrainPassed;var totalDrainFailed=failed-beforeTotalDrainFailed;
var beforeLookupPassed=passed;var beforeLookupFailed=failed;var lookupObservations=new List<object>();
await LookupChecks.Run(Check,()=>Store(),async store=>{var setup=await Start(store);await using var host=setup.Host;Require((await Change(host)).Status==HttpStatusCode.OK);},connection,lookupObservations.Add);
var lookupPassed=passed-beforeLookupPassed;var lookupFailed=failed-beforeLookupFailed;
var beforeResourceHistoryPassed=passed;var beforeResourceHistoryFailed=failed;var resourceHistoryObservations=new List<object>();
await ResourceHistoryChecks.Run(Check,()=>Store(),async store=>{var setup=await Start(store);await using var host=setup.Host;Require((await Change(host)).Status==HttpStatusCode.OK);},connection,resourceHistoryObservations.Add);
var resourceHistoryPassed=passed-beforeResourceHistoryPassed;var resourceHistoryFailed=failed-beforeResourceHistoryFailed;
var beforeIndexedPassed=passed;var beforeIndexedFailed=failed;var indexedObservations=new List<object>();
await IndexedStorageChecks.Run(Check,()=>Store(),async store=>{var setup=await Start(store);await using var host=setup.Host;Require((await Change(host)).Status==HttpStatusCode.OK);},connection,arguments["--connection-file"],indexedObservations.Add);
var indexedPassed=passed-beforeIndexedPassed;var indexedFailed=failed-beforeIndexedFailed;
var beforeReadBudgetPassed=passed;var beforeReadBudgetFailed=failed;var readBudgetObservations=new List<object>();
await ReadBudgetChecks.Run(Check,()=>Store(),connection,readBudgetObservations.Add);
var readBudgetPassed=passed-beforeReadBudgetPassed;var readBudgetFailed=failed-beforeReadBudgetFailed;
var beforeReceiptTransportPassed=passed;var beforeReceiptTransportFailed=failed;var receiptTransportObservations=new List<object>();
await ReceiptTransportChecks.Run(Check,()=>Store(),async store=>{var setup=await Start(store);await using var host=setup.Host;Require((await Change(host)).Status==HttpStatusCode.OK);},connection,arguments["--connection-file"],receiptTransportObservations.Add);
var receiptTransportPassed=passed-beforeReceiptTransportPassed;var receiptTransportFailed=failed-beforeReceiptTransportFailed;
var beforeResourceTransportPassed=passed;var beforeResourceTransportFailed=failed;var resourceTransportObservations=new List<object>();
await ResourceTransportChecks.Run(Check,()=>Store(),async store=>{var setup=await Start(store);await using var host=setup.Host;Require((await Change(host)).Status==HttpStatusCode.OK);},connection,arguments["--connection-file"],resourceTransportObservations.Add);
var resourceTransportPassed=passed-beforeResourceTransportPassed;var resourceTransportFailed=failed-beforeResourceTransportFailed;
var beforeAdmissionPassed=passed;var beforeAdmissionFailed=failed;var admissionObservations=new List<object>();
await ResourceTransportChecks.RunAdmission(Check,()=>Store(),connection,arguments["--connection-file"],admissionObservations.Add);
var admissionPassed=passed-beforeAdmissionPassed;var admissionFailed=failed-beforeAdmissionFailed;
var settingsStore=await Store();var settings=JsonDocument.Parse(await settingsStore.VersionSettings()).RootElement;
await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{passed,failed,checks,schemas,settings,prior_outbox_passed=priorOutboxPassed,prior_outbox_failed=priorOutboxFailed,status_passed=statusPassed,status_failed=statusFailed,relay_budget_passed=relayBudgetPassed,relay_budget_failed=relayBudgetFailed,relay_budget_observations=relayBudgetObservations,drain_passed=drainPassed,drain_failed=drainFailed,drain_observations=drainObservations,total_drain_passed=totalDrainPassed,total_drain_failed=totalDrainFailed,total_drain_observations=totalDrainObservations,lookup_passed=lookupPassed,lookup_failed=lookupFailed,lookup_observations=lookupObservations,resource_history_passed=resourceHistoryPassed,resource_history_failed=resourceHistoryFailed,resource_history_observations=resourceHistoryObservations,indexed_storage_passed=indexedPassed,indexed_storage_failed=indexedFailed,indexed_storage_observations=indexedObservations,read_budget_passed=readBudgetPassed,read_budget_failed=readBudgetFailed,read_budget_observations=readBudgetObservations,receipt_transport_passed=receiptTransportPassed,receipt_transport_failed=receiptTransportFailed,receipt_transport_observations=receiptTransportObservations,resource_transport_passed=resourceTransportPassed,resource_transport_failed=resourceTransportFailed,resource_transport_observations=resourceTransportObservations,admission_passed=admissionPassed,admission_failed=admissionFailed,admission_observations=admissionObservations,scope="Owned PostgreSQL18/Npgsql10.0.3 transaction/outbox conformance; no physical power-loss, all-provider, benchmark or production qualification",providerTopology=OperatingSystem.IsWindows()?"Windows.NET via owned loopback/stdio proxy to WSL container":"WSL.NET directly to WSL loopback container"},new JsonSerializerOptions{WriteIndented=true}));
Console.WriteLine($"PostgreSQL audit outbox: {passed}/{passed+failed}");return failed==0?0:1;
