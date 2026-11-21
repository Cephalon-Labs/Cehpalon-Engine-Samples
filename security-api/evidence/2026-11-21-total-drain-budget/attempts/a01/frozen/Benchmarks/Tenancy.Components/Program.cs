using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;

var output=Path.GetFullPath(args.Single(x=>x.StartsWith("--output=",StringComparison.Ordinal))[9..]);
if (args.Contains("--observe-budget-metrics", StringComparer.Ordinal))
    return await BudgetSnapshotObservation.RunAsync(output, observeMetrics: true);
if (args.Contains("--observe-budget-contention", StringComparer.Ordinal))
    return await BudgetContentionObservation.RunAsync(output);
if (args.Contains("--observe-budget-snapshots", StringComparer.Ordinal))
    return await BudgetSnapshotObservation.RunAsync(output);
if(File.Exists(output)) throw new IOException("Retain previous results; use a new file.");
const int iterations=10_000,warmup=1_000,repetitions=5;
var authority=new FixtureAuthority();
var registry=new TenantOperationRegistryBuilder().Register<ReadRequest,int>("documents.read","documents.read","document",r=>new(r.Tenant,r.Value),r=>new(r.Tenant,"shared"),()=>{authority.Factories++;return new Reader(authority);}).Build();
var dispatcher=new TenantOperationDispatcher(registry,new TenantSecurityServices(authority,new IdentityTrustPolicy([FixtureAuthority.Issuer],["fixture"]),authority,authority,TimeSpan.FromSeconds(30),authority,new FixedClock()));
var correlation=new OperationContext("benchmark");
int Invoke(bool allowed,int value)
{
    var pending=dispatcher.DispatchAsync<ReadRequest,int>("documents.read",new(allowed?authority.A:authority.B,value),correlation);
    if(!pending.IsCompletedSuccessfully) throw new InvalidOperationException("Current-thread allocation protocol requires a synchronous measured path.");
    var result=pending.GetAwaiter().GetResult();
    if(allowed) { if(!result.IsSuccess || result.Value!=value) throw new InvalidOperationException("Allowed result differs.");return result.Value; }
    if(result.IsSuccess || result.Error.Code!="access.denied" || result.Error.Message!="Access denied.") throw new InvalidOperationException("Denial must stay generic.");
    return 0;
}
for(var i=0;i<warmup;i++) {Invoke(true,i);Invoke(false,i);}
var runs=new List<Pair>();
Measurement Measure(bool allowed)
{
    authority.Reset();long checksum=0;
    var before=GC.GetAllocatedBytesForCurrentThread();var started=Stopwatch.GetTimestamp();
    for(var i=0;i<iterations;i++) checksum+=Invoke(allowed,i);
    var elapsed=Stopwatch.GetTimestamp()-started;var allocated=GC.GetAllocatedBytesForCurrentThread()-before;
    var counts=new Counts(authority.Identities,authority.Memberships,authority.Resources,authority.Policies,authority.Factories,authority.Reads,authority.Disposals);
    var correct=allowed ? checksum==(long)iterations*(iterations-1)/2 && counts==new Counts(iterations,iterations,iterations,iterations,iterations,iterations,iterations) : checksum==0 && counts==new Counts(iterations,iterations,0,0,0,0,0);
    return new(elapsed,allocated,elapsed*1_000_000_000d/Stopwatch.Frequency/iterations,(double)allocated/iterations,checksum,counts,correct);
}
for(var i=0;i<repetitions;i++)
{
    Measurement allowed,denied;
    if(i%2==0) {allowed=Measure(true);denied=Measure(false);} else {denied=Measure(false);allowed=Measure(true);}
    runs.Add(new(i,i%2==0?"allowed,denied":"denied,allowed",allowed,denied));
}
double Median(IEnumerable<double> values)=>values.Order().ElementAt(repetitions/2);
var checks=new[]{
    new {name="all outcomes, checksums and authority/ownership counts",passed=runs.All(r=>r.Allowed.Correct && r.Denied.Correct)},
    new {name="authorized median <=100us/op",passed=Median(runs.Select(r=>r.Allowed.NanosecondsPerOperation))<=100_000},
    new {name="authorized median <=16KiB/op",passed=Median(runs.Select(r=>r.Allowed.BytesPerOperation))<=16*1024},
    new {name="denied median <=100us/op",passed=Median(runs.Select(r=>r.Denied.NanosecondsPerOperation))<=100_000},
    new {name="denied median <=8KiB/op",passed=Median(runs.Select(r=>r.Denied.BytesPerOperation))<=8*1024}
};
var report=new {observedAtUtc=DateTimeOffset.UtcNow,scope="Synchronous portable tenant/identity fixture regression smoke, no token crypto/network/provider/production benchmark",framework=RuntimeInformation.FrameworkDescription,os=RuntimeInformation.OSDescription,logicalProcessors=Environment.ProcessorCount,iterations,warmup,repetitions,runs,checks,passed=checks.All(c=>c.passed)};
Directory.CreateDirectory(Path.GetDirectoryName(output)!);
await using(var stream=new FileStream(output,FileMode.CreateNew,FileAccess.Write,FileShare.None)) await JsonSerializer.SerializeAsync(stream,report,new JsonSerializerOptions {WriteIndented=true});
Console.WriteLine($"Tenant guardrails: {checks.Count(c=>c.passed)}/{checks.Length}");
return report.passed?0:1;

sealed record ReadRequest(TenantId Tenant,int Value);
sealed record Counts(int Identities,int Memberships,int Resources,int Policies,int Factories,int Reads,int Disposals);
sealed record Measurement(long ElapsedTicks,long AllocatedBytes,double NanosecondsPerOperation,double BytesPerOperation,long Checksum,Counts Counts,bool Correct);
sealed record Pair(int Repetition,string Order,Measurement Allowed,Measurement Denied);
sealed class FixedClock:TimeProvider { public override DateTimeOffset GetUtcNow()=>FixtureAuthority.Now; }
sealed class FixtureAuthority:IIdentitySource,ITenantMembershipSource,IResourceScopeSource,ITenantAccessPolicy
{
    internal const string Issuer="urn:cehpalon:benchmark-fixture";
    internal static readonly DateTimeOffset Now=new(2026,10,27,0,0,0,TimeSpan.Zero);
    internal readonly TenantId A=new("tenant-a"),B=new("tenant-b");
    private readonly IdentitySnapshot identity=new(new(Issuer,"fixture-alice"),"fixture",Now.AddMinutes(-1),Now.AddHours(1));
    internal int Identities,Memberships,Resources,Policies,Factories,Reads,Disposals;
    public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken ct) {ct.ThrowIfCancellationRequested();Identities++;return ValueTask.FromResult<IdentitySnapshot?>(identity);}
    public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot current,TenantId tenant,CancellationToken ct)
    {ct.ThrowIfCancellationRequested();Memberships++;return ValueTask.FromResult<TenantMembershipSnapshot?>(tenant.Equals(A)?new(current.Principal,A,true,Now.AddMinutes(-1),Now.AddHours(1),"1"):null);}
    public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId tenant,string kind,string id,CancellationToken ct)
    {ct.ThrowIfCancellationRequested();Resources++;return ValueTask.FromResult<ResourceScopeSnapshot?>(tenant.Equals(A) && kind=="document" && id=="shared"?new(A,kind,id,"1"):null);}
    public ValueTask<bool> IsAllowedAsync(TenantAccessRequest request,CancellationToken ct) {ct.ThrowIfCancellationRequested();Policies++;return ValueTask.FromResult(request.OperationId=="documents.read" && request.Action=="documents.read");}
    internal void Reset()=>Identities=Memberships=Resources=Policies=Factories=Reads=Disposals=0;
}
sealed class Reader(FixtureAuthority authority):ITenantOperationHandler<ReadRequest,int>,IDisposable
{
    public ValueTask<OperationResult<int>> HandleAsync(ReadRequest request,TenantOperationContext context,CancellationToken ct)
    {ct.ThrowIfCancellationRequested();context.DemandAccess(request.Tenant,"document","shared","documents.read");authority.Reads++;return ValueTask.FromResult(OperationResult<int>.Success(request.Value));}
    public void Dispose()=>authority.Disposals++;
}
