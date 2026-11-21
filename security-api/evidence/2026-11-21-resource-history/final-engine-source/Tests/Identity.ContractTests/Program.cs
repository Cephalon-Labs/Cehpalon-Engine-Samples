using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using Cehpalon.Engine.Identity;

var pathArgument=args.SingleOrDefault(a=>a.StartsWith("--output=",StringComparison.Ordinal))
    ?? throw new ArgumentException("--output=<new-result.json> is required");
var outputPath=Path.GetFullPath(pathArgument[9..]);
if(File.Exists(outputPath)) throw new IOException("Retain previous results; select a fresh output file.");
var checks=new List<CheckResult>();
async Task Check(string name,Func<Task> test)
{
    try { await test(); checks.Add(new(name,true,null)); }
    catch(Exception error) { checks.Add(new(name,false,error.ToString())); }
}
Task Sync(Action action) { action(); return Task.CompletedTask; }
void Assert(bool value,string message="Contract assertion failed") { if(!value) throw new InvalidOperationException(message); }
void Throws<T>(Action action) where T:Exception
{
    try { action(); }
    catch(T) { return; }
    throw new InvalidOperationException("Expected "+typeof(T).Name);
}
var now=new DateTimeOffset(2026,10,27,12,0,0,TimeSpan.Zero);
const string issuer="urn:fixture:issuer";
const string scheme="fixture-validated";
PrincipalId Principal(string subject="alice")=>new(issuer,subject);
IdentitySnapshot Snapshot(string issuerValue=issuer,string schemeValue=scheme,DateTimeOffset? before=null,DateTimeOffset? after=null)
    =>new(new(issuerValue,"alice"),schemeValue,before??now.AddMinutes(-1),after??now.AddMinutes(1));
var trust=new IdentityTrustPolicy([issuer],[scheme]);

await Check("principal exact issuer-subject equality and dictionary identity",()=>Sync(()=>
{
    var first=Principal(); var same=Principal(); var otherSubject=Principal("Alice"); var otherIssuer=new PrincipalId("urn:fixture:Issuer","alice");
    var values=new Dictionary<PrincipalId,int>{{first,1},{otherSubject,2},{otherIssuer,3}};
    Assert(values[same]==1 && values.Count==3);
    Assert(first.Equals(same) && first.Equals((object)same) && first.GetHashCode()==same.GetHashCode());
    Assert(!first.Equals(otherSubject) && !first.Equals(otherIssuer) && !first.Equals(null) && !first.Equals((object)"alice"));
}));
await Check("principal issuer and subject cannot collide through concatenation",()=>Sync(()=>
{
    var first=new PrincipalId("urn:issuer:a","b:c"); var second=new PrincipalId("urn:issuer:a:b","c");
    Assert(!first.Equals(second));
    var map=new Dictionary<PrincipalId,int>{{first,1},{second,2}}; Assert(map.Count==2);
}));
await Check("issuer text is opaque and not normalized",()=>Sync(()=>
{
    var first=new PrincipalId("https://issuer.example/realm","subject");
    Assert(!first.Equals(new PrincipalId("https://issuer.example/realm/","subject")));
    Assert(!first.Equals(new PrincipalId("https://ISSUER.example/realm","subject")));
    Assert(new PrincipalId("fixture:service","opaque subject").Issuer=="fixture:service");
    Assert(new PrincipalId(" "+issuer,"alice").Issuer==" "+issuer);
}));
await Check("principal blank/null issuer and subject rejected",()=>Sync(()=>
{
    foreach(var invalid in new string?[]{null,""," ","\t\n"})
    {
        Throws<ArgumentException>(()=>new PrincipalId(invalid!,"subject"));
        Throws<ArgumentException>(()=>new PrincipalId(issuer,invalid!));
    }
}));
await Check("principal issuer and subject maximum bounds",()=>Sync(()=>
{
    Assert(new PrincipalId(new('a',2048),new('b',256)).Issuer.Length==2048);
    Throws<ArgumentException>(()=>new PrincipalId(new('a',2049),"x"));
    Throws<ArgumentException>(()=>new PrincipalId(issuer,new('b',257)));
}));
await Check("principal text rejects controls without echoing values",()=>Sync(()=>
{
    foreach(var invalid in new[]{"a\0b","a\r\nb","a\u007fb","a\u0085b"})
    {
        Throws<ArgumentException>(()=>new PrincipalId(invalid,"valid"));
        Throws<ArgumentException>(()=>new PrincipalId(issuer,invalid));
    }
}));
await Check("principal text rejects isolated and reversed UTF16 surrogates",()=>Sync(()=>
{
    foreach(var invalid in new[]{"\uD800","\uDC00","a\uD800b","\uDC00\uD800"})
    {
        Throws<ArgumentException>(()=>new PrincipalId(invalid,"valid"));
        Throws<ArgumentException>(()=>new PrincipalId(issuer,invalid));
    }
}));
await Check("valid supplementary Unicode remains exact and counts UTF16 units",()=>Sync(()=>
{
    var valid=new PrincipalId(issuer,"user😀"); Assert(valid.Subject=="user😀");
    Assert(new PrincipalId(issuer,new string('a',254)+"😀").Subject.Length==256);
    Throws<ArgumentException>(()=>new PrincipalId(issuer,new string('a',255)+"😀"));
    Assert(!new PrincipalId(issuer,"é").Equals(new PrincipalId(issuer,"e\u0301")));
}));
await Check("snapshot is immutable and retains exact principal and scheme",()=>Sync(()=>
{
    var principal=Principal(); var snapshot=new IdentitySnapshot(principal,scheme,now,now.AddTicks(1));
    Assert(ReferenceEquals(snapshot.Principal,principal) && snapshot.AuthenticationScheme==scheme);
    Assert(typeof(PrincipalId).IsSealed && typeof(IdentitySnapshot).IsSealed);
    Assert(typeof(PrincipalId).GetProperties().Concat(typeof(IdentitySnapshot).GetProperties()).All(p=>p.SetMethod is null));
}));
await Check("snapshot rejects null principal and blank scheme",()=>Sync(()=>
{
    Throws<ArgumentNullException>(()=>new IdentitySnapshot(null!,scheme,now,now.AddMinutes(1)));
    foreach(var invalid in new string?[]{null,""," "}) Throws<ArgumentException>(()=>new IdentitySnapshot(Principal(),invalid!,now,now.AddMinutes(1)));
}));
await Check("snapshot scheme exact bounds, controls and malformed UTF16",()=>Sync(()=>
{
    Assert(new IdentitySnapshot(Principal(),new('s',128),now,now.AddSeconds(1)).AuthenticationScheme.Length==128);
    foreach(var invalid in new[]{new string('s',129),"a\0b","a\rb","\uD800","\uDC00"})
        Throws<ArgumentException>(()=>new IdentitySnapshot(Principal(),invalid,now,now.AddSeconds(1)));
}));
await Check("snapshot requires positive validity even across offsets",()=>Sync(()=>
{
    Throws<ArgumentException>(()=>new IdentitySnapshot(Principal(),scheme,now,now));
    Throws<ArgumentException>(()=>new IdentitySnapshot(Principal(),scheme,now,now.AddTicks(-1)));
    Throws<ArgumentException>(()=>new IdentitySnapshot(Principal(),scheme,now.ToOffset(TimeSpan.FromHours(7)),now));
}));
await Check("snapshot normalizes offsets to UTC preserving instants",()=>Sync(()=>
{
    var snapshot=new IdentitySnapshot(Principal(),scheme,now.ToOffset(TimeSpan.FromHours(7)),now.AddMinutes(1).ToOffset(TimeSpan.FromHours(-5)));
    Assert(snapshot.NotBeforeUtc.Offset==TimeSpan.Zero && snapshot.ExpiresAtUtc.Offset==TimeSpan.Zero);
    Assert(snapshot.NotBeforeUtc==now && snapshot.ExpiresAtUtc==now.AddMinutes(1));
}));
await Check("trust defaults deny with either empty allowlist",()=>Sync(()=>
{
    Assert(!new IdentityTrustPolicy([],[]).IsAccepted(Snapshot(),now));
    Assert(!new IdentityTrustPolicy([],[scheme]).IsAccepted(Snapshot(),now));
    Assert(!new IdentityTrustPolicy([issuer],[]).IsAccepted(Snapshot(),now));
}));
await Check("anonymous identity denied",()=>Sync(()=>Assert(!trust.IsAccepted(null,now))));
await Check("explicit trusted issuer scheme and current lifetime accepted",()=>Sync(()=>Assert(trust.IsAccepted(Snapshot(),now))));
await Check("wrong issuer denied even when subject matches",()=>Sync(()=>Assert(!trust.IsAccepted(Snapshot(issuerValue:"urn:attacker"),now))));
await Check("wrong authentication scheme denied",()=>Sync(()=>Assert(!trust.IsAccepted(Snapshot(schemeValue:"unvalidated"),now))));
await Check("issuer and scheme comparisons are ordinal",()=>Sync(()=>
{
    Assert(!trust.IsAccepted(Snapshot(issuerValue:"URN:fixture:issuer"),now));
    Assert(!trust.IsAccepted(Snapshot(schemeValue:"Fixture-validated"),now));
    Assert(!trust.IsAccepted(Snapshot(issuerValue:issuer+"/"),now));
}));
await Check("not-before inclusive lower bound",()=>Sync(()=>
{
    var identity=Snapshot(before:now,after:now.AddSeconds(1));
    Assert(trust.IsAccepted(identity,now) && !trust.IsAccepted(identity,now.AddTicks(-1)));
}));
await Check("expiry exclusive upper bound",()=>Sync(()=>
{
    var identity=Snapshot(before:now.AddSeconds(-1),after:now);
    Assert(!trust.IsAccepted(identity,now) && trust.IsAccepted(identity,now.AddTicks(-1)));
}));
await Check("clock offset does not change instant acceptance",()=>Sync(()=>
{
    Assert(trust.IsAccepted(Snapshot(),now.ToOffset(TimeSpan.FromHours(7))));
    Assert(trust.IsAccepted(Snapshot(),now.ToOffset(TimeSpan.FromHours(-5))));
}));
await Check("expired and not-yet-valid representations denied",()=>Sync(()=>
{
    Assert(!trust.IsAccepted(Snapshot(before:now.AddMinutes(-3),after:now.AddMinutes(-2)),now));
    Assert(!trust.IsAccepted(Snapshot(before:now.AddMinutes(1),after:now.AddMinutes(2)),now));
}));
await Check("trusted allowlists are defensive immutable snapshots",()=>Sync(()=>
{
    var issuers=new List<string>{issuer}; var schemes=new List<string>{scheme};
    var policy=new IdentityTrustPolicy(issuers,schemes);
    issuers[0]="urn:attacker"; schemes.Clear();
    Assert(policy.IsAccepted(Snapshot(),now) && !policy.IsAccepted(Snapshot(issuerValue:"urn:attacker"),now));
    Assert(policy.AllowedIssuers.SetEquals([issuer]) && policy.AllowedSchemes.SetEquals([scheme]));
    if(policy.AllowedIssuers is ISet<string> set) Throws<NotSupportedException>(()=>set.Add("urn:attacker"));
}));
await Check("duplicate trust values rejected, distinct ordinal cases retained",()=>Sync(()=>
{
    Throws<ArgumentException>(()=>new IdentityTrustPolicy([issuer,issuer],[scheme]));
    Throws<ArgumentException>(()=>new IdentityTrustPolicy([issuer],[scheme,scheme]));
    var policy=new IdentityTrustPolicy([issuer,issuer.ToUpperInvariant()],[scheme,scheme.ToUpperInvariant()]);
    Assert(policy.AllowedIssuers.Count==2 && policy.AllowedSchemes.Count==2);
}));
await Check("null and invalid trust collections or values rejected",()=>Sync(()=>
{
    Throws<ArgumentNullException>(()=>new IdentityTrustPolicy(null!,[scheme]));
    Throws<ArgumentNullException>(()=>new IdentityTrustPolicy([issuer],null!));
    foreach(var invalid in new string?[]{null,""," ","x\0y","\uD800"})
    {
        Throws<ArgumentException>(()=>new IdentityTrustPolicy([invalid!],[scheme]));
        Throws<ArgumentException>(()=>new IdentityTrustPolicy([issuer],[invalid!]));
    }
}));
await Check("trust per-value lengths match snapshot representation bounds",()=>Sync(()=>
{
    var policy=new IdentityTrustPolicy([new string('i',2048)],[new string('s',128)]);
    Assert(policy.IsAccepted(new(new(new('i',2048),"x"),new('s',128),now.AddSeconds(-1),now.AddSeconds(1)),now));
    Throws<ArgumentException>(()=>new IdentityTrustPolicy([new string('i',2049)],[scheme]));
    Throws<ArgumentException>(()=>new IdentityTrustPolicy([issuer],[new string('s',129)]));
}));
await Check("trust enumeration maximum counts all values and bounds infinite sequences",()=>Sync(()=>
{
    Assert(new IdentityTrustPolicy(Enumerable.Range(0,256).Select(i=>"issuer"+i),[scheme]).AllowedIssuers.Count==256);
    Assert(new IdentityTrustPolicy([issuer],Enumerable.Range(0,256).Select(i=>"scheme"+i)).AllowedSchemes.Count==256);
    Throws<ArgumentException>(()=>new IdentityTrustPolicy(Enumerable.Range(0,257).Select(i=>"issuer"+i),[scheme]));
    Throws<ArgumentException>(()=>new IdentityTrustPolicy([issuer],Enumerable.Range(0,257).Select(i=>"scheme"+i)));
    var count=0;
    IEnumerable<string> Forever() { while(true) { count++; yield return issuer+count; } }
    Throws<ArgumentException>(()=>new IdentityTrustPolicy(Forever(),[scheme])); Assert(count==257);
}));
await Check("parallel read-only trust checks have no shared mutable principal state",async()=>
{
    var calls=Enumerable.Range(0,64).Select(i=>Task.Run(()=>
    {
        var snapshot=new IdentitySnapshot(Principal("subject"+i),scheme,now.AddSeconds(-1),now.AddSeconds(1));
        return trust.IsAccepted(snapshot,now) && snapshot.Principal.Subject=="subject"+i;
    }));
    Assert((await Task.WhenAll(calls)).All(x=>x));
});
await Check("fresh fixture source can change identity without policy cache",async()=>
{
    var source=new FixtureSource(Snapshot()); IIdentitySource contract=source;
    Assert(trust.IsAccepted(await contract.ResolveAsync(CancellationToken.None),now));
    source.Value=null;
    Assert(!trust.IsAccepted(await contract.ResolveAsync(CancellationToken.None),now));
    Assert(source.Calls==2);
});
await Check("fixture source observes pre-cancellation before reading identity",async()=>
{
    var source=new FixtureSource(Snapshot()); using var cancelled=new CancellationTokenSource(); cancelled.Cancel();
    try { await source.ResolveAsync(cancelled.Token); throw new InvalidOperationException("Expected cancellation"); }
    catch(OperationCanceledException error) { Assert(error.CancellationToken==cancelled.Token && source.Calls==0); }
});
await Check("source contract permits asynchronous cancellation propagation",async()=>
{
    var started=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var source=new WaitingSource(started); using var cancelled=new CancellationTokenSource();
    var pending=source.ResolveAsync(cancelled.Token).AsTask(); await started.Task; cancelled.Cancel();
    try { await pending; throw new InvalidOperationException("Expected cancellation"); }
    catch(OperationCanceledException error) { Assert(error.CancellationToken==cancelled.Token); }
});
await Check("identity value shapes contain no raw token, claims, role or tenant authority bag",()=>Sync(()=>
{
    var names=typeof(IdentitySnapshot).GetProperties().Select(p=>p.Name).ToArray();
    Assert(names.Order().SequenceEqual(new[]{"AuthenticationScheme","ExpiresAtUtc","NotBeforeUtc","Principal","SessionId"}.Order()));
    var session=typeof(IdentitySnapshot).GetProperty(nameof(IdentitySnapshot.SessionId))!;
    Assert(session.PropertyType==typeof(string) && session.SetMethod is null);
    Assert(new System.Reflection.NullabilityInfoContext().Create(session).ReadState==System.Reflection.NullabilityState.Nullable);
    Assert(typeof(IIdentitySource).GetMethods().Single().GetParameters().Single().ParameterType==typeof(CancellationToken));
}));
await Check("identity assembly references BCL only and not Core or provider frameworks",()=>Sync(()=>
{
    var names=typeof(IdentitySnapshot).Assembly.GetReferencedAssemblies().Select(a=>a.Name!).ToArray();
    Assert(names.All(n=>n.StartsWith("System.",StringComparison.Ordinal) || n=="netstandard"),string.Join(',',names));
}));

var report=new {observedAtUtc=DateTimeOffset.UtcNow,framework=RuntimeInformation.FrameworkDescription,os=RuntimeInformation.OSDescription,architecture=RuntimeInformation.ProcessArchitecture.ToString(),scope="Experimental BCL identity representation/trust contracts and fixture source cancellation only; no JWT/OIDC/IdP/tenant/provider/supportedWindows/hostedCI/benchmark/production authentication proof",passed=checks.Count(c=>c.Passed),failed=checks.Count(c=>!c.Passed),checks};
Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
await using(var stream=new FileStream(outputPath,FileMode.CreateNew,FileAccess.Write,FileShare.None)) await JsonSerializer.SerializeAsync(stream,report,new JsonSerializerOptions{WriteIndented=true});
Console.WriteLine($"Identity contracts: {report.passed}/{checks.Count}");
return report.failed==0?0:1;

sealed record CheckResult(string Name,bool Passed,string? Error);
sealed class FixtureSource(IdentitySnapshot? value):IIdentitySource
{
    public IdentitySnapshot? Value {get;set;}=value;
    public int Calls {get;private set;}
    public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken token) { token.ThrowIfCancellationRequested(); Calls++; return ValueTask.FromResult(Value); }
}
sealed class WaitingSource(TaskCompletionSource started):IIdentitySource
{
    public async ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken token) { started.TrySetResult(); await Task.Delay(Timeout.InfiniteTimeSpan,token); return null; }
}
