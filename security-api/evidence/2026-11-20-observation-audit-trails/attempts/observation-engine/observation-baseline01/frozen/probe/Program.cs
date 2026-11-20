using System.Text.Json;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;
var output=args.Single(a=>a.StartsWith("--output=",StringComparison.Ordinal))[9..];
var results=new List<object>();
foreach(var phase in new[]{"membership","policy","audit"})
{
 var f=new Fixture(phase);var result=await f.Run();
 results.Add(new{phase,utc_stalled=true,original_cap_seconds=2,elapsed_monotonic_seconds=3,handler_admitted=f.Factories==1,success=result.IsSuccess,authorization_events=f.Events.Count(e=>e.Stage==TenantAuditStage.Authorization),terminal_outcome=f.Events.Last().Outcome.ToString()});
 if(!result.IsSuccess||f.Factories!=1)throw new InvalidOperationException("Baseline expectation changed.");
}
await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{scope="Controlled old-source UTC-stall observation-origin reproduction, not remote exploit/provider/production or benchmark proof",engine_revision="9850bed57d9b8db7c22e130cc40d3afcd31e41d6",results},new JsonSerializerOptions{WriteIndented=true}));Console.WriteLine("Baseline reproduction: three old-source admissions after original observation cap.");
sealed class Clock:TimeProvider
{public DateTimeOffset Now=new(2026,11,20,0,0,0,TimeSpan.Zero);public long Timestamp;public override long TimestampFrequency=>TimeSpan.TicksPerSecond;public override DateTimeOffset GetUtcNow()=>Now;public override long GetTimestamp()=>Timestamp;}
sealed class Fixture(string phase):IIdentitySource,IIdentitySessionStatusSource,ITenantMembershipSource,IResourceScopeSource,ITenantAccessPolicy,ITenantAuditSink
{
 public Clock Clock{get;}=new();public int Factories;public List<TenantAuditEvent> Events{get;}=[];
 public ValueTask<IdentitySnapshot?> ResolveAsync(CancellationToken token)=>ValueTask.FromResult<IdentitySnapshot?>(new(new("issuer","alice"),"Bearer",Clock.Now.AddMinutes(-1),Clock.Now.AddMinutes(5),"session-a"));
 public ValueTask<SessionStatusSnapshot?> ResolveAsync(IdentitySnapshot i,CancellationToken token)=>ValueTask.FromResult<SessionStatusSnapshot?>(new(i.Principal,i.AuthenticationScheme,i.SessionId!,true,Clock.Now.AddMinutes(-1),Clock.Now.AddMinutes(5)));
 public ValueTask<TenantMembershipSnapshot?> ResolveAsync(IdentitySnapshot i,TenantId t,CancellationToken token){if(phase=="membership")Clock.Timestamp+=TimeSpan.FromSeconds(3).Ticks;return ValueTask.FromResult<TenantMembershipSnapshot?>(new(i.Principal,t,true,Clock.Now.AddMinutes(-1),Clock.Now.AddMinutes(5),"m1"));}
 public ValueTask<ResourceScopeSnapshot?> ResolveAsync(TenantId t,string kind,string id,CancellationToken token)=>ValueTask.FromResult<ResourceScopeSnapshot?>(new(t,kind,id,"r1"));
 public ValueTask<bool> IsAllowedAsync(TenantAccessRequest r,CancellationToken token){if(phase=="policy")Clock.Timestamp+=TimeSpan.FromSeconds(3).Ticks;return ValueTask.FromResult(true);}
 public ValueTask AppendAsync(TenantAuditEvent e,CancellationToken token){Events.Add(e);if(phase=="audit"&&e.Stage==TenantAuditStage.Authorization)Clock.Timestamp+=TimeSpan.FromSeconds(3).Ticks;return ValueTask.CompletedTask;}
 public ValueTask<OperationResult<string>> Run(){var registry=new TenantOperationRegistryBuilder().Register<string,string>("document.read","read","document",x=>x,x=>new(new("A"),x),()=>{Factories++;return new Handler();}).Build();var services=new TenantSecurityServices(new SessionValidatingIdentitySource(this,this,TimeSpan.FromSeconds(2),Clock),new(["issuer"],["Bearer"]),this,this,TimeSpan.FromSeconds(30),this,Clock,new(this));return new TenantOperationDispatcher(registry,services).DispatchAsync<string,string>("document.read","shared",new("baseline"));}
 sealed class Handler:ITenantOperationHandler<string,string>{public ValueTask<OperationResult<string>> HandleAsync(string r,TenantOperationContext c,CancellationToken t){c.DemandAccess(new("A"),"document",r,"read");return ValueTask.FromResult(OperationResult<string>.Success("ok"));}}
}
