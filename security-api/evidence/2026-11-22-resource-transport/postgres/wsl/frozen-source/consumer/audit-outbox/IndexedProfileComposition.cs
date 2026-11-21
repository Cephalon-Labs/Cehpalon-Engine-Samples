using System.Text.Json;
using System.Text.RegularExpressions;
using Cehpalon.Engine.Composition;

namespace AuditOutbox;

public enum IndexedProfileOpenMode { CreateNew, OpenExisting }
public sealed class IndexedProfileCounters
{
    public int FactoryCalls,CredentialCalls,Constructors,FactoryFailures;public List<string> Events{get;}=[];public PostgresIndexedAuditStorage? LastConstructed;
}
public sealed class IndexedProfileActivation(ActivationPlan plan,ActivationLease lease,PostgresIndexedAuditStorage? storage):IAsyncDisposable
{
    public ActivationPlan Plan{get;}=plan;public ActivationLease Lease{get;}=lease;public PostgresIndexedAuditStorage? Storage{get;}=storage;
    public ValueTask DisposeAsync()=>Lease.DisposeAsync();
}
// This is an actual project-selected Support module, not registration text standing in for activation.
public static class IndexedProfileComposition
{
    public const string ModuleId="audit.indexed.v1";
    public static string Configuration(bool enabled)=>JsonSerializer.Serialize(new{Cehpalon=new{SchemaVersion=1,Architecture="Modular",Topology="SingleProcess",Pattern="RequestReply",Modules=new Dictionary<string,object>{{ModuleId,new{Enabled=enabled}}}}});
    public static CompositionCompilation Compile(string configuration)=>CompositionCompiler.Compile(configuration,[new ModuleDescriptor(ModuleId,ModuleRole.Support)]);
    public static async Task<IndexedProfileActivation> ActivateAsync(string configuration,string ownedSchema,IndexedProfileOpenMode mode,Func<CancellationToken,ValueTask<string>>? credentials,IndexedProfileCounters counters,CancellationToken token=default)
    {
        var compiled=Compile(configuration);if(!compiled.IsSuccess)throw new ArgumentException("Invalid indexed profile configuration: "+string.Join(',',compiled.Diagnostics.Select(d=>d.Code)),nameof(configuration));var plan=compiled.Plan!;counters.Events.Add("plan.validated");
        if(plan.ActivationOrder.Contains(ModuleId))
        {
            if(!Regex.IsMatch(ownedSchema,"\\Aao_[a-f0-9]{32}\\z",RegexOptions.CultureInvariant))throw new ArgumentException("Owned indexed profile schema required.",nameof(ownedSchema));
            if(!Enum.IsDefined(mode))throw new ArgumentOutOfRangeException(nameof(mode));ArgumentNullException.ThrowIfNull(credentials);
        }
        PostgresIndexedAuditStorage? storage=null;
        var registration=new ModuleRegistration(ModuleId,async ct=>
        {
            counters.FactoryCalls++;counters.Events.Add("factory");PostgresIndexedAuditStorage? candidate=null;
            try
            {
                ct.ThrowIfCancellationRequested();counters.CredentialCalls++;counters.Events.Add("credential");var connection=await credentials!(ct);ct.ThrowIfCancellationRequested();counters.Constructors++;candidate=new PostgresIndexedAuditStorage(connection,ownedSchema);counters.LastConstructed=candidate;counters.Events.Add("constructor");
                if(mode==IndexedProfileOpenMode.CreateNew){counters.Events.Add("create");await candidate.CreateNewAsync(ct);}else{counters.Events.Add("open");await candidate.OpenExistingAsync(ct);}
                storage=candidate;counters.Events.Add("ready");return candidate;
            }
            catch{counters.FactoryFailures++;if(candidate is not null){await candidate.DisposeAsync();counters.Events.Add("partial.disposed");}throw;}
        });
        var lease=await PlanActivator.ActivateAsync(plan,[registration],token);return new(plan,lease,storage);
    }
}
