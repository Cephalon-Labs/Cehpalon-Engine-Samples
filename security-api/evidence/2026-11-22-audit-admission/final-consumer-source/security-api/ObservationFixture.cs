namespace SecurityApi;

/// <summary>Deterministic in-memory controls; this is not a provider and never alters system/JWT clocks.</summary>
public sealed class ObservationFixture
{
    private readonly object gate=new();private readonly Dictionary<string,int> effects=new(StringComparer.Ordinal);
    public ObservationClock Clock{get;}=new();
    public TimeSpan Lifetime{get;init;}=TimeSpan.FromSeconds(5);
    public TimeSpan? InnerLifetime{get;init;}
    public Action<string,string?>? StageHook;
    public bool RejectBusiness,FailCleanup;
    public void At(string stage,string? tenant)=>StageHook?.Invoke(stage,tenant);
    public void RecordEffect(string tenant){lock(gate){effects.TryGetValue(tenant,out var count);effects[tenant]=count+1;}}
    public int Effects(string tenant){lock(gate)return effects.TryGetValue(tenant,out var count)?count:0;}
}

/// <summary>UTC is frozen; only this fixture's monotonic counter advances by declared steps.</summary>
public sealed class ObservationClock:TimeProvider
{
    private readonly DateTimeOffset now=DateTimeOffset.UtcNow;private long timestamp;
    public int UtcReads,TimestampReads;
    public override long TimestampFrequency=>TimeSpan.TicksPerSecond;
    public override DateTimeOffset GetUtcNow(){Interlocked.Increment(ref UtcReads);return now;}
    public override long GetTimestamp(){Interlocked.Increment(ref TimestampReads);return Interlocked.Read(ref timestamp);}
    public void AdvanceMonotonic(TimeSpan elapsed){if(elapsed<TimeSpan.Zero)throw new ArgumentOutOfRangeException(nameof(elapsed));Interlocked.Add(ref timestamp,elapsed.Ticks);}
}

public sealed record ObservationSummary(string Protection,int BusinessFactories,int BusinessDisposals,int AuditEvents,int StatusCalls,int AuthenticationCallbacks,int EffectsA,int EffectsB);
