using Cehpalon.Engine.Identity;

namespace SecurityApi;

/// <summary>Trusted local status fixture. Session IDs are synthetic, unique per login, and never reactivated.</summary>
public sealed class SessionFixture
{
    private readonly object gate=new();
    private readonly Dictionary<(string Issuer,string Subject,string Scheme,string Session),bool> sessions=[];
    public int FactoryCalls,ProviderConstructors,StatusCalls;
    public bool FailCreation,FailLookup;
    public SessionReply Reply;
    public Func<IdentitySnapshot,CancellationToken,Task>? LookupGate;
    public IIdentitySessionStatusSource Create()
    {
        Interlocked.Increment(ref FactoryCalls);
        if(FailCreation)throw new IOException("Controlled session provider startup failure.");
        if(FactoryCalls!=1)throw new InvalidOperationException("Fixture session provider must activate once.");
        return new StatusProvider(this);
    }
    private sealed class StatusProvider:IIdentitySessionStatusSource
    {
        private readonly SessionFixture owner;
        public StatusProvider(SessionFixture owner){this.owner=owner;Interlocked.Increment(ref owner.ProviderConstructors);}
        public ValueTask<SessionStatusSnapshot?> ResolveAsync(IdentitySnapshot identity,CancellationToken token)=>owner.ResolveAsync(identity,token);
    }
    public void Register(string subject,string sessionId,string scheme="Bearer")
    {
        lock(gate)
        {
            if(!sessions.TryAdd((JwtFixture.Issuer,subject,scheme,sessionId),true))
                throw new InvalidOperationException("Fixture sessions cannot be reused or reactivated.");
        }
    }
    public void Revoke(string subject,string sessionId,string scheme="Bearer")
    {
        lock(gate)
        {
            var key=(JwtFixture.Issuer,subject,scheme,sessionId);
            if(!sessions.ContainsKey(key))throw new InvalidOperationException("Cannot revoke an unknown fixture session.");
            sessions[key]=false;
        }
    }
    private async ValueTask<SessionStatusSnapshot?> ResolveAsync(IdentitySnapshot identity,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();Interlocked.Increment(ref StatusCalls);
        if(LookupGate is not null)await LookupGate(identity,token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        if(FailLookup)throw new IOException("Controlled session provider lookup failure.");
        if(identity.SessionId is null)return null;
        bool active;
        lock(gate)if(!sessions.TryGetValue((identity.Principal.Issuer,identity.Principal.Subject,identity.AuthenticationScheme,identity.SessionId),out active))return null;
        if(Reply==SessionReply.Missing)return null;
        var now=DateTimeOffset.UtcNow;
        return new(new(Reply==SessionReply.WrongIssuer?"urn:other-issuer":identity.Principal.Issuer,
            Reply==SessionReply.WrongSubject?"another-subject":identity.Principal.Subject),
            Reply==SessionReply.WrongScheme?"another-scheme":identity.AuthenticationScheme,
            Reply==SessionReply.WrongSession?"another-session":identity.SessionId,
            active&&Reply!=SessionReply.Inactive,
            Reply==SessionReply.Future?now.AddMinutes(1):now.AddMinutes(-1),
            Reply==SessionReply.Expired?now.AddSeconds(-1):now.AddMinutes(2));
    }
}

public enum SessionReply { Normal,Missing,Inactive,WrongIssuer,WrongSubject,WrongScheme,WrongSession,Future,Expired }
public sealed record SessionObservation(string Protection,int BusinessFactories,int BusinessDisposals,int AuditEvents,int SessionFactoryCalls,int StatusCalls,int AuthenticationCallbacks,int ProviderConstructors);
