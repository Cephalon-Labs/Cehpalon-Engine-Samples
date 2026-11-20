using System.Collections.ObjectModel;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;

namespace Cehpalon.Engine.Tenancy;

public sealed class TenantSecurityServices
{
    public TenantSecurityServices(IIdentitySource identitySource,IdentityTrustPolicy identityTrust,ITenantMembershipSource memberships,IResourceScopeSource resources,TimeSpan maximumLeaseLifetime,ITenantAccessPolicy? policy=null,TimeProvider? timeProvider=null,TenantAuditServices? audit=null)
    {
        IdentitySource=identitySource??throw new ArgumentNullException(nameof(identitySource)); IdentityTrust=identityTrust??throw new ArgumentNullException(nameof(identityTrust));
        Memberships=memberships??throw new ArgumentNullException(nameof(memberships)); Resources=resources??throw new ArgumentNullException(nameof(resources));
        if(maximumLeaseLifetime<=TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(maximumLeaseLifetime));
        MaximumLeaseLifetime=maximumLeaseLifetime; Policy=policy??DenyPolicy.Instance; TimeProvider=timeProvider??TimeProvider.System;
        Audit=audit;
    }
    public IIdentitySource IdentitySource { get; }
    public IdentityTrustPolicy IdentityTrust { get; }
    public ITenantMembershipSource Memberships { get; }
    public IResourceScopeSource Resources { get; }
    public TimeSpan MaximumLeaseLifetime { get; }
    public ITenantAccessPolicy Policy { get; }
    public TimeProvider TimeProvider { get; }
    public TenantAuditServices? Audit { get; }
    private sealed class DenyPolicy:ITenantAccessPolicy
    {
        internal static readonly DenyPolicy Instance=new();
        public ValueTask<bool> IsAllowedAsync(TenantAccessRequest request,CancellationToken cancellationToken)=>ValueTask.FromResult(false);
    }
}

/// <summary>Trusted registration phase; callbacks must be pure and freeze must produce a defensive request snapshot.</summary>
public sealed class TenantOperationRegistryBuilder
{
    private readonly Dictionary<string,ITenantRegistration> registrations=new(StringComparer.Ordinal);
    public TenantOperationRegistryBuilder Register<TRequest,TResponse>(string operationId,string action,string kind,Func<TRequest,TRequest> freezeRequest,Func<TRequest,TenantTarget> selectTarget,Func<ITenantOperationHandler<TRequest,TResponse>> factory)
    {
        OperationId.RequireValid(operationId); OperationId.RequireValid(action); OperationId.RequireValid(kind);
        ArgumentNullException.ThrowIfNull(freezeRequest); ArgumentNullException.ThrowIfNull(selectTarget); ArgumentNullException.ThrowIfNull(factory);
        if(!registrations.TryAdd(operationId,new TenantRegistration<TRequest,TResponse>(operationId,action,kind,freezeRequest,selectTarget,factory))) throw new ArgumentException("Duplicate operation ID.",nameof(operationId));
        return this;
    }
    public TenantOperationRegistry Build()=>new(registrations);
}

public sealed class TenantOperationRegistry
{
    private readonly IReadOnlyDictionary<string,ITenantRegistration> registrations;
    internal TenantOperationRegistry(Dictionary<string,ITenantRegistration> registrations)
    {
        this.registrations=new ReadOnlyDictionary<string,ITenantRegistration>(new Dictionary<string,ITenantRegistration>(registrations,StringComparer.Ordinal));
        OperationIds=Array.AsReadOnly(registrations.Keys.Order(StringComparer.Ordinal).ToArray());
    }
    public IReadOnlyList<string> OperationIds { get; }
    internal bool TryGet(string operationId,out ITenantRegistration? registration)=>registrations.TryGetValue(operationId,out registration);
}

public sealed class TenantOperationDispatcher
{
    private readonly TenantOperationRegistry registry;
    private readonly TenantSecurityServices services;
    private readonly OperationConcurrencyBudget? budget;
    private readonly TenantOperationConcurrencyBudget? tenantBudget;
    public TenantOperationDispatcher(TenantOperationRegistry registry,TenantSecurityServices services)
    { this.registry=registry??throw new ArgumentNullException(nameof(registry)); this.services=services??throw new ArgumentNullException(nameof(services)); }

    /// <summary>Apply a shared capacity budget after fresh authorization and through owned-handler cleanup.</summary>
    public TenantOperationDispatcher(TenantOperationRegistry registry, TenantSecurityServices services, OperationConcurrencyBudget budget)
        : this(registry, services) => this.budget = budget ?? throw new ArgumentNullException(nameof(budget));

    private TenantOperationDispatcher(TenantOperationRegistry registry, TenantSecurityServices services,
        TenantOperationConcurrencyBudget tenantBudget)
        : this(registry, services) => this.tenantBudget = tenantBudget ?? throw new ArgumentNullException(nameof(tenantBudget));

    /// <summary>Share a total and per-tenant capacity budget across protected dispatchers.</summary>
    public static TenantOperationDispatcher WithTenantConcurrencyBudget(
        TenantOperationRegistry registry, TenantSecurityServices services, TenantOperationConcurrencyBudget tenantBudget)
        => new(registry, services, tenantBudget);

    public ValueTask<OperationResult<TResponse>> DispatchAsync<TRequest,TResponse>(string operationId,TRequest request,OperationContext correlation,CancellationToken cancellationToken=default)
    {
        OperationId.RequireValid(operationId); ArgumentNullException.ThrowIfNull(correlation); cancellationToken.ThrowIfCancellationRequested();
        if(!registry.TryGet(operationId,out var registration)) return ValueTask.FromResult(OperationResult<TResponse>.Failure(new("operation.not_found","The requested operation is not registered.")));
        if(registration is not TenantRegistration<TRequest,TResponse> typed) return ValueTask.FromResult(OperationResult<TResponse>.Failure(new("operation.contract_mismatch","The requested operation does not use these request/response contracts.")));
        return typed.DispatchAsync(request,correlation,services,budget,tenantBudget,cancellationToken);
    }
}

internal interface ITenantRegistration;

internal sealed class TenantRegistration<TRequest,TResponse> : ITenantRegistration
{
    private readonly string operationId,action,kind;
    private readonly Func<TRequest,TRequest> freeze;
    private readonly Func<TRequest,TenantTarget> select;
    private readonly object origin=new();
    private readonly OperationDispatcher core;
    internal TenantRegistration(string operationId,string action,string kind,Func<TRequest,TRequest> freeze,Func<TRequest,TenantTarget> select,Func<ITenantOperationHandler<TRequest,TResponse>> factory)
    {
        this.operationId=operationId; this.action=action; this.kind=kind; this.freeze=freeze; this.select=select;
        core=new(new OperationRegistryBuilder().Register<AuthorizedInvocation,TResponse>(operationId,()=>new HandlerBridge(factory,origin,operationId)).Build());
    }
    internal ValueTask<OperationResult<TResponse>> DispatchAsync(TRequest request,OperationContext correlation,TenantSecurityServices services,
        OperationConcurrencyBudget? budget,TenantOperationConcurrencyBudget? tenantBudget,CancellationToken token)
        => services.Audit is null
            ? DispatchCoreAsync(request,correlation,services,budget,tenantBudget,token,null)
            : DispatchAuditedAsync(request,correlation,services,budget,tenantBudget,token);

    private async ValueTask<OperationResult<TResponse>> DispatchAuditedAsync(TRequest request,OperationContext correlation,TenantSecurityServices services,
        OperationConcurrencyBudget? budget,TenantOperationConcurrencyBudget? tenantBudget,CancellationToken token)
    {
        var id=Guid.NewGuid(); TenantAccessRequest? authority=null; var mayHaveExecuted=false;
        TenantAuditWriteException? authorizationAuditFailure=null;
        TenantAuditEvent Entry(TenantAuditStage stage,TenantAuditOutcome outcome)=>new(id,stage,outcome,
            services.TimeProvider.GetUtcNow(),operationId,action,kind,authority?.Identity.Principal,authority?.Tenant,authority?.Resource.ResourceId,services.Audit?.ParentInvocationId);
        async ValueTask Authorized(TenantAccessRequest access)
        {
            authority=access;
            try { await services.Audit!.AppendAsync(Entry(TenantAuditStage.Authorization,TenantAuditOutcome.Authorized),false).ConfigureAwait(false); }
            catch(TenantAuditWriteException failure) { authorizationAuditFailure=failure; throw; }
            mayHaveExecuted=true;
        }
        OperationResult<TResponse>? result=null; Exception? executionFailure=null;
        try { result=await DispatchCoreAsync(request,correlation,services,budget,tenantBudget,token,Authorized).ConfigureAwait(false); }
        catch(TenantAuditWriteException failure) when(ReferenceEquals(failure,authorizationAuditFailure)) { throw; }
        catch(Exception failure) { executionFailure=failure; }
        var outcome=executionFailure is OperationCanceledException?TenantAuditOutcome.Cancelled:
            executionFailure is not null?TenantAuditOutcome.Faulted:
            result!.IsSuccess?TenantAuditOutcome.Succeeded:
            result.Error!.Code=="access.denied"?TenantAuditOutcome.Denied:TenantAuditOutcome.Rejected;
        try { await services.Audit!.AppendAsync(Entry(TenantAuditStage.Terminal,outcome),mayHaveExecuted).ConfigureAwait(false); }
        catch(TenantAuditWriteException auditFailure) when(executionFailure is not null)
        { throw new AggregateException("Operation and required audit persistence failed.",executionFailure,auditFailure); }
        if(executionFailure is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(executionFailure).Throw();
        return result!.IsSuccess && authority is not null && !authority.Identity.SatisfiesObservationConstraints()
            ? Denied() : result!;
    }

    private async ValueTask<OperationResult<TResponse>> DispatchCoreAsync(TRequest request,OperationContext correlation,TenantSecurityServices services,
        OperationConcurrencyBudget? budget,TenantOperationConcurrencyBudget? tenantBudget,CancellationToken token,
        Func<TenantAccessRequest,ValueTask>? authorized)
    {
        token.ThrowIfCancellationRequested();
        var frozen=freeze(request);
        var target=select(frozen)??throw new InvalidOperationException("Target selector returned null.");
        token.ThrowIfCancellationRequested();
        var identity=await services.IdentitySource.ResolveAsync(token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        if(!services.IdentityTrust.IsAccepted(identity,services.TimeProvider.GetUtcNow())) return Denied();
        var membership=await services.Memberships.ResolveAsync(identity!,target.Tenant,token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        if(!ValidMembership(identity!,target.Tenant,membership,services.TimeProvider.GetUtcNow())) return Denied();
        var resource=await services.Resources.ResolveAsync(target.Tenant,kind,target.ResourceId,token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        if(resource is null || !resource.Tenant.Equals(target.Tenant) || !StringComparer.Ordinal.Equals(resource.Kind,kind) || !StringComparer.Ordinal.Equals(resource.ResourceId,target.ResourceId)) return Denied();
        var policyTime=services.TimeProvider.GetUtcNow();
        if(!services.IdentityTrust.IsAccepted(identity,policyTime) || !ValidMembership(identity!,target.Tenant,membership,policyTime)) return Denied();
        var access=new TenantAccessRequest(operationId,action,identity!,membership!,resource);
        var policyExpires=DateTimeOffset.MaxValue;
        var policyNotBefore=policyTime;
        bool allowed;
        if(services.Policy is ILeasedTenantAccessPolicy leasedPolicy)
        {
            var decision=await leasedPolicy.EvaluateAsync(access,token).ConfigureAwait(false);
            allowed=decision is not null && decision.IsAllowed;
            if(allowed) { policyExpires=decision!.ExpiresAtUtc; policyNotBefore=decision.NotBeforeUtc>policyTime?decision.NotBeforeUtc:policyTime; }
        }
        else allowed=await services.Policy.IsAllowedAsync(access,token).ConfigureAwait(false);
        if(!allowed || !identity!.SatisfiesObservationConstraints()) { token.ThrowIfCancellationRequested(); return Denied(); }
        token.ThrowIfCancellationRequested();
        if(authorized is not null) await authorized(access).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        var now=services.TimeProvider.GetUtcNow();
        if(!services.IdentityTrust.IsAccepted(identity,now) || !ValidMembership(identity!,target.Tenant,membership,now) || now<policyNotBefore || now>=policyExpires) return Denied();
        var maximum=services.MaximumLeaseLifetime.Ticks>DateTimeOffset.MaxValue.Ticks-now.UtcTicks?DateTimeOffset.MaxValue:now.Add(services.MaximumLeaseLifetime);
        var expires=identity!.ExpiresAtUtc<membership!.ExpiresAtUtc?identity.ExpiresAtUtc:membership.ExpiresAtUtc;
        if(maximum<expires) expires=maximum;
        if(policyExpires<expires) expires=policyExpires;
        using var lease=new AuthorizationLease(services.TimeProvider,now,expires,identity);
        var context=new TenantOperationContext(access,correlation,lease,origin);
        try
        {
            var invocation = new AuthorizedInvocation(frozen, context);
            var work = tenantBudget is not null
                ? tenantBudget.DispatchAsync<AuthorizedInvocation, TResponse>(resource.Tenant, core, operationId, invocation, correlation, token)
                : budget is null
                    ? core.DispatchAsync<AuthorizedInvocation,TResponse>(operationId, invocation, correlation, token)
                    : budget.DispatchAsync<AuthorizedInvocation,TResponse>(core, operationId, invocation, correlation, token);
            // Core returns after owned cleanup. Never replace an explicit business failure or cleanup fault.
            var result = await work.ConfigureAwait(false);
            return result.IsSuccess && !identity.SatisfiesObservationConstraints() ? Denied() : result;
        }
        catch(TenantAccessDeniedException) { return Denied(); }
    }
    private static bool ValidMembership(IdentitySnapshot identity,TenantId tenant,TenantMembershipSnapshot? membership,DateTimeOffset now)
        =>membership is not null && membership.IsActive && membership.Principal.Equals(identity.Principal) && membership.Tenant.Equals(tenant) && membership.NotBeforeUtc<=now && now<membership.ExpiresAtUtc;
    private static OperationResult<TResponse> Denied()=>OperationResult<TResponse>.Failure(new("access.denied","Access denied."));
    private sealed record AuthorizedInvocation(TRequest Request,TenantOperationContext Context);
    private sealed class HandlerBridge(Func<ITenantOperationHandler<TRequest,TResponse>> factory,object origin,string operationId):IOperationHandler<AuthorizedInvocation,TResponse>,IAsyncDisposable
    {
        private ITenantOperationHandler<TRequest,TResponse>? owned;
        public async ValueTask<OperationResult<TResponse>> HandleAsync(AuthorizedInvocation request,OperationContext correlation,CancellationToken token)
        {
            request.Context.DemandBinding(origin,operationId); token.ThrowIfCancellationRequested();
            owned=factory()??throw new InvalidOperationException("The tenant handler factory returned null.");
            request.Context.DemandBinding(origin,operationId); token.ThrowIfCancellationRequested();
            return await owned.HandleAsync(request.Request,request.Context,token).ConfigureAwait(false);
        }
        public async ValueTask DisposeAsync()
        {
            try
            {
                if(owned is IAsyncDisposable asyncDisposable) await asyncDisposable.DisposeAsync().ConfigureAwait(false);
                else if(owned is IDisposable disposable) disposable.Dispose();
            }
            catch(TenantAccessDeniedException failure)
            {
                // Cleanup is an infrastructure/lifecycle failure, not a fresh authorization denial.
                // Preserve its cause without letting the outer semantic-denial mapper hide it.
                throw new InvalidOperationException("Owned tenant handler cleanup failed.",failure);
            }
        }
    }
}
