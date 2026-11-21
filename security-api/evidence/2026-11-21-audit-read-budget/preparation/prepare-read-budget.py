from pathlib import Path
p=Path('src/Cehpalon.Engine.Tenancy/Audit.cs')
s=p.read_text(encoding='utf-8')
for name,interface,method,final in [('ResourceHistory','ITenantChangeAuditResourceHistorySource','ReadAsync','resource history'),('Lookup','ITenantChangeAuditLookupSource','FindAsync','trail lookup'),('History','ITenantChangeAuditHistorySource','ReadAsync','trail')]:
 start=s.index('public sealed class TenantChangeAudit'+name+'Reader\n')
 end=s.index('\n}\n',start)+2
 part=s[start:end]
 marker='    private readonly TenantChangeAuditPolicy policy;'
 part=part.replace(marker,marker+'\n    private readonly TimeSpan? readTimeout;',1)
 activation='    /// <summary>Optional cooperative budget; null preserves legacy tokens, faults and guard order.</summary>\n    public static TenantChangeAudit'+name+'Reader? ActivateWithBudget(TenantChangeAuditPolicy policy, TimeSpan? readTimeout,\n        Func<'+interface+'>? sourceFactory = null)\n    {\n        ArgumentNullException.ThrowIfNull(policy);\n        if (policy.Mode == TenantChangeAuditMode.Disabled) return null;\n        if (readTimeout is { } timeout) TenantChangeAuditOutboxExecutor<object>.RequireBound(timeout, nameof(readTimeout));\n        ArgumentNullException.ThrowIfNull(sourceFactory);\n        return new(sourceFactory() ?? throw new ArgumentException("The trusted '+final+' source factory returned null."), policy, readTimeout);\n    }\n    private TenantChangeAudit'+name+'Reader('+interface+' source, TenantChangeAuditPolicy policy, TimeSpan? readTimeout)\n        : this(source, policy) { this.readTimeout = readTimeout; }\n'
 at=part.index('    private static bool Bound(') if name=='ResourceHistory' else part.index('    public async ValueTask<')
 part=part[:at]+activation+part[at:]
 source=part.index('        var '+('record' if name=='Lookup' else 'page')+' = await source.')
 finish=part.rindex('        return projected;')+len('        return projected;')
 body=part[source:finish].replace(', cancellationToken).ConfigureAwait(false)', ', budget?.Token ?? cancellationToken).ConfigureAwait(false)',1)
 body=body.replace('        cancellationToken.ThrowIfCancellationRequested(); context.DemandAccess', '        cancellationToken.ThrowIfCancellationRequested(); budget?.Demand(); context.DemandAccess')
 # The original history final scope-only guard remains exactly so when budget is null.
 finalguard='        context.DemandAccess(context.Tenant, "audit-trail", "tenant", "read");\n        return projected;'
 if name=='History': body=body.replace(finalguard,'        budget?.Demand(); context.DemandAccess(context.Tenant, "audit-trail", "tenant", "read");\n        budget?.Demand();\n        return projected;')
 else: body=body.replace('        return projected;', '        budget?.Demand();\n        return projected;')
 body='\n'.join('    '+line for line in body.splitlines())
 replacement='        using var budget = readTimeout is { } bound ? new TenantChangeAuditReadBudget(cancellationToken, bound) : null;\n        budget?.Demand();\n        try\n        {\n'+body+'\n        }\n        catch (OperationCanceledException failure) when (budget is not null)\n        {\n            var classified = budget.Classify(failure);\n            if (ReferenceEquals(classified, failure)) throw;\n            throw classified;\n        }'
 part=part[:source]+replacement+part[finish:]
 s=s[:start]+part+s[end:]
at=s.index('/// <summary>Exact resource selection under a captured immutable read policy;')
helper='''// Per configured invocation only. Provider lifetime and arbitrary callbacks remain provider-owned.
internal sealed class TenantChangeAuditReadBudget : IDisposable
{
    private readonly CancellationToken caller;
    private readonly CancellationTokenSource deadline;
    private readonly CancellationTokenSource linked;
    internal TenantChangeAuditReadBudget(CancellationToken caller, TimeSpan timeout)
    {
        this.caller = caller; deadline = new(timeout);
        try { linked = CancellationTokenSource.CreateLinkedTokenSource(caller, deadline.Token); }
        catch { deadline.Dispose(); throw; }
    }
    internal CancellationToken Token => linked.Token;
    internal void Demand() { caller.ThrowIfCancellationRequested(); deadline.Token.ThrowIfCancellationRequested(); }
    internal Exception Classify(OperationCanceledException failure)
    {
        if (caller.IsCancellationRequested) return new OperationCanceledException("The audit read caller requested cancellation.", failure, caller);
        return deadline.IsCancellationRequested ? new TimeoutException("The cooperative audit read budget expired.", failure) : failure;
    }
    public void Dispose() { linked.Dispose(); deadline.Dispose(); }
}
'''
s=s[:at]+helper+s[at:]
p.write_bytes(s.encode('utf-8'))
