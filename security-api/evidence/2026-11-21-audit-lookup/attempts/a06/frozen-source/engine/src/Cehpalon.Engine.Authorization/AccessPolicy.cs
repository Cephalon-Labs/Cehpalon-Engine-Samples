using System.Collections.Frozen;
using Cehpalon.Engine.Core;
using Cehpalon.Engine.Identity;
using Cehpalon.Engine.Tenancy;

namespace Cehpalon.Engine.Authorization;

public enum AttributeScope { Subject, Resource, Environment }

/// <summary>Bounded immutable ordinal attributes from a trusted authority, not request metadata.</summary>
public sealed class AccessAttributes
{
    private readonly FrozenDictionary<string, string> values;
    public AccessAttributes(IEnumerable<KeyValuePair<string, string>> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        var copy = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var item in values.Take(65))
        {
            if (copy.Count == 64 || !copy.TryAdd(Text(item.Key), Text(item.Value)))
                throw new ArgumentException("At most 64 unique attributes are supported.", nameof(values));
        }
        this.values = copy.ToFrozenDictionary(StringComparer.Ordinal);
    }
    public IReadOnlyDictionary<string, string> Values => values;
    internal static string Text(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > 256 || value.Any(char.IsControl))
            throw new ArgumentException("Attribute text exceeds its bound or contains controls.", nameof(value));
        // Reject malformed UTF-16 rather than allowing encoder replacement to alias values.
        for (var i = 0; i < value.Length; i++)
            if (char.IsLowSurrogate(value[i]) || char.IsHighSurrogate(value[i]) &&
                (++i == value.Length || !char.IsLowSurrogate(value[i])))
                throw new ArgumentException("Attribute text contains malformed UTF-16.", nameof(value));
        return value;
    }
}

public sealed class AttributePredicate
{
    private readonly AttributeScope leftScope;
    private readonly string leftKey;
    private readonly AttributeScope? rightScope;
    private readonly string right;
    private AttributePredicate(AttributeScope leftScope, string leftKey, AttributeScope? rightScope, string right)
    {
        if (!Enum.IsDefined(leftScope) || rightScope is { } scope && !Enum.IsDefined(scope))
            throw new ArgumentOutOfRangeException(nameof(leftScope));
        this.leftScope = leftScope; this.leftKey = AccessAttributes.Text(leftKey);
        this.rightScope = rightScope; this.right = AccessAttributes.Text(right);
    }
    public static AttributePredicate EqualTo(AttributeScope scope, string key, string value) => new(scope, key, null, value);
    public static AttributePredicate Match(AttributeScope leftScope, string leftKey, AttributeScope rightScope, string rightKey)
        => new(leftScope, leftKey, rightScope, rightKey);
    internal bool Matches(AuthorizationFacts facts)
    {
        if (!facts.Attributes(leftScope).Values.TryGetValue(leftKey, out var left)) return false;
        var expected = right;
        if (rightScope is { } scope && !facts.Attributes(scope).Values.TryGetValue(right, out expected)) return false;
        return StringComparer.Ordinal.Equals(left, expected);
    }
}

/// <summary>Exact operation/action/kind rule. Any listed role AND all predicates; an unconstrained grant is invalid.</summary>
public sealed class AccessRule
{
    internal FrozenSet<string> Roles { get; }
    internal AttributePredicate[] Predicates { get; }
    public AccessRule(string operationId, string action, string resourceKind,
        IEnumerable<string>? anyRoles = null, IEnumerable<AttributePredicate>? allAttributes = null)
    {
        OperationId = Cehpalon.Engine.Core.OperationId.RequireValid(operationId);
        Action = Cehpalon.Engine.Core.OperationId.RequireValid(action);
        ResourceKind = Cehpalon.Engine.Core.OperationId.RequireValid(resourceKind);
        var roles = (anyRoles ?? []).Take(65).Select(AccessAttributes.Text).ToArray();
        Predicates = (allAttributes ?? []).Take(65).ToArray();
        if (roles.Length > 64 || Predicates.Length > 64 || Predicates.Any(x => x is null) ||
            roles.Distinct(StringComparer.Ordinal).Count() != roles.Length || roles.Length + Predicates.Length == 0)
            throw new ArgumentException("Rules need bounded, unique roles and/or non-null attribute constraints.");
        Roles = roles.ToFrozenSet(StringComparer.Ordinal);
    }
    public string OperationId { get; }
    public string Action { get; }
    public string ResourceKind { get; }
}

/// <summary>Fresh authoritative facts bound to this exact membership/resource snapshot.</summary>
public sealed class AuthorizationFacts
{
    private readonly FrozenSet<string> roles;
    public AuthorizationFacts(PrincipalId principal, TenantId tenant, string membershipVersion,
        string resourceKind, string resourceId, string resourceVersion, DateTimeOffset notBeforeUtc,
        DateTimeOffset expiresAtUtc, IEnumerable<string> roles, AccessAttributes? subject = null,
        AccessAttributes? resource = null, AccessAttributes? environment = null)
    {
        Principal = principal ?? throw new ArgumentNullException(nameof(principal));
        Tenant = tenant ?? throw new ArgumentNullException(nameof(tenant));
        MembershipVersion = AccessAttributes.Text(membershipVersion);
        ResourceKind = OperationId.RequireValid(resourceKind);
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceId);
        if (resourceId.Length > 512) throw new ArgumentException("Resource ID exceeds its bound.", nameof(resourceId));
        ResourceId = resourceId; ResourceVersion = AccessAttributes.Text(resourceVersion);
        if (expiresAtUtc <= notBeforeUtc) throw new ArgumentException("Facts need a positive validity interval.");
        NotBeforeUtc = notBeforeUtc.ToUniversalTime(); ExpiresAtUtc = expiresAtUtc.ToUniversalTime();
        ArgumentNullException.ThrowIfNull(roles);
        var copy = roles.Take(65).Select(AccessAttributes.Text).ToArray();
        if (copy.Length > 64 || copy.Distinct(StringComparer.Ordinal).Count() != copy.Length)
            throw new ArgumentException("At most 64 unique roles are supported.", nameof(roles));
        this.roles = copy.ToFrozenSet(StringComparer.Ordinal);
        Subject = subject ?? new([]); Resource = resource ?? new([]); Environment = environment ?? new([]);
    }
    public PrincipalId Principal { get; }
    public TenantId Tenant { get; }
    public string MembershipVersion { get; }
    public string ResourceKind { get; }
    public string ResourceId { get; }
    public string ResourceVersion { get; }
    public DateTimeOffset NotBeforeUtc { get; }
    public DateTimeOffset ExpiresAtUtc { get; }
    public IReadOnlySet<string> Roles => roles;
    public AccessAttributes Subject { get; }
    public AccessAttributes Resource { get; }
    public AccessAttributes Environment { get; }
    internal AccessAttributes Attributes(AttributeScope scope) => scope switch
    { AttributeScope.Subject => Subject, AttributeScope.Resource => Resource, AttributeScope.Environment => Environment,
        _ => throw new ArgumentOutOfRangeException(nameof(scope)) };
}

public interface IAuthorizationFactsSource
{
    ValueTask<AuthorizationFacts?> ResolveAsync(TenantAccessRequest request, CancellationToken cancellationToken);
}

/// <summary>Fresh default-deny RBAC/ABAC policy; no protocol or database dependencies.</summary>
public sealed class RoleAttributeAccessPolicy : ILeasedTenantAccessPolicy
{
    private readonly FrozenDictionary<(string, string, string), AccessRule> rules;
    private readonly IAuthorizationFactsSource source;
    private readonly TimeProvider clock;
    public RoleAttributeAccessPolicy(IEnumerable<AccessRule> rules, IAuthorizationFactsSource source, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(rules);
        var copy = rules.Take(1025).ToArray();
        if (copy.Length > 1024 || copy.Any(x => x is null)) throw new ArgumentException("At most 1024 non-null rules are supported.", nameof(rules));
        this.rules = copy.ToFrozenDictionary(x => (x.OperationId, x.Action, x.ResourceKind));
        this.source = source ?? throw new ArgumentNullException(nameof(source)); clock = timeProvider ?? TimeProvider.System;
    }
    public async ValueTask<bool> IsAllowedAsync(TenantAccessRequest request, CancellationToken cancellationToken)
        => (await EvaluateAsync(request,cancellationToken).ConfigureAwait(false)).IsAllowed;

    public async ValueTask<TenantPolicyDecision> EvaluateAsync(TenantAccessRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request); cancellationToken.ThrowIfCancellationRequested();
        if (!rules.TryGetValue((request.OperationId, request.Action, request.Resource.Kind), out var rule)) return TenantPolicyDecision.Denied;
        var facts = await source.ResolveAsync(request, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (facts is null || !facts.Principal.Equals(request.Identity.Principal) || !facts.Tenant.Equals(request.Tenant) ||
            !StringComparer.Ordinal.Equals(facts.MembershipVersion, request.Membership.Version) ||
            !StringComparer.Ordinal.Equals(facts.ResourceKind, request.Resource.Kind) ||
            !StringComparer.Ordinal.Equals(facts.ResourceId, request.Resource.ResourceId) ||
            !StringComparer.Ordinal.Equals(facts.ResourceVersion, request.Resource.Version)) return TenantPolicyDecision.Denied;
        var before = clock.GetUtcNow();
        var allowed = facts.NotBeforeUtc <= before && before < facts.ExpiresAtUtc &&
            (rule.Roles.Count == 0 || rule.Roles.Overlaps(facts.Roles)) && rule.Predicates.All(x => x.Matches(facts));
        cancellationToken.ThrowIfCancellationRequested();
        var after = clock.GetUtcNow();
        return allowed && after >= before && facts.NotBeforeUtc <= after && after < facts.ExpiresAtUtc
            ? new(true,after,facts.ExpiresAtUtc) : TenantPolicyDecision.Denied;
    }
}
