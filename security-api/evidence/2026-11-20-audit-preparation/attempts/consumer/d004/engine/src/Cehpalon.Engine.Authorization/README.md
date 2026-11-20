# Optional RBAC and ABAC

Experimental portable `net11.0` policy over the existing tenant dispatch boundary. No ASP.NET, token parser, provider or account store dependency. Plain Core dispatch remains public unless the consumer wires protected gateways through `TenantOperationDispatcher`.

```csharp
var policy = new RoleAttributeAccessPolicy([
    new AccessRule("document.read", "read", "document", ["reader"], [
        AttributePredicate.Match(AttributeScope.Subject, "department",
            AttributeScope.Resource, "department"),
        AttributePredicate.EqualTo(AttributeScope.Environment, "network", "private")])
], trustedFactsSource);
```

Any configured role must match and every attribute predicate must match. Use only roles for RBAC, only predicates for ABAC, or both. Empty unconstrained grants reject at startup; missing rules/facts/attributes deny. Roles, attribute values and identifiers use exact ordinal matching. Rule/attribute inputs are frozen with bounded enumeration. No implicit admin bypass, wildcard, dynamic code evaluation or cached permission decision.

Implement `IAuthorizationFactsSource` over trusted data. Resolve on each call and bind principal, tenant, membership version, resource kind/ID/version and validity. Caller request metadata/headers are not authority. Do not copy unverified token roles into facts. Tenant dispatcher checks membership and resource ownership before policy. The leased policy decision caps the checked operation context by fact expiry; UTC rollback across policy/audit and post-audit expiry deny. A data port must still demand the checked context before accessing tenant data. This is not atomic authorization/data access or instantaneous distributed revocation.

Only instantiate/register this policy when the consumer selects it. Not referencing/activating the module creates no authority provider, endpoint or background work. See the actual `security-api` consumer in Samples for generated gateways, Composition, JWT, both transports and optional audit/history. External identity/provider and original benchmark qualification remain open.
