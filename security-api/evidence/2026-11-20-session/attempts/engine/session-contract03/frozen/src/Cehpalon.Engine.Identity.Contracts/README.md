# Experimental identity source contracts

This BCL-only net11.0 component provides exact issuer/subject value keys,
immutable time-bounded identity snapshots and an explicit issuer/scheme allowlist.
It does not reference Core, ASP.NET, a provider SDK or a token library.

Constructing `PrincipalId` or `IdentitySnapshot` validates bounded data only. It
does **not** authenticate a caller. A trusted host adapter implements
`IIdentitySource.ResolveAsync`, obtains the identity from an established protocol
implementation and is called afresh for each secured invocation. A JWT/OIDC
adapter must validate the expected signature/key, issuer, audience, token type,
lifetime and subject semantics before supplying these values. No such adapter,
JWT parser, key discovery/rotation, browser login or external IdP proof is supplied
here. Correlation metadata, headers and caller-created snapshots are not authority.

`IdentityTrustPolicy` makes a defensive immutable copy of explicit issuer/scheme
allowlists. Empty lists deny all. Comparison is ordinal and case-sensitive; no
trimming, URI canonicalization or issuer/subject normalization occurs. The issuer
is deliberately opaque to permit non-OIDC service/fixture identities; accepting
an opaque value here is not proof it satisfies an OIDC issuer URL contract.
Subjects are keyed together with their issuer. Values reject blank/control and
malformed UTF16 input; lengths are bounded in UTF16 code units (issuer2048,
subject256, scheme128), with at most256 entries per allowlist.

Validity is `[NotBeforeUtc, ExpiresAtUtc)`, checked against a caller-supplied
trusted clock. The policy does not choose clock skew, refresh credentials, revoke
sessions or reinterpret roles. Snapshot constructors normalize time offsets to
UTC while preserving instants, require a positive interval and expose no mutation.
An upstream source remains responsible for freshness and protocol revocation;
the surrounding secured dispatcher must recheck expiration before business work.

The executable [contract suite](../../Tests/Identity.ContractTests/README.md)
tests component data/lifetime/trust boundaries only. Local Windows26H2 is
observational/unlisted; #3 remains Blocked and hosted CI is unpassed. No complete
tenant/provider/transport/security/production or Maturity promotion is claimed.

## Optional session-status observation

The original four-argument IdentitySnapshot constructor still creates a sessionless identity. An explicit five-argument overload additionally carries an immutable, exact SessionId (at most256 UTF16 code units, no blank/control/malformed input). This identifier is supplied by trusted authenticated mapping; constructing it is not authentication or session authority.

Select SessionValidatingIdentitySource(inner, statusSource, maximumObservationLifetime, timeProvider) only for protected profiles that require application session checks. The lifetime must be positive and at most five minutes. IIdentitySessionStatusSource receives the established identity and returns bounded SessionStatusSnapshot facts for the exact principal (issuer and subject), scheme and session ID. Every ResolveAsync calls the inner source and session source afresh; anonymous/sessionless/expired identities skip the session source. Missing/inactive/expired/future/misbound status denies. Cancellation and infrastructure/clock faults propagate without a cached fallback.

The observation freezes UTC and monotonic time before identity resolution and rechecks both after identity and session-source awaits. Time consumed by both lookups reduces the remaining cap, including frozen UTC; backward observations deny. The returned validity starts at completion and ends at the minimum of identity expiry, status expiry, startUTC+cap and completionUTC+(cap-elapsed), using bounded arithmetic. This bound applies to this source observation and its returned UTC interval. The original monotonic origin is not propagated through later membership/policy/audit awaits, so this is not an end-to-end admission/revocation bound when UTC stalls later.

The host owns a trusted session store/provider, unique IDs per login/generation, revocation tombstones and lifecycle. Never reactivate/reuse an ID while old credentials carrying it may still be accepted; a response-only version would not prevent replay and is not exposed as anti-replay authority. There is no built-in blacklist, token issuer, OAuth logout/revocation/introspection endpoint, database or network refresh.

Inject the decorated source into TenantSecurityServices. Protected dispatch/switch/read sets re-resolve it even if the host authentication handler caches a ticket. Read-set children pin the original SessionId (including null) along with principal/scheme and preserve it when clamping validity. The guard does not clear HttpContext.User, remove cached host tickets/cookies or change unrelated RequireAuthorization routes. Every other protected entrypoint needs its own equivalent configured check. A denied tenant operation normally returns access.denied (HTTP403), not a global401 logout.

Revocation after this observation can race later admission; already admitted work may finish. No live revocation subscription, provider transaction, retroactive rollback or distributed/session-store qualification follows. Required operation audit continues its existing denial/fault/authorized-tenant rules; session management audit/retention belongs to the host. The portable decorator observes the supplied CancellationToken: hosts must pass/link request abort where needed (the HTTP adapter does). Optional copies/lookups add unmeasured work; no performance improvement is claimed.
