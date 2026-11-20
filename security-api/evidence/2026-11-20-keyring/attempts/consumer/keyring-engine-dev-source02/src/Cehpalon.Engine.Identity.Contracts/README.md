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
