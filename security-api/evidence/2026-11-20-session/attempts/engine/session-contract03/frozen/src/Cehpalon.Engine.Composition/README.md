# Experimental Composition compiler and owned lifecycle

This `net11.0` component has no Core, host, DI, transport or provider dependencies.
It accepts the complete appsettings JSON text, validates the `Cehpalon` section,
and returns an immutable plan before receiving or invoking any runtime factory.
Other top-level host sections can coexist. This is a startup snapshot: changing
configuration requires compilation and a new owned activation lifecycle; there
is no live-reload transaction or provider migration.

```json
{
  "Cehpalon": {
    "SchemaVersion": 1,
    "Architecture": "Modular",
    "Topology": "SingleProcess",
    "Pattern": "RequestReply",
    "Modules": {
      "api": { "Enabled": true },
      "graphql": { "Enabled": false },
      "worker": { "Enabled": false }
    }
  }
}
```

Schema 1 supports only that architecture/topology/pattern tuple. Explicit module
roots can activate support dependencies; an entrypoint dependency needs its own
explicit true selection. Explicit false forbids activation, including activation
as a dependency. All unspecified entrypoints remain off. The descriptor catalog
is trusted application metadata, not a capability sandbox: marking a resource
as support does not prove that its factory has no endpoint or background work.

Unknown settings/modules, case ambiguity, duplicate keys, malformed types,
unknown profiles/versions, missing dependencies and catalog cycles reject the
plan. Inactive catalog components are also checked. Limits are 1 MiB UTF-8 JSON,
depth 32, 256 descriptors/selections/dependencies/registrations, and canonical
ASCII module IDs `[a-z][a-z0-9_.-]{0,127}`. The compiler preserves no raw secrets
in its malformed-JSON diagnostic. Descriptor and plan collections are defensive
snapshots; this does not deep-clone arbitrary business/provider state.

Call `PlanActivator.ActivateAsync` with lazy `ModuleRegistration` factories only
after successful compilation. It checks the entire registration set before any
factory: all enabled modules must have one, duplicates/unknown registrations
reject, and known disabled registrations are allowed but never invoked.

Every invoked factory transfers one **distinct newly owned** `IAsyncDisposable`
resource. Do not return shared/container-owned resources. A factory that throws
before returning is responsible for its partial allocations. Cancellation before
activation invokes zero factories; cancellation after acquiring a resource is
checked before the next factory, then rolls back. In-flight cancellation is
cooperative and depends on the factory honoring the token.

An `ActivationLease` disposes resources in reverse activation order; concurrent
or repeated disposal waits for the same cleanup and does not repeat callbacks.
All cleanup attempts run even if one fails. Rollback aggregates cleanup errors
with the activation/cancellation exception first. Cleanup-only errors aggregate
and remain observable on repeated lease disposal. A resource must not await its
own owning lease's disposal from its disposal callback.

API/GraphQL/Worker labels in the contract suite are counters/recorder fixtures,
not implemented HTTP/GraphQL/Worker hosts. This slice does not establish external
provider integration, tenant/authentication authority, topology portability,
benchmarks, production qualification, supported Windows or hosted CI success.
