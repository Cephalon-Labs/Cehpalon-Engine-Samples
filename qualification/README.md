# W0 owned provider qualification fixtures

These are bounded SDK/third-party compatibility fixtures, separate from the three
business sample implementations. No Engine tenant/outbox/HA/benchmark/production
claim follows from these probes.

Prerequisites: Docker Linux engine, Python3 and the tested cryptography version
recorded in `evidence/host-tools.json`. Read the verified registry lock from Docs
`internal/evidence/w0/artifacts/container-manifests.json`. It pins multiarch index,
Linux/amd64 platform and config digests. Large SDK/model/runner binaries stay in
the workspace's private `.tools` cache outside all three Git repositories.

```text
python qualification/qualify_providers.py start --lock ../Cehpalon-Engine-Docs/internal/evidence/w0/artifacts/container-manifests.json
python qualification/qualify_providers.py probe
# Run the Engine PlatformQualification harness with its owned-fixture wrapper.
python qualification/qualify_providers.py stop
```

The controller uses labeled owned containers and a labeled bridge with loopback-only
published host ports. It records each container ID before port inspection. Secrets
and endpoints are in ignored `.local/qualification/owned-state.json`; they are
never printed into tracked evidence. No account/cloud secrets are provisioned.
This bridge does not claim outbound-network isolation. Provider links use local
plaintext protocols; the Keycloak password grant is a fixture-only setup and is
not a production/browser/OIDC-security certification.

Probe scope: exact installed image config/OS/Java/Erlang versions; PostgreSQL query;
Rabbit version; Keycloak discovery/audience/JWKS RSA signature; Qdrant filtered
vector upsert/query; optional Valkey PING. The Engine driver harness independently
tests real transaction/cancellation and publisher-confirm/manual-ack behavior.

Stop rechecks ownership labels before removing only these containers, their
anonymous volumes and network; checks loopback ports and removes current private
password/token values and generated env files. Download caches are retained.
Failed startup and prior probe results remain evidence. Rerunning start requires
the prior fixture set to be stopped; it does not replace unrelated containers.
