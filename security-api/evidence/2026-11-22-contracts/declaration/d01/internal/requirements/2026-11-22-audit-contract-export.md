# Offline audit contract export requirements

Accepted2026-11-22; #18 with #7/#8 regressions. [ADR0055](../adr/ADR-0055-offline-audit-read-contract-export.md).

- Projects can export selected receipt/resource OpenAPI and GraphQL SDL without credentials, DB, WebApplication, listener or authority calls.
- Runtime mapping and export share actual typed bindings and pure selection/validation. Default APIs, explicit disabled behavior, generated gateways and existing security/capacity/lifetime remain compatible.
- Artifacts describe actual serializers and vendor schema, remain detached/deterministic, include hashes and clearly state structural/authority limits. Generated six-ID registry metadata is checked without handler creation.
- Publish a new artifact directory without overwriting existing data; retain failed attempts. The CLI export branch precedes legacy connection-file access.
- Prove selected/disabled/schema-to-wire parity and actual tenant isolation/fresh revocation/cursor bounds/GraphQL siblings/shared capacity on both client hosts.
- Run targeted16 checks per host with exact committed/frozen/binary maps; reuse prior332/651 and unchanged Engine evidence explicitly. Original benchmark/M0/#3 Blocked/#20/all metadata/hours remain unchanged; sync tracking/Docs/Project/mains.
