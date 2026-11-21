# Audit contract export LF correction declaration02

Declared2026-11-22 before any corrected SDK execution. [Original protocol](audit-contract-export.md) remains unchanged with all16 checks/host and original benchmark criteria.

The first Windows offline execution at consumeracba0da compiled Release with0warnings/errors, then passed7/8 checks. Its deterministic UTF8/LF group failed. Retained CLI artifacts show1503 CRLF in openapi.json and72 CRLF in manifest.json; schema.graphql has0 CRLF. The exporter shared indented JsonSerializerOptions omitted NewLine. The local .NET11 reference documentation identifies Environment.NewLine as the default and accepts explicit LF/CRLF values.

Correct only that shared options initializer by adding NewLine="\n". This applies before encoding/hash generation to OpenAPI and manifest JSON; SDL already normalizes LF. Do not normalize or replace first-attempt artifacts. Change no test, schema semantics, DTO, runtime serializer, transport/authority/budget/storage/SQL/package, threshold or original benchmark setting.

Retain original root driver01, Windows offline01 raw/build/binaries/tests7pass1fail/observations7, source freeze01(116inputs/declaration01fourfiles), and original committed source. New corrected committed source receives source freeze02 including declaration01+02, then a complete new matrix in ahx-driver02: Windows offline8, WSL offline8, exact fixture start, Windows wire8 and WSL wire8 from each host's new verified offline binaries. Each corrected host builds once; the prior failed Windows build remains an additional historical attempt, not a discarded or qualifying run. No unchanged passing-suite repeat and no favorable selection.

Fixture is still stopped with no new helper/private connection files. All-off/selected schema, real cross-tenant parity/revocation/sibling/capacity controls, independent source/raw review, baseline332/651 reuse, #3 Blocked/#20/M0/allmetadata/nullhours and original benchmark criteria remain required.
