# Independent collector robustness review

Five owned synthetic TLS1.3/HTTP1.1 fixture cases passed against the final build02 driver. These are fault-injection robustness checks, not a capacity observation or benchmark result. The test harness changes no Engine, Samples runtime, canonical evidence, budgets, request cap or scheduling policy.

| Case | Observed result |
| --- | --- |
| Connection: close on first held response | Managed exit1; all130 started rows joined; TLS/client/failure evidence retained; no offered phase |
| Explicit Content-Length:0 | Managed exit1; all130 started rows joined; TLS/client/failure evidence retained; no offered phase |
| Invalid business body after common release | Managed exit1;129 successful preparation reads; all130 rows joined; no offered phase |
| One held response never returns headers | Shared preparation deadline30.014947617s; process exit30.351927449s; all130 rows joined; no phase; no worker leak |
| Valid130 preparation reads, then HTTP503 for every offered request | Actual barrier128 held/distinct load TLS connections;4000 ordered raw observations retained;4000http.503 errors,0correct; phase TLS129before/129after; matching structured preflight rejection; no warmup/measurement |

Every test retained nonempty TLS history and before/after client snapshots, managed exit1, coherent failure stage/flags, and all started preparation completed timestamps. All fixture worker threads joined. No test was replaced or retried. Read `summary.json` for exact checks, source/binary/script hashes and per-file hashes; raw per-test evidence remains alongside it. The private CA/server fixture lives under a native-Linux0700 directory with0600 PFX/key/PEM files and is excluded from evidence.

Read-only Driver review found no blocking fairness or cleanup flaw. Both variants use identical fresh LOAD and separate CONTROL pools; the stronger proof joins128 observed first-use LOAD TLS identities to128 simultaneously held framed responses. The common release precedes every held body read. One shared30s token bounds reset, serial warm reads, header barrier and body validation. Offered records, writer ordering, cap128, rate and1s scheduled deadline remain unchanged. Phase-finally joins request tasks before TLS/client snapshots and raw persistence. The complete-preflight rejection has authoritative counts and no later phase.

Limits: synthetic fixture covers HTTP fault paths; real GraphQL success and business/state semantics remain the separate clean conformance/probe/full-rerun obligations. These tests do not prove abrupt termination persistence, disk-full recovery, production socket longevity or reference environment qualification. Header Task.WhenAll can wait until the common30s deadline after an early failed header if another header is stalled; bounded cleanup was verified, with no unbounded join. No timing/capacity interpretation is made from these runs.
