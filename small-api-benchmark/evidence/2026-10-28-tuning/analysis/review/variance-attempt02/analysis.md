# GraphQL variance: attempt02 offline analysis

All20 original main measured runs were analyzed without dropping requests, windows or runs. Exact script: `.local/analyze_variance_attempt02.py`; full per-operation, per-second and15second-window decomposition is in `analysis.json`, with source gzip hashes. No new workload or build ran in this analysis.

## What the records establish

| GraphQL Engine pair | Scheduled p95 ms | Sent→completed p95 ms | Queue p95 ms | Server CPU ms | Server GC0/1/2 | TLS connections, all phases |
| --- | --- | --- | --- | --- | --- | --- |
|1|0.364532|0.360685|0.004051|43213.1|781/4/0|131|
|2|0.343007|0.339601|0.003701|44041.8|743/4/0|128|
|3|0.480505|0.474793|0.005616|48668.6|777/5/0|147|
|4|0.382131|0.378339|0.004177|63475.1|828/4/0|133|
|5|0.369469|0.365306|0.004386|43624.2|738/4/0|130|

The all-five scheduled CV remains12.3680920685%; sent→completed CV is12.2999602970%. Baseline GraphQL sent CV is2.4976274004%. Therefore offered pacing delay alone does not explain the failed stability gate. A change that only removes a few microseconds before `sent` is not an evidenced solution.

Pair3 is elevated across all12 fifteen-second windows: sent p95 ranges0.3966–0.5461ms, versus its0.474793ms whole-run value. Get/list/set sent p95 values are0.465395/0.520665/0.467885ms. The increase is not confined to a single operation or one isolated spike. Among9001 requests at or above its scheduled p95, only51 (0.57%) spend at least half their duration before `sent`; their queue median is0.004584ms. No request/window is excluded from these observations or the CV.

"Sent" precedes `HttpClient.SendAsync`; "completed" follows body read, JSON parse and semantic validation. That interval includes client pool/connection/TLS/socket scheduling, network, server execution, client continuations/GC and validation. It is **not a server-only timer**. End-to-end evidence cannot assign the increase solely to Core/GraphQL or solely to the collector.

No GraphQL run has a server Gen2 collection. Pair3 has one more Gen1 than other Engine pairs, but neither the largest Gen0 count nor the largest server CPU/allocated bytes; pair4 consumes substantially more server CPU with a lower p95. Aggregate counts have no pause/event timeline, so they neither prove nor rule out GC-duration effects. Driver CPU/GC/threadpool statistics were not retained, limiting collector attribution.

Pair3's147 TLS connections exceed128–133 in other Engine runs, but the connection list spans preparation/preflight/warmup/measurement and lacks timestamps. It cannot establish when the extra connections occurred. Roughly19 additional handshakes alone do not directly explain9001 tail requests; they may be a symptom of broader scheduling/pool pressure. Correlation is not a demonstrated cause.

## Concrete fair improvements and checks

1. **Use native Linux deployment/storage uniformly.** The retained SDK/runtime, application dependencies and compressed evidence writer ran through DrvFs. Moving all three to native Linux is a legitimate deployment/collector change, applied equally to baseline and Engine. The2×2 SDK-location × application-location diagnostic should keep content/work directory, private certificate, control-file output filesystem, CPU masks, GC/env and first-response definition constant, hash identical bytes and verify actual runtime resolution. Ready-file I/O is inside the startup path, so changing it between cells would confound the factors. Retain all48 starts; three/cell is descriptive and not a full four-position Latin-square balance or a p95 acceptance sample. A later full native run must disclose its deployment/harness difference; it cannot claim Engine code alone caused a gain.
2. **Observe the collector before assigning a cause.** Add equal cheap driver phase-boundary CPU/GC/threadpool counters and timestamp TLS connection observations. Preserve end-to-end scheduled latency. These would distinguish pre-send delay, post-send collector pressure and connection churn; they do not change workload/rate/cap/deadline/budgets.
3. **Remove avoidable recorder contention fairly.** Current raw JSON/gzip writing runs on a ThreadPool task concurrently with a busy-pacing offered loop and asynchronous client parsing on two collector CPUs. The recorder allocates boxed arrays/JSON strings per request and performs filesystem writes. Native output is the smallest correction. A later declared collector revision could use a dedicated writer or preallocated indexed records with deferred encoding, identically for both variants. It must preserve every offered/drop/error record, bounded memory, failure/termination evidence and phase-boundary metrics; deferring output must not silently extend server metric intervals or lose partial failed phases. This is a plausible contributor, not a proven cause in attempt02.
4. **If changing keepalive/pool configuration, freeze both sides.** Timestamped connection evidence should guide an explicit shared keepalive policy. A client idle timeout/server keepalive longer than a complete run can avoid unnecessary churn, but it changes retained-connection memory and must be applied to both baseline and Engine, measured through the original idle gate, and recorded. Current untimestamped counts alone do not prove this will fix CV.
5. **Keep code changes semantically grounded.** A proposal such as avoiding redundant linked-cancellation allocation when tokens are identical can be correct, but requires cancellation equivalence tests and an equally optimized native baseline when it shares that logic. Its small allocation saving is not evidence that it explains pair3. Avoid padding the baseline, sleeping every response, adding a CV denominator floor, discarding pair3, selecting only good windows, or weakening the10% rule.

## Remaining uncertainty and acceptance boundary

The persistent after-send elevation is compatible with shared-host scheduling/frequency/resource contention, collector work, networking or server behavior. There is no retained per-request server duration, driver GC timeline, TLS timeline, CPU frequency or host contention trace that identifies a unique cause. Unreserved WSL CPUs and no2GiB cap remain nonqualifying independently of these numerical outcomes.

No variance fix is claimed from this analysis. Freeze changed source/deployment/collector configuration before a complete original startup/idle/load/diagnostic rerun; retain all five values and all failures. Startup absolute1s and CV10% remain unchanged, no artificial minimum or baseline penalty is introduced, and #3 stays Blocked.
