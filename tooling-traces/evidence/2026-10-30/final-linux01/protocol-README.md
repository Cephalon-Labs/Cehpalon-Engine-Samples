# Bounded tooling observations

`tools/benchmark_tooling.py` builds the locked Engine CLI, `Benchmarks/Tooling.Components` driver and a real CLI-generated Small API outside the CLI clock. It retains the actual consumer package lock, emitted typed registry, runtime dependency graph, source hashes and all command logs. The Engine lock must be updated to the actual committed driver revision before the final run.

Run Windows and Linux sequentially, with the exact pinned SDK and a fresh ignored Samples `.local` destination. The coordinator owns timing isolation. Do not start an owned build, load generator or other timing workload concurrently.

```powershell
python tools/benchmark_tooling.py --dotnet D:/Cephalon/.tools/dotnet11/win-x64/dotnet.exe --engine-root D:/Cephalon/Cehpalon-Engine --output .local/tooling-benchmark-win01
```

```sh
python3 tools/benchmark_tooling.py --dotnet /home/tom/.local/share/cehpalon-benchmark-deployment/tuning-20261028/sdk/dotnet --engine-root /mnt/d/Cephalon/Cehpalon-Engine --output .local/tooling-benchmark-linux01
```

`--integration` marks an uncommitted preliminary attempt. `--prepare-only` builds and verifies fixtures without running either timing series; its completed preparation report has `mode=preparation_only`, `benchmark_complete=false`, `correctness_status=not_run` and `canonical=false`. Existing destinations are refused. Failed attempts remain retained and invalidate the attempt; there are no retries, discarded outliers or selective reruns.

The fixed phase order is build/preflight, one complete generator driver invocation, then the CLI's eighteen rounds. The generator driver retains N=1/3/32 × fresh/no-op/edit, independent manual typed registry versus actual generator DriverRun+Emit, two paired primers and five paired repetitions with three iterations. The 270 measurements, 36 primers and 12 unmeasured state seeds remain separate. The harness replays the exact paired matrix/order/IDs, semantic cases, append-only raw journal, all fifteen-value extrema/percentiles, and CV of the five repetition means. Exact semantic parity and emitted/runtime behavior are correctness prerequisites; the measured generator stage does not claim full build costs or a universal code-generation advantage.

The CLI base order is `new-portable`, `new-small-api`, `validate-portable`, `validate-small-api`, `export-api`, `export-both`, `export-graphql`, `export-off`. For rounds 0–17, rotate the base order by `round % 8`, then reverse odd rounds. Rounds 0–2 are primers; rounds 3–17 are measurements. This predeclares all 144 fresh-process launches, including 24 primers and 120 measurements. A fixed valid project name and source root are used. Every scaffold and export destination is fresh; validation reads frozen built fixture configurations.

The timer starts immediately before subprocess launch and ends when the process exits and captured stdout/stderr have drained. Log persistence and output verification occur afterward. Captured pipes and subprocess supervision are included in absolute costs. Per-process CPU is explicitly null because this portable runner does not measure it. Preparation disables compiler sharing and owned MSBuild node reuse; it never shuts down shared build servers. No forced GC, TLS host or API load is used by the CLI series.

Every launch checks the actual complete output: exact 9/14 scaffold files and 17/32 observed source hashes, exact validation plans, selected contract artifacts and deterministic hashes, three typed operations, zero business/host/TLS/authority work, and selected GraphQL registration/schema/provider creation and disposal. GraphQL-off counters must remain zero. Every primer and measurement retains its order, process times, raw stdout/stderr hashes and verification result, including failed or timed-out processes. Launch failures also retain a partial manifest.

These are fresh-process, OS/filesystem-cache-primed observations, **not cold-disk** measurements. Preparation, primers and per-invocation verification prime caches. The CLI has no fabricated competitive baseline. All fifteen measured values per scenario feed minimum, maximum, nearest-rank p50/p95 (`ceil(p*n)-1` index), mean, sample standard deviation and sample CV. The compiler comparison uses CV of five repetition means, and the CLI uses CV of fifteen measured launches. CV greater than 15% flags an unstable observation; it is descriptive and never a numeric performance pass/fail gate. Correctness and matrix completeness require 100% success.

The report records observed SDK, source and output filesystem mounts/types and exact runtime information. Windows NTFS and a WSL native SDK with `/mnt/d` source/output involve different storage paths; the two-host observations cannot establish an operating-system speedup. Shared-host affinity or logical CPU inventory does not establish reserved resources or a reference machine. Completed full attempts use `status=completed`, `correctness_status=passed`, `performance_status=observed`, and `qualification_status=not_qualified`; uncertainty flags stay descriptive. The results remain bounded #20 evidence: #3 stays Blocked, full Test/Benchmark gates stay Planned, runtime maturity stays M0, and provider/platform/production/release qualification and actual person-hours remain unestablished.
