# Tooling component observations

This fixed protocol observes the current Roslyn 4.14 generator plus compilation
emit against an independently authored, typed manual registration compilation.
The manual baseline is already authored: its authoring cost is not timed. This is
not a competitive framework comparison, full tooling qualification, or runtime
dispatch benchmark. #20 remains M0 with its full Test/Benchmark gate Planned;
provider/Windows SDK evidence for #3 remains separate and Blocked.

Build with the repository's pinned .NET SDK, then invoke the built executable:

```text
dotnet restore Benchmarks/Tooling.Components/Tooling.Components.csproj --locked-mode
dotnet build Benchmarks/Tooling.Components/Tooling.Components.csproj -c Release --no-restore
dotnet Benchmarks/Tooling.Components/bin/Release/net11.0/Tooling.Components.dll --output=<new-json-path>
```

There are no workload tuning flags. Every attempt requires new output paths. The
final report and append-only `.rows.jsonl` retain failures and every recorded row;
an abrupt process loss can leave only the journal. Exact fixture inputs are
deterministic functions of this versioned source, size and ID version. Keep this
source revision alongside raw attempts. Source, registry and PE SHA-256 values are
recorded; unequal PE hashes between variants are expected and are not a failure.

The schedule is sizes 1, 3, 32, each in fresh, noop, edit order. Each case has two
paired primer iterations, followed by five repetitions of three paired measured
iterations. There are 36 primer and 270 measured rows. Case index starts at zero.
The generator is first exactly when `(caseIndex + pairSequence) % 2 == 0`.
Pair sequence is 0, 1 for primers, then 2 through 16. Repetition and iteration are
zero based; primers have repetition -1 and iteration 0 or 1.

Fresh creates new compiler graphs for both variants and a new driver before each
pair. Noop retains the original input, manual compilation and returned generator
driver. Edit starts from version 0, replaces the first handler syntax tree and
manual registry tree outside timing, and retains each updated graph and driver.
Even pair sequences use version 1 (`bench.changed000`), odd sequences version 0
(`bench.op000`); the seed/primer/measurement boundary never skips an edit. The 12
unmeasured seed emits for noop/edit are explicitly reported. Each size also has a
separate tracked cache preflight. Timed drivers have tracking disabled.

Common references, parsing, fixture construction, independent manual source
authoring, graph construction/replacement, buffer creation, semantic checks,
hashing and persistence are outside the clocks. Generator wall time covers
`RunGeneratorsAndUpdateCompilation` plus actual PE `Emit`; manual wall time covers
actual PE `Emit`. Every iteration must emit successfully with no error diagnostic.
The manual baseline retains the operation attributes and common handler/harness
sources, and never consumes generated source. Its registration method's normalized
syntax must equal the generator's typed registrations after every emit. Separate
preflight and postflight PE execution proves zero eager factories, all operation
IDs, N correct dispatches and N owned-handler disposals for both variants.

Monotonic wall ticks bracket exactly those operations. Process CPU includes the
small matching timer/allocation instrumentation bracket. CPU ticks are quantized;
zero stays zero. Process-wide precise allocated-byte counts include Roslyn worker
allocations and any background process noise. GC collection deltas are retained;
there is no forced GC, latency floor, outlier removal or retry selection. Raw
timings include JIT/cache/GC and shared-host effects. Collector/hash/output work
outside timing can affect subsequent process state, and unloaded collectible
assemblies are not forced to collect.

Each summary uses all 15 measured rows and the five repetition means, with sample
standard deviation (ddof=1). CV above 15% flags descriptive instability; it never
turns observations into a numeric performance pass/fail. Raw extrema and p50/p95
use all 15 rows with nearest-rank indexing `ceil(p*n)-1`. Correctness requires the entire fixed matrix, AST/runtime parity and
successful emits. Environment metadata reports runtime, OS, CPU count/affinity,
memory/GC and assembly versions/hashes. The SDK string is the expected repository
pin, not an actual SDK probe; orchestration must record the actual build SDK.
Affinity does not reserve resources and these observations set `reference=false`.
