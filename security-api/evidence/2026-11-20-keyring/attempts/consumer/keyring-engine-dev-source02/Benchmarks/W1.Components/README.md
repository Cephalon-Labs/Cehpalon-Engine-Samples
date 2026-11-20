# W1 component performance smoke

Read the [predeclared protocol](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/validation/w1-component-protocol.md) before running. This is a bounded local regression guard, not a framework comparison, production SLO or supported-Windows qualification.

Release executable: `dotnet Benchmarks/W1.Components/bin/Release/net11.0/W1.Components.dll --output=path/to/new-result.json` after a locked restore/build. Results refuse to overwrite an existing file. All five repetitions are retained; no outlier filtering. The direct Core baseline includes the same new owned handler, success result, context, request, cancellation checks and disposal. Dispatcher plumbing and lookup/type guards are deliberately additional work.

Run on the declared local WSL host without a debugger or competing qualification workload. Record OS/runtime, processor count, memory and process affinity together with Engine revision/source/lock hashes. Do not turn an unmeasured path or an unavailable host into a pass. No generator-speed, cold-start, real transport, provider, tenant/security or end-to-end performance claim.
