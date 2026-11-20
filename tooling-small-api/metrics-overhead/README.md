# Protected HTTPS budget listener comparison

This Samples-owned entrypoint augments an actual CLI-generated Small API without changing its generated business, host, transport or gateway sources. One Release executable runs the server and load client in separate processes. The baseline uses a business budget without creating a meter/listener/sampler. The observed policy explicitly collects aggregate gauges after requested 10 ms asynchronous delays and retains indexed samples in preallocated storage.

Use the pinned SDK and a clean Engine `5f8f252e901e85c50d7fc6f4b760e457965ce3bb`. First run `tools/verify_tooling_small_api.py --live-metrics` into a new ignored output, then:

```text
python tools/observe_https_metrics.py prepare --dotnet <pinned-sdk> --functional .local/<functional-output> --output .local/<new-preparation>
python tools/observe_https_metrics.py run --prepared .local/<preparation> --profile conformance --output .local/<new-conformance>
python tools/analyze_https_metrics.py --input .local/<conformance> --output .local/<conformance>/analysis.json
python tools/observe_https_metrics.py run --prepared .local/<preparation> --profile measure --output .local/<new-measurement>
python tools/analyze_https_metrics.py --input .local/<measurement> --output .local/<measurement>/analysis.json
```

Follow the [frozen protocol](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/validation/https-metrics-overhead.md). Complete Windows before WSL and avoid competing owned work. Every arm, offered request, collection, failed preparation and first callback is retained. A failed attempt cannot be replaced by a favorable unchanged-source rerun. Credentials stay in private pipes; the controller retains only public metadata. No trust store or host scheduling policy changes.

The workload mixes HTTP/GraphQL and both fixture tenants, with six alternating pairs for each budget mode. Process resource deltas include background work and matching control gaps. This is a descriptive shared-host observation; it does not replace canonical benchmark gates, establish real provider support or qualify production. Keep #3 Blocked.

Run `tools/verify_https_metrics_evidence.py --input <actual-conformance> --output <new-report>` to validate real captured data and reject 17 altered datasets. Use `tools/summarize_https_metrics_attempt.py` for an incomplete attempt; it preserves failed/unpaired arms and does not pool executions or qualify them. The controller waits for a rejected warmup's partial report before stopping owned children.

[Retained source, complete WSL series and incomplete Windows attempts](../evidence/2026-11-20-https-metrics-overhead/README.md) include every entered arm. Final analysis removes CV for signed paired differences; original outputs remain available. [Results and limits](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/https-metrics-overhead.md).
