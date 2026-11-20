# Windows warmup drop investigation

This optional diagnostic copy leaves the benchmark consumer and Engine product code unchanged. It adds numeric request/producer/native-thread markers and a server request DiagnosticListener, captures owned-process CLR/TPL EventPipe data, then validates independent before/after QPC receipts. Runtime packages use the existing TraceEvent 4.0.0 / Diagnostics.NETCore.Client 0.2.750501 lock graph. No kernel session, driver, trust-store or host scheduling change is made.

From Samples, use a previously verified actual generated consumer preparation and a fresh ignored output:

```text
python tools/trace_https_warmup.py prepare --base .local/<verified-preparation> --dotnet <pinned-sdk> --output .local/<trace-preparation>
python tools/trace_https_warmup.py run --prepared .local/<trace-preparation> --mode fixtures --output .local/<fixtures>
python tools/analyze_https_warmup.py --input .local/<fixtures> --output .local/<fixtures>/analysis.json
python tools/trace_https_warmup.py run --prepared .local/<trace-preparation> --mode conformance --output .local/<conformance>
python tools/analyze_https_warmup.py --input .local/<conformance> --output .local/<conformance>/analysis.json
python tools/trace_https_warmup.py run --prepared .local/<trace-preparation> --mode warmups --output .local/<warmups>
python tools/analyze_https_warmup.py --input .local/<warmups> --output .local/<warmups>/analysis.json
```

Stop on any failed command; source freezes reject edits after preparation. The required fixture and conformance validations precede the fixed four warmups. Run `python -B -m unittest discover -s tools -p test_https_warmup.py` for the offline adversarial checks. Follow the [declared protocol](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/validation/windows-warmup-drops.md). This is perturbed tracing, with explicit observer work and allocation. Synthetic forced GC is confined to fixtures. Never treat an intentional post-warmup ABORT as a canonical benchmark result or repeat a workload until drops match.

Raw nettraces stay in ignored local storage; they can contain private metadata. Public evidence contains numeric/identity-normalized exports, hashes, receipts, source and replayable analysis. Keep process/session scope when interpreting pseudonymized pointer identities. Missing, duplicate, ambiguous or incomplete evidence cannot establish absence of GC or a scheduler cause.

The historical five-drop burst is replayable from committed prior raw data. New traces cannot reconstruct its missing runtime history. Producer awaits include timer readiness and managed continuation dispatch; process-level TaskScheduled-to-TaskStarted envelopes lack exact request lineage and do not establish OS runnable delay. Keep uncovered time unknown and #3 Blocked.
