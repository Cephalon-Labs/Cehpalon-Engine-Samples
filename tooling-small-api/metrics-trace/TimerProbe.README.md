# Windows timer/publication probes

These synthetic probes augment a verified diagnostic consumer with a separate `timer-probe` entrypoint. They do not change the HTTPS workload or Engine continuation policy. The four fixed profiles are Task.Delay(1), one-shot timer with asynchronous completion, timer with inline-eligible completion, and accepted ThreadPool work with asynchronous completion. Native timer-ready and kernel switch/ready timestamps remain unavailable.

```text
python tools/observe_timer_publication.py prepare --base .local/<verified-trace-preparation> --dotnet <pinned-sdk> --output .local/<new-probe-preparation>
python tools/observe_timer_publication.py run --prepared .local/<probe-preparation> --mode preflight --output .local/<new-preflight>
python tools/analyze_timer_publication.py --input .local/<preflight> --output .local/<preflight>/analysis.json
python tools/observe_timer_publication.py run --prepared .local/<probe-preparation> --mode compare --preflight .local/<preflight>/analysis.json --output .local/<new-comparison>
python tools/analyze_timer_publication.py --input .local/<comparison> --output .local/<comparison>/analysis.json
```

Stop on failure. The controller requires a validated preflight from the exact preparation. All source/binary hashes are checked before targets start. Four alternating control/trace pairs retain 128 trials per profile, all first calls, races and outliers. Raw points and trace markers reconcile by process/profile/trial/kind/native TID/QPC; missing or ambiguous evidence invalidates analysis. Preserve partial failures and every original trace locally.

Publication is bracketed before/after TrySetResult. A resumption racing the publisher's after-point has a zero conservative lower bound. Inline requires matching callback TID and bracket containment, not TID alone. Arm-to-managed-callback includes timer eligibility, dispatch, OS/runtime and observer work. It is not pure timer wait. The publication-to-observed-resume interval is also not kernel scheduler share or an exact first-instruction timestamp.

Run `test_timer_publication.py` and the existing `test_https_warmup.py` tests through unittest discovery. Analysis replays without private nettraces from normalized exports. [Protocol](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/validation/windows-timer-publication.md). Keep #3 Blocked and the benchmark criteria unchanged.
