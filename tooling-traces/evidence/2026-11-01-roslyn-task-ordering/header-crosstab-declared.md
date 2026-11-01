# Recorded native-header cross-tab declaration

Before tool replay/cross-tab counts, also classify whether the task execution-start native header TID equals the wait caller header TID. Preserve same/different/unknown, cross-tab with the literal start-event vs waitbegin relation, and expose every record. Same header is descriptive and does not prove native lifetime, exact inline callpath, CPU or blocked/runqueue duration. This is needed to avoid interpreting start-after-wait as necessarily waiting for another worker. No targets/captures/gates/thresholds change.
