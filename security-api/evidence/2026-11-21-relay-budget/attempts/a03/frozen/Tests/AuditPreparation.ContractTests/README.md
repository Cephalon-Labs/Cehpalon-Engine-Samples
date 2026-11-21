# Audit preparation contracts

This executable verifies actual registry metadata, pre-provider catalog validation, strict registry-instance binding and opaque single-attempt completion. It covers pre-effect denial/cancellation, retained/expired contexts, metadata/empty-field laziness, exact receipt binding, failed-first/null/cancel consumption, real independently scheduled concurrent completions held inside a fixture sink, and post-mutation possible effects. Existing low-level recording remains compatible.

Run through the repository-pinned SDK with a fresh ignored output directory. The integrator includes this suite in the complete locked Release Windows/WSL verification. Results contain sanitized check names/counts, not payload values or credentials.

Baseline evidence under `.local/audit-preparation-baseline01` records the prior API creating a sink and mutating fixture state before a missing-rule recording failure. Its pre-run runtime/probe source and raw output are retained. This does not establish a real database transaction, provider readiness, durable audit, backend exactly-once, production or benchmark qualification. #3 remains Blocked; original gates remain unchanged.
