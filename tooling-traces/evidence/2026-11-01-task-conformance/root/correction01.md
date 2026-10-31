# Predeclared collection correction 01

2026-11-01. Pair01 is retained as failed conformance: target semantic cases and basic parser loss gates passed, but custom EventSource emitted an undefined-keyword error instead of positive markers. This is preparation failure, not a task-lineage pass.

Before rebuild/repeat, add the required nested EventSource Keywords.Diagnostic constant and reference it from the existing marker attribute. Strengthen runner to require complete positive marker parity and reject EventSourceMessage/provider errors, retaining raw events and exact source01. Repeat the ENTIRE declared plain then TPL pair once as pair02; same cases/order/provider values/runtime/GC/concurrency/gates. No subset selection, stitching or performance pass. Root independently validates sidecar/marker/task linkage after the basic runner.
