# ADR0022 - Synthetic task lineage conformance

Date: 2026-11-01 (Asia/Bangkok). Status: accepted for bounded synthetic diagnosis under Engine #20; #3 remains Blocked.

## Fixed protocol before builds/captures

Use the installed pinned Linux/WSL SDK/runtime, existing owned reverse-port EventPipe capture/resume/cleanup and parser, with a new isolated synthetic target. No Engine/generator/CLI target or original benchmark, scheduler capture/permissions, GC flags, compiler concurrency or production settings change. Root is sole remote writer.

Target cases, exactly once in order: (1) scheduled Task.Run completion with latch; (2) already-completed task GetResult; (3) synchronous task wait released by owned OS thread; (4) forced inline task through a custom queued scheduler; (5) nested parent/child tasks; (6) throwing task; (7) cancellation of a running blocked task. Journal actual task/scheduler IDs, native TIDs, case markers, outcomes and complete owned-thread joins. No forced GC.

First fixed lane: uninstrumented target/sidecar. Second fixed lane: identical target with existing CLR+sample/marker providers plus System.Threading.Tasks.TplEventSource:0x43:5. Freeze target/runner/helper/parser source, source hashes, exact binary/tool/runtime pins and outputs for each attempt. This is one descriptive pair, not statistical overhead, equivalence, performance improvement or qualification. Record duration/CPU/allocation if observable without changing semantics; do not invent missing counters.

TPL parser/assembler must retain actual IDs/versions/templates/payload/header TIDs, loss/read errors and all failures. Expected templates are scheduled7v1, started8v0, completed9v1, waitbegin10v3, waitend11v0. Validate against emitted metadata. TaskWait intervals may contain inline/spin/blocked work and cannot be labeled blocked time. Completed-before-wait may have no TaskWait. Match only validated process/task-scheduler/task lifetimes; task IDs with zero/duplicate/reuse, malformed ordering, unknown fields or missing starts/ends stay rejected/unknown. Missing observations never become zero delay. Preserve nested and exceptional semantics.

Focused fixtures cover legal/inline/completed/exceptional/nested histories and malformed/ambiguous/reused/unfinished/out-of-order/ID-version/type/boundary identities. Independent review plus actual positive synthetic trace are required before claiming bounded task-to-native-thread linkage. All output must remain separate from legacy GC pairing; no exclusive GC/scheduler share or general Roslyn task ownership follows.

Any preparation defect retains failed source/raw attempts. Predeclare correction before a complete repeat; no favorable selection/stitching. If a declared lane cannot meet its gates, report it rather than weakening gates. Keep original #20 gates/dependencies/estimates/null hours and #3 entire tracking row unchanged; sync only scoped #20 body.

## Parallel source review

Review exact VMR GC caller paths/retry/header generation without new capture. Locating source improves the contract evidence but neither prior model becomes certified merely from source similarity. Preserve raw prior models and state binary correspondence limits.
