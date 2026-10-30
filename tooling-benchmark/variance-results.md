# Tooling variance results - 2026-10-30

The variance goal remains unresolved. All correctness checks pass, but generator unstable distributions progress Windows4->6->7 and Linux3->5->4 across baseline/Candidate01/Candidate02. Windows export-off CV15.22->10.34->16.64%, mean320.04->332.68->346.84ms. Both complete candidates are retained; the favorable middle result is not selected as final proof.

Current benchmark lock pins55c630fc5d4c47258a1a2b0da4a16ce8bc42b9f7. Full Small API/export/portable regressions and their three profile locks pin1b9d538b4311cf574912596a0f547ae5ae788070. Only journal option reuse differs; no runtime/template/generator algorithm change in55. Components509/506repeat at both; every full benchmark has270generator measurements+36primers and144CLI launches per host. Correctness passed; performance Observed, qualification not_qualified. Full #20 gates Planned/M0 and #3 Blocked unchanged.

[All raw and diagnostic](evidence/2026-10-30-variance), [original usage/protocol](README.md), [full three-series report](https://github.com/Cephalon-Labs/Cehpalon-Engine-Docs/blob/main/internal/planning/tooling-variance.md). No general speedup, fixed-variance, provider/production/reference or distribution claim.
