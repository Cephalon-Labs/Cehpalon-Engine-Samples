# Strict point-boundary clarification before replay

Use strict inequalities for recorded sample timestamp inside execution and callerwait brackets, plus guaranteedEmitcore for rowqueries. Samples exactly at any boundary or in an inverted/empty core are retained as boundary/unassigned context, not promoted as inside. Preserve candidate indices and all no-sample/unknown queries. New strict counts do not replace the prior ADR0023 closed-interval point observations. No new workload, gates, thresholds or causal interpretation.
