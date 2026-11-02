# Overflow/counting refinement before code/replay

Exact copied kernel source reviewed independently, consistent with source reviewer findings:

- kernel/events/ring_buffer.c 174–195,248–265: normal full forward nonoverwrite ring cannot overwrite unread data; publication fails and lost_samples increments. An observed head-tail exceeding capacity is an invariant/reader failure, not intended normal overflow evidence.
- A later successfully published event can include a coalesced PERF_RECORD_LOST; an end-of-session LOST record is not required. Terminal PERF_FORMAT_LOST is independent of whether a LOST record fit. Do not add LOST records to lost_samples as disjoint losses.
- core.c 10552–10604: event count increments before regs/sampling/ACTIVE and overflow handling. At sample_period1 each ordinary eligible active event normally attempts output; count=deliveredSAMPLE+lost is not an unconditional ABI identity because other suppression/throttle/state paths exist. Tracepoint payload filter precedes the increment (10995–11017/11101).

Recommended frozen gate: one fixed bounded pressure/no-drain negative must end with nonzero terminal read-format LOST. If fixed pressure yields no loss, mark negative inconclusive/failure, preserve and stop; no adaptive extra work or unchanged repeat. Positive fresh session can conservatively require loss0, no unexpected/throttle/malformed records and count equal decoded SAMPLE count per FD with stable terminal readbacks, rejecting discrepancies without inventing loss arithmetic.

This refines the pre-code plan's earlier mention of overrun as a negative signal: overrun rejects a ring, but does not establish the intended ordinary overflow mechanism. No active operations were performed by this reviewer.
