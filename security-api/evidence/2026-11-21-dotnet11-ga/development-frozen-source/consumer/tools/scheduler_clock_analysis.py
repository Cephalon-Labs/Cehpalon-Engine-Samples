"""Execution-specific clock brackets; no transferable timing-error bound."""

import hashlib
import struct


ROW = struct.Struct("<IIIIQQ")
SLOTS = 128


def require(ok, message):
    if not ok:
        raise ValueError(message)


def analyze(raw, counts, capacity, batches):
    require(type(capacity) is int and 1 <= capacity <= SLOTS, "invalid capacity")
    require(len(raw) == SLOTS * ROW.size and len(counts) == 4, "invalid ledger shape")
    references = [(batch["cpu"], point) for batch in batches for point in batch["rows"]]
    require(all(batch["syscall"] == 186 and batch["affinity"] == [batch["cpu"]]
                and batch["cpu"] in (0, 1) for batch in batches), "invalid actor reference batch")
    require(tuple(counts) == (len(references), max(0, len(references) - capacity), 0, 0),
            "fixed counter reconciliation failed")
    used = min(len(references), capacity)
    require(not any(raw[used * ROW.size:]), "nonzero unused ledger slots")
    observations = []
    for index, values in enumerate(ROW.iter_unpack(raw[:used * ROW.size])):
        ordinal, cpu_begin, cpu_end, reserved, begin, end = values
        cpu, reference = references[index]
        low, high = reference["before_ns"], reference["after_ns"]
        require(ordinal == index + 1 and cpu_begin == cpu_end == cpu and reserved == 0,
                "ordinal, CPU or reserved field differs")
        require(type(low) is int and type(high) is int and 0 < low <= high
                and begin > 0 and end > 0, "invalid reference or callback timestamp")
        observations.append({"ordinal": ordinal, "cpu": cpu,
                             "reference_bracket_ns": [low, high],
                             "fast_points_ns": [begin, end],
                             "conditional_discrepancy_intervals_ns": [[begin-high, begin-low], [end-high, end-low]],
                             "within_reference_bracket": low <= begin <= high and low <= end <= high,
                             "recorded_callback_backwards": end < begin})
    return {"status": "completed_bounded_clock_observations", "ledger_sha256": hashlib.sha256(raw).hexdigest(),
            "attempted": counts[0], "lost": counts[1], "retained": used,
            "observations": observations,
            "outside_reference_brackets": sum(not row["within_reference_bracket"] for row in observations),
            "recorded_callback_backwards": sum(row["recorded_callback_backwards"] for row in observations),
            "physical_scheduler_duration_certified": False, "transferable_clock_error_bound": None,
            "historical_roslyn_qualified": False}
