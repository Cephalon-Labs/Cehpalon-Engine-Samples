"""Mask conditional recorded-state labels affected by publication-order ambiguity."""

from collections import Counter


KINDS = {"birth", "initial_enrollment", "in", "out", "waking", "wakeup",
         "wake_new", "exit", "free"}
MAX_ROWS = 262144


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value):
    return type(value) is int and 0 <= value < (1 << 64)


def sets_state(row):
    if row["kind"] in {"in", "wakeup", "wake_new"}:
        return True
    state = row["raw_state"]
    return row["kind"] == "out" and (state in {0, 1, 2} or bool(state & 0x80000000))


def ordering_masks(rows):
    """Return merged half-open masks for one generation in reservation order.

    Callback completion timestamps cannot establish exact scheduler transition
    times. These masks bound only ambiguities visible in the retained order.
    They do not turn an unmasked label into measured CPU or runqueue duration.
    """
    require(type(rows) is list and 1 <= len(rows) <= MAX_ROWS, "invalid generation row count")
    previous_slot = -1
    for row in rows:
        require(type(row) is dict and integer(row.get("slot")) and row["slot"] > previous_slot
                and row.get("kind") in KINDS and integer(row.get("mono_ns")) and row["mono_ns"] > 0
                and integer(row.get("raw_state")), "invalid or unordered generation record")
        previous_slot = row["slot"]
    exits = [row for row in rows if row["kind"] == "exit"]
    require(len(exits) == 1, "expected one observed exit boundary")
    exit_ns = exits[0]["mono_ns"]
    counts = Counter(row["mono_ns"] for row in rows)

    hulls = []
    for left, right in zip(rows, rows[1:]):
        a, b = left["mono_ns"], right["mono_ns"]
        if b <= a:
            hulls.append({"begin_ns": b, "end_ns": a,
                          "source_slots": [left["slot"], right["slot"]],
                          "reasons": ["tie" if a == b else "reversal"]})
    if not hulls:
        return []

    masks = []
    for hull in hulls:
        begin, latest = hull["begin_ns"], hull["end_ns"]
        last_member = max(row["slot"] for row in rows if begin <= row["mono_ns"] <= latest)
        reset = next((row for row in rows
                      if row["slot"] > last_member and latest < row["mono_ns"] < exit_ns
                      and counts[row["mono_ns"]] == 1 and sets_state(row)
                      and not any(other["begin_ns"] <= row["mono_ns"] <= other["end_ns"]
                                  for other in hulls)), None)
        end = exit_ns if reset is None else reset["mono_ns"]
        if begin < end:
            masks.append({**hull, "end_ns": end, "reset_slot": None if reset is None else reset["slot"]})

    merged = []
    for mask in sorted(masks, key=lambda item: (item["begin_ns"], item["end_ns"])):
        if not merged or mask["begin_ns"] > merged[-1]["end_ns"]:
            merged.append({**mask, "source_slots": mask["source_slots"][:],
                           "reasons": mask["reasons"][:]})
            continue
        prior = merged[-1]
        if mask["end_ns"] > prior["end_ns"]:
            prior["end_ns"], prior["reset_slot"] = mask["end_ns"], mask["reset_slot"]
        prior["source_slots"] = sorted(set(prior["source_slots"] + mask["source_slots"]))
        prior["reasons"] = sorted(set(prior["reasons"] + mask["reasons"]))
    return merged
