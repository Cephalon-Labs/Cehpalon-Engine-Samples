"""Decode sanitized scheduler identities and conservative state intervals."""

from collections import defaultdict
import struct
from scheduler_recorded_order import ordering_masks


ROW = struct.Struct("<IIIIQIIII")
KINDS = {1: "birth", 2: "wake_new", 3: "in", 4: "out", 5: "waking",
         6: "wakeup", 7: "exit", 8: "free", 10: "initial_enrollment"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decode_scheduler(raw, report, execution_id, slots=262144):
    attempted, lost, faults, frees, total, initial = report["terminal_counts"]
    require(len(raw) == slots * ROW.size and 0 < attempted <= slots and lost == faults == 0
            and 0 < frees == total <= 64 and 0 <= initial <= total, "invalid terminal scheduler ledger")
    require(not any(raw[attempted * ROW.size:]), "nonzero unused scheduler slots")
    groups = defaultdict(list)
    for slot, row in enumerate(ROW.iter_unpack(raw[:attempted * ROW.size])):
        kind, cpu, target, state, stamp, tid, global_tid, generation, parent = row
        require(kind in KINDS and 1 <= generation <= total and 0 <= parent <= total
                and tid > 0 and global_tid > 0 and stamp > 0,
                "malformed scheduler record")
        require((target != 0xFFFFFFFF) == (kind in {2, 5, 6}) and (kind == 4 or state == 0),
                "scheduler field presence mismatch")
        groups[generation].append({"slot": slot, "kind": KINDS[kind], "cpu": cpu,
                                   "target_cpu": None if target == 0xFFFFFFFF else target,
                                   "raw_state": state, "mono_ns": stamp, "local_tid": tid,
                                   "global_tid": global_tid, "generation": generation, "parent": parent})
    require(set(groups) == set(range(1, total + 1)), "missing scheduler generations")
    identities, timelines = [], {}
    for generation, rows in sorted(groups.items()):
        rows.sort(key=lambda row: (row["mono_ns"], row["slot"]))
        require(len({(row["local_tid"], row["global_tid"], row["parent"]) for row in rows}) == 1,
                "generation changed identity")
        by_kind = defaultdict(list)
        for row in rows:
            by_kind[row["kind"]].append(row)
        starts = by_kind["birth"] + by_kind["initial_enrollment"]
        require(len(starts) == len(by_kind["exit"]) == len(by_kind["free"]) == 1,
                "missing or duplicate generation lifecycle endpoints")
        start, end, free = starts[0], by_kind["exit"][0], by_kind["free"][0]
        require(start["mono_ns"] < end["mono_ns"] < free["mono_ns"] == rows[-1]["mono_ns"],
                "invalid lifecycle clock ordering")
        if start["kind"] == "birth":
            require(len(by_kind["wake_new"]) == 1
                    and start["mono_ns"] < by_kind["wake_new"][0]["mono_ns"] < end["mono_ns"],
                    "born generation lacks first wake")
        require(any(row["kind"] == "out" and row["raw_state"] == 128
                    and end["mono_ns"] < row["mono_ns"] < free["mono_ns"] for row in rows),
                "generation lacks terminal switch-out")
        identities.append({"execution_id": execution_id, "generation": generation,
                           "local_tid": start["local_tid"], "global_tid": start["global_tid"],
                           "parent_generation": start["parent"], "born_ns": start["mono_ns"],
                           "exit_ns": end["mono_ns"], "free_ns": free["mono_ns"],
                           "initial_state_unknown": start["kind"] == "initial_enrollment"})
        masks = ordering_masks(sorted(rows, key=lambda row: row["slot"]))
        timelines[generation] = mask_intervals(state_intervals(rows, start["mono_ns"], end["mono_ns"]), masks)
    require(sum(row["initial_state_unknown"] for row in identities) == initial, "initial count mismatch")
    return identities, timelines, dict(groups)


def state_intervals(rows, start_ns, end_ns):
    intervals = []
    previous, status = start_ns, "unknown"
    grouped = defaultdict(list)
    for row in rows:
        if start_ns <= row["mono_ns"] <= end_ns:
            grouped[row["mono_ns"]].append(row)
    for stamp, events in sorted(grouped.items()):
        if previous < stamp:
            intervals.append({"begin_ns": previous, "end_ns": stamp, "state": status})
        status = "unknown"
        if len(events) == 1:
            event = events[0]
            kind, raw_state = event["kind"], event["raw_state"]
            if kind == "in":
                status = "running_observed"
            elif kind in {"wake_new", "wakeup"}:
                status = "runnable_observed"
            elif kind == "out":
                if raw_state & 0x80000000 or raw_state == 0:
                    status = "runnable_observed"
                elif raw_state in {1, 2}:
                    status = "off_cpu_sleep_state"
        previous = stamp
    return intervals


def mask_intervals(intervals, masks):
    result = []
    for row in intervals:
        cuts = {row["begin_ns"], row["end_ns"]}
        for mask in masks:
            for edge in (mask["begin_ns"], mask["end_ns"]):
                if row["begin_ns"] < edge < row["end_ns"]:
                    cuts.add(edge)
        edges = sorted(cuts)
        for begin, end in zip(edges, edges[1:]):
            unknown = any(begin < mask["end_ns"] and end > mask["begin_ns"] for mask in masks)
            result.append({"begin_ns": begin, "end_ns": end, "state": "unknown" if unknown else row["state"]})
    return result
