"""Bounded same-execution TPL, scheduler and literal GC-boundary observations."""

import argparse
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from fractions import Fraction
import hashlib
import json
from pathlib import Path

from scheduler_eventpipe_join import join_eventpipe_point
from scheduler_recorded_order import ordering_masks
from scheduler_trace_model import decode_scheduler


def read(path):
    return json.loads(path.read_bytes())


def records(path):
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            yield json.loads(line)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def union(windows):
    result = []
    for begin, end in sorted(windows):
        if not result or begin > result[-1][1]:
            result.append([begin, end])
        else:
            result[-1][1] = max(result[-1][1], end)
    return result


def partition(windows, intervals, interval_ends=None):
    totals = defaultdict(Fraction)
    ends = interval_ends if interval_ends is not None else [row["end_ns"] for row in intervals]
    for begin, end in union(windows):
        require(begin < end, "nonpositive query window")
        covered = Fraction(0)
        index = bisect_right(ends, begin)
        for position in range(index, len(intervals)):
            row = intervals[position]
            if row["begin_ns"] >= end:
                break
            overlap = min(end, row["end_ns"]) - max(begin, row["begin_ns"])
            if overlap > 0:
                totals[row["state"]] += overlap
                covered += overlap
        require(covered <= end - begin, "scheduler intervals overlap")
        totals["unknown"] += end - begin - covered
    return {key: str(value) for key, value in sorted(totals.items())}


def join_point(event, identities, execution, pid, offset):
    return join_eventpipe_point(event, identities, execution_id=execution, target_pid=pid, offset_ms=offset)


def target_gc_boundary(event, pid):
    return (event.get("provider") == "Microsoft-Windows-DotNETRuntime"
            and event.get("processId") == pid and event.get("name", "").replace("/", "").startswith(
                ("GCSuspendEEStart", "GCSuspendEEStop", "GCRestartEEStart", "GCRestartEEStop")))


def wait_core(wait, identities, execution, pid, offset):
    start = join_point(wait["begin"]["event"], identities, execution, pid, offset)
    end = join_point(wait["end"]["event"], identities, execution, pid, offset)
    if start["status"] != "active" or end["status"] != "active" or start["generation"] != end["generation"]:
        return {"status": "unknown_lifecycle_or_clock", "begin": start, "end": end}
    lo, hi = Fraction(start["mapped_mono_ns"][1]), Fraction(end["mapped_mono_ns"][0])
    if lo >= hi:
        return {"status": "unknown_nonpositive_guaranteed_core", "begin": start, "end": end}
    return {"status": "bound", "generation": start["generation"], "core_ns": [str(lo), str(hi)],
            "begin": start, "end": end}


def analyze(base, lineage, out):
    capture = read(base / "generator/capture.json")
    scheduler = read(base / "scheduler/scheduler.json")
    require(capture["status"] == scheduler["status"] == "completed", "complete input channels required")
    raw = (base / "scheduler/scheduler-ledger.bin").read_bytes()
    require(hashlib.sha256(raw).hexdigest() == scheduler["ledger_sha256"], "raw scheduler hash differs")
    execution = base.name
    identities, timelines, groups = decode_scheduler(raw, scheduler, execution)
    interval_ends = {key: [row["end_ns"] for row in value] for key, value in timelines.items()}
    point_times = {}
    for generation, rows in groups.items():
        by_kind = defaultdict(list)
        for row in rows:
            by_kind[row["kind"]].append(row["mono_ns"])
        point_times[generation] = {kind: sorted(times) for kind, times in by_kind.items()}
    ordering = {}
    for generation, rows in groups.items():
        physical = sorted(rows, key=lambda row: row["slot"])
        reversal_count = sum(right["mono_ns"] < left["mono_ns"] for left, right in zip(physical, physical[1:]))
        tie_count = sum(right["mono_ns"] == left["mono_ns"] for left, right in zip(physical, physical[1:]))
        ordering[str(generation)] = {"physical_timestamp_reversals": reversal_count, "physical_ties": tie_count,
                                    "unknown_masks": ordering_masks(physical)}
    save(out / "recorded-order.json", ordering)
    summary = read(lineage / "summary.json")
    offset = summary["clock_offset_ms_exact_fraction"]
    pid = capture["target_pid"]
    tasks = read(lineage / "task-observations.json")
    require(summary["pid"] == tasks["process_id"] == pid, "target PID differs")
    require(tasks["errors"] == [] and tasks["unfinished_waits"] == [], "TPL histories incomplete")
    selected = {}
    row_count = 0
    for row in records(lineage / "rows.jsonl"):
        if row["row_identity"]["phase"] != "measurement":
            continue
        row_count += 1
        for wait in row["observed_caller_waits"]:
            if wait["row_scope"] == "entire_wait_inside_guaranteed_emit_core":
                selected.setdefault(wait["wait_index"], []).append({"emit_sequence": row["emit_sequence"], **wait})
    require(row_count == 270, "original measured Emit corpus differs")
    executions = {row["task_id"]: row for row in tasks["tasks"]
                  if row["status"] == "complete_observed_lifetime"}
    queries = []
    union_by_generation = defaultdict(list)
    for index, associations in sorted(selected.items()):
        wait = tasks["waits"][index]
        require(wait["caller_native_tid"] == pid and wait["behavior"] == 1, "selected caller wait differs")
        core = wait_core(wait, identities, execution, pid, offset)
        query = {"wait_index": index, "awaited_task_id": wait["task_id"], "associations": associations, **core}
        if core["status"] == "bound":
            begin, end = map(Fraction, core["core_ns"])
            generation = core["generation"]
            query["caller_conditional_recorded_state_ns"] = partition(
                [(begin, end)], timelines[generation], interval_ends[generation])
            query["caller_recorded_points"] = {
                kind: bisect_left(times, end) - bisect_right(times, begin)
                for kind, times in point_times[generation].items()
            }
            union_by_generation[generation].append((begin, end))
            task = executions.get(wait["task_id"])
            if task:
                worker = wait_core({"begin": task["start"], "end": task["complete"]},
                                   identities, execution, pid, offset)
                query["task_execution_binding"] = worker
                if worker["status"] == "bound":
                    a, b = map(Fraction, worker["core_ns"])
                    a, b = max(a, begin), min(b, end)
                    if a < b:
                        query["task_execution_conditional_recorded_state_ns"] = partition(
                            [(a, b)], timelines[worker["generation"]], interval_ends[worker["generation"]])
        queries.append(query)
    gc_events = []
    for index, event in enumerate(records(base / "generator/analysis/events.jsonl")):
        if target_gc_boundary(event, pid):
            gc_events.append({"raw_record_index": index, "event": event,
                              "identity": join_point(event, identities, execution, pid, offset)})
    gc_clock = sorted((Fraction(item["identity"]["mapped_mono_ns"][0]),
                       Fraction(item["identity"]["mapped_mono_ns"][1]),
                       item["raw_record_index"]) for item in gc_events)
    gc_lows = [item[0] for item in gc_clock]
    gc_highs = [item[1] for item in gc_clock]
    require(gc_highs == sorted(gc_highs), "GC mapped clock widths differ")
    for query in queries:
        if query["status"] != "bound":
            continue
        begin, end = map(Fraction, query["core_ns"])
        contained, uncertain = [], []
        first = bisect_left(gc_highs, begin)
        last = bisect_right(gc_lows, end)
        for low, high, raw_index in gc_clock[first:last]:
            if low > begin and high < end:
                contained.append(raw_index)
            elif high >= begin and low <= end:
                uncertain.append(raw_index)
        query["literal_gc_boundaries_contained"] = contained
        query["literal_gc_boundaries_clock_edge"] = uncertain
    point_status = Counter()
    point_path = out / "point-identity-joins.jsonl"
    with point_path.open("x", encoding="utf-8", newline="\n") as stream:
        for point in records(lineage / "points.jsonl"):
            event = {"processId": point["process_id"], "threadId": point["native_tid"],
                     "timeMsec": point["time_msec"]}
            binding = join_point(event, identities, execution, pid, offset)
            point_status[(point["kind"], binding["status"])] += 1
            stream.write(json.dumps({"sample_record_index": point["sample_record_index"],
                                     "kind": point["kind"], **binding}) + "\n")
    save(out / "generations.json", identities)
    save(out / "gc-boundaries.json", gc_events)
    with (out / "wait-joins.jsonl").open("x", encoding="utf-8", newline="\n") as stream:
        for query in queries:
            stream.write(json.dumps(query) + "\n")
    totals = {str(generation): partition(windows, timelines[generation])
              for generation, windows in union_by_generation.items()}
    result = {
        "status": "completed_bounded_same_execution_observations",
        "target_pid": pid, "clock_offset_ms": offset, "kernel_records": scheduler["terminal_counts"][0],
        "generations": len(identities), "initial_enrollments": sum(row["initial_state_unknown"] for row in identities),
        "measured_emit_rows": row_count, "distinct_selected_waits": len(queries),
        "wait_identity_statuses": dict(Counter(query["status"] for query in queries)),
        "whole_point_corpus_identity_statuses": {kind + "/" + status: count for (kind, status), count in point_status.items()},
        "literal_gc_boundary_count": len(gc_events),
        "waits_with_contained_gc_boundary": sum(bool(q.get("literal_gc_boundaries_contained")) for q in queries),
        "within_generation_timestamp_reversals": sum(row["physical_timestamp_reversals"] for row in ordering.values()),
        "within_generation_timestamp_ties": sum(row["physical_ties"] for row in ordering.values()),
        "caller_wait_core_union_conditional_recorded_state_ns": totals,
        "gc_pause_total_ns": None, "exclusive_gc_scheduler_share": None,
        "limits": [
            "Identity links require the same execution and strict lifecycle containment.",
            "Initial records begin at enrollment and leave earlier lifetime unknown.",
            "Conditional state intervals use recorded BPF callback points, not exact scheduler transition time.",
            "Publication and timestamp ordering ambiguity remains explicit and masked as unknown.",
            "TPL waits and compiler frames do not establish a direct compiler callsite or useful work.",
            "GC boundaries remain unpaired literal events, with no certified pause total or exclusive cause.",
        ],
    }
    save(out / "summary.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--lineage", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    print(json.dumps(analyze(args.capture.resolve(), args.lineage.resolve(), args.output.resolve())))
