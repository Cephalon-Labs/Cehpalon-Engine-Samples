"""Separate diagnostic suspension from source-linked blocking GC observations."""

import argparse
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from fractions import Fraction
import json
from pathlib import Path


CLR = "Microsoft-Windows-DotNETRuntime"
SAMPLE = "Microsoft-DotNETCore-SampleProfiler"
PHASES = ((9, 10, 1, "GC/SuspendEEStart", "GCSuspendEETraceData"),
          (8, 137, 1, "GC/SuspendEEStop", "GCNoUserDataTraceData"),
          (7, 136, 1, "GC/RestartEEStart", "GCNoUserDataTraceData"),
          (3, 132, 1, "GC/RestartEEStop", "GCNoUserDataTraceData"))
START = (1, 1, 2, "GC/Start", "GCStartTraceData")
STOP = (2, 2, 1, "GC/Stop", "GCEndTraceData")
PREFIX = "Microsoft.Diagnostics.Tracing.Parsers.Clr."


def require(ok, message):
    if not ok:
        raise ValueError(message)


def matches(event, shape):
    return (event["eventId"], event["opcode"], event["version"], event["name"], event["templateType"]) == (
        *shape[:4], PREFIX + shape[4])


def time(event):
    return Fraction(str(event["timeMsec"]))


def lines(path):
    with path.open(encoding="utf-8") as f:
        for line in f:
            yield json.loads(line)


def read(path):
    return json.loads(path.read_bytes())


def validated_groups(boundaries, pid, execution):
    groups = defaultdict(list)
    for row in boundaries:
        e, ident = row["event"], row["identity"]
        require(e["provider"] == CLR and e["processId"] == pid and ident["execution_id"] == execution,
                "foreign boundary in scoped input")
        shape = next((shape for shape in PHASES if matches(e, shape)), None)
        require(shape is not None, "boundary metadata differs from the pinned EventPipe schema")
        keys = {"ClrInstanceID", "Reason", "Count"} if shape[0] == 9 else {"ClrInstanceID"}
        require(e["payload"].keys() == keys and all(type(v) is int for v in e["payload"].values()),
                "boundary payload fields differ")
        gen = ident["generation"] if ident["status"] == "active" else None
        groups[(e["payload"]["ClrInstanceID"], gen, e["threadId"])].append(row)
    return groups


def observed_blocks(group, generation):
    """Reject a whole unmatched emitter stream rather than recovering by phase shifts."""
    if generation is None or len(group) % 4:
        return None
    result = []
    previous = None
    for i in range(0, len(group), 4):
        b = group[i:i + 4]
        if not all(matches(r["event"], shape) for r, shape in zip(b, PHASES)):
            return None
        clocks = [time(r["event"]) for r in b]
        if (previous is not None and clocks[0] <= previous) or any(x >= y for x, y in zip(clocks, clocks[1:])):
            return None
        previous = clocks[-1]
        result.append(b)
    return result


def classify(block, collection_events, sample_count):
    e = block[0]["event"]
    reason, count, inst = (e["payload"][k] for k in ("Reason", "Count", "ClrInstanceID"))
    if reason == 0 and count == -1:
        return "other_with_samples" if sample_count else "other_without_samples"
    if reason == 2 and count == -1:
        return "appdomain_shutdown"
    if reason == 6 and count >= 0:
        return "gc_preparation_unresolved"
    if reason != 1 or count < 0:
        return "unknown_reason"
    if len(collection_events) != 2:
        return "gc_collection_link_unresolved"
    start, stop = (r[1] for r in collection_events)
    if (not matches(start, START) or not matches(stop, STOP) or start["payload"].get("Type") != 0
            or any(x["payload"].get("ClrInstanceID") != inst or x["threadId"] != e["threadId"]
                   or x["payload"].get("Count") != count + 1 for x in (start, stop))
            or start["payload"].get("Depth") != stop["payload"].get("Depth")
            or not time(block[1]["event"]) < time(start) < time(stop) < time(block[2]["event"])):
        return "gc_collection_link_unresolved"
    return "blocking_gc_linked"


def interval(block, inner):
    left, right = block[1:3] if inner else (block[0], block[3])
    low = left["identity"]["mapped_mono_ns"]
    high = right["identity"]["mapped_mono_ns"]
    return [str(Fraction(low[1])), str(Fraction(high[0]))]


def intersect(bounds, episodes):
    a, b = map(Fraction, bounds)
    return [row["episode_id"] for row, low, high in episodes if max(a, low) < min(b, high)]


def analyze(capture, output):
    metadata = read(capture / "scheduler-joins/summary.json")
    pid = metadata["target_pid"]
    boundaries = read(capture / "scheduler-joins/gc-boundaries.json")
    mapped = {r["raw_record_index"]: r["event"] for r in boundaries}
    require(len(mapped) == len(boundaries) == metadata["literal_gc_boundary_count"], "missing or duplicate raw index")
    samples, collections = [], []
    verified = set()
    for i, event in enumerate(lines(capture / "generator/analysis/events.jsonl")):
        if i in mapped:
            require(mapped[i] == event, f"boundary differs from raw event {i}")
            verified.add(i)
        if event["processId"] != pid:
            continue
        if event["provider"] == SAMPLE:
            samples.append(i)
        elif event["provider"] == CLR and event["eventId"] in (1, 2):
            require(matches(event, START) or matches(event, STOP), "collection metadata differs")
            collections.append((i, event))
    require(verified == mapped.keys(), "raw replay missed a phase receipt")
    indices = [i for i, _ in collections]
    groups = validated_groups(boundaries, pid, capture.name)
    episodes, unresolved = [], []
    for (_, gen, _), group in groups.items():
        blocks = observed_blocks(group, gen)
        if blocks is None:
            unresolved.append({"generation": gen, "raw_indices": [x["raw_record_index"] for x in group]})
            continue
        for block in blocks:
            raw = [x["raw_record_index"] for x in block]
            require(raw == sorted(set(raw)), "phase indices must strictly increase")
            start, end = raw[1:3]
            anchors = collections[bisect_right(indices, start):bisect_left(indices, end)]
            nsamples = bisect_left(samples, end) - bisect_right(samples, start)
            kind = classify(block, anchors, nsamples)
            row = {"episode_id": raw[0], "generation": gen, "raw_indices": raw, "class": kind,
                   "reason": block[0]["event"]["payload"]["Reason"], "sample_records_inside": nsamples,
                   "candidate_collection_indices": [i for i, _ in anchors]}
            if kind == "blocking_gc_linked":
                row["inner_core_ns"] = interval(block, True)
                row["outer_possible_ns"] = [block[0]["identity"]["mapped_mono_ns"][0],
                                             block[3]["identity"]["mapped_mono_ns"][1]]
            episodes.append(row)
    require(4 * len(episodes) + sum(len(r["raw_indices"]) for r in unresolved) == len(boundaries),
            "phase accounting did not reconcile")
    episodes.sort(key=lambda r: r["episode_id"])
    linked = [r for r in episodes if r["class"] == "blocking_gc_linked"]
    invocations = [(r, *map(Fraction, r["inner_core_ns"])) for r in linked]
    outer = [(r, *map(Fraction, r["outer_possible_ns"])) for r in linked]
    counts = Counter()
    output.mkdir(exist_ok=False)
    with (output / "wait-gc-episodes.jsonl").open("x", encoding="utf-8") as f:
        native = lines(capture / "boundary-joins/wait-boundary-joins.jsonl")
        waits = lines(capture / "scheduler-joins/wait-joins.jsonl")
        for wait, context in zip(waits, native, strict=True):
            require(wait["wait_index"] == context["wait_index"] and wait["status"] == context["status"],
                    "same-execution wait rows differ")
            counts["selected_waits"] += 1
            if wait["status"] != "bound":
                continue
            confident = intersect(wait["core_ns"], invocations)
            wait_envelope = (wait["begin"]["mapped_mono_ns"][0], wait["end"]["mapped_mono_ns"][1])
            possible = intersect(wait_envelope, outer)
            require(set(confident) <= set(possible), "inner overlap lacks outer containment")
            caller = bool(context["caller_entry_ordinals"])
            worker = bool(context["worker_entry_ordinals"])
            for key, hit in (("caller_pair", caller), ("task_pair", worker), ("literal_boundary", context["gc_record_indices"]),
                             ("linked_gc_inner_overlap", confident), ("linked_gc_outer_overlap", possible),
                             ("task_pair_with_linked_gc_inner_overlap", worker and confident),
                             ("caller_pair_with_linked_gc_inner_overlap", caller and confident)):
                counts[key] += bool(hit)
            f.write(json.dumps({"wait_index": wait["wait_index"], "linked_gc_inner_episode_ids": confident,
                                "linked_gc_possible_outer_episode_ids": possible,
                                "caller_pair": caller, "task_pair": worker}) + "\n")
    result = {"runtime_phase_rows": len(boundaries), "block_classes": dict(Counter(r["class"] for r in episodes)),
              "unresolved_phase_rows": sum(len(r["raw_indices"]) for r in unresolved),
              "collection_events": len(collections), "sample_records": len(samples),
              "waits": dict(counts), "physical_pause_total_ns": None, "exclusive_gc_scheduler_share": None}
    for name, value in (("summary.json", result), ("episodes.json", episodes), ("unresolved.json", unresolved)):
        (output / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.capture, args.output)))
