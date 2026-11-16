"""Compare linked GC episodes with caller, awaited-task and callback intervals."""
import argparse
from collections import Counter
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import json
from pathlib import Path

from analyze_roslyn_gc_episodes import CLR, PHASES, lines, matches, read, require
from scheduler_boundary_analysis import ROW
from scheduler_trace_model import decode_scheduler


@dataclass(frozen=True)
class Episode:
    inner: tuple
    outer: tuple
    phase_brackets: tuple
    generation: int


def interval(bounds):
    return tuple(map(Fraction, bounds))


def intersection(a, b):
    return max(a[0], b[0]), min(a[1], b[1])


def overlaps(a, b):
    lo, hi = intersection(a, b)
    return lo < hi


def strict_contains(window, bounds):
    return window[0] < bounds[0] <= bounds[1] < window[1]


def event_window(binding, capture_id):
    require(all(binding[side]["execution_id"] == capture_id and binding[side]["status"] == "active"
                and binding[side]["generation"] == binding["generation"] for side in ("begin", "end")),
            "Binding is outside the scoped lifetime")
    start, end = (interval(binding[side]["mapped_mono_ns"]) for side in ("begin", "end"))
    core = interval(binding["core_ns"])
    require(start[0] <= start[1] == core[0] < core[1] == end[0] <= end[1], "Clock core disagrees with event brackets")
    return core, (start[0], end[1])


def matching_episodes(window, episodes, use_inner):
    return [key for key, episode in episodes.items() if overlaps(window, episode.inner if use_inner else episode.outer)]


def receipt_scope(receipt, inner, outer):
    if strict_contains(inner, receipt):
        return "strictly_inside_gc_inner"
    if overlaps(inner, receipt):
        return "partly_overlaps_gc_inner"
    lo, hi = intersection(outer, receipt)
    return "possible_gc_outer" if lo <= hi else "outside_gc_outer"


def phase_position(phase, entry, ret):
    if phase[1] < entry[0]:
        return "before_entry"
    if strict_contains((entry[1], ret[0]), phase):
        return "between_receipts"
    if ret[1] < phase[0]:
        return "after_return"
    return "receipt_edge"


def linked_episodes(gc_path, phases_path, capture_id):
    phases = {row["raw_record_index"]: row for row in read(phases_path)}
    episodes = {}
    for row in read(gc_path):
        if row["class"] != "blocking_gc_linked":
            continue
        key = row["episode_id"]
        require(key not in episodes and row["reason"] == 1 and row["raw_indices"][0] == key,
                "Duplicate or invalid linked episode identity")
        receipts = [phases[i] for i in row["raw_indices"]]
        require(len(receipts) == 4 and all(x["event"]["provider"] == CLR and matches(x["event"], pattern)
                and x["identity"]["execution_id"] == capture_id and x["identity"]["status"] == "active"
                and x["identity"]["generation"] == row["generation"]
                for x, pattern in zip(receipts, PHASES, strict=True)), "Linked phase identity differs")
        brackets = tuple(interval(x["identity"]["mapped_mono_ns"]) for x in receipts)
        inner, outer = interval(row["inner_core_ns"]), interval(row["outer_possible_ns"])
        require(inner == (brackets[1][1], brackets[2][0]) and outer == (brackets[0][0], brackets[3][1])
                and inner[0] < inner[1] and strict_contains(outer, inner), "Invalid linked GC bracket")
        episodes[key] = Episode(inner, outer, brackets, row["generation"])
    return episodes


def pair_observations(ordinals, pairs, raw, task_generation, task_window, episodes):
    for ordinal in ordinals:
        pair = pairs[ordinal]
        require(pair["generation"] == task_generation and pair["correlation_exclusion"] is None,
                "Unusable pair in task core")
        entry, ret = (ROW.unpack_from(raw, (pair[key] - 1) * ROW.size) for key in ("entry_ordinal", "return_ordinal"))
        require(entry[:3] == (ordinal, task_generation, 1)
                and ret[:3] == (pair["return_ordinal"], task_generation, 2)
                and entry[7] == ret[7] and entry[6] == ret[6] == 0
                and entry[8] <= entry[9] < ret[8] <= ret[9]
                and pair["is_switch"] == bool(ret[3]), "Pair differs from raw boundary receipts")
        bounds = (entry[8], ret[9])
        require(bounds == (pair["entry_begin_ns"], pair["return_end_ns"]) and strict_contains(task_window, bounds),
                "Pair crosses task or wait core edge")
        for key in matching_episodes(bounds, episodes, False):
            episode = episodes[key]
            inner, outer = episode.inner, episode.outer
            yield {"entry_ordinal": ordinal, "return_ordinal": pair["return_ordinal"], "gc_episode": key,
                   "switch": pair["is_switch"], "pair_overlaps_gc_inner": overlaps(bounds, inner),
                   "gc_inner_between_receipts": strict_contains((entry[9], ret[8]), inner),
                   "gc_emitter_is_task": episode.generation == task_generation,
                   "phase_positions": [phase_position(phase, entry[8:10], ret[8:10])
                                       for phase in episode.phase_brackets],
                   "entry_receipt": receipt_scope(entry[8:10], inner, outer),
                   "return_receipt": receipt_scope(ret[8:10], inner, outer)}


def analyze(capture, output):
    capture_id = capture.name
    relatives = ("scheduler/scheduler.json", "scheduler/boundaries.bin", "scheduler-joins/wait-joins.jsonl",
                 "boundary-joins/pairs.jsonl", "boundary-joins/wait-boundary-joins.jsonl",
                 "gc-episodes/episodes.json", "gc-episodes/wait-gc-episodes.jsonl", "scheduler-joins/gc-boundaries.json",
                 "scheduler/scheduler-ledger.bin")
    scheduler_path, raw_path, waits_path, pairs_path, queries_path, gc_path, prior_path, phases_path, ledger_path = [
        capture / rel for rel in relatives]
    scheduler = read(scheduler_path)
    raw = raw_path.read_bytes()
    count, lost, faults, reserved = scheduler["boundary_counts"]
    require(scheduler["status"] == "completed" and not scheduler["cleanup_errors"] and len(raw) % ROW.size == 0
            and 0 < count <= len(raw) // ROW.size and lost == faults == reserved == 0
            and not any(raw[count * ROW.size:])
            and hashlib.sha256(raw).hexdigest() == scheduler["boundary_sha256"] == scheduler["boundary_second_sha256"],
            "Raw boundary completeness or detached read parity failed")
    pairs = {pair["entry_ordinal"]: pair for pair in lines(pairs_path)}
    require(all(0 < k < pair["return_ordinal"] <= count for k, pair in pairs.items()), "Invalid pair ordinal")
    episodes = linked_episodes(gc_path, phases_path, capture_id)
    output.mkdir()
    counts, pair_counts = Counter(), Counter()
    distinct_worker_pairs, distinct_pair_episodes = set(), set()
    with (output / "wait-intervals.jsonl").open("x", encoding="utf-8", newline="\n") as stream:
        previous = -1
        for wait, query in zip(lines(waits_path), lines(queries_path), strict=True):
            key, status = wait["wait_index"], wait["status"]
            require(previous < key == query["wait_index"] and status == query["status"], "Wait identity or order differs")
            previous = key
            counts["selected_waits"] += 1
            result = {"wait_index": key, "status": status}
            if status == "bound":
                counts["bound_waits"] += 1
                callbacks = query["worker_entry_ordinals"] or []
                distinct_worker_pairs.update(callbacks)
                analyze_wait(capture_id, wait, callbacks, result, episodes, pairs, raw, counts, pair_counts,
                             distinct_pair_episodes)
            else:
                counts["unbound_waits"] += 1
            stream.write(json.dumps(result, separators=(",", ":")) + "\n")
    prior = {row["wait_index"]: row for row in lines(prior_path)}
    checked = 0
    for row in lines(output / "wait-intervals.jsonl"):
        if row["status"] != "bound":
            continue
        earlier = prior[row["wait_index"]]
        require(row["caller_gc_inner"] == earlier["linked_gc_inner_episode_ids"]
                and row["caller_gc_outer"] == earlier["linked_gc_possible_outer_episode_ids"],
                "Caller GC results drifted from previous replay")
        checked += 1
    require(checked == len(prior), "Earlier bound waits do not reconcile")
    lifecycle = worker_lifecycle(ledger_path, scheduler, capture_id, raw, pairs, distinct_worker_pairs,
                                 distinct_pair_episodes, episodes, output / "worker-lifecycle.jsonl")
    result = {"capture_id": capture_id, "linked_gc_episodes": len(episodes), "wait_counts": dict(counts),
              "pair_episode_observations": dict(pair_counts),
              "distinct_worker_pairs": {"switch": sum(pairs[k]["is_switch"] for k in distinct_worker_pairs),
                                        "no_switch": sum(not pairs[k]["is_switch"] for k in distinct_worker_pairs)},
              "distinct_pair_episode_links": len(distinct_pair_episodes),
              "worker_lifecycle": lifecycle,
              "inputs_sha256": {rel: digest(capture / rel) for rel in relatives}}
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    return result


def worker_lifecycle(path, scheduler, capture_id, raw, pairs, ordinals, unique_links, episodes, destination):
    ledger = path.read_bytes()
    second = scheduler["second_read"]
    require(second["counts"] == scheduler["terminal_counts"]
            and hashlib.sha256(ledger).hexdigest() == scheduler["ledger_sha256"] == second["ledger_sha256"],
            "Lifecycle ledger hash or terminal counts differ")
    _, _, groups = decode_scheduler(ledger, scheduler, capture_id, slots=scheduler["lifecycle_slots"])
    pair_rows, state_counts, gc_counts = {}, Counter(), Counter()
    for ordinal in sorted(ordinals):
        pair = pairs[ordinal]
        entry, ret = (ROW.unpack_from(raw, (pair[key] - 1) * ROW.size) for key in ("entry_ordinal", "return_ordinal"))
        middle = [row for row in groups[pair["generation"]] if entry[9] < row["mono_ns"] < ret[8]]
        outs = [row for row in middle if row["kind"] == "out"]
        state = str(outs[0]["raw_state"]) if len(outs) == 1 else "no_unique_out"
        state_counts["switch/" + state if pair["is_switch"] else "no_switch/records_" + str(len(middle))] += 1
        pair_rows[ordinal] = (entry, ret, middle)
    for ordinal, key in sorted(unique_links):
        entry, ret, middle = pair_rows[ordinal]
        ep = episodes[key]
        if not overlaps((entry[8], ret[9]), ep.inner):
            continue
        gc_counts["inner_links"] += 1
        ordered = ([r["kind"] for r in middle] == ["out", "waking", "wakeup", "in"]
                   and all(a["slot"] < b["slot"] and a["mono_ns"] < b["mono_ns"]
                           for a, b in zip(middle, middle[1:])))
        gc_counts["ordered_out_waking_wakeup_in"] += ordered
        if ordered:
            gc_counts["ordered_switch_out_raw_" + str(middle[0]["raw_state"])] += 1
            gc_counts["ordered_waking_after_restart_begin"] += middle[1]["mono_ns"] > ep.phase_brackets[2][1]
        gc_counts["entry_between_suspend_receipts"] += (
            ep.phase_brackets[0][1] < entry[8] <= entry[9] < ep.phase_brackets[1][0])
        gc_counts["return_before_restart_stop"] += ret[9] < ep.phase_brackets[3][0]
        gc_counts["return_after_restart_stop"] += ep.phase_brackets[3][1] < ret[8]
    with destination.open("x", encoding="utf-8", newline="\n") as stream:
        for ordinal, (entry, ret, middle) in pair_rows.items():
            row = {"entry_ordinal": ordinal, "return_ordinal": ret[0], "generation": entry[1],
                   "switch": bool(ret[3]), "entry_bracket_ns": list(entry[8:10]),
                   "return_bracket_ns": list(ret[8:10]), "intervening_lifecycle_rows": middle}
            stream.write(json.dumps(row, separators=(",", ":")) + "\n")
    return {"distinct_pairs_by_raw_switch_out_or_record_count": dict(state_counts),
            "distinct_gc_inner_pair_episode_order": dict(gc_counts)}


def analyze_wait(capture_id, wait, ordinals, result, episodes, pairs, raw, counts, pair_counts, distinct_links):
    caller, caller_outer = event_window(wait, capture_id)
    caller_gc = matching_episodes(caller, episodes, True)
    caller_possible = matching_episodes(caller_outer, episodes, False)
    require(set(caller_gc) <= set(caller_possible), "Caller inner overlap lacks possible overlap")
    counts["caller_gc_inner"] += bool(caller_gc)
    counts["caller_gc_outer"] += bool(caller_possible)
    result.update(caller_gc_inner=caller_gc, caller_gc_outer=caller_possible)
    binding = wait.get("task_execution_binding", {})
    status = binding.get("status", "no_complete_task_execution")
    result["task_status"] = status
    counts["task/" + status] += 1
    if status != "bound":
        require(not ordinals, "Unbound task has callback pairs")
        return
    task, task_outer = event_window(binding, capture_id)
    shared = intersection(caller, task)
    outer = intersection(caller_outer, task_outer)
    counts["positive_shared_core"] += shared[0] < shared[1]
    counts["positive_shared_outer"] += outer[0] < outer[1]
    definite = matching_episodes(shared, episodes, True)
    possible = matching_episodes(outer, episodes, False)
    require(set(definite) <= set(possible) <= set(caller_possible), "Task overlap escapes enclosing intervals")
    observations = list(pair_observations(ordinals, pairs, raw, binding["generation"], shared, episodes))
    inner = [ob for ob in observations if ob["pair_overlaps_gc_inner"]]
    inner_receipts = {"strictly_inside_gc_inner", "partly_overlaps_gc_inner"}
    receipt = [ob for ob in observations if inner_receipts.intersection((ob["entry_receipt"], ob["return_receipt"]))]
    for label, present in (("shared_gc_inner", definite), ("shared_gc_outer", possible),
                           ("shared_gc_outer_only", possible and not definite),
                           ("task_pair", ordinals), ("task_pair_and_caller_gc_inner", ordinals and caller_gc),
                           ("task_pair_and_shared_gc_inner", ordinals and definite),
                           ("pair_envelope_gc_inner", inner), ("pair_envelope_gc_outer", observations),
                           ("receipt_inside_gc_inner", receipt)):
        counts[label] += bool(present)
    for ob in observations:
        kind = "switch" if ob["switch"] else "no_switch"
        distinct_links.add((ob["entry_ordinal"], ob["gc_episode"]))
        pair_counts[f"{kind}/gc_outer"] += 1
        pair_counts[f"{kind}/gc_inner"] += ob["pair_overlaps_gc_inner"]
        pair_counts[f"{kind}/gc_inner_between_receipts"] += ob["gc_inner_between_receipts"]
        pair_counts[f"{kind}/gc_emitter_is_task"] += ob["gc_emitter_is_task"]
        for side in ("entry_receipt", "return_receipt"):
            pair_counts[f"{kind}/{side}/{ob[side]}"] += 1
    result.update(shared_gc_inner=definite, shared_gc_outer=possible, worker_pair_count=len(ordinals),
                  pair_gc_observations=observations)


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.capture, args.output)))
