"""Join execution-local GCEvent tokens, exact callsites and Roslyn scheduler observations."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

from analyze_roslyn_gc_callsites import load_object_rows
from analyze_roslyn_gc_episodes import lines, read, require
from analyze_roslyn_gc_task_intervals import digest, linked_episodes, strict_contains


def transitions(rows):
    result = defaultdict(list)
    for row in rows:
        if row["site"] in ("reset", "set"):
            result[row["object_token"]].append(row)
    for group in result.values():
        group.sort(key=lambda row: row["ns"])
    return result


def object_context(call, ret, branch_rows, changes):
    branch = [row for row in branch_rows if call["ns"] < row["ns"] < ret["ns"]]
    if len(branch) != 1:
        return None, "missing_or_multiple_wait_branches"
    wait = branch[0]
    group = changes[wait["object_token"]]
    before = [r for r in group if r["ns"] < wait["ns"]]
    after = [r for r in group if wait["ns"] < r["ns"] < ret["ns"]]
    if not before or before[-1]["site"] != "reset" or len(after) != 1 or after[0]["site"] != "set":
        return None, "missing_or_ambiguous_reset_set"
    reset, setter = before[-1], after[0]
    if not (reset["slot"] < wait["slot"] < setter["slot"] < ret["slot"]) or any(
            r["ns"] in (wait["ns"], ret["ns"]) for r in group) or (
            len(before) > 1 and before[-2]["ns"] == reset["ns"]):
        return None, "object_order_edge"
    if reset["tid"] != setter["tid"] or wait["tid"] == setter["tid"]:
        return None, "different_reset_set_threads_or_self_set"
    return (reset, wait, setter), None


def ordered_switch(context, receipt, masks):
    _, wait, setter = context
    rows = receipt["intervening_lifecycle_rows"]
    if [r["kind"] for r in rows] != ["out", "waking", "wakeup", "in"]:
        return False
    require(all(r["local_tid"] == wait["tid"] and r["generation"] == receipt["generation"] for r in rows),
            "Switch lifecycle is from a different worker")
    entry, ret = receipt["entry_bracket_ns"], receipt["return_bracket_ns"]
    if any(max(entry[0], mask["begin_ns"]) <= min(ret[1], mask["end_ns"]) for mask in masks):
        return False
    a, b, c, d = (r["mono_ns"] for r in rows)
    return (wait["ns"] < a < setter["ns"] < b < c < d
            and all(x["slot"] < y["slot"] for x, y in zip(rows, rows[1:]))
            and strict_contains((entry[1], ret[0]), (a, d)))


def emitter_proof(context, episode, lives):
    reset, _, setter = context
    emitter = lives[episode.generation]
    phases = episode.phase_brackets
    same_emitter = all(emitter["local_tid"] == row["tid"] and emitter["born_ns"] < row["ns"] < emitter["exit_ns"]
                       for row in (reset, setter))
    reset_in_suspend = phases[0][1] < reset["ns"] < phases[1][0]
    set_in_restart = phases[2][1] < setter["ns"] < phases[3][0]
    return {"same_gc_emitter": same_emitter, "reset_in_suspend": reset_in_suspend, "set_in_restart": set_in_restart}


def analyze(capture, output):
    relative = ("scheduler/scheduler.json", "scheduler/event-object.tokens.json", "callsite-joins/observations.json",
                "gc-task-intervals/worker-lifecycle.jsonl", "scheduler-joins/recorded-order.json",
                "scheduler-joins/generations.json", "gc-episodes/episodes.json", "scheduler-joins/gc-boundaries.json")
    scheduler = read(capture / relative[0])
    rows = load_object_rows(capture, scheduler)
    by_slot = {row["slot"]: row for row in rows}
    by_tid = defaultdict(list)
    for row in rows:
        if row["site"] == "wait":
            by_tid[row["tid"]].append(row)
    mutations = transitions(rows)
    lives = {r["generation"]: r for r in read(capture / relative[5])}
    require(all(row["execution_id"] == capture.name for row in lives.values()), "Foreign generation")
    episodes = linked_episodes(capture / relative[6], capture / relative[7], capture.name)
    lifecycles = {r["entry_ordinal"]: r for r in lines(capture / relative[3])}
    ordering = read(capture / relative[4])
    results = []
    counts = Counter()
    strict_calls, strict_gc = set(), set()
    for entry in read(capture / relative[2]):
        generation = entry["generation"]
        tid = lives[generation]["local_tid"]
        counts["waits_with_bound_worker_callsites"] += 1
        marks = set()
        for site in entry["callsites"]:
            call, ret = (by_slot[site[key]] for key in ("call_ordinal", "return_ordinal"))
            require(call["site"] == "call" and ret["site"] == "return" and call["tid"] == ret["tid"] == tid
                    and call["ns"] == site["call_ns"] and ret["ns"] == site["return_ns"], "Pair provenance differs")
            context, rejected = object_context(call, ret, by_tid[tid], mutations)
            record = {"wait_index": entry["wait_index"], "call": call["slot"], "return": ret["slot"],
                      "worker_generation": generation, "rejected": rejected, "same_object_switches": [],
                      "episode_checks": []}
            if context:
                marks.add("same_object_reset_wait_set")
                reset, wait, setter = context
                record.update(reset=reset["slot"], event_wait=wait["slot"], setter=setter["slot"],
                              object_token=wait["object_token"])
                switches = [key for key in site["nested_switch_entries"]
                            if ordered_switch(context, lifecycles[key], ordering[str(generation)]["unknown_masks"])]
                record["same_object_switches"] = switches
                if switches:
                    marks.add("same_object_ordered_switch")
                for link in site["strict_nested_gc_overlaps"]:
                    key = link["scheduler_entry"]
                    episode_id = link["gc_episode"]
                    if key not in switches:
                        continue
                    proof = emitter_proof(context, episodes[episode_id], lives)
                    record["episode_checks"].append({"episode": episode_id, "entry": key, **proof})
                    marks.add("same_object_switch_linked_gc")
                    if all(proof.values()):
                        marks.add("same_object_gc_emitter_inside_phases")
                        strict_calls.add(call["slot"])
                        strict_gc.add(episode_id)
            results.append(record)
        counts.update(sorted(marks))
    result = {"capture_id": capture.name, "receipts": len(rows), "site_roles": dict(Counter(r["site"] for r in rows)),
              "object_tokens": sorted({r["object_token"] for r in rows if r["object_token"] is not None}),
              "wait_counts": dict(counts), "distinct_strict_callsites": len(strict_calls),
              "distinct_strict_gc_episodes": len(strict_gc),
              "candidate_call_exclusions": dict(Counter(r["rejected"] for r in results if r["rejected"])),
              "inputs_sha256": {name: digest(capture / name) for name in relative}}
    output.mkdir()
    for name, value in (("summary.json", result), ("observations.json", results)):
        (output / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("capture", "output"):
        parser.add_argument("--" + field, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(analyze(args.capture, args.output)))
