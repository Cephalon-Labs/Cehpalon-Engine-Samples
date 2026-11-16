"""Bind exact CoreCLR callsite receipts to same-execution Roslyn worker waits."""
import argparse
from collections import Counter, defaultdict
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import struct

from analyze_roslyn_gc_episodes import lines, read, require
from analyze_roslyn_gc_task_intervals import event_window, intersection, linked_episodes, overlaps, strict_contains


ROW = struct.Struct("<IIIIQQ")
CAPACITY = 16384


def pair_endpoints(records, identities):
    by_tid = defaultdict(list)
    for identity in identities:
        by_tid[identity["local_tid"]].append(identity)
    by_generation, exclusions = defaultdict(list), {}
    for ordinal, _, tid, site, stamp, _ in records:
        candidates = [life for life in by_tid[tid] if life["born_ns"] < stamp < life["exit_ns"]]
        if len(candidates) != 1:
            exclusions[ordinal] = "ambiguous_lifetime" if candidates else "outside_observed_lifetime"
        else:
            by_generation[candidates[0]["generation"]].append((ordinal, site, stamp))
    pairs = defaultdict(list)
    for generation, group in by_generation.items():
        if any(a[2] >= b[2] for a, b in zip(group, group[1:])):
            exclusions.update((row[0], "nonincreasing_generation_clock") for row in group)
            continue
        pending, depth = [], 0
        for row in group:
            if row[1] == 1:
                depth += 1
                pending.append(row)
            elif depth == 0:
                exclusions[row[0]] = "return_without_observed_call"
            else:
                depth -= 1
                pending.append(row)
                if depth == 0:
                    if len(pending) == 2:
                        call, ret = pending
                        pairs[generation].append({"call_ordinal": call[0], "return_ordinal": ret[0],
                                                  "call_ns": call[2], "return_ns": ret[2]})
                    else:
                        exclusions.update((x[0], "ambiguous_nested_endpoints") for x in pending)
                    pending = []
        exclusions.update((x[0], "open_call_tail") for x in pending)
    require(2 * sum(map(len, pairs.values())) + len(exclusions) == len(records), "Incomplete site accounting")
    return pairs, exclusions


def site_terminal(scheduler):
    used, lost, faults, reserved = scheduler["callsite_terminal"]
    require(scheduler["status"] == "completed" and not scheduler["cleanup_errors"]
            and scheduler["callsite_capacity"] == CAPACITY and 0 <= used <= CAPACITY
            and [used, lost, faults, reserved] == scheduler["callsite_before_detach"]
            and lost == faults == reserved == scheduler["callsite_recursion_misses"] == 0
            and scheduler["callsite_sha256"] == scheduler["callsite_second_sha256"],
            "Callsite capture or detached ledger invalid")
    return used


def load_object_rows(capture, scheduler):
    used = site_terminal(scheduler)
    raw = (capture / "scheduler/event-object.tokens.json").read_bytes()
    require(hashlib.sha256(raw).hexdigest() == scheduler["event_object_tokens_sha256"], "Token export hash differs")
    rows = json.loads(raw)
    names = {"call", "return", "wait", "set", "reset"}
    require(len(rows) == used and all(row["slot"] == index and row["site"] in names
            and type(row["tid"]) is int and row["tid"] > 0
            and type(row["ns"]) is int and row["ns"] > scheduler["arm_complete_ns"]
            and (row["object_token"] is None if row["site"] in ("call", "return")
                 else type(row["object_token"]) is int and row["object_token"] > 0)
            for index, row in enumerate(rows, 1)), "Invalid object-token receipt")
    return rows


def load_sites(capture, identities):
    scheduler = read(capture / "scheduler/scheduler.json")
    expected = scheduler["target_pid"]
    if "event_object_tokens_sha256" in scheduler:
        records = [(row["slot"], expected, row["tid"], 1 if row["site"] == "call" else 2, row["ns"], 0)
                   for row in load_object_rows(capture, scheduler) if row["site"] in ("call", "return")]
    else:
        used = site_terminal(scheduler)
        raw = (capture / "scheduler/callsite-ledger.bin").read_bytes()
        require(len(raw) == CAPACITY * ROW.size and not any(raw[used * ROW.size:])
                and hashlib.sha256(raw).hexdigest() == scheduler["callsite_sha256"], "Raw callsite ledger differs")
        records = list(ROW.iter_unpack(raw[:used * ROW.size]))
        require(all(row[0] == ordinal and row[1] == expected and row[2] > 0
                    and row[3] in (1, 2) and row[4] > scheduler["arm_complete_ns"] and row[5] == 0
                    for ordinal, row in enumerate(records, 1)), "Invalid raw callsite receipt")
    pairs, excluded = pair_endpoints(records, identities)
    return len(records), pairs, excluded


def worker_links(site, worker_sites, gc_observations, episodes, generation):
    window = site["call_ns"], site["return_ns"]
    nested, strong = [], []
    for receipt in worker_sites:
        require(receipt["generation"] == generation, "Scheduler receipt belongs to another worker")
        if not receipt["switch"]:
            continue
        entry, ret = receipt["entry_bracket_ns"], receipt["return_bracket_ns"]
        if not strict_contains(window, (entry[0], ret[1])):
            continue
        entry_id = receipt["entry_ordinal"]
        nested.append(entry_id)
        for obs in gc_observations.get(entry_id, []):
            if not obs["gc_inner_between_receipts"]:
                continue
            episode = episodes[obs["gc_episode"]]
            require(strict_contains((entry[1], ret[0]), episode.inner), "Inner GC order differs")
            events = receipt["intervening_lifecycle_rows"]
            ordered_wake = ([row["kind"] for row in events] == ["out", "waking", "wakeup", "in"]
                            and all(a["mono_ns"] < b["mono_ns"] and a["slot"] < b["slot"]
                                    for a, b in zip(events, events[1:]))
                            and events[1]["mono_ns"] > episode.phase_brackets[2][1])
            strong.append({"scheduler_entry": entry_id, "gc_episode": obs["gc_episode"],
                           "distinct_gc_emitter": episode.generation != generation,
                           "ordered_switch_wake_after_restart": ordered_wake})
    return nested, strong


def analyze(capture, intervals, output):
    identities = read(capture / "scheduler-joins/generations.json")
    require(all(row["execution_id"] == capture.name for row in identities), "Foreign scheduler identity")
    total, pairs, excluded = load_sites(capture, identities)
    episodes = linked_episodes(capture / "gc-episodes/episodes.json", capture / "scheduler-joins/gc-boundaries.json",
                              capture.name)
    lifecycle = {row["entry_ordinal"]: row for row in lines(intervals / "worker-lifecycle.jsonl")}
    wait_counts, observations = Counter(), []
    strong_episodes, strong_calls = set(), set()
    streams = (capture / "scheduler-joins/wait-joins.jsonl", capture / "boundary-joins/wait-boundary-joins.jsonl",
               intervals / "wait-intervals.jsonl")
    for wait, boundary, interval in zip(*(lines(path) for path in streams), strict=True):
        key = wait["wait_index"]
        require(key == boundary["wait_index"] == interval["wait_index"]
                and wait["status"] == boundary["status"] == interval["status"], "Wait receipts differ")
        wait_counts["selected"] += 1
        if wait["status"] != "bound":
            wait_counts["unbound_caller"] += 1
            continue
        task = wait.get("task_execution_binding", {})
        if task.get("status") != "bound":
            wait_counts["unbound_task"] += 1
            continue
        generation = task["generation"]
        shared = intersection(event_window(wait, capture.name)[0], event_window(task, capture.name)[0])
        if shared[0] >= shared[1]:
            wait_counts["no_positive_shared_core"] += 1
            continue
        wait_counts["positive_shared_core"] += 1
        worker_sites = [lifecycle[ord_] for ord_ in boundary["worker_entry_ordinals"]]
        gc_by_entry = defaultdict(list)
        for row in interval["pair_gc_observations"]:
            gc_by_entry[row["entry_ordinal"]].append(row)
        candidates = []
        for site in pairs[generation]:
            window = site["call_ns"], site["return_ns"]
            if not strict_contains(shared, window):
                continue
            gc_overlap = [ep for ep, episode in episodes.items() if overlaps(window, episode.inner)]
            nested, strong = worker_links(site, worker_sites, gc_by_entry, episodes, generation)
            candidates.append({**site, "linked_gc_inner_overlaps": gc_overlap, "nested_switch_entries": nested,
                               "strict_nested_gc_overlaps": strong})
            strong_episodes.update(row["gc_episode"] for row in strong)
            if strong:
                strong_calls.add(site["call_ordinal"])
        for label, present in (("worker_callsite", candidates),
                               ("worker_callsite_gc_inner", any(row["linked_gc_inner_overlaps"] for row in candidates)),
                               ("worker_callsite_nested_switch", any(row["nested_switch_entries"] for row in candidates)),
                               ("worker_callsite_strict_gc", any(row["strict_nested_gc_overlaps"] for row in candidates)),
                               ("worker_callsite_gc_and_ordered_wake", any(row["ordered_switch_wake_after_restart"]
                                  for pair in candidates for row in pair["strict_nested_gc_overlaps"]))):
            wait_counts[label] += bool(present)
        if candidates:
            observations.append({"wait_index": key, "task_id": wait["awaited_task_id"], "generation": generation,
                                 "shared_core_ns": list(map(str, shared)), "callsites": candidates})
    output.mkdir()
    result = {"capture_id": capture.name, "rows": total, "bound_pairs": sum(map(len, pairs.values())),
              "endpoint_exclusions": dict(Counter(excluded.values())), "wait_counts": dict(wait_counts),
              "distinct_strict_callsites": len(strong_calls), "distinct_strict_gc_episodes": len(strong_episodes)}
    for name, value in (("pairs.json", pairs), ("excluded.json", excluded),
                        ("observations.json", observations), ("summary.json", result)):
        (output / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("capture", "intervals", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(analyze(args.capture, args.intervals, args.output)))
