"""Replay reason-0 suspensions against precise-allocation probe windows."""
import argparse
from bisect import bisect_right
from collections import Counter
from fractions import Fraction
import json
from pathlib import Path

from analyze_roslyn_gc_episodes import CLR, PHASES, matches
from analyze_roslyn_task_lineage import clock_map, number, records, require, stage_window
from analyze_tooling_tasks import sha


def probe_windows(spans, pid, offset):
    windows = []
    counts = Counter()
    wall_starts = {span["startTicks"]: span for span in spans if span["stage"] == "compiler.wall"}
    require(len(wall_starts) == sum(span["stage"] == "compiler.wall" for span in spans), "Duplicate wall start")
    for setup in (span for span in spans if span["stage"] == "execute.setup"):
        wall = wall_starts.pop(setup["endTicks"])
        fields = ("phase", "caseIndex", "pairSequence", "state", "variant", "size", "frequency")
        require(all(setup[field] == wall[field] for field in fields)
                and setup["osThreadId"] == wall["osThreadId"] == pid, "Setup and wall identity differ")
        require(wall["sequence"] - setup["sequence"] == (3 if setup["variant"] == "generator" else 2),
                "Unexpected setup-to-wall marker ordering")
        counts[setup["phase"]] += 1
        pre = stage_window(setup, offset)
        post = stage_window({**wall, "startTicks": wall["endTicks"], "endTicks": setup["markerBeforeTicks"]}, offset)
        windows.extend(((pre[1], pre[2], pre[1], setup["sequence"], setup["phase"], "before"),
                        (post[0], post[2], post[1], setup["sequence"], setup["phase"], "after")))
    require(not wall_starts and counts == {"preflight": 12, "seed": 12, "primer": 36, "measurement": 270},
            "Complete Execute invocation census differs")
    require(all(lo < hi and (i == 0 or windows[i-1][1] < lo)
                for i, (lo, hi, *_) in enumerate(windows)), "Probe windows must be positive, ordered and disjoint")
    return windows, dict(counts)


def replay(capture, lineage_dir, gc_episodes):
    generator = capture / "generator"
    lineage_path = lineage_dir / "summary.json"
    lineage = json.loads(lineage_path.read_bytes())
    pid = lineage["pid"]
    spans_path = generator / "generator.json.spans.jsonl"
    raw_path = generator / "analysis/events.jsonl"
    episode_path = gc_episodes / "episodes.json"
    spans = list(records(spans_path))
    episodes = [item for item in json.loads(episode_path.read_bytes()) if item["reason"] == 0]
    sought = {i for episode in episodes for i in episode["raw_indices"]}
    raw, markers, reason_starts = {}, {}, set()
    event_count = 0
    for i, event in enumerate(records(raw_path)):
        event_count += 1
        if i in sought:
            raw[i] = event
        if event["provider"] == CLR and event["eventId"] == 9 and event["payload"]["Reason"] == 0:
            reason_starts.add(i)
        if event["provider"] == "Cehpalon-Tooling-Diagnostic":
            key = event["payload"]["sequence"]
            require(key not in markers, "Duplicate stage marker")
            markers[key] = event
    require(event_count == lineage["raw_events"], "Incomplete raw event stream")
    require(reason_starts == {episode["raw_indices"][0] for episode in episodes}, "Reason-0 starts do not reconcile")
    offset = clock_map(spans, markers, pid)
    require(list(map(str, offset)) == lineage["clock_offset_ms_exact_fraction"], "Prior clock bounds differ")
    windows, counts = probe_windows(spans, pid, offset)
    starts = [window[0] for window in windows]
    assigned, outside, other_tids = {}, Counter(), Counter()
    rows = []
    generations = json.loads((capture / "scheduler-joins/generations.json").read_bytes())
    main = [row["generation"] for row in generations if row["local_tid"] == pid]
    require(len(main) == 1, "Exactly one admitted main lifetime required")
    by_sequence = {span["sequence"]: span for span in spans}
    for episode in episodes:
        events = [raw[i] for i in episode["raw_indices"]]
        require(len(events) == 4 and all(evt["provider"] == CLR and matches(evt, pattern)
                                        for evt, pattern in zip(events, PHASES, strict=True)),
                "Invalid quartet")
        require(events[0]["payload"]["Reason"] == 0 and events[0]["payload"]["Count"] in (-1, 4294967295)
                and {evt["processId"] for evt in events} == {pid}, "Invalid reason-0 record")
        times = [number(evt["timeMsec"]) for evt in events]
        require(times == sorted(set(times)), "Non-increasing quartet")
        tids = {evt["threadId"] for evt in events}
        require(len(tids) == 1, "Mixed emitter quartet")
        tid = next(iter(tids))
        if tid != pid:
            require(episode["generation"] != main[0], "Foreign TID uses main generation")
            outside["other_thread_with_samples" if episode["sample_records_inside"] else "other_thread_without_samples"] += 1
            other_tids[tid] += 1
            continue
        require(episode["generation"] == main[0] and episode["sample_records_inside"] == 0, "Main emitter proof differs")
        index = bisect_right(starts, times[0]) - 1
        if index < 0 or not starts[index] < times[0] < times[-1] < windows[index][1]:
            outside["main_outside_probe_window"] += 1
            continue
        require(index not in assigned, "Multiple main-thread quartets in the same probe window")
        assigned[index] = episode["episode_id"]
        lo, hi, strict_lower, sequence, phase, position = windows[index]
        emit = by_sequence[sequence + (2 if by_sequence[sequence]["variant"] == "generator" else 1)]
        require(emit["stage"] == "pe.emit", "Expected Emit marker")
        _, _, earliest_emit_end, latest_emit_end = stage_window(emit, offset)
        if position == "after":
            require(earliest_emit_end < times[0], "Post probe precedes possible Emit return")
        rows.append({"raw_indices": episode["raw_indices"], "generation": main[0], "setup_sequence": sequence,
                     "phase": phase, "probe_position": position, "window_ms": [str(lo), str(hi)],
                     "strict_window": strict_lower < times[0],
                     "strictly_after_emit": position == "after" and latest_emit_end < times[0]})
    require(len(assigned) == len(windows), "Incomplete one-to-one probe mapping")
    require(len(assigned) + sum(outside.values()) == len(episodes) and len(raw) == 4 * len(episodes),
            "Reason-0 receipt accounting differs")
    matches_by_scope = Counter(row["probe_position"] + ("/strict" if row["strict_window"] else "/start_edge")
                               for row in rows)
    wait_path = capture / "boundary-joins/wait-boundary-joins.jsonl"
    probe_indices = {i for row in rows for i in row["raw_indices"]}
    candidate_waits = sum(bool(probe_indices.intersection(wait["gc_record_indices"]))
                          for wait in records(wait_path) if wait["status"] == "bound")
    return rows, {"pid": pid, "main_generation": main[0], "execution_counts": counts, "probe_windows": len(windows),
                  "matched_main_quartets": len(assigned), "other_quartets": dict(outside), "reason0_quartets": len(episodes),
                  "other_emitter_counts": dict(other_tids), "waits_with_contained_probe_boundary": candidate_waits,
                  "matches_by_scope": dict(matches_by_scope),
                  "post_quartets_strictly_after_emit": sum(row["strictly_after_emit"] for row in rows),
                  "inputs_sha256": {str(path.name): sha(path) for path in (spans_path, raw_path, episode_path,
                                      lineage_path, capture / "scheduler-joins/generations.json", wait_path)}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("capture", "lineage", "gc-episodes", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    rows, summary = replay(args.capture, args.lineage, args.gc_episodes)
    args.output.mkdir()
    with (args.output / "matches.jsonl").open("x", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(summary))
