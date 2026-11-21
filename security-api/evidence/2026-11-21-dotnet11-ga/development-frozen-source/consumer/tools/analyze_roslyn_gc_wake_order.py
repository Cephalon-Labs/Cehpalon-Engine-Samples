"""Replay recorded wake intervals for exact GC wait callsites in one Roslyn execution."""
import argparse
from collections import Counter
from fractions import Fraction
import json
from pathlib import Path
from statistics import median

from analyze_roslyn_gc_episodes import lines, read, require
from analyze_roslyn_gc_task_intervals import digest, linked_episodes, strict_contains


PHASES = ("out", "waking", "wakeup", "in")
GAPS = ("out_to_waking", "waking_to_wakeup", "wakeup_to_in")


def touches(left, right):
    return max(left[0], right[0]) <= min(left[1], right[1])


def recorded_gaps(receipt, masks):
    rows = receipt["intervening_lifecycle_rows"]
    if tuple(row["kind"] for row in rows) != PHASES:
        return None, "other_lifecycle_shape"
    if rows[0]["raw_state"] != 8193:
        return None, "other_switch_out_state"
    stamps = [row["mono_ns"] for row in rows]
    require(all(row["generation"] == receipt["generation"] for row in rows), "Foreign worker lifecycle")
    if any(a["slot"] >= b["slot"] or a["mono_ns"] >= b["mono_ns"] for a, b in zip(rows, rows[1:])):
        return None, "nonincreasing_lifecycle_order"
    bounds = receipt["entry_bracket_ns"][1], receipt["return_bracket_ns"][0]
    require(strict_contains(bounds, (stamps[0], stamps[-1])), "Lifecycle points cross the scheduler receipt edge")
    envelope = receipt["entry_bracket_ns"][0], receipt["return_bracket_ns"][1]
    if any(touches(envelope, (row["begin_ns"], row["end_ns"])) for row in masks):
        return None, "visible_order_mask"
    return dict(zip(GAPS, (b - a for a, b in zip(stamps, stamps[1:])))), None


def event_to_point(bounds, point):
    require(bounds[0] <= bounds[1], "Inverted event clock bracket")
    return tuple(str(Fraction(point - bound)) for bound in reversed(bounds))


def summarize(rows):
    return {name: [str(min(values)), str(median(map(Fraction, values))), str(max(values))]
            for name in GAPS if (values := [row["recorded_gaps_ns"][name] for row in rows])}


def other_envelopes(episode_rows, phase_rows):
    phases = {row["raw_record_index"]: row["identity"] for row in phase_rows}
    for row in episode_rows:
        if row["class"] != "blocking_gc_linked":
            first, *_, last = (phases[index] for index in row["raw_indices"])
            bounds = Fraction(first["mapped_mono_ns"][0]), Fraction(last["mapped_mono_ns"][1])
            require(bounds[0] < bounds[1], "Invalid other episode outer bracket")
            yield row["class"], bounds


def analyze(capture, output):
    relative = ("callsite-joins/observations.json", "callsite-joins/summary.json",
                "gc-task-intervals/worker-lifecycle.jsonl", "scheduler-joins/recorded-order.json",
                "gc-episodes/episodes.json", "scheduler-joins/gc-boundaries.json")
    paths = [capture / path for path in relative]
    observations, prior = map(read, paths[:2])
    require(prior["capture_id"] == capture.name, "Callsite execution differs")
    lifetime, order = {r["entry_ordinal"]: r for r in lines(paths[2])}, read(paths[3])
    episodes = linked_episodes(paths[4], paths[5], capture.name)
    other = list(other_envelopes(read(paths[4]), read(paths[5])))
    findings = {}
    callsite_classes = {}
    for wait in observations:
        for call in wait["callsites"]:
            bounds = call["call_ns"], call["return_ns"]
            possible = [key for key, episode in episodes.items() if touches(bounds, episode.outer)]
            classes = sorted({kind for kind, hull in other if touches(bounds, hull)}
                             | ({"blocking_gc_linked"} if possible else set()))
            require(callsite_classes.setdefault(call["call_ordinal"], classes) == classes,
                    "Duplicate callsite carries conflicting episode classes")
            strong = {row["scheduler_entry"]: row["gc_episode"] for row in call["strict_nested_gc_overlaps"]}
            require(set(strong) <= set(call["nested_switch_entries"]), "Strict link missing nested switch")
            for entry in call["nested_switch_entries"]:
                key = call["call_ordinal"], entry
                receipt = lifetime[entry]
                require(receipt["switch"] and receipt["generation"] == wait["generation"]
                        and strict_contains(bounds, (receipt["entry_bracket_ns"][0], receipt["return_bracket_ns"][1])),
                        "Nested switch proof differs")
                events = receipt["intervening_lifecycle_rows"]
                gaps, excluded = recorded_gaps(receipt, order[str(wait["generation"])]["unknown_masks"])
                strict = strong.get(entry)
                row = {"call_ordinal": key[0], "scheduler_entry_ordinal": entry, "generation": wait["generation"],
                       "lifecycle_slots": [r["slot"] for r in events], "kinds": [r["kind"] for r in events],
                       "linked_outer_touch_or_overlap": possible, "strict_gc_episode": strict,
                       "recorded_gaps_ns": gaps, "excluded_reason": excluded}
                if gaps is None:
                    row["group"] = "other"
                else:
                    _, waking, wakeup, dispatch = events
                    row.update(group=("strict_linked_gc" if strict is not None else
                                      "comparison" if not possible else "other_linked_gc_overlap"),
                               waking_on_different_cpu=waking["cpu"] != wakeup["cpu"],
                               wakeup_cpu_matches_in_cpu=wakeup["cpu"] == dispatch["cpu"],
                               other_episode_outer_classes=[kind for kind in classes if kind != "blocking_gc_linked"])
                    if strict is not None:
                        gc = episodes[strict]
                        require(strict in possible
                                and strict_contains((receipt["entry_bracket_ns"][1], receipt["return_bracket_ns"][0]),
                                                    gc.inner), "GC inner bound crosses scheduler receipts")
                        row.update(restart_begin_to_waking_ns=event_to_point(gc.phase_brackets[2], waking["mono_ns"]),
                                   restart_end_to_waking_ns=event_to_point(gc.phase_brackets[3], waking["mono_ns"]),
                                   restart_end_to_switch_in_ns=event_to_point(gc.phase_brackets[3], dispatch["mono_ns"]),
                                   restart_end_to_call_return_ns=event_to_point(gc.phase_brackets[3], call["return_ns"]),
                                   largest_gap=max(gaps, key=gaps.get))
                if key not in findings:
                    findings[key] = {**row, "waits": []}
                require({k: v for k, v in findings[key].items() if k != "waits"} == row,
                        "Duplicate link carries conflicting evidence")
                findings[key]["waits"].append(wait["wait_index"])
    values = list(findings.values())
    strict = [row for row in values if row["group"] == "strict_linked_gc"]
    comparison = [row for row in values if row["group"] == "comparison"]
    require(len({w for row in values if row["strict_gc_episode"] is not None for w in row["waits"]})
            == prior["wait_counts"]["worker_callsite_strict_gc"], "Strict input wait count differs")
    result = {"capture_id": capture.name, "distinct_callsite_switch_links": len(values),
              "distinct_callsites": len(callsite_classes),
              "callsites_by_outer_episode_class": dict(Counter(
                  kind for classes in callsite_classes.values() for kind in classes)),
              "callsites_without_any_episode_outer_overlap": sum(not classes for classes in callsite_classes.values()),
              "groups": dict(Counter(row["group"] for row in values)),
              "exclusions": dict(Counter(row["excluded_reason"] for row in values if row["excluded_reason"])),
              "strict_waits": len({wait for row in strict for wait in row["waits"]}),
              "comparison_waits": len({wait for row in comparison for wait in row["waits"]}),
              "comparison_other_episode_outer_classes": dict(Counter(
                  kind for row in comparison for kind in row["other_episode_outer_classes"])),
              "comparison_without_any_episode_outer_overlap": sum(not row["other_episode_outer_classes"]
                                                                  for row in comparison),
              "recorded_gap_ns_min_median_max": {"strict_linked_gc": summarize(strict), "comparison": summarize(comparison)},
              "inputs_sha256": {path: digest(capture / path) for path in relative}}
    output.mkdir()
    for name, content in (("summary.json", result), ("observations.json", values)):
        (output / name).write_text(json.dumps(content, indent=2) + "\n", encoding="utf-8", newline="\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.capture, args.output)))
