"""Join complete recorded scheduler pairs to same-execution wait and task cores."""

import argparse
from bisect import bisect_right
from collections import Counter, defaultdict
from fractions import Fraction
import hashlib
import json
from pathlib import Path

from scheduler_boundary_analysis import ROW, require
from scheduler_boundary_program import ROSLYN_BOUNDARY_SLOTS


def read(path):
    return json.loads(path.read_bytes())


def pair_rows(rows, identities):
    by_generation = {row["generation"]: row for row in identities}
    pending, previous = {}, {}
    retired, ambiguous = set(), set()
    pairs, prefixes = [], []
    for index, row in enumerate(rows, 1):
        ordinal, gen, kind, flag, cpu0, cpu1, retired_flag, tid, begin, end = row
        identity = by_generation.get(gen)
        require(identity is not None and tid == identity["local_tid"] and ordinal == index
                and kind in (1, 2) and flag in (0, 1) and retired_flag in (0, 1)
                and (gen not in retired or retired_flag == 1)
                and 0 < begin and 0 < end, f"invalid boundary record {index}")
        if retired_flag:
            retired.add(gen)
        prior = previous.get(gen)
        if end < begin or cpu0 != cpu1:
            ambiguous.add(ordinal)
        if prior is not None and prior[9] >= begin:
            ambiguous.update((prior[0], ordinal))
        previous[gen] = row
        if kind == 1:
            require(gen not in pending, f"nested entry for generation {gen}")
            pending[gen] = row
        elif gen in pending:
            entry = pending.pop(gen)
            pairs.append((entry, row))
        else:
            require(prior is None, f"unexpected noninitial return for generation {gen}")
            label = "initial_or_unknown" if identity["initial_state_unknown"] or not flag or retired_flag else "born_prefix"
            prefixes.append({"generation": gen, "ordinal": ordinal, "class": label})
    tails = []
    for gen, row in sorted(pending.items()):
        require(row[6] == 1, f"closed generation {gen} has an unexplained live tail")
        tails.append({"generation": gen, "ordinal": row[0]})
    usable = defaultdict(list)
    exclusions = Counter()
    paired_rows = []
    for entry, exit_row in pairs:
        ident = by_generation[entry[1]]
        if entry[6] or exit_row[6]:
            reason = "retired_endpoint"
        elif entry[0] in ambiguous or exit_row[0] in ambiguous:
            reason = "visible_clock_or_cpu_ambiguity"
        elif not ident["born_ns"] < entry[8] < exit_row[8] <= exit_row[9] < ident["exit_ns"]:
            reason = "outside_strict_lifecycle"
        else:
            reason = None
        pair = {"generation": entry[1], "entry_ordinal": entry[0], "return_ordinal": exit_row[0],
                "entry_begin_ns": entry[8], "return_end_ns": exit_row[9], "is_switch": bool(exit_row[3]),
                "entry_preempt_mode": bool(entry[3]), "cpu_endpoint_changed": entry[4] != exit_row[4],
                "correlation_exclusion": reason}
        paired_rows.append(pair)
        if reason is None:
            usable[entry[1]].append(pair)
        else:
            exclusions[reason] += 1
    return paired_rows, prefixes, tails, usable, exclusions, sorted(ambiguous)


def contained(starts, pairs, bounds):
    low, high = map(Fraction, bounds)
    start = bisect_right(starts, low)
    hits = []
    for index in range(start, len(pairs)):
        pair = pairs[index]
        if pair["entry_begin_ns"] >= high:
            break
        if pair["return_end_ns"] < high:
            hits.append(pair["entry_ordinal"])
    return hits


def analyze(capture, joins, output):
    scheduler = read(capture / "scheduler/scheduler.json")
    raw = (capture / "scheduler/boundaries.bin").read_bytes()
    count, lost, faults, reserved = scheduler["boundary_counts"]
    require(scheduler["status"] == "completed" and 0 < count <= ROSLYN_BOUNDARY_SLOTS
            and lost == faults == reserved == 0 and len(raw) == ROSLYN_BOUNDARY_SLOTS * ROW.size
            and hashlib.sha256(raw).hexdigest() == scheduler["boundary_sha256"] == scheduler["boundary_second_sha256"]
            and not any(raw[count * ROW.size:]), "boundary ledger failed identity or completeness gates")
    identities = read(joins / "generations.json")
    require(all(row["execution_id"] == capture.name for row in identities), "mismatching execution")
    pairs, prefixes, tails, usable, excluded, ambiguous = pair_rows(ROW.iter_unpack(raw[:count * ROW.size]), identities)
    require(len(pairs) * 2 + len(prefixes) + len(tails) == count, "boundary row accounting differs")
    for group in usable.values():
        group.sort(key=lambda p: p["entry_begin_ns"])
    starts = {key: [p["entry_begin_ns"] for p in group] for key, group in usable.items()}
    output.mkdir(exist_ok=False)
    counters = Counter()
    with (output / "wait-boundary-joins.jsonl").open("x", encoding="utf-8") as out:
        with (joins / "wait-joins.jsonl").open(encoding="utf-8") as source:
            for line in source:
                wait = json.loads(line)
                counters["selected_waits"] += 1
                if wait["status"] != "bound":
                    out.write(json.dumps({"wait_index": wait["wait_index"], "status": wait["status"]}) + "\n")
                    continue
                counters["bound_waits"] += 1
                gen = wait["generation"]
                caller = contained(starts.get(gen, []), usable.get(gen, []), wait["core_ns"])
                worker_binding = wait.get("task_execution_binding", {})
                worker = None
                if worker_binding.get("status") == "bound":
                    lo, hi = map(Fraction, wait["core_ns"])
                    a, b = map(Fraction, worker_binding["core_ns"])
                    w = worker_binding["generation"]
                    worker = contained(starts.get(w, []), usable.get(w, []), (max(lo, a), min(hi, b)))
                gc = wait["literal_gc_boundaries_contained"]
                for key, present in (("caller_pair", caller), ("worker_pair", worker), ("gc_boundary", gc),
                                     ("caller_pair_and_gc_boundary", caller and gc),
                                     ("worker_pair_and_gc_boundary", worker and gc)):
                    counters[key] += bool(present)
                out.write(json.dumps({"wait_index": wait["wait_index"], "status": "bound",
                                      "caller_entry_ordinals": caller, "worker_entry_ordinals": worker,
                                      "gc_record_indices": gc}) + "\n")
    (output / "pairs.jsonl").write_text("".join(json.dumps(p) + "\n" for p in pairs), encoding="utf-8")
    result = {"rows": count, "pairs": len(pairs), "switch_pairs": sum(p["is_switch"] for p in pairs),
              "prefixes": prefixes, "retired_tails": tails, "ambiguous_ordinals": ambiguous,
              "excluded_pairs": dict(excluded), "usable_pairs": sum(map(len, usable.values())),
              "wait_counts": dict(counters), "physical_scheduler_duration_certified": False,
              "gc_pause_total_ns": None, "exclusive_gc_scheduler_share": None}
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("capture", "joins", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(analyze(args.capture, args.joins, args.output)))
