"""Pair scoped scheduler callbacks by owned generation and reservation order.

These records identify software callbacks, not physical CPU dispatch boundaries.
No elapsed scheduler or GC duration is derived from the retained fast clocks.
"""

from collections import Counter, defaultdict
import hashlib
import struct


ROW = struct.Struct("<8I2Q")
LEGACY_ROW = struct.Struct("<IIIIQIIII")
SLOTS = 1024
LEGACY_SLOTS = 512
U32_MAX = (1 << 32) - 1


def require(ok, message):
    if not ok:
        raise ValueError(message)


def unsigned(value):
    return type(value) is int and 0 <= value <= U32_MAX


def counters(values, length):
    require(type(values) in (tuple, list) and len(values) == length
            and all(unsigned(value) for value in values), "invalid unsigned terminal counters")
    return tuple(values)


def legacy_lifetime(raw, counts, leader_tid):
    attempted, lost, faults, frees, admitted = counters(counts, 5)
    require(type(raw) is bytes and len(raw) == LEGACY_SLOTS * LEGACY_ROW.size,
            "invalid fixed legacy ledger size")
    require(0 < attempted <= LEGACY_SLOTS and lost == faults == 0 and frees == admitted == 1,
            "legacy lifetime is incomplete")
    require(not any(raw[attempted * LEGACY_ROW.size:]), "legacy unused slots are nonzero")
    rows = []
    identity = None
    for slot, values in enumerate(LEGACY_ROW.iter_unpack(raw[:attempted * LEGACY_ROW.size])):
        kind, cpu, target, state, stamp, local, global_tid, generation, parent = values
        require(1 <= kind <= 8 and cpu < 32 and stamp > 0 and generation == 1 and parent == 0,
                "legacy row is outside the one-worker fixture")
        require(local > 0 and global_tid > 0 and local != leader_tid,
                "legacy worker identity is invalid")
        current = (local, global_tid)
        identity = current if identity is None else identity
        require(current == identity, "legacy generation changed numeric identity")
        require((target != U32_MAX) == (kind in (2, 5, 6))
                and (target == U32_MAX or target < 32) and (kind == 4 or state == 0),
                "legacy raw fields have invalid presence")
        rows.append({"slot": slot, "kind": kind, "cpu": cpu, "raw_state": state,
                     "fast_ns": stamp, "local_tid": local, "global_tid": global_tid})
    kinds = [row["kind"] for row in rows]
    for kind in (1, 2, 7, 8):
        require(kinds.count(kind) == 1, "legacy lifecycle endpoint missing or duplicated")
    birth, first_wake, retired, free = (kinds.index(kind) for kind in (1, 2, 7, 8))
    require(birth == 0 < first_wake < retired < free == len(rows)-1,
            "legacy lifecycle reservation order is invalid")
    terminal = [row for row in rows if row["kind"] == 4 and row["raw_state"] == 128]
    require(len(terminal) == 1 and retired < terminal[0]["slot"] < free,
            "legacy terminal switch is missing or unordered")
    return {"generation": 1, "local_tid": identity[0], "global_tid": identity[1],
            "birth_slot": birth, "first_wake_slot": first_wake,
            "retired_slot": retired, "terminal_switch_slot": terminal[0]["slot"],
            "free_slot": free, "rows": len(rows),
            "ledger_sha256": hashlib.sha256(raw).hexdigest()}


def analyze(boundary_raw, boundary_counts, capacity, legacy_raw, legacy_counts, leader_tid):
    require(type(leader_tid) is int and leader_tid > 0 and leader_tid <= U32_MAX,
            "invalid held leader TID")
    require(type(capacity) is int and capacity in (1, SLOTS), "unsupported fixed boundary capacity")
    require(type(boundary_raw) is bytes and len(boundary_raw) == SLOTS * ROW.size,
            "invalid fixed boundary ledger size")
    attempted, lost, faults, reserved = counters(boundary_counts, 4)
    require(attempted > 0 and faults == reserved == 0, "boundary counter fault or empty ledger")
    used = min(attempted, capacity)
    require(lost == attempted-used and not any(boundary_raw[used*ROW.size:]),
            "boundary loss or zero-padding reconciliation failed")
    if capacity == 1:
        require(attempted > 1 and lost > 0, "capacity-negative did not exercise publication loss")
    else:
        require(attempted <= SLOTS and lost == 0, "positive boundary ledger lost data")
    lifetime = legacy_lifetime(legacy_raw, legacy_counts, leader_tid)
    rows = []
    retired_seen = False
    for slot, values in enumerate(ROW.iter_unpack(boundary_raw[:used*ROW.size])):
        ordinal, generation, kind, raw_bool, cpu_begin, cpu_end, retired, local, begin, end = values
        require(ordinal == slot+1 and generation in (0, 1) and kind in (1, 2),
                "unknown, missing, duplicate or out-of-order boundary header")
        require(raw_bool in (0, 1) and retired in (0, 1) and cpu_begin < 32 and cpu_end < 32
                and begin > 0 and end > 0, "invalid boundary bool, CPU or timestamp")
        require(local == (leader_tid if generation == 0 else lifetime["local_tid"]),
                "boundary numeric identity differs from its owned generation")
        require(generation != 0 or retired == 0, "held leader cannot carry a worker retirement flag")
        if generation == 1:
            require(not retired_seen or retired == 1, "worker retirement flag moved backwards")
            retired_seen = retired_seen or retired == 1
        rows.append({"slot": slot, "ordinal": ordinal, "generation": generation,
                     "kind": "entry" if kind == 1 else "exit", "raw_bool": raw_bool,
                     "cpu_begin": cpu_begin, "cpu_end": cpu_end, "retired": retired,
                     "local_tid": local, "fast_begin_ns": begin, "fast_end_ns": end,
                     "recorded_body_backwards": end < begin})
    result = {"status": "completed_bounded_boundary_observations", "capacity": capacity,
              "attempted": attempted, "lost": lost, "retained": used,
              "ledger_sha256": hashlib.sha256(boundary_raw).hexdigest(),
              "worker_lifetime": lifetime, "decoded": rows, "complete_pairs": [],
              "prefixes": [], "open_invocations": [], "classification_complete": False,
              "physical_scheduler_duration_certified": False,
              "historical_roslyn_qualified": False, "general_capture_ready": False,
              "gc_cause_certified": False,
              "limits": ["Pairs follow owned generation and reservation order, never CPU or timestamp sorting.",
                         "Entry bool is the exact preempt-mode comparison, not a voluntary/blocking oracle.",
                         "Exit bool describes the saved invocation's switch selection, not physical residence.",
                         "Fast callback points provide no transferable timing or GC causal guarantee."]}
    if capacity == 1:
        result["pairing_status"] = "not_classified_capacity_loss"
        result["coverage"] = {}
        return result
    require({row["generation"] for row in rows} == {0, 1}, "positive boundary fixture lacks leader or worker rows")
    pending = {}
    seen = Counter()
    grouped = defaultdict(list)
    for row in rows:
        generation = row["generation"]
        grouped[generation].append(row)
        if row["kind"] == "entry":
            require(generation not in pending, "nested or duplicate invocation entry")
            pending[generation] = row
        elif generation in pending:
            entry = pending.pop(generation)
            result["complete_pairs"].append({"generation": generation,
                                             "invocation_entry_ordinal": entry["ordinal"],
                                             "exit_ordinal": row["ordinal"],
                                             "entry_preempt_mode": bool(entry["raw_bool"]),
                                             "is_switch": bool(row["raw_bool"]),
                                             "entry_retired": entry["retired"],
                                             "exit_retired": row["retired"],
                                             "entry_cpu": entry["cpu_begin"],
                                             "exit_cpu": row["cpu_begin"],
                                             "entry_exit_cpu_changed": entry["cpu_begin"] != row["cpu_begin"],
                                             "entry_slot": entry["slot"], "exit_slot": row["slot"]})
        else:
            require(seen[generation] == 0, "unexpected noninitial unmatched invocation exit")
            classification = ("leader_left_censored_exit" if generation == 0 else
                              "owned_newborn_exit_prefix" if row["raw_bool"] == 1 else
                              "unknown_worker_exit_prefix")
            result["prefixes"].append({"generation": generation, "exit_ordinal": row["ordinal"],
                                       "classification": classification, "raw_bool": row["raw_bool"]})
        seen[generation] += 1
    for generation, entry in sorted(pending.items()):
        if generation == 1:
            require(entry["retired"] == 1, "closed worker has an unexplained live invocation tail")
            classification = "unreturned_retired_lifetime_entry"
        else:
            classification = "leader_open_at_detach"
        result["open_invocations"].append({"generation": generation,
                                           "entry_ordinal": entry["ordinal"],
                                           "classification": classification,
                                           "entry_preempt_mode": bool(entry["raw_bool"])})
    coverage = Counter({"complete_switch_pairs": 0, "complete_no_switch_pairs": 0,
                        "entry_exit_cpu_changed_pairs": 0, "leader_left_censored_exits": 0,
                        "owned_newborn_exit_prefixes": 0, "unknown_worker_exit_prefixes": 0,
                        "unreturned_retired_lifetime_entries": 0, "leader_open_at_detach": 0})
    for pair in result["complete_pairs"]:
        coverage["complete_switch_pairs" if pair["is_switch"] else "complete_no_switch_pairs"] += 1
        coverage["entry_exit_cpu_changed_pairs"] += pair["entry_exit_cpu_changed"]
    for prefix in result["prefixes"]:
        key = {"leader_left_censored_exit": "leader_left_censored_exits",
               "owned_newborn_exit_prefix": "owned_newborn_exit_prefixes",
               "unknown_worker_exit_prefix": "unknown_worker_exit_prefixes"}[prefix["classification"]]
        coverage[key] += 1
    for entry in result["open_invocations"]:
        coverage["unreturned_retired_lifetime_entries" if entry["generation"] else "leader_open_at_detach"] += 1
    coverage["recorded_body_backwards"] = sum(row["recorded_body_backwards"] for row in rows)
    coverage["recorded_cpu_changed_within_body"] = sum(row["cpu_begin"] != row["cpu_end"] for row in rows)
    coverage["per_generation_adjacent_fast_reversals"] = sum(
        right["fast_begin_ns"] < left["fast_begin_ns"]
        for group in grouped.values() for left, right in zip(group, group[1:]))
    accounted = 2*len(result["complete_pairs"]) + len(result["prefixes"]) + len(result["open_invocations"])
    require(accounted == len(rows), "boundary invocation accounting did not conserve every row")
    result.update(classification_complete=True, pairing_status="completed_reservation_order_classification",
                  coverage=dict(coverage), accounted_rows=accounted)
    return result
