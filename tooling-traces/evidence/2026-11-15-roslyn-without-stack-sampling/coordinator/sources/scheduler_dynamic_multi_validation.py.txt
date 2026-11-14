"""Validate the bounded A/B/C fixture's retained publication ledger."""

import struct

from collect_scheduler_dynamic_fixture import EVENT_NAMES, U32_MAX, require, validate_ledger


RECORD = struct.Struct("<IIIIQIIII")
SLOTS = 512
LABELS = ("A", "B", "C")
PARENT_GENERATIONS = (0, 1, 0)


def worker_controls(report, main_cpu, worker_cpu):
    workers = report["workers"]
    require(set(workers) == set(LABELS), "expected exactly the declared A/B/C controls")
    for label, worker in workers.items():
        park, oracle, joined = (worker[name] for name in ("parked", "park_oracle", "joined"))
        tid = park["worker_tid"]
        require(type(tid) is int and tid > 0 and joined["worker_tid"] == tid,
                f"worker {label} has inconsistent TID receipts")
        require((park["worker_cpu"], oracle["worker_cpu"], joined["worker_cpu"], joined["main_cpu"])
                == (worker_cpu, worker_cpu, worker_cpu, main_cpu),
                f"worker {label} CPU receipts differ from the pinned CPUs")
        require((oracle["syscall"], oracle["fd"], oracle["count"], oracle["state"])
                == (0, park["park_read_fd"], 1, "S"),
                f"worker {label} lacked the blocked-read receipt")
        require(worker["run_before_ns"] <= park["mono_ns"] <= oracle["mono_ns"]
                <= joined["write_before_ns"] <= min(joined["write_after_ns"], joined["worker_read_return_ns"])
                <= max(joined["write_after_ns"], joined["worker_read_return_ns"]) <= joined["joined_ns"],
                f"worker {label} control intervals are unordered")
    require(max(workers[label]["park_oracle"]["mono_ns"] for label in ("A", "B"))
            <= workers["A"]["joined"]["write_before_ns"], "A and B did not overlap in the parked state")
    require(workers["A"]["joined"]["joined_ns"] <= workers["B"]["joined"]["write_before_ns"]
            and workers["B"]["joined"]["joined_ns"] <= workers["C"]["run_before_ns"],
            "worker release and readmission controls are unordered")
    require(workers["A"]["parked"]["worker_tid"] != workers["B"]["parked"]["worker_tid"],
            "overlapping workers have the same local TID")
    return workers


def validate_multi_ledger(report, rows, counts, capacity, main_cpu, worker_cpu):
    """Validate raw fixed slots and preserve global slot indices in each worker chain."""
    require(capacity in {1, SLOTS} and len(rows) == SLOTS
            and all(len(row) == RECORD.size for row in rows), "unexpected multiworker ledger shape")
    attempted, lost, faults, frees, admitted = counts
    require(faults == 0 and frees == admitted == len(LABELS) and 24 <= attempted <= 4096,
            "invalid multiworker terminal counters")
    used = min(attempted, capacity)
    require(lost == attempted - used and not any(any(row) for row in rows[used:]),
            "publication accounting differs from fixed capacity")
    workers = worker_controls(report, main_cpu, worker_cpu)

    decoded = []
    open_generations = {}
    grouped = {}
    for slot, row in enumerate(rows[:used]):
        kind, emitter, target, aux, stamp, local, global_tid, generation, parent = RECORD.unpack(row)
        require(1 <= kind < len(EVENT_NAMES) and 1 <= generation <= len(LABELS),
                "unknown or incomplete multiworker row")
        label = LABELS[generation - 1]
        require(parent == PARENT_GENERATIONS[generation - 1], f"unexpected parent for {label}")
        identity = (local, global_tid)
        require(local == workers[label]["parked"]["worker_tid"] and global_tid > 0,
                f"kernel identity differs from the receipt for {label}")
        if kind == 1:
            require(generation == len(grouped) + 1, "unexpected or repeated generation birth")
            require(parent == 0 or parent in open_generations, "nested birth has no admitted live parent")
            require(generation != 3 or not open_generations, "C was admitted before A and B were freed")
            require(all(local != other[0] and global_tid != other[1] for other in open_generations.values()),
                    "overlapping generations reuse a numeric TID")
            open_generations[generation] = identity
            grouped[generation] = []
        require(open_generations.get(generation) == identity, "record is stale or has an unbound identity")
        decoded.append({"kind": EVENT_NAMES[kind], "emitter_cpu": emitter,
                        "target_cpu": None if target == U32_MAX else target,
                        "raw_state": aux, "mono_ns": stamp, "local_tid": local, "global_tid": global_tid,
                        "generation": generation, "parent_generation": parent})
        grouped[generation].append(slot)
        if kind == 8:
            del open_generations[generation]
    report["decoded"] = decoded

    if capacity == 1:
        birth = decoded[0]
        require(lost > 0 and birth["kind"] == "birth" and birth["generation"] == 1
                and birth["target_cpu"] is None and birth["raw_state"] == 0
                and workers["A"]["run_before_ns"] <= birth["mono_ns"] <= workers["A"]["parked"]["mono_ns"],
                "overflow negative did not retain only the admitted A birth")
        return

    require(lost == 0 and len(grouped) == len(LABELS) and not open_generations,
            "positive ledger is incomplete")
    chains = {}
    for generation, slots in grouped.items():
        label = LABELS[generation - 1]
        stamps = [decoded[slot]["mono_ns"] for slot in slots]
        require(all(left < right for left, right in zip(stamps, stamps[1:])),
                f"generation {generation} timestamps are not strictly increasing")
        proof = workers[label].copy()
        validate_ledger(proof, [rows[slot][:32] for slot in slots], (len(slots), 0, 0, 1),
                        SLOTS, main_cpu, worker_cpu)
        chains[label] = {kind: slots[index] for kind, index in proof["chain_slots"].items()}
        require(stamps[0] <= workers[label]["parked"]["mono_ns"],
                f"generation {generation} birth followed its actor marker")

    def stamp(label, kind):
        return decoded[chains[label][kind]]["mono_ns"]

    require(stamp("A", "first_switch") < stamp("B", "birth") < stamp("A", "exit"),
            "nested B birth is outside A's active lifetime")
    require(stamp("A", "free") <= workers["B"]["joined"]["write_before_ns"],
            "A was not freed before the controller woke B")
    require(stamp("B", "free") <= workers["C"]["run_before_ns"] < stamp("C", "birth"),
            "C launch did not follow B free")
    report["chain_slots"] = chains
