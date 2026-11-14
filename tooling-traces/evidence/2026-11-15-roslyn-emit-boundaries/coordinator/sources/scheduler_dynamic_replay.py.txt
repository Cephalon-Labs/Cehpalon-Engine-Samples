"""Offline contract for sanitized records from a bounded dynamic-thread fixture."""

from dataclasses import dataclass


class ReplayError(ValueError):
    """The retained records cannot establish the declared fixture evidence."""


@dataclass
class Thread:
    global_tid: int
    local_tid: int
    phase: str
    first_switch: bool = False
    remote_waking: bool = False
    remote_wakeup: bool = False


BASE_FIELDS = {"sequence", "kind", "generation"}
IDENTITY_FIELDS = {"global_tid", "local_tid"}
KINDS = {
    "seed": IDENTITY_FIELDS,
    "birth": IDENTITY_FIELDS | {"parent"},
    "wake_new": set(),
    "switch_in": set(),
    "waking": {"emitter_cpu", "target_cpu"},
    "wakeup": {"emitter_cpu", "target_cpu"},
    "exit": set(),
    "free": set(),
}


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def replay(records, terminal, expected_births):
    """Validate one fixed offline fixture in publication order.

    This assumes a separately verified producer. It cannot authenticate the
    seed, kernel events, negative controls, or terminal counter provenance.
    """
    if not _integer(expected_births, 1, 16):
        raise ReplayError("expected birth count outside fixture bounds")
    if type(records) is not list or not 1 <= len(records) <= 4096:
        raise ReplayError("record count outside fixture bounds")
    if type(terminal) is not dict or set(terminal) != {
        "attempted", "published", "failed", "faults"
    }:
        raise ReplayError("unexpected terminal counter fields")
    if any(not _integer(value, 0, (1 << 64) - 1) for value in terminal.values()):
        raise ReplayError("invalid terminal counter")
    if terminal["faults"] or terminal["failed"]:
        raise ReplayError("producer reported a fault or publication failure")
    if not terminal["attempted"] == terminal["published"] == len(records):
        raise ReplayError("terminal counters do not reconcile with records")

    threads = {}
    occupied_global = set()
    occupied_local = set()
    for sequence, record in enumerate(records, start=1):
        if type(record) is not dict or not BASE_FIELDS <= record.keys():
            raise ReplayError("missing base record fields")
        kind = record["kind"]
        if type(kind) is not str or kind not in KINDS:
            raise ReplayError("unknown record kind")
        if set(record) != BASE_FIELDS | KINDS[kind]:
            raise ReplayError("unexpected record fields")
        generation = record["generation"]
        if not _integer(record["sequence"], sequence, sequence):
            raise ReplayError("invalid publication sequence")
        if not _integer(generation, 1, expected_births + 1):
            raise ReplayError("generation outside fixture bounds")
        if (sequence == 1) != (kind == "seed"):
            raise ReplayError("seed must occur exactly once and first")

        if kind in {"seed", "birth"}:
            if generation != len(threads) + 1:
                raise ReplayError("new generation is not the next allocated generation")
            if kind == "birth":
                parent = record["parent"]
                if not _integer(parent, 1, generation - 1) or parent not in threads:
                    raise ReplayError("birth has no prior parent generation")
                if threads[parent].phase != "active" or not threads[parent].first_switch:
                    raise ReplayError("birth parent is not active and previously switched in")
            global_tid, local_tid = record["global_tid"], record["local_tid"]
            if not all(_integer(tid, 1, (1 << 31) - 1) for tid in (global_tid, local_tid)):
                raise ReplayError("invalid numeric task identity")
            if global_tid in occupied_global or local_tid in occupied_local:
                raise ReplayError("numeric task identity overlaps a retained generation")
            occupied_global.add(global_tid)
            occupied_local.add(local_tid)
            threads[generation] = Thread(
                global_tid, local_tid, "active" if kind == "seed" else "born",
                first_switch=kind == "seed",
            )
            continue

        thread = threads.get(generation)
        if thread is None or generation == 1:
            raise ReplayError("fixture lifecycle record has no admitted child generation")
        if kind == "wake_new" and thread.phase == "born":
            thread.phase = "active"
        elif kind == "switch_in" and thread.phase == "active":
            thread.first_switch = True
        elif kind in {"waking", "wakeup"} and thread.phase == "active" and thread.first_switch:
            emitter, target = record["emitter_cpu"], record["target_cpu"]
            if not all(_integer(cpu, 0, (1 << 31) - 1) for cpu in (emitter, target)):
                raise ReplayError("invalid wake CPU")
            if emitter != target and kind == "waking":
                thread.remote_waking = True
            if emitter != target and kind == "wakeup":
                thread.remote_wakeup = True
        elif kind == "exit" and thread.phase == "active" and thread.first_switch:
            thread.phase = "exited"
        elif kind == "free" and thread.phase == "exited":
            thread.phase = "freed"
            occupied_global.remove(thread.global_tid)
            occupied_local.remove(thread.local_tid)
        else:
            raise ReplayError(f"invalid {kind} in {thread.phase} for generation {generation}")

    children = [thread for generation, thread in threads.items() if generation != 1]
    if len(children) != expected_births or any(child.phase != "freed" for child in children):
        raise ReplayError("declared child lifecycles did not complete")
    # Independent event observations. They do not pair a single remote wake.
    if not any(child.remote_waking for child in children):
        raise ReplayError("no remote waking observation")
    if not any(child.remote_wakeup for child in children):
        raise ReplayError("no remote wakeup observation")
    return {
        "completed_births": len(children),
        "remote_waking_generations": sum(child.remote_waking for child in children),
        "remote_wakeup_generations": sum(child.remote_wakeup for child in children),
        "capture_ready": False,
    }
