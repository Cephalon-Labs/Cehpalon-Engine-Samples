"""Validate and summarize one frozen CLR collector overhead matrix offline."""

from fractions import Fraction
import re
from statistics import median


ORDER = (
    ("off", "on"),  # Primer pair, retained separately.
    ("off", "on"),
    ("on", "off"),
    ("off", "on"),
    ("on", "off"),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def uint(value):
    return type(value) is int and 0 <= value < 2**64


def sequence(receipt, keys):
    values = tuple(receipt.get(key) for key in keys)
    require(all(uint(value) for value in values), f"missing or invalid timestamps: {keys}")
    return values


def rational(value):
    return {"numerator": value.numerator, "denominator": value.denominator}


def read_case(row, *, slot, pair, mode, fixture_sha256, runtime_sha256, rounds, checksum):
    phase = "primer" if pair == 0 else "measured"
    require(type(row) is dict and type(row.get("slot")) is int and type(row.get("pair")) is int
            and (row.get("slot"), row.get("phase"), row.get("pair"), row.get("mode"))
            == (slot, phase, pair, mode), f"slot {slot}: order differs from frozen matrix")
    require(row.get("passed") is True, f"slot {slot}: native run did not pass")
    require(row.get("fixture_sha256") == fixture_sha256 and row.get("runtime_sha256") == runtime_sha256,
            f"slot {slot}: executed source identity differs from frozen matrix")

    ready, completed, controller = (row.get(key) for key in ("ready", "completed", "controller"))
    require(all(type(item) is dict for item in (ready, completed, controller)),
            f"slot {slot}: missing case receipts")
    require(ready.get("kind") == "ready" and completed.get("kind") == "completed",
            f"slot {slot}: unexpected actor receipt kind")
    pid, main_tid, worker_tid = ready.get("pid"), ready.get("main_tid"), completed.get("worker_tid")
    require(all(uint(value) and value > 0 for value in (pid, main_tid, worker_tid))
            and pid == main_tid and worker_tid != main_tid,
            f"slot {slot}: missing or invalid native thread identities")
    require(ready.get("stopwatch_frequency") == 1_000_000_000
            and type(ready.get("stopwatch_frequency")) is int,
            f"slot {slot}: unexpected Stopwatch frequency")
    require(uint(completed.get("rounds")) and completed["rounds"] == rounds
            and completed.get("checksum") == checksum,
            f"slot {slot}: fixed rounds or checksum differ")

    prepare, run, done, cleanup = sequence(controller, (
        "prepare_start_ns", "run_send_ns", "done_receive_ns", "cleanup_end_ns",
    ))
    work_start, work_end, ping_start, ping_end = sequence(completed, (
        "work_begin_ns", "work_end_ns", "ping_begin_ns", "ping_end_ns",
    ))
    work_tick_start, work_tick_end, ping_tick_start, ping_tick_end = sequence(completed, (
        "work_begin_ticks", "work_end_ticks", "ping_begin_ticks", "ping_end_ticks",
    ))
    cpu_start, cpu_end = sequence(completed, ("ping_begin_process_cpu_ns", "ping_end_process_cpu_ns"))
    require(prepare <= run <= work_start <= ping_start < min(work_end, ping_end)
            <= max(work_end, ping_end) <= done <= cleanup,
            f"slot {slot}: monotonic bracket is unordered")
    require(work_tick_start <= ping_tick_start < min(work_tick_end, ping_tick_end),
            f"slot {slot}: Stopwatch bracket is unordered")
    require(cpu_start <= cpu_end, f"slot {slot}: process CPU clock ran backwards")
    return {
        "slot": slot, "phase": phase, "pair": pair, "mode": mode,
        "pid": pid, "worker_tid": worker_tid,
        "ping_ns": ping_end - ping_start, "work_ns": work_end - work_start,
        "ping_ticks": ping_tick_end - ping_tick_start, "work_ticks": work_tick_end - work_tick_start,
        "ping_process_cpu_ns": cpu_end - cpu_start,
        "preparation_ns": run - prepare, "controller_command_ns": done - run,
        "cleanup_ns": cleanup - done,
    }


def summarize_overhead(rows, *, fixture_sha256, runtime_sha256, expected_rounds, expected_checksum):
    """Summarize all four measured pairs. Reject missing or invalid cases, including primers."""
    for identity in (fixture_sha256, runtime_sha256):
        require(type(identity) is str and re.fullmatch(r"[0-9a-f]{64}", identity),
                "expected a frozen lowercase SHA-256 identity")
    require(uint(expected_rounds) and expected_rounds > 0 and type(expected_checksum) is str
            and re.fullmatch(r"[0-9a-f]{16}", expected_checksum),
            "expected frozen rounds and checksum")
    require(type(rows) is list and len(rows) == 2 * len(ORDER),
            "expected all ten cases in execution order")

    cases = []
    for pair, modes in enumerate(ORDER):
        for position, mode in enumerate(modes):
            slot = 2 * pair + position + 1
            cases.append(read_case(rows[slot - 1], slot=slot, pair=pair, mode=mode,
                                   fixture_sha256=fixture_sha256, runtime_sha256=runtime_sha256,
                                   rounds=expected_rounds, checksum=expected_checksum))
    for previous, following in zip(rows, rows[1:]):
        require(previous["controller"]["cleanup_end_ns"] <= following["controller"]["prepare_start_ns"],
                f"slot {following['slot']}: controller intervals overlap or run backwards")

    names = ("ping_ns", "work_ns")
    deltas = {name: [] for name in names}
    percentages = {name: [] for name in names}
    pairs = []
    for pair, modes in enumerate(ORDER[1:], start=1):
        by_mode = {row["mode"]: row for row in cases[2 * pair:2 * pair + 2]}
        off_case, on_case = by_mode["off"], by_mode["on"]
        result = {"pair": pair, "order": list(modes),
                  "off_slot": off_case["slot"], "on_slot": on_case["slot"]}
        for name in names:
            off, on = off_case[name], on_case[name]
            delta = on - off
            percentage = Fraction(100 * delta, off)
            deltas[name].append(Fraction(delta))
            percentages[name].append(percentage)
            result[name] = {"off_ns": off, "on_ns": on, "on_minus_off_ns": delta,
                            "on_minus_off_percent_of_off": rational(percentage)}
        pairs.append(result)

    metrics = {}
    for name in names:
        ns, percent = deltas[name], percentages[name]
        metrics[name] = {
            "on_minus_off_ns": {"median": rational(median(ns)), "min": int(min(ns)), "max": int(max(ns))},
            "on_minus_off_percent_of_off": {"median": rational(median(percent)),
                                             "min": rational(min(percent)), "max": rational(max(percent))},
        }

    return {
        "schema_version": 1,
        "scope": "Descriptive paired synthetic CLR observer overhead on the recorded host",
        "fixture_sha256": fixture_sha256, "runtime_sha256": runtime_sha256,
        "rounds": expected_rounds, "checksum": expected_checksum,
        "primary_metric": "ping_ns", "primer_cases": cases[:2], "measured_cases": cases[2:],
        "pairs": pairs, "metrics": metrics,
    }
