"""Pure EventPipe point-to-owned-generation joins with explicit clock uncertainty."""

from fractions import Fraction
import math


MAX_GENERATIONS = 64
NS_PER_MS = 1_000_000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, minimum=0):
    return type(value) is int and minimum <= value <= (1 << 63) - 1


def rational(value, *, nonnegative=False):
    require(type(value) in (int, float, str, Fraction) and type(value) is not bool,
            "expected an exact or finite clock value")
    if type(value) is float:
        require(math.isfinite(value), "clock value is not finite")
    try:
        result = value if type(value) is Fraction else Fraction(str(value))
    except (ValueError, ZeroDivisionError) as error:
        raise ValueError("invalid clock value") from error
    require(not nonnegative or result >= 0, "clock value is negative")
    return result


def validate_generations(records, execution_id):
    require(type(records) is list and len(records) <= MAX_GENERATIONS,
            "generation table exceeds the fixed join bound")
    seen = set()
    for row in records:
        require(type(row) is dict and row.get("execution_id") == execution_id,
                "generation belongs to another execution")
        generation = row.get("generation")
        require(integer(generation, 1) and generation <= MAX_GENERATIONS and generation not in seen,
                "invalid or duplicate generation ordinal")
        seen.add(generation)
        require(integer(row.get("local_tid"), 1) and integer(row.get("born_ns"))
                and type(row.get("initial_state_unknown")) is bool,
                "invalid generation identity or enrollment boundary")
        begin, exit_at, free_at = row["born_ns"], row.get("exit_ns"), row.get("free_ns")
        require(exit_at is None or integer(exit_at) and begin <= exit_at,
                "generation exit precedes identity enrollment")
        require(free_at is None or integer(free_at) and begin <= free_at,
                "generation free precedes identity enrollment")
        require(exit_at is None or free_at is None or exit_at <= free_at,
                "generation free precedes exit")


def join_eventpipe_point(event, generations, *, execution_id, target_pid, offset_ms):
    """Bind one native header to a generation under the supplied execution context.

    offset_ms is EventPipe relative milliseconds minus MONOTONIC milliseconds,
    bounded by the existing matched-marker logging-call intersection. The caller
    verifies that Stopwatch uses the same zero-offset monotonic time namespace.
    For left-censored pre-arm records, born_ns means enrollment time. The
    function does not infer a native birth or scheduler state at that boundary.
    """
    require(type(execution_id) is str and bool(execution_id) and integer(target_pid, 1),
            "missing execution context")
    require(type(event) is dict and integer(event.get("processId"), 1)
            and integer(event.get("threadId"), 1), "invalid EventPipe native header")
    require(type(offset_ms) in (list, tuple) and len(offset_ms) == 2,
            "expected two clock offset bounds")
    offset_low, offset_high = (rational(value) for value in offset_ms)
    require(offset_low <= offset_high, "clock offset intersection is empty")
    event_ms = rational(event.get("timeMsec"), nonnegative=True)
    native_low = (event_ms - offset_high) * NS_PER_MS
    native_high = (event_ms - offset_low) * NS_PER_MS
    require(native_low >= 0, "mapped event precedes monotonic origin")
    validate_generations(generations, execution_id)

    result = {
        "execution_id": execution_id,
        "status": "missing",
        "generation": None,
        "mapped_mono_ns": [str(native_low), str(native_high)],
        "candidate_generations": [],
        "lifetime_left_censored": None,
        "scheduler_state": None,
    }
    if event["processId"] != target_pid:
        result["status"] = "foreign_process"
        return result

    candidates = [
        row for row in generations
        if row["local_tid"] == event["threadId"] and native_high >= row["born_ns"]
        and (row.get("free_ns") is None or native_low <= row["free_ns"])
    ]
    result["candidate_generations"] = sorted(row["generation"] for row in candidates)
    if not candidates:
        return result
    if len(candidates) != 1:
        result["status"] = "ambiguous"
        return result

    row = candidates[0]
    result["lifetime_left_censored"] = row["initial_state_unknown"]
    begin, exit_at, free_at = row["born_ns"], row.get("exit_ns"), row.get("free_ns")
    if native_low <= begin or free_at is not None and native_high >= free_at:
        result["status"] = "boundary"
    elif exit_at is None:
        result["status"] = "incomplete_lifetime"
    elif native_high < exit_at:
        result["status"] = "active"
        result["generation"] = row["generation"]
    elif native_low > exit_at and free_at is not None:
        result["status"] = "retired"
        result["generation"] = row["generation"]
    elif native_low > exit_at:
        result["status"] = "incomplete_lifetime"
    else:
        result["status"] = "boundary"
    return result
