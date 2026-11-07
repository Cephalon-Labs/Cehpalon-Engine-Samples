"""Exercise the full scheduler profile on the bounded CLR fixture before Roslyn."""

import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import subprocess

from collect_scheduler_clr_fixture import APP, HOST, execute
from collect_scheduler_dynamic_fixture import mono, receive
from preflight_scheduler_pidfd_seed import finish_actor, require
from preflight_scheduler_dynamic_verifier import verify_host
from roslyn_scheduler_session import SchedulerSession, save
from scheduler_trace_model import decode_scheduler


def run(folder):
    verify_host()
    folder.mkdir(parents=True, exist_ok=False)
    report = {"status": "preparing", "controller": {"prepare_start_ns": mono()},
              "cleanup_errors": [], "closed_fds": 0, "forced_cleanup": False}
    save(folder / "conformance.json", report)
    session = SchedulerSession(folder / "scheduler")
    try:
        with ExitStack() as cleanup:
            actor = subprocess.Popen([str(HOST), str(APP)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     bufsize=0, user=1000, group=1000, extra_groups=[],
                                     cwd=APP.parent, env={})
            cleanup.callback(finish_actor, actor, report)
            report["ready"] = receive(actor, "ready")
            require(report["ready"]["pid"] == actor.pid and report["ready"]["threadpool_count"] == 0,
                    "unexpected CLR conformance actor")
            session.arm(actor, folder)
            report["prearm_cohort"] = session.report["prearm_cohort"]
            execute(actor, report)
            session.finish(actor, report["reaped_ns"])
            session.close()
            require(session.report["status"] == "completed", "scheduler conformance capture failed")
            generations, intervals, groups = decode_scheduler(
                (session.folder / "scheduler-ledger.bin").read_bytes(), session.report, "conformance")
            callback = [row for row in generations if row["local_tid"] == report["parked"]["worker_tid"]]
            require(len(callback) == 1 and not callback[0]["initial_state_unknown"]
                    and callback[0]["born_ns"] < report["parked"]["mono_ns"]
                    and report["completed"]["work_end_ns"] < callback[0]["exit_ns"],
                    "CLR callback did not bind a post-arm birth")
            main = [row for row in generations if row["local_tid"] == actor.pid]
            require(len(main) == 1 and main[0]["initial_state_unknown"]
                    and main[0]["born_ns"] < report["completed"]["work_begin_ns"],
                    "pre-arm leader was not enrolled before controlled work")
            report.update(status="completed", generations=generations, callback_generation=callback[0]["generation"])
    except Exception as error:
        report.update(status="failed", failure=type(error).__name__ + ": " + str(error))
        raise
    finally:
        session.close()
        save(folder / "conformance.json", report)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    run(parser.parse_args().output.resolve())
