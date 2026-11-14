"""One unchanged Roslyn corpus with scoped scheduler and EventPipe diagnostics."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import traceback

import capture_roslyn_task_lineage as lineage
import trace_tooling as runtime
from collect_scheduler_clr_fixture import HOST
from preflight_scheduler_dynamic_verifier import verify_host
from roslyn_scheduler_session import SchedulerSession


ROOT = Path(__file__).resolve().parents[1]
ENGINE = "55c630fc5d4c47258a1a2b0da4a16ce8bc42b9f7"
DRIVER_SOURCE = ROOT / ".local/tooling-wait-driver-linux01"
DRIVER = ROOT / ".local/tooling-wait-build-linux01/driver-artifacts/bin/TraceDriver/release/TraceDriver.dll"
TOOL = ROOT / ".local/tooling-trace-preparation-linux01/tools/.store/dotnet-trace/10.0.750501/dotnet-trace/10.0.750501/tools/net8.0/any/dotnet-trace.dll"
ANALYZER = ROOT / ".local/tooling-trace-analyzer-linux02/artifacts/bin/TraceAnalysis/release/TraceAnalysis.dll"
ANALYZER_SHA = "e85a233cb0af33718338281fccc5b7cc4dd721e0063405c2c99655bc6190fdc8"
TOOL_SHA = "33c4e4de008b8fe347b1d9dcaec6f33f79efeb0281a501eee1fcabc1fe8ef7df"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory():
    paths = [HOST, TOOL, ANALYZER]
    paths += [p for p in DRIVER.parent.iterdir() if p.is_file() and p.suffix in {".dll", ".json", ".pdb"}]
    paths += [p for p in (HOST.parent / "shared/Microsoft.NETCore.App/11.0.0-rc.3.26522.148").iterdir() if p.is_file()]
    return {str(path): sha(path) for path in sorted(paths)}


def preflight(*, host_check=verify_host, engine=None):
    host_check()
    runtime.require(os.geteuid() == 0, "Root owns only the scheduler coordinator")
    engine = engine or ROOT.parent / "Cehpalon-Engine"
    git_options = dict(cwd=engine, text=True, user=1000, group=1000, extra_groups=[])
    runtime.require(subprocess.check_output(["/usr/bin/git", "rev-parse", "HEAD"], **git_options).strip() == ENGINE
                    and not subprocess.check_output(["/usr/bin/git", "status", "--porcelain"], **git_options).strip(),
                    "Clean exact Engine revision required")
    runtime.require(sha(DRIVER) == lineage.DRIVER and sha(TOOL) == TOOL_SHA and sha(ANALYZER) == ANALYZER_SHA,
                    "Unchanged prebuilt driver, collector and parser required")
    prepared = runtime.read(DRIVER_SOURCE / "wait-diagnostic-manifest.json")
    runtime.require(prepared["engine_revision"] == ENGINE, "Prepared source Engine revision")
    for name, digest in prepared["final_files_sha256"].items():
        runtime.require(sha(DRIVER_SOURCE / name) == digest, "Prepared source differs")
    for name, digest in lineage.PINS.items():
        runtime.require(sha(ROOT / "tools" / name) == digest, "Pinned helper differs")
    return inventory()


def run(out, *, host_check=verify_host, engine=None, session_options=None):
    binaries = preflight(host_check=host_check, engine=engine)
    out.mkdir(parents=True, exist_ok=False)
    os.chown(out, 1000, 1000)
    report = {"status": "preparing", "engine_revision": ENGINE,
              "providers": lineage.PROVIDERS, "binary_sha256_before": binaries,
              "canonical": False, "capture_ready": False}
    runtime.save(out / "manifest.json", report)
    session = SchedulerSession(out / "scheduler", host_check=host_check, **(session_options or {}))
    try:
        before = lineage.state()
        report["source_before"] = before
        runtime.PROVIDERS = lineage.PROVIDERS
        generator = out / "generator"
        capture = runtime.capture_runtime(
            [HOST, DRIVER, "--output=" + str(generator / "generator.json")],
            ROOT, generator, HOST, TOOL, ANALYZER, timeout=600,
            owned_identity=(1000, 1000), scheduler=session,
        )
        report["capture_status"] = capture["status"]
        analysis = runtime.analyze(generator, HOST, ANALYZER,
                                   generator / "generator.json.spans.jsonl", expected_markers=2956)
        report["semantics"] = runtime.verify_generator(generator / "generator.json")
        runtime.require(analysis["payloadReadErrors"] == analysis["eventsLost"] == analysis["etlxEventsLost"] == 0,
                        "Managed parser/loss gate failed")
        report["scheduler_status"] = session.report["status"]
        runtime.require(session.report["status"] == "completed", "Native scheduler channel incomplete")
        report["source_after"] = lineage.state()
        report["binary_sha256_after"] = inventory()
        runtime.require(before == report["source_after"] and binaries == report["binary_sha256_after"],
                        "Diagnostic source or binary changed")
        runtime.require(sum(path.stat().st_size for path in out.rglob("*") if path.is_file()) < 2 * 1024 ** 3,
                        "Diagnostic output exceeded the declared limit")
        report["status"] = "completed"
    except Exception:
        report.update(status="failed", failure=traceback.format_exc())
        raise
    finally:
        runtime.save(out / "manifest.json", report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    runtime.require(out.is_relative_to(ROOT / ".local") and out != ROOT / ".local",
                    "A fresh isolated Samples .local output is required")
    run(out)
    print(json.dumps({"status": "completed", "output": str(out)}))


if __name__ == "__main__":
    main()
