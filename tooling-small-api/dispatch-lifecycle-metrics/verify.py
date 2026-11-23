"""Verify dispatch and lifecycle histograms on the generated HTTPS consumer."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet", required=True, type=Path)
    parser.add_argument("--verified-attempt", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    attempt = args.verified_attempt.resolve()
    existing = json.loads((attempt / "manifest.json").read_bytes())
    if existing.get("status") != "passed" or existing.get("source_state") != "exact clean committed source":
        raise ValueError("Expected successful exact-revision generated Small API verification")
    original = attempt / "generated Small API ไทย & spaces"
    engine = (attempt / "engine source ไทย & spaces").resolve()
    engine_manifest = original / "engine-source.json"
    observed = json.loads(engine_manifest.read_bytes())
    if Path(observed["sourceRoot"]).resolve() != engine or Path(existing["consumer_engine_root"]).resolve() != engine:
        raise ValueError("Unexpected generated Engine reference root")

    def verify_engine():
        revision = subprocess.check_output(["git", "-C", str(engine), "rev-parse", "HEAD"], text=True).strip()
        dirty = subprocess.check_output(["git", "-C", str(engine), "status", "--porcelain"])
        if revision != existing["engine_revision"] or dirty:
            raise ValueError("Engine source checkout differs from the verified revision")
        for entry in observed["inputs"]:
            relative = Path(entry["path"])
            path = (engine / relative).resolve()
            if relative.is_absolute() or not path.is_relative_to(engine) or path.stat().st_size != entry["bytes"] or digest(path) != entry["sha256"]:
                raise ValueError(f"Observed Engine source changed: {relative}")

    verify_engine()
    runtime = args.out.resolve() / "consumer"
    runtime.mkdir(parents=True, exist_ok=False)
    artifacts = args.out.resolve() / "artifacts"
    for filename, expected in existing["generated_files_sha256"].items():
        if Path(filename).name != filename or digest(original / filename) != expected:
            raise ValueError(f"Generated source changed: {filename}")
        shutil.copyfile(original / filename, runtime / filename)
    lock = original / "packages.lock.json"
    if digest(lock) != existing["consumer_package_lock_sha256"]:
        raise ValueError("Consumer lock changed")
    shutil.copyfile(lock, runtime / lock.name)
    source = Path(__file__).with_name("SmallApiHistogramProbe.cs")
    shutil.copyfile(source, runtime / "SmallApiHistogramProbe.cs")
    project = runtime / "Consumer.csproj"
    contents = project.read_text(encoding="utf-8")
    split = contents.index(">") + 1
    project.write_text(contents[:split] + "\n  <PropertyGroup><StartupObject>SmallApiHistogramProbe</StartupObject></PropertyGroup>"
                       + '\n  <ItemGroup><Compile Include="SmallApiHistogramProbe.cs" /></ItemGroup>'
                       + contents[split:], encoding="utf-8", newline="\n")
    env = dict(os.environ, DOTNET_NOLOGO="1", DOTNET_CLI_TELEMETRY_OPTOUT="1")
    report = {"status": "started", "engine_revision": existing["engine_revision"], "sdk": existing["sdk"],
              "baseline_consumer_manifest_sha256": digest(attempt / "manifest.json"),
              "generated_source_inputs": existing["generated_files_sha256"],
              "engine_source_manifest_sha256": digest(engine_manifest), "engine_input_count": len(observed["inputs"]),
              "observer_source_sha256": digest(source), "proof_project_sha256": digest(project),
              "packages_lock_sha256": digest(runtime / lock.name), "cases": []}

    def save():
        (args.out / "manifest.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    def run(name, *command):
        try:
            result = subprocess.run([str(args.dotnet.resolve()), *map(str, command)], cwd=runtime, env=env,
                                    capture_output=True, timeout=180)
        except subprocess.TimeoutExpired as failure:
            (args.out / f"{name}.log").write_bytes((failure.stdout or b"") + (failure.stderr or b""))
            raise
        (args.out / f"{name}.log").write_bytes(result.stdout + result.stderr)
        result.check_returncode()

    save()
    try:
        run("restore", "restore", project, "--configfile", runtime / "NuGet.Config", "--locked-mode",
            "--artifacts-path", artifacts)
        run("build", "build", project, "--configuration", "Release", "--no-restore", "--artifacts-path", artifacts,
            "-p:UseSharedCompilation=false", "-warnaserror")
        directory = artifacts / "bin/Consumer/release"
        assembly, = (p.with_name(p.name.removesuffix(".runtimeconfig.json") + ".dll")
                     for p in directory.glob("*.runtimeconfig.json"))
        for mode, expected_checks, expected_measurements in (
            ("healthy", 6, 12), ("publication-fault", 12, 0), ("measurement-fault", 6, 12)
        ):
            output = args.out.resolve() / f"{mode}.json"
            run(mode, assembly, mode, output)
            data = json.loads(output.read_bytes())
            if data["mode"] != mode or len(data["checks"]) != expected_checks or len(data["measurements"]) != expected_measurements:
                raise ValueError(f"Incomplete observation for {mode}")
            report["cases"].append({"mode": mode, "wire_controls": expected_checks,
                                    "measurements": expected_measurements, "output_sha256": digest(output)})
        verify_engine()
        report["status"] = "passed"
    except Exception as failure:
        report.update(status="failed", error=str(failure))
        raise
    finally:
        save()


if __name__ == "__main__":
    main()
