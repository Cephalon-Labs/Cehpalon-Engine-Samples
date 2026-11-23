"""Run the dispatch completion proof against an exact clean Engine revision."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = HERE / "DispatchCorrelationProbe.cs"
DRAIN_SOURCE = HERE / "DispatchDrainProbe.cs"
DRAIN_ENGINE = "5e92ac1c7fa1e150e7e97de6d68e94b31ffba053"
GENERATED_FILES = {
    "Catalog.cs", "Consumer.csproj", "ContractExport.cs", "FixtureHost.cs",
    "NuGet.Config", "Program.cs", "README.md", "SelfTest.cs",
    "appsettings.graphql-only.json", "appsettings.graphql.json", "appsettings.json",
    "appsettings.off.json", "engine-source.json", "global.json",
}


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def read_json(path):
    return json.loads(path.read_bytes())


def replace_once(path, anchor, updated):
    original = path.read_text(encoding="utf-8")
    if original.count(anchor) != 1:
        raise ValueError(f"Expected one proof insertion point in {path.name}.")
    path.write_text(original.replace(anchor, updated, 1), encoding="utf-8", newline="\n")


def verify_inventory(engine, generated):
    observed = read_json(generated / "engine-source.json")
    if (observed["provenance"] != "observed-source-bytes-not-git-attestation"
            or Path(observed["sourceRoot"]).resolve() != engine):
        raise ValueError("Generated Engine source observation points to the wrong checkout.")
    seen = set()
    for item in observed["inputs"]:
        relative = Path(item["path"])
        source = (engine / relative).resolve()
        if (relative.is_absolute() or not source.is_relative_to(engine) or source in seen
                or source.stat().st_size != item["bytes"] or digest(source) != item["sha256"]):
            raise ValueError("Generated Engine inputs changed or escaped the checkout.")
        seen.add(source)
    if (engine / "src/Cehpalon.Engine.Core/OperationRegistry.cs") not in seen:
        raise ValueError("Generated source inventory did not cover the Core dispatcher.")
    return len(seen)


def verify_receipts(result):
    cases = result["cases"]
    if (result["runtime"] != ".NET 11.0.0" or result["outcome"] != "passed"
            or result["allOff"] is not True or result["shutdowns"] != 2 or result["unscopedSignals"] != 0
            or len(cases) != 17 or sum(row["Records"] for row in cases) != 16
            or sum(row["Histograms"] for row in cases) != 34
            or any(row["Records"] and (
                row["TraceMatchesNative"] is not True or row["PrivateValuesExcluded"] is not True
            ) for row in cases)):
        raise ValueError("Protected HTTPS proof has incomplete receipts.")
    overlapping = [row for row in cases if row["Scenario"] == "overlapping-requests"]
    parallel_graphql = [row for row in cases if row["Scenario"] == "parallel-graphql-fields"]
    if (len(overlapping) != 4 or len(parallel_graphql) != 1
            or parallel_graphql[0]["Records"] != 4
            or any(row["OverlappingReads"] != 4 for row in overlapping + parallel_graphql)):
        raise ValueError("Concurrent proof receipts differ from the declared overlap cases.")


def verify_drain_receipts(result):
    if (result["runtime"] != ".NET 11.0.0" or result["outcome"] != "passed"
            or result["wireCases"] != 18 or result["completions"] != 14 or result["histograms"] != 20
            or result["unscopedSignals"] != 0 or len(result["lanes"]) != 2):
        raise ValueError("Drain proof has incomplete receipts.")

    for lane, budget, cleanup, held_transport, held_status in zip(
        result["lanes"], ("total", "tenant"), ("success", "fault"), ("graphql", "http"), (200, 500)
    ):
        if lane["Budget"] != budget or lane["CleanupOutcome"] != cleanup:
            raise ValueError("Drain budget or owned cleanup outcome differs.")
        checked = ("CanceledWaitDidNotReleaseWork", "CompletionAfterOwnedCleanup", "OwnedListenerClosed",
                   "FreshListenerClosed")
        if any(lane[name] is not True for name in checked):
            raise ValueError("Drain waiter, cleanup order or listener proof differs.")
        for case, active, closed in (("Open", 1, False), ("Closed", 1, True), ("HeldCleanup", 1, True),
                                     ("Drained", 0, True), ("RestartedOpen", 0, False)):
            snapshot = {"MaximumConcurrentOperations": 2, "ActiveOperations": active, "IsAdmissionClosed": closed}
            if lane[case] != snapshot:
                raise ValueError("Drain permit accounting differs.")
        expected = []
        for transport in ("http", "graphql"):
            expected.extend([
                (transport, "authorized-after-close", 503 if transport == "http" else 200, 1, 1, "Failure"),
                (transport, "authenticated-denial-after-close", 403 if transport == "http" else 200, 1, 1, "Failure"),
                (transport, "anonymous-after-close", 401, 0, 0, None),
            ])
        expected.extend([
            (held_transport, "admitted-during-close", held_status, 1, 2, cleanup.capitalize()),
            ("http", "fresh-host-owner", 200, 1, 2, "Success"),
            ("graphql", "fresh-host-owner", 200, 1, 2, "Success"),
        ])
        columns = ("Transport", "Scenario", "Status", "Records", "Histograms", "Outcome")
        if [tuple(row[column] for column in columns) for row in lane["Cases"]] != expected:
            raise ValueError("Drain transport or completion receipts differ.")
        if any(row["Records"] and (
            row["TraceMatchesNative"] is not True or row["PrivateValuesExcluded"] is not True
        ) for row in lane["Cases"]):
            raise ValueError("Drain trace or privacy confirmation missing.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet", required=True, type=Path)
    parser.add_argument("--engine-root", required=True, type=Path)
    parser.add_argument("--engine-revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--drain", action="store_true", help="Verify owned graceful drain and fresh activation")
    args = parser.parse_args()
    engine = args.engine_root.resolve(strict=True)
    dotnet = args.dotnet.resolve(strict=True)
    revision = args.engine_revision
    output = (ROOT / args.output).resolve()
    private = (ROOT / ".local").resolve()
    if output == private or not output.is_relative_to(private):
        raise ValueError("Use a new ignored output directory under Samples .local.")
    if re.fullmatch("[0-9a-f]{40}", revision) is None:
        raise ValueError("An exact full Engine commit is required.")
    if args.drain and revision != DRAIN_ENGINE:
        raise ValueError("The drain protocol requires its declared Engine revision.")
    output.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, DOTNET_NOLOGO="1", DOTNET_CLI_TELEMETRY_OPTOUT="1")
    report = {
        "status": "started", "engine_revision": revision,
        "probe_sha256": digest(SOURCE), "drain_probe_sha256": digest(DRAIN_SOURCE),
        "verifier_sha256": digest(Path(__file__)),
        "protocol_sha256": digest(HERE / "README.md"), "steps": []
    }

    def save():
        (output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")

    def run(step, cwd, *command):
        log = output / f"{step}.log"
        try:
            result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, timeout=240)
        except subprocess.TimeoutExpired as error:
            log.write_bytes((error.stdout or b"") + (error.stderr or b""))
            report["steps"].append({"step": step, "timeout_seconds": 240, "log_sha256": digest(log)})
            raise
        log.write_bytes(result.stdout + result.stderr)
        report["steps"].append({"step": step, "exit": result.returncode, "log_sha256": digest(log)})
        if result.returncode != 0:
            raise RuntimeError(f"{step} failed (exit {result.returncode}). See the local log.")
        return result.stdout.decode("utf-8-sig").strip()

    def verify_engine(stage):
        head = run(f"engine-head-{stage}", engine, "git", "rev-parse", "HEAD")
        status = run(f"engine-status-{stage}", engine, "git", "status", "--porcelain")
        if head != revision or status:
            raise ValueError("Engine checkout does not match the selected clean commit.")

    save()
    try:
        verify_engine("before")
        sdk = run("sdk", engine, dotnet, "--version")
        if sdk != "11.0.100" or sdk != read_json(ROOT / "tooling-small-api/engine-lock.json")["sdk"]:
            raise ValueError("Expected the Tools and Samples SDK pin, .NET 11.0.100.")
        report["sdk"] = sdk
        report["samples_revision"] = run("samples-head", ROOT, "git", "rev-parse", "HEAD")
        tooling = engine / "src/Cehpalon.Engine.Tooling/Cehpalon.Engine.Tooling.csproj"
        engine_artifacts = output / "engine-artifacts"
        run("cli-restore", engine, dotnet, "restore", tooling, "--configfile", engine / "NuGet.Config",
            "--locked-mode", "--artifacts-path", engine_artifacts)
        run("cli-build", engine, dotnet, "build", tooling, "-c", "Release",
            "--no-restore", "--artifacts-path", engine_artifacts, "-p:UseSharedCompilation=false", "-warnaserror")
        cli = engine_artifacts / "bin/Cehpalon.Engine.Tooling/release/cehpalon.dll"
        generated = output / "generated"
        run("new", ROOT, dotnet, cli, "new", "--profile", "small-api", "--name", "DispatchCorrelationProof",
            "--output", generated, "--engine-root", engine)
        if {path.name for path in generated.iterdir()} != GENERATED_FILES:
            raise ValueError("Expected the fourteen Small API scaffold files.")
        report["generated_sha256"] = {name: digest(generated / name) for name in sorted(GENERATED_FILES)}
        report["engine_input_count"] = verify_inventory(engine, generated)
        project = generated / "Consumer.csproj"
        fixture = generated / "FixtureHost.cs"
        replace_once(fixture, "new OperationDispatcher(core.Build())",
                     "DispatchCorrelationProbe.CreateDispatcher(core.Build())")
        replace_once(fixture, "app.UseAuthentication();",
                     "app.Use(DispatchCorrelationProbe.ObserveRequest);\n                app.UseAuthentication();")
        overlay = [project, fixture]
        if args.drain:
            replace_once(fixture, "    private ActivationLease? lease;",
                         "    private ActivationLease? lease;\n"
                         "    public Task CloseAdmissionForProof(CancellationToken token = default) =>\n"
                         "        tenantBudget?.DrainAsync(token) ?? budget?.DrainAsync(token)\n"
                         '        ?? throw new InvalidOperationException("Drain proof requires a budget.");')
            catalog = generated / "Catalog.cs"
            replace_once(catalog, "ITenantOperationHandler<SetLabel,Item>,IDisposable",
                         "ITenantOperationHandler<SetLabel,Item>,IDisposable,IAsyncDisposable")
            disposal = "    public void Dispose() => Interlocked.Increment(ref store.Disposals);"
            replace_once(catalog, disposal, disposal + "\n"
                         "    public ValueTask DisposeAsync() => DispatchCorrelationProbe.DisposeOwnedHandler(store, Dispose);")
            overlay.append(catalog)
        else:
            # The optional proof class still compiles in ordinary mode. No drain path can reach this helper.
            replace_once(fixture, "    private ActivationLease? lease;",
                         "    private ActivationLease? lease;\n"
                         "    public Task CloseAdmissionForProof(CancellationToken token = default) =>\n"
                         '        throw new InvalidOperationException("Drain overlay not selected.");')
        replace_once(project, '<Project Sdk="Microsoft.NET.Sdk.Web">',
                     '<Project Sdk="Microsoft.NET.Sdk.Web">\n'
                     '  <PropertyGroup><StartupObject>DispatchCorrelationProbe</StartupObject></PropertyGroup>\n'
                     '  <ItemGroup><Compile Include="DispatchCorrelationProbe.cs" />'
                     '<Compile Include="DispatchDrainProbe.cs" /></ItemGroup>')
        for proof in (SOURCE, DRAIN_SOURCE):
            copy = generated / proof.name
            shutil.copyfile(proof, copy)
            overlay.append(copy)
        report["proof_overlay_sha256"] = {path.name: digest(path) for path in overlay}

        artifacts = output / "consumer-artifacts"
        lock = generated / "packages.lock.json"
        restore = (dotnet, "restore", project, "--configfile", generated / "NuGet.Config",
                   "--artifacts-path", artifacts)
        run("consumer-restore", generated, *restore)
        report["packages_lock_sha256"] = digest(lock)
        run("consumer-locked-restore", generated, *restore, "--locked-mode")
        if digest(lock) != report["packages_lock_sha256"]:
            raise ValueError("Locked restore changed the generated package lock.")
        shutil.copyfile(lock, output / "consumer-packages.lock.json")
        run("consumer-build", generated, dotnet, "build", project, "-c", "Release",
            "--no-restore", "--artifacts-path", artifacts, "-p:UseSharedCompilation=false", "-warnaserror")
        binary = artifacts / "bin/Consumer/release"
        runtime, = binary.glob("*.runtimeconfig.json")
        assembly = runtime.with_name(runtime.name.removesuffix(".runtimeconfig.json") + ".dll")
        report["consumer_binary_sha256"] = {
            path.name: digest(path) for path in (runtime, assembly, binary / "Cehpalon.Engine.Core.dll")
        }
        receipt = output / ("drain-results.json" if args.drain else "trace-results.json")
        mode = ("--drain",) if args.drain else ()
        run("wire-proof", generated, dotnet, assembly, receipt, *mode)
        verify = verify_drain_receipts if args.drain else verify_receipts
        verify(read_json(receipt))
        verify_engine("after")
        if verify_inventory(engine, generated) != report["engine_input_count"]:
            raise ValueError("Engine source inputs changed across proof.")
        report["wire_sha256"] = digest(receipt)
        report["status"] = "passed"
    except Exception as error:
        report.update(status="failed", failure=str(error))
        raise
    finally:
        save()


if __name__ == "__main__":
    main()
