"""No-network tests for the fixed driver protocol and owned process lifecycle."""

import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import small_api_remote_driver as remote


JOB = "f1" * 16
ARGS = ["--load-client", "--url=https://127.0.0.1:4443", "--transport=http", "--rate=1000",
        "--warmup=60", "--seconds=180", "--preflight-only=true"]


def framed(files, *, receipt=None):
    sizes = sum(len(value) for _, value in files)
    rows = [remote.message({"type": "begin", "job_id": JOB, "protocol": remote.PROTOCOL,
                            "files": len(files), "bytes": sizes})]
    for name, content in files:
        rows.extend([remote.message({"type": "file", "path": name, "bytes": len(content),
                     "sha256": hashlib.sha256(content).hexdigest()}), content])
    rows.append(remote.message({"type": "end", "receipt": receipt or {"job_id": JOB, "state": "exited",
                               "returncode": 0, "child_joined": True, "failure": None}}))
    return io.BytesIO(b"".join(rows))


class ProtocolTests(unittest.TestCase):
    def test_arguments_unchanged_and_lab_preflight_only(self):
        self.assertEqual(remote.driver_arguments(ARGS, "127.0.0.1", True)["rate"], "1000")
        self.assertEqual(remote.driver_arguments(ARGS[:-1], "127.0.0.1", False)["seconds"], "180")
        for values in (ARGS[:-1], [*ARGS[:-1], "--output=/tmp/redirect"],
                       [*ARGS[:1], "--url=https://PRIVATE@example.com:4443", *ARGS[2:]],
                       [*ARGS[:1], "--url=https://127.0.0.1:4443/private", *ARGS[2:]],
                       [*ARGS[:1], "--url=https://127.0.0.1:4443; id", *ARGS[2:]],
                       [*ARGS[:-1], "--warmup-only=true"], [*ARGS[:-1], "--seconds=1"]):
            with self.subTest(values=values), self.assertRaises(remote.RemoteDriverError):
                remote.driver_arguments(values, "127.0.0.1", True)

    def test_public_or_unapproved_loopback_target_is_rejected(self):
        with self.assertRaises(remote.RemoteDriverError):
            remote.private_app_addresses("8.8.8.8", 443, False)
        with self.assertRaises(remote.RemoteDriverError):
            remote.private_app_addresses("127.0.0.1", 443, False)
        self.assertEqual(remote.private_app_addresses("127.0.0.1", 443, True), ["127.0.0.1"])

    def test_invalid_ssh_targets_and_explicit_options(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            identity = base / "identity"
            known_hosts = base / "known hosts"
            identity.write_text("fixture only")
            known_hosts.write_text("fixture only")
            subject = remote.RemoteDriver.__new__(remote.RemoteDriver)
            subject.app_host = "172.20.0.3"
            subject.lab = True
            subject.config = {"host": "127.0.0.1", "port": 2222, "user": "benchmark", "identity_file": str(identity),
                              "known_hosts": str(known_hosts), "remote_helper": "/owned spaces/helper 'quote'.py",
                              "remote_dotnet": "/usr/share/dotnet/dotnet", "remote_publish_dir": "/owned/publish",
                              "remote_job_root": "/owned/jobs"}
            if sys.platform != "win32":
                command = subject._ssh_command()
                for option in ("BatchMode=yes", "StrictHostKeyChecking=yes", "IdentityAgent=none", "ForwardAgent=no",
                               "ForwardX11=no", "ClearAllForwardings=yes", "ProxyCommand=none", "UpdateHostKeys=no"):
                    self.assertIn(option, command)
                self.assertEqual(shlex.split(command[-1])[3], subject.config["remote_helper"])
                self.assertEqual(command[-2], "127.0.0.1")
            subject.config["host"] = "-oProxyCommand=sh"
            with self.assertRaises(remote.RemoteDriverError):
                subject._ssh_command()

    def test_evidence_roundtrip_failure_and_recovery_never_overwrites(self):
        files = [("stdout.txt", b"partial output\n"), ("nested/results.json", b"{}\n")]
        receipt = {"job_id": JOB, "state": "exited", "returncode": 1, "child_joined": True, "failure": None}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self.assertEqual(remote.receive_evidence(framed(files, receipt=receipt), root, JOB)["receipt"]["returncode"], 1)
            self.assertEqual((root / "nested/results.json").read_bytes(), files[1][1])
            remote.receive_evidence(framed(files, receipt=receipt), root, JOB)
            with self.assertRaises(remote.RemoteDriverError):
                remote.receive_evidence(framed([("stdout.txt", b"replacement")], receipt=receipt), root, JOB)
            self.assertEqual((root / "stdout.txt").read_bytes(), files[0][1])

    def test_evidence_rejects_traversal_reserved_paths_and_duplicate_rows(self):
        for name in ("../outer.txt", "/abs.txt", "a/../outer.txt", "a\\b.txt", "remote-result.json", "invocation.json"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises(remote.RemoteDriverError):
                    remote.receive_evidence(framed([(name, b"data")]), Path(temporary).resolve(), JOB)
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(remote.RemoteDriverError):
                remote.receive_evidence(framed([("a", b"data"), ("a", b"data")]), Path(temporary).resolve(), JOB)

    def test_truncated_and_unverified_join_are_not_a_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fragment = framed([("partial.txt", b"precious")]).getvalue().split(b"precious")[0] + b"pre"
            with self.assertRaises(remote.RemoteDriverError):
                remote.receive_evidence(io.BytesIO(fragment), root, JOB)
            self.assertFalse((root / "partial.txt").exists())
            [stored] = (root / ".remote-transfer-parts").iterdir()
            self.assertEqual(stored.read_bytes(), b"pre")
            with self.assertRaises(remote.RemoteDriverError):
                remote.receive_evidence(framed([], receipt={"job_id": JOB, "state": "exited", "returncode": 0,
                                                           "child_joined": False}), root, JOB)

    @unittest.skipUnless(sys.platform == "linux", "Linux symlink and FIFO fixture")
    def test_tree_and_local_destination_reject_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "elsewhere"
            source.mkdir()
            (root / "link").symlink_to(source, target_is_directory=True)
            with self.assertRaises(remote.RemoteDriverError):
                remote.tree_files(root, 8)
            with self.assertRaises(remote.RemoteDriverError):
                remote.receive_evidence(framed([("link/attempt.txt", b"data")]), root, JOB)
            self.assertFalse((source / "attempt.txt").exists())


@unittest.skipUnless(sys.platform == "linux" and shutil.which("openssl"), "Linux process lease and local CA fixture")
class LocalHelperTests(unittest.TestCase):
    """Connect to the helper via a subprocess. No SSH or load process is launched."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.publish = self.root / "publish"
        self.publish.mkdir()
        self.jobs = self.root / "jobs"
        self.jobs.mkdir(mode=0o700)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.assembly = self.publish / remote.ASSEMBLY
        self.assembly.write_text("no load")
        self.assembly.with_suffix(".deps.json").write_text("{}")
        self.assembly.with_suffix(".runtimeconfig.json").write_text(json.dumps({"runtimeOptions": {"tfm": "net11.0",
            "frameworks": [{"name": "Microsoft.NETCore.App", "version": "11.0.0"},
                           {"name": "Microsoft.AspNetCore.App", "version": "11.0.0"}]}}))
        self.helper = self.root / "small_api_remote_driver.py"
        shutil.copyfile(remote.__file__, self.helper)
        (self.root / remote.RESOURCE_MODULE).write_text(
            "import os\nclass ReferenceResourceError(RuntimeError): pass\n"
            "def capture_driver_resources():\n return {'affinity_cpus': sorted(os.sched_getaffinity(0))}\n")
        self.dotnet = self.root / "fake-dotnet"
        self.dotnet.write_text(f"#!{sys.executable}\n" + """import sys, time
from pathlib import Path
if sys.argv[1] == '--version':
    print('11.0.100')
elif sys.argv[1] == '--list-runtimes':
    print('Microsoft.NETCore.App 11.0.0 [fixture]')
    print('Microsoft.AspNetCore.App 11.0.0 [fixture]')
else:
    output = Path(next(arg[9:] for arg in sys.argv if arg.startswith('--output=')))
    (output / 'partial-raw.txt').write_text('retained')
    print('fake driver output', flush=True)
    if Path(sys.argv[1]).read_text() == 'delay':
        time.sleep(30)
    else:
        sys.exit(1)
""")
        self.dotnet.chmod(0o700)
        private = self.root / "test-only-ca.key"
        cert = self.root / "test-only-ca.pem"
        subprocess.run(["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-subj", "/CN=driver-test-only",
                        "-addext", "basicConstraints=critical,CA:TRUE", "-days", "1", "-keyout", private,
                        "-out", cert], check=True, capture_output=True)
        self.ca = subprocess.check_output(["openssl", "x509", "-in", cert, "-outform", "DER"])
        self.addCleanup(private.unlink, missing_ok=True)
        self._ssh = patch.dict(os.environ, {"SSH_CONNECTION": "127.0.0.1 54321 127.0.0.1 22"})
        self._ssh.start()
        self.addCleanup(self._ssh.stop)

    def driver(self):
        subject = remote.RemoteDriver.__new__(remote.RemoteDriver)
        subject.lab = True
        subject.app_host = "127.0.0.1"
        subject.sdk = "11.0.100"
        subject.helper_sha = remote.digest(self.helper)
        subject.resource_sha = remote.digest(self.root / remote.RESOURCE_MODULE)
        subject.deployment = remote.deployment(self.assembly)
        subject._check_host_pin = lambda: None
        subject.command = [sys.executable, "-I", "-B", self.helper, "--remote-helper", "--lab", "--dotnet", self.dotnet,
                           "--publish", self.publish, "--job-root", self.jobs, "--app-host", subject.app_host]
        subject.probe()
        return subject

    def test_failed_driver_returns_full_verified_evidence(self):
        driver = self.driver()
        job = driver.start(ARGS, self.ca, self.evidence, 10)
        self.addCleanup(job.terminate)
        self.assertEqual(job.wait(timeout=12), 1)
        self.assertIsNone(job.failure)
        self.assertEqual(job.result["receipt"]["state"], "exited")
        self.assertTrue(job.result["receipt"]["child_joined"])
        self.assertEqual((self.evidence / "partial-raw.txt").read_text(), "retained")
        self.assertFalse((self.jobs / job.job_id / "root-ca.der").exists())
        job.terminate()
        job.kill()

    def test_closing_stdin_lease_joins_and_preserves_partial_files(self):
        self.assembly.write_text("delay")
        driver = self.driver()
        job = driver.start(ARGS, self.ca, self.evidence, 10)
        self.addCleanup(job.terminate)
        marker = self.jobs / job.job_id / "raw/partial-raw.txt"
        deadline = time.monotonic() + 5
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(.05)
        self.assertTrue(marker.exists())
        job.terminate()
        self.assertEqual(job.wait(timeout=6), 124)
        self.assertEqual(job.result["receipt"]["state"], "lease-closed")
        self.assertTrue(job.result["receipt"]["child_joined"])
        self.assertEqual((self.evidence / marker.name).read_text(), "retained")

    def test_server_deadline_joins_without_controller_cancellation(self):
        self.assembly.write_text("delay")
        driver = self.driver()
        job = driver.start(ARGS, self.ca, self.evidence, 2)
        self.addCleanup(job.terminate)
        self.assertEqual(job.wait(timeout=6), 124)
        self.assertEqual(job.result["receipt"]["state"], "deadline")
        self.assertTrue(job.result["receipt"]["child_joined"])
        self.assertEqual((self.evidence / "partial-raw.txt").read_text(), "retained")

    def test_recovery_only_retrieves_existing_joined_evidence(self):
        driver = self.driver()
        job = driver.start(ARGS, self.ca, self.evidence, 10)
        self.addCleanup(job.terminate)
        self.assertEqual(job.wait(timeout=12), 1)
        recovered = self.root / "recovered"
        recovered.mkdir()
        self.assertEqual(driver.recover(job.job_id, recovered), 1)
        self.assertEqual(sorted(path.name for path in self.jobs.iterdir()), [job.job_id])
        self.assertEqual((recovered / "partial-raw.txt").read_bytes(), (self.evidence / "partial-raw.txt").read_bytes())

    def test_source_drift_refuses_before_owned_child_launch(self):
        driver = self.driver()
        self.assembly.write_text("changed after probe")
        job = driver.start(ARGS, self.ca, self.evidence, 10)
        self.addCleanup(job.terminate)
        self.assertEqual(job.wait(timeout=12), 125)
        self.assertEqual(job.result["receipt"]["state"], "failed-before-launch")
        self.assertIsNone(job.result["receipt"]["child"])

    def test_connection_failure_has_stable_exit_and_ambiguous_join(self):
        driver = self.driver()
        driver.command = [sys.executable, "-c", "import sys; sys.stdin.readline(); print('interrupted')"]
        job = driver.start(ARGS, self.ca, self.evidence, 10)
        self.addCleanup(job.terminate)
        self.assertEqual(job.wait(timeout=5), 125)
        self.assertEqual(job.poll(), 125)
        self.assertIsNone(job.result)
        self.assertIsInstance(job.failure, remote.RemoteDriverError)
        self.assertTrue((self.evidence / "remote-transfer-failure.json").exists())
        job.terminate()
        job.kill()


if __name__ == "__main__":
    unittest.main()
