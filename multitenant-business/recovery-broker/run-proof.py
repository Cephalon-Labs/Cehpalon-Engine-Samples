"""Run the exact owned RabbitMQ restart fixture and retain each attempt."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import secrets
import socket
import struct
import subprocess
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PROJECT = HERE / "BrokerRestartProof.csproj"
IMAGE = "registry-1.docker.io/library/rabbitmq@sha256:184d4ae2a5d7fd4cbe1ad7165d1fb6c1377735ed2744c6be478deed5e8f0ba88"
CONFIG = "sha256:f145e7a82c858bcb253703571f5dce9ca48854358a68025c638e3fb5a4318969"
QUEUE = "cephalon-restart"
SDK = "11.0.100"
LABEL = "io.cephalon.broker-fixture"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except ConnectionRefusedError:
        return False


def amqp_ready(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.75) as connection:
            connection.sendall(b"AMQP\x00\x00\x09\x01")
            with connection.makefile("rb") as reply:
                header = reply.read(11)
    except (ConnectionError, TimeoutError):
        return False
    if len(header) != 11:
        return False
    frame_type, channel, size, class_id, method_id = struct.unpack("!BHIHH", header)
    return (frame_type, channel, class_id, method_id) == (1, 0, 10, 10) and size >= 4


def wait_until(action, description, seconds=60):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        observed = action()
        if observed is not None:
            return observed
        time.sleep(0.25)
    raise RuntimeError(f"Timed out waiting for {description}.")


class Proof:
    def __init__(self, dotnet, out, revision):
        self.dotnet = dotnet
        self.out = out
        self.revision = revision
        self.name = "cephalon-broker-" + secrets.token_hex(12)
        self.container = None
        self.ports = set()
        self.seed = None
        self.fixture_value = secrets.token_urlsafe(32)
        self.environment = dict(os.environ, DOTNET_NOLOGO="1", DOTNET_CLI_TELEMETRY_OPTOUT="1")
        for variable in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
            self.environment.pop(variable, None)
        self.report = {"status": "started", "samples_revision": revision, "restarts": []}

    def write(self):
        (self.out / "report.json").write_text(json.dumps(self.report, indent=2) + "\n",
                                            encoding="utf-8", newline="\n")

    def run(self, stage, command, *, extra_env=None, timeout=30, check=True):
        environment = dict(self.environment, **(extra_env or {}))
        with (self.out / f"{stage}.log").open("ab") as journal:
            try:
                process = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, timeout=timeout)
            except subprocess.TimeoutExpired as error:
                journal.write((error.stdout or b"") + (error.stderr or b""))
                raise RuntimeError(f"{stage} exceeded its deadline.") from error
            journal.write(process.stdout + process.stderr)
        if check:
            require(process.returncode == 0, f"{stage} failed with exit {process.returncode}. See the private log.")
        return process

    def docker(self, stage, *args, **options):
        return self.run(stage, ("docker", "--context", "default", *args), **options)

    @staticmethod
    def text(command):
        return command.stdout.decode("utf-8").strip()

    def source(self):
        head = self.text(self.run("source", ("git", "rev-parse", "HEAD")))
        status = self.text(self.run("source", ("git", "status", "--porcelain")))
        require(head == self.revision and not status, "Expected the selected clean Samples commit.")
        paths = (*sorted(HERE.glob("*.*")), ROOT / "global.json", ROOT / "NuGet.Config")
        return {path.relative_to(ROOT).as_posix(): digest(path) for path in paths if path.is_file()}

    def build(self):
        require(platform.system() == "Linux" and platform.machine() == "x86_64", "Expected Linux x86_64.")
        context = self.text(self.docker("context", "context", "inspect", "default",
                                        "--format", "{{.Endpoints.docker.Host}}"))
        require(context == "unix:///var/run/docker.sock", "Expected the local default Docker socket.")
        docker_version = self.text(self.docker("docker-info", "info", "--format",
                                               "{{.ServerVersion}} {{.OSType}} {{.Architecture}}"))
        require(docker_version.endswith(" linux x86_64"), "Expected a Linux amd64 Docker daemon.")
        sdk = self.text(self.run("sdk", (self.dotnet, "--version")))
        require(sdk == SDK == read(ROOT / "global.json")["sdk"]["version"], "Expected pinned SDK 11.0.100.")
        self.report.update(sdk=sdk, docker=docker_version, host=platform.platform(), source=self.source())
        artifacts = self.out / "artifacts"
        self.run("restore", (self.dotnet, "restore", PROJECT, "--configfile", ROOT / "NuGet.Config",
                             "--locked-mode", "--artifacts-path", artifacts), timeout=180)
        self.run("build", (self.dotnet, "build", PROJECT, "--no-restore", "-c", "Release",
                           "--artifacts-path", artifacts, "-warnaserror"), timeout=180)
        folder = artifacts / "bin/BrokerRestartProof/release"
        self.report["execution_artifacts"] = {
            path.name: digest(path) for path in sorted(folder.iterdir()) if path.suffix in {".dll", ".json"}
        }
        return folder / "BrokerRestartProof.dll"

    def start_fixture(self):
        fields = "{{.Id}} {{.Os}} {{.Architecture}}"
        image = self.docker("image", "image", "inspect", "--format", fields, IMAGE, check=False)
        if image.returncode != 0:
            self.docker("image-pull", "pull", "--platform", "linux/amd64", IMAGE, timeout=180)
            image = self.docker("image", "image", "inspect", "--format", fields, IMAGE)
        require(self.text(image) == f"{CONFIG} linux amd64", "Pinned image identity or platform differed.")
        label = f"{LABEL}={self.name}"
        self.docker("network", "network", "create", "--driver", "bridge", "--label", label, self.name)
        self.docker("volume", "volume", "create", "--label", label, self.name)
        container = self.text(self.docker("container", "container", "create", "--platform", "linux/amd64",
            "--name", self.name, "--label", label, "--network", self.name,
            "--publish", "127.0.0.1::5672", "--env", "RABBITMQ_DEFAULT_USER=cephalon_fixture",
            "--env", "RABBITMQ_DEFAULT_PASS", "--mount", f"type=volume,source={self.name},target=/var/lib/rabbitmq",
            IMAGE, extra_env={"RABBITMQ_DEFAULT_PASS": self.fixture_value}))
        require(re.fullmatch("[a-f0-9]{64}", container), "Expected the full owned container ID.")
        self.container = container
        self.report["fixture"] = {"image": IMAGE, "config_digest": CONFIG, "platform": "linux/amd64"}
        return self.start()

    def inspect_identity(self):
        label = '{{index .Config.Labels "' + LABEL + '"}}'
        fields = "{{.Id}} {{.Image}} {{.Config.Hostname}} " + label
        identity = self.text(self.docker("ownership", "container", "inspect", "--format", fields, self.container))
        require(identity == f"{self.container} {CONFIG} {self.container[:12]} {self.name}", "Owned fixture identity changed.")
        mount = self.text(self.docker("ownership", "container", "inspect", "--format",
            "{{range .Mounts}}{{println .Type .Name .Destination}}{{end}}", self.container))
        require(mount == f"volume {self.name} /var/lib/rabbitmq", "Expected the same owned broker volume.")
        return self.text(self.docker("ownership", "container", "inspect", "--format",
                                     "{{.State.StartedAt}}", self.container))

    def start(self):
        self.inspect_identity()
        self.docker("start", "container", "start", self.container)
        binding = self.text(self.docker("listener", "container", "port", self.container, "5672/tcp"))
        match = re.fullmatch(r"127\.0\.0\.1:([0-9]+)", binding)
        require(match is not None, "Expected exactly one loopback AMQP binding.")
        port = int(match[1])
        self.ports.add(port)

        def ready():
            active = self.text(self.docker("ready", "container", "inspect", "--format",
                                          "{{.State.Running}}", self.container))
            require(active == "true", "The owned broker exited during startup.")
            return True if amqp_ready(port) else None

        wait_until(ready, "AMQP Connection.Start from the broker")
        version = self.text(self.docker("broker-version", "container", "exec", self.container,
                                        "rabbitmq-diagnostics", "-q", "server_version"))
        erlang = self.text(self.docker("broker-version", "container", "exec", self.container,
                                       "rabbitmq-diagnostics", "-q", "erlang_version"))
        require(version == "4.4.0" and re.search(r"\b29\.1\.2\b", erlang), "Running broker versions differed.")
        self.report["fixture"].update(server=version, erlang_otp="29.1.2", client="7.2.2", runtime="11.0.0")
        return port

    def queue(self, ready, unacknowledged):
        expected = {"name": QUEUE, "type": "quorum", "durable": True,
                    "messages_ready": ready, "messages_unacknowledged": unacknowledged}

        def inspect():
            result = self.docker("queue-state", "container", "exec", self.container, "rabbitmqctl", "-q",
                                 "list_queues", "--formatter", "json", *expected, check=False, timeout=20)
            if result.returncode != 0:
                return None
            rows = json.loads(result.stdout)
            return rows[0] if rows == [expected] else None

        return wait_until(inspect, f"durable quorum queue state {ready} ready, {unacknowledged} unacknowledged")

    def disconnect(self, port):
        before = self.inspect_identity()
        self.docker("stop", "container", "stop", "--timeout", "30", self.container, timeout=40)
        status = self.text(self.docker("stop-verification", "container", "inspect", "--format",
                                       "{{.State.Running}} {{.State.ExitCode}}", self.container))
        require(status == "false 0", "Expected a verified graceful stop with exit zero.")
        wait_until(lambda: True if not port_open(port) else None, "stopped loopback listener", seconds=15)
        return before

    def restart(self, before):
        port = self.start()
        require(self.inspect_identity() != before, "The same container did not start a new broker process.")
        self.report["restarts"].append({
            "graceful_exit": 0, "listener_closed_before_restart": True, "same_container_and_volume": True,
            "new_process_observed": True,
        })
        return port

    def client_env(self, port):
        return {"CEPHALON_BROKER_FIXTURE_PORT": str(port), "CEPHALON_BROKER_FIXTURE_VALUE": self.fixture_value}

    def exercise(self, assembly):
        port = self.start_fixture()
        with (self.out / "seed.log").open("xb") as journal:
            self.seed = subprocess.Popen((self.dotnet, assembly, "seed", self.out), cwd=ROOT,
                env=dict(self.environment, **self.client_env(port)), stdout=journal, stderr=subprocess.STDOUT)
        seed_path = self.out / "seed-ready.json"

        def seed_ready():
            require(self.seed.poll() is None, "The seed client exited before broker stop.")
            return read(seed_path) if seed_path.exists() else None

        seed = wait_until(seed_ready, "publisher, acknowledgement and held delivery receipts")
        require(seed == {"confirmed": 3, "payloadsMatched": True, "acknowledgedBeforeStop": 1,
                         "acknowledgementChannelClosed": True, "deliveredUnacknowledged": 1, "ready": 1,
                         "consumerOpen": True}, "Seed receipt differed.")
        self.report["seed"] = seed
        self.report["before_stop"] = self.queue(1, 1)
        require(self.seed.poll() is None, "The seed process must remain active through broker stop.")
        before = self.disconnect(port)
        require(self.seed.wait(timeout=20) == 0, "The seed client failed to observe shutdown.")
        stopped = read(self.out / "seed-stopped.json")
        require(stopped == {"connectionClosed": True, "autoRecovery": False}, "Seed client closure was not observed.")
        self.report["seed_stop"] = stopped
        port = self.restart(before)
        self.report["after_first_restart"] = self.queue(2, 0)
        self.run("recover", (self.dotnet, assembly, "recover", self.out), extra_env=self.client_env(port), timeout=45)
        self.report["recovery"] = read(self.out / "first-restart.json")
        self.report["after_acknowledgement"] = self.queue(0, 0)
        port = self.restart(self.disconnect(port))
        self.report["after_second_restart"] = self.queue(0, 0)
        self.run("verify-empty", (self.dotnet, assembly, "verify-empty", self.out),
                 extra_env=self.client_env(port), timeout=45)
        self.report["empty"] = read(self.out / "second-restart.json")

    def cleanup(self):
        # Match the unique label on objects created by this invocation before removal.
        label = f"label={LABEL}={self.name}"
        containers = self.text(self.docker("cleanup", "container", "ls", "--all", "--quiet", "--no-trunc",
                                           "--filter", label)).splitlines()
        require(len(containers) <= 1 and (self.container is None or containers in ([], [self.container])),
                "Cleanup container ownership was ambiguous.")
        for container in containers:
            require(re.fullmatch("[a-f0-9]{64}", container), "Cleanup requires a complete fixture container ID.")
            status = self.text(self.docker("cleanup", "container", "inspect", "--format", "{{.State.Running}}", container))
            if status == "true":
                self.docker("cleanup", "container", "stop", "--timeout", "30", container, timeout=40)
            self.docker("cleanup", "container", "rm", container)
        if self.seed is not None and self.seed.poll() is None:
            self.seed.terminate()
            self.seed.wait(timeout=15)
        for kind in ("volume", "network"):
            names = self.text(self.docker("cleanup", kind, "ls", "--filter", label, "--format", "{{.Name}}")).splitlines()
            require(names in ([], [self.name]), f"Cleanup {kind} ownership was ambiguous.")
            if names:
                self.docker("cleanup", kind, "rm", self.name)
            require(not self.text(self.docker("cleanup", kind, "ls", "--filter", label, "--format", "{{.Name}}")),
                    f"Owned {kind} remained after cleanup.")
        require(not self.text(self.docker("cleanup", "container", "ls", "--all", "--quiet", "--filter", label)),
                "Owned container remained after cleanup.")
        for port in self.ports:
            wait_until(lambda: True if not port_open(port) else None, "removed broker listener", seconds=15)
        self.report["cleanup"] = {"container_gone": True, "volume_gone": True, "network_gone": True,
                                  "loopback_closed": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet", required=True, type=Path)
    parser.add_argument("--samples-revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = (ROOT / args.output).resolve()
    private = (ROOT / ".local").resolve()
    require(output != private and output.is_relative_to(private), "Use a new Samples .local directory.")
    require(re.fullmatch("[a-f0-9]{40}", args.samples_revision), "Expected full Samples SHA.")
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    proof = Proof(args.dotnet.resolve(strict=True), output, args.samples_revision)
    proof.write()
    fixture_attempted = False
    try:
        assembly = proof.build()
        fixture_attempted = True
        proof.exercise(assembly)
        require(proof.source() == proof.report["source"], "Samples source changed during proof.")
        proof.report["status"] = "passed"
    except Exception as error:
        proof.report.update(status="failed", failure=str(error))
        raise
    finally:
        try:
            if fixture_attempted:
                if proof.report["status"] == "failed" and proof.container is not None:
                    try:
                        proof.docker("broker-private", "container", "logs", proof.container, check=False)
                    finally:
                        proof.cleanup()
                else:
                    proof.cleanup()
        except Exception as error:
            proof.report.update(status="failed", cleanup_failure=str(error))
            raise
        finally:
            proof.write()


if __name__ == "__main__":
    main()
