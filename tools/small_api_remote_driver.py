"""Fixed Small API load-driver transport for explicitly provisioned SSH hosts."""

import argparse
import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import selectors
import shlex
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit


ASSEMBLY = "SmallApi.Benchmark.dll"
RESOURCE_MODULE = "small_api_reference_resources.py"
PROTOCOL = 1
MAX_MESSAGE = 32 * 1024
MAX_CA = 12 * 1024
MAX_FILES = 128
MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
BLOCK = 256 * 1024
PRIVATE_NETWORKS = tuple(map(ipaddress.ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")))
HEX64 = re.compile(r"[0-9a-f]{64}")
JOB_ID = re.compile(r"[0-9a-f]{32}")
COMPONENT = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,119}")
DRIVER_OPTIONS = {"url", "transport", "rate", "warmup", "seconds"}
DRIVER_MODES = {"warmup-only", "preflight-only"}


class RemoteDriverError(RuntimeError):
    """A remote transport, deployment, or cleanup receipt failed validation."""


def require(condition, message):
    if not condition:
        raise RemoteDriverError(message)


def regular_input(path):
    require(stat.S_ISREG(path.lstat().st_mode), "Expected a regular source file.")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) |
                         getattr(os, "O_BINARY", 0))
    try:
        require(stat.S_ISREG(os.fstat(descriptor).st_mode), "Source file type changed.")
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def digest(path):
    with regular_input(path) as source:
        hashed = hashlib.sha256()
        for chunk in iter(lambda: source.read(BLOCK), b""):
            hashed.update(chunk)
    return hashed.hexdigest()


def remote_path(value):
    require(isinstance(value, str) and 1 < len(value) <= 4096 and value.startswith("/")
            and not value.startswith("//") and not any(ord(char) < 32 or ord(char) == 127 for char in value)
            and ".." not in PurePosixPath(value).parts, "Expected an absolute provisioned remote path.")
    return value


def host_name(value):
    require(isinstance(value, str) and 0 < len(value) <= 253 and "%" not in value, "Invalid configured host name.")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        require(all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", part)
                    for part in value.split(".")), "Invalid configured host name.")
        return value.lower()


def evidence_path(value):
    require(isinstance(value, str) and 0 < len(value) <= 240, "Invalid evidence path.")
    parts = value.split("/")
    require(len(parts) <= 8 and all(COMPONENT.fullmatch(part) for part in parts), "Invalid evidence path.")
    require(not parts[0].startswith("remote-") and parts[0] != "invocation.json", "Reserved evidence path.")
    return parts


def driver_arguments(arguments, app_host, lab):
    require(isinstance(arguments, (list, tuple)) and 6 <= len(arguments) <= 7 and arguments[0] == "--load-client",
            "Expected only canonical load-client arguments.")
    options = {}
    for value in arguments[1:]:
        require(isinstance(value, str) and value.startswith("--") and "=" in value and len(value) <= 512
                and not any(ord(char) < 33 or ord(char) == 127 for char in value), "Invalid driver argument.")
        key, raw = value[2:].split("=", 1)
        require(key in DRIVER_OPTIONS | DRIVER_MODES and key not in options, "Unexpected or repeated driver argument.")
        options[key] = raw
    modes = options.keys() & DRIVER_MODES
    require(DRIVER_OPTIONS <= options.keys() and len(modes) <= 1 and all(options[key] == "true" for key in modes),
            "Incomplete or conflicting canonical driver arguments.")
    require(not lab or modes == {"preflight-only"}, "Lab driver permits only the bounded collector preflight.")
    require(options["transport"] in {"http", "graphql"} and options["warmup"] == "60", "Unexpected transport or warmup.")
    if "warmup-only" in modes:
        require(options["rate"] == "1000" and options["seconds"] == "1", "Unexpected idle warmup dimensions.")
    else:
        require(options["rate"] in {"100", "500", "1000", "2000"} and options["seconds"] == "180",
                "Unexpected fixed load dimensions.")
    try:
        uri = urlsplit(options["url"])
        port = uri.port
    except ValueError as error:
        raise RemoteDriverError("Invalid private HTTPS app endpoint.") from error
    require(uri.scheme == "https" and uri.hostname is not None and host_name(uri.hostname) == app_host
            and uri.username is None and uri.password is None and uri.path in {"", "/"} and not uri.query
            and not uri.fragment and port is not None and port > 0,
            "Only the explicitly configured private HTTPS app endpoint is allowed.")
    return options


def private_app_addresses(host, port, lab):
    addresses = {ipaddress.ip_address(row[4][0]) for row in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    require(addresses and all(any(address in network for network in PRIVATE_NETWORKS) or lab and address.is_loopback
                              for address in addresses), "App endpoint must resolve entirely to the private test network.")
    return sorted(map(str, addresses))


def read_message(stream):
    raw = stream.readline(MAX_MESSAGE + 1)
    require(raw and len(raw) <= MAX_MESSAGE and raw.endswith(b"\n"), "Incomplete or oversized remote message.")
    value = json.loads(raw)
    require(isinstance(value, dict), "Expected a remote JSON object.")
    return value


def message(value):
    raw = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii") + b"\n"
    require(len(raw) <= MAX_MESSAGE, "Remote protocol message is oversized.")
    return raw


def write_json(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as output:
        json.dump(value, output, indent=2, allow_nan=False)
        output.write("\n")


def validate_public_ca(value):
    require(isinstance(value, bytes) and 0 < len(value) <= MAX_CA, "Invalid public CA size.")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=value)
    require(context.get_ca_certs(binary_form=True) == [value], "Expected one DER-encoded public CA certificate.")
    return value


def directory_without_links(path):
    require(path.is_absolute() and path.is_dir() and path.resolve() == path, "Expected a provisioned directory without links.")


def tree_files(root, limit):
    directory_without_links(root)
    files = []
    directory_count = 0
    for directory, directories, names in os.walk(root, followlinks=False):
        current = Path(directory)
        directory_count += 1
        require(directory_count <= limit and len(files) + len(names) <= limit and
                len(current.relative_to(root).parts) <= 8, "Transfer tree exceeds its bounded shape.")
        for name in directories:
            require(stat.S_ISDIR((current / name).lstat().st_mode), "Directory link found in transfer tree.")
        for name in names:
            path = current / name
            require(stat.S_ISREG(path.lstat().st_mode), "Nonregular file found in transfer tree.")
            files.append(path)
    return sorted(files)


def deployment(assembly):
    require(assembly.name == ASSEMBLY and assembly.is_file(), "Expected the exact Small API publish assembly.")
    files = tree_files(assembly.parent, 512)
    hashes = [(path.relative_to(assembly.parent).as_posix(), digest(path)) for path in files]
    runtime = assembly.with_suffix(".runtimeconfig.json")
    dependencies = assembly.with_suffix(".deps.json")
    config = json.loads(runtime.read_bytes())["runtimeOptions"]
    frameworks = config.get("frameworks", [])
    require(config.get("tfm") == "net11.0" and {(row["name"], row["version"]) for row in frameworks} == {
        ("Microsoft.NETCore.App", "11.0.0"), ("Microsoft.AspNetCore.App", "11.0.0")},
        "Expected a framework-dependent publish for .NET and ASP.NET Core 11.0.0.")
    return {"assembly_sha256": digest(assembly), "runtimeconfig_sha256": digest(runtime),
            "deps_sha256": digest(dependencies), "publish_files": len(files),
            "publish_sha256": hashlib.sha256(json.dumps(hashes, ensure_ascii=True, separators=(",", ":")).encode("ascii")).hexdigest()}


def fixed_environment(dotnet_path, work_dir):
    return {"PATH": "/usr/bin:/bin", "HOME": str(work_dir), "LANG": "C.UTF-8", "TZ": "UTC",
            "DOTNET_ROOT": str(dotnet_path.parent), "DOTNET_ROLL_FORWARD": "Disable", "DOTNET_NOLOGO": "1",
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_EnableDiagnostics": "0", "DOTNET_PROCESSOR_COUNT": "2"}


def resource_probe(lab):
    resource_path = Path(__file__).with_name(RESOURCE_MODULE)
    require(resource_path.is_file() and not resource_path.is_symlink(), "Missing adjacent provisioned resource helper.")
    spec = importlib.util.spec_from_file_location("benchmark_reference_resources", resource_path)
    helper = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = helper
    spec.loader.exec_module(helper)
    try:
        evidence = helper.capture_driver_resources()
    except helper.ReferenceResourceError as error:
        if not lab:
            raise
        evidence = dict(error.evidence, pid=os.getpid(), affinity_cpus=sorted(os.sched_getaffinity(0)),
                        cgroup_root_visible=False, cgroup_membership=Path("/proc/self/cgroup").read_text().splitlines(),
                        scope="observed lab facts; reference resource proof unavailable")
    return evidence, digest(resource_path)


def ssh_endpoints():
    values = os.environ.get("SSH_CONNECTION", "").split()
    require(len(values) == 4, "Driver helper must run inside the approved SSH connection.")
    source, source_port, destination, destination_port = values
    return {"controller_ip": str(ipaddress.ip_address(source)), "controller_port": int(source_port),
            "driver_ip": str(ipaddress.ip_address(destination)), "driver_port": int(destination_port)}


def probe(dotnet_path, publish, work_dir, app_host, lab):
    require(platform.system() == "Linux" and platform.machine() == "x86_64"
            and os.confstr("CS_GNU_LIBC_VERSION").startswith("glibc "), "Driver requires Linux x86_64 with glibc.")
    env = fixed_environment(dotnet_path, work_dir)

    def dotnet_query(option):
        return subprocess.check_output([dotnet_path, option], cwd=publish, env=env, timeout=8, text=True).strip()

    installed = dotnet_query("--list-runtimes")
    required = ("Microsoft.NETCore.App 11.0.0 ", "Microsoft.AspNetCore.App 11.0.0 ")
    require(all(any(row.startswith(runtime) for row in installed.splitlines()) for runtime in required),
            "Exact .NET and ASP.NET Core 11.0.0 runtimes are required on the driver.")
    resources, resource_sha = resource_probe(lab)
    return {"protocol": PROTOCOL, "helper_sha256": digest(Path(__file__)), "resource_helper_sha256": resource_sha,
            "scope": "lab-preflight-only" if lab else "approved-private-driver",
            "sdk": dotnet_query("--version"), "runtimes": installed.splitlines(), "dotnet_sha256": digest(dotnet_path),
            "deployment": deployment(publish / ASSEMBLY), "dotnet": str(dotnet_path), "publish_dir": str(publish),
            "environment": env, "resources": resources, "ssh_connection": ssh_endpoints(),
            "app_host": app_host, "app_addresses": private_app_addresses(app_host, 443, lab)}


def fixture_request(request, key_set, operation):
    require(request.keys() == key_set | {"operation", "protocol"} and request["protocol"] == PROTOCOL
            and request["operation"] == operation, "Unexpected request fields for the fixed remote protocol.")


def join_child(child):
    if child.poll() is None:
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            return child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    return child.wait(timeout=5)


def child_resources(pid):
    try:
        return {"pid": pid, "affinity_cpus": sorted(os.sched_getaffinity(pid)),
                "cgroup": Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii").splitlines()}
    except ProcessLookupError:
        return None
    except FileNotFoundError:
        return None


def stable_resources(before, after, lab, *, pressure=False):
    fixed = ("system", "architecture", "kernel", "libc", "machine_id_sha256", "boot_id_sha256", "mem_total_bytes",
             "affinity_cpus", "cgroup_root_visible", "cgroup_relative", "cgroup_membership")
    require(all(before.get(key) == after.get(key) for key in fixed), "Remote identity or effective allocation changed.")
    if not lab:
        require(before.get("cgroup_root_visible") is True and after.get("cgroup_root_visible") is True,
                "Remote reference cgroup hierarchy is unavailable.")
        left = before["hierarchy"]
        right = after["hierarchy"]
        require(left and len(left) == len(right), "Remote cgroup hierarchy changed.")
        fixed_nodes = ("cgroup_relative", "directory_id", "controls")
        pressure_names = {"cpu.stat": {"nr_throttled", "throttled_usec"},
                          "memory.events": {"high", "max", "oom", "oom_kill", "oom_group_kill"},
                          "memory.events.local": {"high", "max", "oom", "oom_kill", "oom_group_kill"}}
        for start, stop in zip(left, right):
            require(all(start[key] == stop[key] for key in fixed_nodes), "Remote cgroup controls changed.")
            if pressure:
                for source, names in pressure_names.items():
                    first = start["counters"].get(source)
                    last = stop["counters"].get(source)
                    require((first is None) == (last is None) and (first is None or
                            all(first.get(name) == last.get(name) for name in names)),
                            "Remote resource pressure or a counter reset was observed.")


def compare_driver(accepted, observed, lab):
    fixed = ("protocol", "helper_sha256", "resource_helper_sha256", "scope", "sdk", "runtimes", "dotnet_sha256",
             "deployment", "dotnet", "publish_dir", "environment", "app_host", "app_addresses")
    require(all(accepted.get(key) == observed.get(key) for key in fixed), "Remote job does not match the accepted driver probe.")
    endpoints = ("controller_ip", "driver_ip", "driver_port")
    require(all(accepted["ssh_connection"][key] == observed["ssh_connection"][key] for key in endpoints),
            "Remote SSH peer allocation changed.")
    stable_resources(accepted["resources"], observed["resources"], lab)


def driver_binding(observed):
    resources = observed["resources"]
    portable = {key: value for key, value in resources.items()
                if key not in {"hierarchy", "pid", "observed_monotonic_ns"}}
    portable["hierarchy"] = [{key: value for key, value in node.items() if key != "counters"}
                              for node in resources.get("hierarchy", [])]
    binding = {key: value for key, value in observed.items() if key not in {"resources", "ssh_connection"}}
    binding["resources"] = portable
    binding["ssh_connection"] = {key: value for key, value in observed["ssh_connection"].items() if key != "controller_port"}
    return hashlib.sha256(json.dumps(binding, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()


def launch_job(request, dotnet_path, publish, job_root, app_host, lab):
    fixture_request(request, {"job_id", "arguments", "timeout", "ca", "deployment", "sdk", "helper_sha256",
                              "resource_helper_sha256", "driver_binding_sha256"}, "run")
    job_id = str(request["job_id"])
    require(JOB_ID.fullmatch(job_id) and type(request["timeout"]) is int and 1 <= request["timeout"] <= 310,
            "Invalid job receipt ID or deadline.")
    deadline = time.monotonic() + request["timeout"]
    options = driver_arguments(request["arguments"], app_host, lab)
    private_app_addresses(app_host, urlsplit(options["url"]).port, lab)
    ca = validate_public_ca(base64.b64decode(request["ca"], validate=True))

    job = job_root / job_id
    job.mkdir(mode=0o700)
    raw = job / "raw"
    raw.mkdir(mode=0o700)
    ca_file = job / "root-ca.der"
    ca_file.write_bytes(ca)
    state = {"job_id": job_id, "returncode": 125, "state": "failed-before-launch", "child_joined": True,
             "child": None, "failure": None}
    disconnect = threading.Event()
    old_handlers = {value: signal.signal(value, lambda _, __: disconnect.set())
                    for value in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)}
    try:
        observed = probe(dotnet_path, publish, job_root, app_host, lab)
        require(all(observed[field] == request[field] for field in
                    ("deployment", "sdk", "helper_sha256", "resource_helper_sha256")),
                "Provisioned driver source, SDK, or publish bytes differ from the selected build.")
        state["driver"] = observed
        require(driver_binding(observed) == request["driver_binding_sha256"],
                "Driver identity or effective allocation changed before launch.")
        command = [dotnet_path, publish / ASSEMBLY, *request["arguments"], f"--ca-file={ca_file}", f"--output={raw}"]
        with selectors.DefaultSelector() as lease, (raw / "stdout.txt").open("xb") as stdout, \
                (raw / "stderr.txt").open("xb") as stderr:
            lease.register(sys.stdin.fileno(), selectors.EVENT_READ)
            if disconnect.is_set() or lease.select(0):
                state.update(state="lease-closed", returncode=124)
            elif time.monotonic() >= deadline:
                state.update(state="deadline", returncode=124)
            else:
                child = subprocess.Popen(command, cwd=publish, env=fixed_environment(dotnet_path, job_root),
                                         stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
                state["child_joined"] = False
                try:
                    state["child"] = child_resources(child.pid)
                    if not lab:
                        require(state["child"] is not None and
                                state["child"]["affinity_cpus"] == observed["resources"]["affinity_cpus"] and
                                state["child"]["cgroup"] == ["0::" + observed["resources"]["cgroup_relative"]],
                                "Owned driver process does not inherit the observed allocation.")
                    while child.poll() is None:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            state["state"] = "deadline"
                            break
                        if disconnect.is_set() or lease.select(min(0.25, remaining)):
                            state["state"] = "lease-closed"
                            break
                    else:
                        state["state"] = "exited"
                finally:
                    exit_code = join_child(child)
                    state.update(child_joined=True, child_returncode=exit_code,
                                 returncode=exit_code if state["state"] == "exited" else 124)
        state["resources_after"], resource_digest = resource_probe(lab)
        require(resource_digest == observed["resource_helper_sha256"], "Driver resource helper changed during the job.")
        stable_resources(observed["resources"], state["resources_after"], lab, pressure=True)
    except Exception as error:
        if "child_returncode" in state:
            state["state"] = "failed"
        state["failure"] = type(error).__name__
        state["returncode"] = 125
    finally:
        ca_file.unlink()
        for value, handler in old_handlers.items():
            signal.signal(value, handler)
        write_json(job / "result.json", state)
    return job


def send_evidence(job, stream):
    directory_without_links(job)
    root = job / "raw"
    with regular_input(job / "result.json") as source:
        receipt = json.load(source)
    require(receipt.get("job_id") == job.name and receipt.get("child_joined") is True,
            "Remote job has not published a joined receipt.")
    files = tree_files(root, MAX_FILES)
    entries = []
    total = 0
    for path in files:
        name = path.relative_to(root).as_posix()
        evidence_path(name)
        size = path.stat().st_size
        total += size
        require(size <= MAX_FILE and total <= MAX_TOTAL and len(entries) < MAX_FILES,
                "Remote evidence exceeds the declared transfer bound.")
        entries.append((path, {"path": name, "bytes": size, "sha256": digest(path)}))
    stream.write(message({"type": "begin", "job_id": job.name, "protocol": PROTOCOL, "files": len(entries), "bytes": total}))
    for path, header in entries:
        stream.write(message({"type": "file", **header}))
        remaining = header["bytes"]
        directory_without_links(path.parent)
        with regular_input(path) as source:
            while remaining:
                chunk = source.read(min(BLOCK, remaining))
                require(chunk, "Remote evidence changed while transferring.")
                stream.write(chunk)
                remaining -= len(chunk)
            require(source.read(1) == b"", "Remote evidence changed while transferring.")
    stream.write(message({"type": "end", "receipt": receipt}))
    stream.flush()


def initialize_destination(root, name):
    path = root
    for part in evidence_path(name)[:-1]:
        path /= part
        path.mkdir(exist_ok=True, mode=0o700)
        directory_without_links(path)
    return path / evidence_path(name)[-1]


def receive_evidence(stream, root, job_id):
    directory_without_links(root)
    begin = read_message(stream)
    require(begin.keys() == {"type", "job_id", "protocol", "files", "bytes"} and begin["type"] == "begin"
            and begin["job_id"] == job_id and begin["protocol"] == PROTOCOL
            and type(begin["files"]) is int and type(begin["bytes"]) is int
            and 0 <= begin["files"] <= MAX_FILES and 0 <= begin["bytes"] <= MAX_TOTAL,
            "Invalid remote evidence manifest.")
    total = 0
    received = {}
    partial = root / ".remote-transfer-parts"
    partial.mkdir(exist_ok=True, mode=0o700)
    directory_without_links(partial)
    for _ in range(begin["files"]):
        header = read_message(stream)
        require(header.keys() == {"type", "path", "bytes", "sha256"} and header["type"] == "file"
                and isinstance(header["path"], str) and header["path"] not in received
                and type(header["bytes"]) is int and 0 <= header["bytes"] <= MAX_FILE
                and isinstance(header["sha256"], str) and HEX64.fullmatch(header["sha256"]),
                "Invalid or duplicate remote evidence file header.")
        remaining = header["bytes"]
        total += remaining
        require(total <= begin["bytes"], "Evidence exceeds its declared transfer size.")
        path = initialize_destination(root, header["path"])
        hasher = hashlib.sha256()
        with tempfile.NamedTemporaryFile(dir=partial, prefix="partial-", delete=False) as output:
            temporary = Path(output.name)
            while remaining:
                chunk = stream.read(min(BLOCK, remaining))
                require(chunk, "Truncated remote evidence file.")
                output.write(chunk)
                hasher.update(chunk)
                remaining -= len(chunk)
        require(hasher.hexdigest() == header["sha256"], "Remote evidence SHA-256 differs.")
        try:
            os.link(temporary, path)
        except FileExistsError:
            require(stat.S_ISREG(path.lstat().st_mode) and path.stat().st_size == header["bytes"]
                    and digest(path) == header["sha256"], "Recovery evidence conflicts with a local file.")
        temporary.unlink()
        received[header["path"]] = header["sha256"]
    require(total == begin["bytes"], "Remote evidence total differs.")
    end = read_message(stream)
    require(end.keys() == {"type", "receipt"} and end["type"] == "end" and isinstance(end["receipt"], dict),
            "Missing remote completion receipt.")
    receipt = end["receipt"]
    require(receipt.get("job_id") == job_id and receipt.get("child_joined") is True
            and type(receipt.get("returncode")) is int and -255 <= receipt["returncode"] <= 255
            and receipt.get("state") in {"exited", "failed-before-launch", "failed", "deadline", "lease-closed"}
            and (receipt["returncode"] != 0 or receipt["state"] == "exited" and receipt.get("failure") is None),
            "Invalid or missing owned child join evidence.")
    require(stream.read(1) == b"", "Unexpected bytes after the final remote receipt.")
    return {"receipt": receipt, "files_sha256": received, "bytes": total}


class RemoteDriver:
    """Select one pre-provisioned SSH driver and verify live deployment before using it."""

    def __init__(self, config, local_assembly, expected_sdk, *, lab=False):
        expected = {"host", "user", "known_hosts", "identity_file", "remote_helper", "remote_dotnet",
                    "remote_publish_dir", "remote_job_root", "app_host"}
        optional = {"port", "host_key_alias", "remote_python"}
        require(isinstance(config, dict) and expected <= config.keys() <= expected | optional,
                "Invalid remote driver configuration fields.")
        self.config = dict(config)
        self.app_host = host_name(config["app_host"])
        self.lab = lab
        self.sdk = expected_sdk
        self.deployment = deployment(Path(local_assembly).resolve(strict=True))
        self.helper_sha = digest(Path(__file__))
        self.resource_sha = digest(Path(__file__).with_name(RESOURCE_MODULE))
        self.command = self._ssh_command()
        self.known_hosts_sha = digest(Path(config["known_hosts"]))
        self.observed = None

    def _ssh_command(self):
        config = self.config
        host = host_name(config["host"])
        user = config["user"]
        port = config.get("port", 22)
        require(isinstance(user, str) and re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_.-]{0,63}", user)
                and type(port) is int and 1 <= port <= 65535, "Invalid SSH username or port.")
        identity = Path(config["identity_file"])
        known_hosts = Path(config["known_hosts"])
        for item in (identity, known_hosts):
            require(item.is_absolute() and item.is_file() and not item.is_symlink()
                    and not any(char in str(item) for char in '"\\\r\n%'),
                    "Explicit absolute identity and known_hosts files are required.")
        require(known_hosts.stat().st_size > 0, "Pinned known_hosts is empty.")
        options = ["BatchMode=yes", "StrictHostKeyChecking=yes", "GlobalKnownHostsFile=/dev/null",
                   f'UserKnownHostsFile="{known_hosts}"', "IdentityAgent=none", "IdentitiesOnly=yes",
                   "ForwardAgent=no", "ForwardX11=no", "ClearAllForwardings=yes", "RequestTTY=no", "PermitLocalCommand=no",
                   "ProxyCommand=none", "ProxyJump=none", "ControlMaster=no", "ControlPath=none", "UpdateHostKeys=no",
                   "PreferredAuthentications=publickey", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
                   "ConnectionAttempts=1", "ConnectTimeout=8",
                   "ServerAliveInterval=5", "ServerAliveCountMax=2", "LogLevel=ERROR"]
        if "host_key_alias" in config:
            options.append(f'HostKeyAlias={host_name(config["host_key_alias"])}')
        remote = [remote_path(config.get("remote_python", "/usr/bin/python3")), "-I", "-B",
                  remote_path(config["remote_helper"]), "--remote-helper", "--dotnet", remote_path(config["remote_dotnet"]),
                  "--publish", remote_path(config["remote_publish_dir"]), "--job-root", remote_path(config["remote_job_root"]),
                  "--app-host", self.app_host]
        if self.lab:
            remote.append("--lab")
        return ("/usr/bin/ssh", "-F", "/dev/null", "-T", *(value for option in options for value in ("-o", option)),
                "-i", str(identity), "-p", str(port), "-l", user, "--", host, shlex.join(remote))

    def _check_host_pin(self):
        path = Path(self.config["known_hosts"])
        require(not path.is_symlink() and digest(path) == self.known_hosts_sha, "Configured SSH host key pin changed.")

    def probe(self):
        self._check_host_pin()
        request = message({"protocol": PROTOCOL, "operation": "probe"})
        reply = subprocess.run(self.command, input=request, capture_output=True, timeout=30)
        require(reply.returncode == 0 and len(reply.stdout) <= MAX_MESSAGE and reply.stdout.count(b"\n") == 1,
                "Pinned SSH host did not provide a complete driver probe.")
        observed = json.loads(reply.stdout)
        require(observed.get("protocol") == PROTOCOL and observed.get("helper_sha256") == self.helper_sha
                and observed.get("resource_helper_sha256") == self.resource_sha and observed.get("sdk") == self.sdk
                and observed.get("deployment") == self.deployment and observed.get("app_host") == self.app_host
                and observed.get("scope") == ("lab-preflight-only" if self.lab else "approved-private-driver"),
                "Driver probe differs from the selected deployment or helper sources.")
        self.observed = observed
        return observed

    def start(self, arguments, public_ca, directory, timeout):
        self._check_host_pin()
        require(self.observed is not None, "Probe the pinned driver deployment before starting work.")
        driver_arguments(arguments, self.app_host, self.lab)
        require(type(timeout) is int and 1 <= timeout <= 310, "Invalid remote driver deadline.")
        ca = validate_public_ca(public_ca if isinstance(public_ca, bytes) else Path(public_ca).read_bytes())
        job_id = secrets.token_hex(16)
        request = {"protocol": PROTOCOL, "operation": "run", "job_id": job_id, "arguments": list(arguments),
                   "timeout": timeout, "ca": base64.b64encode(ca).decode("ascii"), "deployment": self.deployment,
                   "sdk": self.sdk, "helper_sha256": self.helper_sha, "resource_helper_sha256": self.resource_sha,
                   "driver_binding_sha256": driver_binding(self.observed)}
        directory = Path(directory).resolve(strict=True)
        write_json(directory / "remote-launch.json", {key: value for key, value in request.items() if key != "ca"} |
                   {"public_ca_sha256": hashlib.sha256(ca).hexdigest()})
        return RemoteJob(self, directory, job_id, request)

    def recover(self, job_id, directory):
        """Retrieve completed evidence for an existing job. It does not launch work."""
        self._check_host_pin()
        require(isinstance(job_id, str) and JOB_ID.fullmatch(job_id), "Invalid recovery job ID.")
        directory = Path(directory).resolve(strict=True)
        request = {"protocol": PROTOCOL, "operation": "collect", "job_id": job_id}
        job = RemoteJob(self, directory, job_id, request)
        return job.wait(timeout=45)


class RemoteJob:
    """Process-like handle with an SSH stdin lease and joined evidence receipt."""

    def __init__(self, driver, directory, job_id, request):
        self.driver = driver
        self.directory = directory
        self.job_id = job_id
        self.returncode = None
        self.result = None
        self.failure = None
        recovering = request["operation"] == "collect"
        log_name = f"remote-recovery-ssh-{secrets.token_hex(4)}.log" if recovering else "remote-ssh.log"
        with (directory / log_name).open("xb") as stderr:
            self._process = subprocess.Popen(driver.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr)
        try:
            self._process.stdin.write(message(request))
            self._process.stdin.flush()
            if recovering:
                self._process.stdin.close()
        except BaseException:
            self.kill()
            self._process.wait(timeout=5)
            self._process.stdout.close()
            raise
        self._thread = threading.Thread(target=self._receive, daemon=True)
        self._thread.start()

    def _receive(self):
        try:
            with self._process.stdout as stream:
                receipt = receive_evidence(stream, self.directory, self.job_id)
            require(self._process.wait(timeout=5) == 0, "SSH failed after transferring remote evidence.")
            write_json(self.directory / "remote-result.json", receipt)
            self.result = receipt
            remote = receipt["receipt"]
            if remote.get("driver") and self.driver.observed:
                try:
                    compare_driver(self.driver.observed, remote["driver"], self.driver.lab)
                except RemoteDriverError as error:
                    self.failure = error
                    write_json(self.directory / "remote-allocation-failure.json", {"job_id": self.job_id, "message": str(error)})
            self.returncode = 125 if self.failure is not None else remote["returncode"]
        except Exception as error:
            self.failure = RemoteDriverError(f"Remote evidence unverified for job {self.job_id}: {error}")
            self.returncode = 125
            try:
                self.kill()
                self._process.wait(timeout=5)
                write_json(self.directory / "remote-transfer-failure.json", {"job_id": self.job_id,
                           "status": "join-unverified; retrieve joined evidence when the pinned host is reachable",
                           "error": type(error).__name__})
            except (OSError, subprocess.TimeoutExpired):
                pass
        finally:
            self.terminate()

    def poll(self):
        if self._thread.is_alive():
            return None
        return self.returncode

    def wait(self, timeout=None):
        self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            self.terminate()
            raise subprocess.TimeoutExpired("remote Small API driver", timeout)
        return self.poll()

    def terminate(self):
        try:
            self._process.stdin.close()
        except OSError:
            pass

    def kill(self):
        self.terminate()
        if self._process.poll() is None:
            try:
                self._process.kill()
            except ProcessLookupError:
                pass

    def recover(self):
        require(not self._thread.is_alive(), "Wait for the existing SSH channel before recovering its job.")
        if self.result is not None:
            return self.returncode
        return self.driver.recover(self.job_id, self.directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote-helper", required=True, action="store_true")
    parser.add_argument("--dotnet", required=True, type=Path)
    parser.add_argument("--publish", required=True, type=Path)
    parser.add_argument("--job-root", required=True, type=Path)
    parser.add_argument("--app-host", required=True)
    parser.add_argument("--lab", action="store_true")
    args = parser.parse_args()
    try:
        directory_without_links(args.publish)
        directory_without_links(args.job_root)
        require(args.job_root.stat().st_uid == os.getuid() and stat.S_IMODE(args.job_root.stat().st_mode) == 0o700,
                "Remote job root must be owned by the SSH user with mode 0700.")
        require(args.dotnet.is_absolute() and args.dotnet.resolve(strict=True) == args.dotnet
                and args.dotnet.is_file() and os.access(args.dotnet, os.X_OK), "Invalid provisioned dotnet executable.")
        app_host = host_name(args.app_host)
        request = read_message(sys.stdin.buffer)
        operation = request.get("operation")
        if operation == "probe":
            fixture_request(request, set(), operation)
            sys.stdout.buffer.write(message(probe(args.dotnet, args.publish, args.job_root, app_host, args.lab)))
        elif operation == "run":
            job = launch_job(request, args.dotnet, args.publish, args.job_root, app_host, args.lab)
            send_evidence(job, sys.stdout.buffer)
        elif operation == "collect":
            fixture_request(request, {"job_id"}, operation)
            job_id = request["job_id"]
            require(isinstance(job_id, str) and JOB_ID.fullmatch(job_id), "Invalid recovery job ID.")
            send_evidence(args.job_root / job_id, sys.stdout.buffer)
        else:
            raise RemoteDriverError("Unknown operation in the fixed driver helper protocol.")
        return 0
    except Exception as error:
        print(f"Remote helper stopped ({type(error).__name__}).", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
