"""Verify order replay across independent PostgreSQL, broker and child process boundaries."""

import argparse
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import platform
import re
import secrets
import subprocess
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
BUSINESS = HERE.parent
ROOT = BUSINESS.parent
APP = BUSINESS / "order-replay"
BROKER_SUPPORT = BUSINESS / "recovery-broker/run-proof.py"
spec = spec_from_file_location("owned_replay_broker", BROKER_SUPPORT)
broker = module_from_spec(spec)
spec.loader.exec_module(broker)
require, digest, read, wait_until = broker.require, broker.digest, broker.read, broker.wait_until

ENGINE = "6fe7254404cf6b148370bd95befe8331e8932354"
PG_IMAGE = "registry-1.docker.io/library/postgres@sha256:9770878138a2e83abcb10856d30cc3f24dae0d317bb956db6ab9159de6c3c80d"
PG_CONFIG = "sha256:79061104669bb30919d015b549c764e2d8021a18ee39cb175581a2588fe90dbe"
PG_LABEL = "io.cephalon.replay-postgres"
DATABASE = "cephalon_replay_proof"
OWNER = "cephalon_replay_owner"
RUNTIME = "cephalon_replay_runtime"
QUEUE = "cephalon-order-replay"

BOOTSTRAP = r"""
\getenv owner_value CEPHALON_REPLAY_OWNER_VALUE
\getenv runtime_value CEPHALON_REPLAY_RUNTIME_VALUE
CREATE ROLE cephalon_replay_owner LOGIN NOSUPERUSER NOCREATEROLE NOBYPASSRLS PASSWORD :'owner_value';
CREATE ROLE cephalon_replay_runtime LOGIN NOSUPERUSER NOCREATEROLE NOBYPASSRLS PASSWORD :'runtime_value';
REVOKE ALL ON DATABASE cephalon_replay_proof FROM PUBLIC;
GRANT CONNECT, CREATE ON DATABASE cephalon_replay_proof TO cephalon_replay_owner;
GRANT CONNECT ON DATABASE cephalon_replay_proof TO cephalon_replay_runtime;
"""
ROLE_SNAPSHOT = """
SELECT jsonb_build_object(
    'roles', (SELECT jsonb_agg(jsonb_build_array(rolname, rolcanlogin, rolsuper, rolbypassrls, rolcreaterole)
                       ORDER BY rolname)
              FROM pg_roles WHERE rolname IN ('cephalon_replay_owner', 'cephalon_replay_runtime')),
    'runtime_is_owner_member', pg_has_role('cephalon_replay_runtime', 'cephalon_replay_owner', 'MEMBER'),
    'runtime_can_create', has_database_privilege('cephalon_replay_runtime', current_database(), 'CREATE'),
    'relations', (SELECT jsonb_agg(jsonb_build_array(relname, pg_get_userbyid(relowner),
                                  relrowsecurity, relforcerowsecurity) ORDER BY relname)
                  FROM pg_class JOIN pg_namespace ON pg_namespace.oid = relnamespace
                  WHERE nspname = 'cephalon_replay' AND relkind = 'r'));
"""
LEDGER = """
SELECT jsonb_build_object(
    'stock', coalesce((SELECT jsonb_agg(jsonb_build_array(tenant_id, sku, available) ORDER BY tenant_id, sku)
                      FROM cephalon_replay.stock), '[]'::jsonb),
    'orders', coalesce((SELECT jsonb_agg(jsonb_build_array(tenant_id, order_id, sku, quantity, status, revision)
                                        ORDER BY tenant_id, order_id) FROM cephalon_replay.orders), '[]'::jsonb),
    'outbox', coalesce((SELECT jsonb_agg(jsonb_build_array(tenant_id, event_id, order_id, sku, quantity, published)
                                        ORDER BY tenant_id, event_id) FROM cephalon_replay.outbox), '[]'::jsonb),
    'inbox', coalesce((SELECT jsonb_agg(jsonb_build_array(tenant_id, event_id, order_id) ORDER BY tenant_id, event_id)
                       FROM cephalon_replay.inbox), '[]'::jsonb));
"""
PHASES = {
    "create": (0, "Order and outbox committed together."),
    "publish-confirm-only": (76, "Publisher confirm observed before outbox mark."),
    "publish": (0, "Identical event confirmed and outbox marked."),
    "worker-exit-after-commit": (77, "Worker commit acknowledged before delivery ACK."),
    "worker-replay": (0, "Duplicate deliveries acknowledged: 1 redelivered and 1 initial; no second mutation."),
    "verify": (0, "Final order, stock, inbox and tenant isolation verified; queue empty."),
}


def ledger_expected(*, created, published, reserved):
    order = "00000000-0000-0000-0000-000000000101"
    event = "00000000-0000-0000-0000-000000000201"
    sku = "fixture-sku"
    orders = [["B", order, sku, 2, "pending", 0]]
    if created:
        orders.insert(0, ["A", order, sku, 2, "reserved" if reserved else "pending", int(reserved)])
    return {
        "stock": [["A", sku, 8 if reserved else 10], ["B", sku, 20]],
        "orders": orders,
        "outbox": [["A", event, order, sku, 2, published]] if created else [],
        "inbox": [["A", event, order]] if reserved else [],
    }


class ReplayProof(broker.Proof):
    def __init__(self, dotnet, engine, out, revision):
        super().__init__(dotnet, out, revision)
        self.engine = engine
        self.pg_name = self.name + "-postgres"
        self.pg_container = None
        self.pg_port = None
        self.admin_value = secrets.token_hex(24)
        self.owner_value = secrets.token_hex(24)
        self.runtime_value = secrets.token_hex(24)
        self.report.update(engine=ENGINE, phases=[], checkpoints={})

    def source_snapshot(self):
        head = self.text(self.run("source", ("git", "rev-parse", "HEAD")))
        status = self.text(self.run("source", ("git", "status", "--porcelain")))
        engine_head = self.text(self.run("source", ("git", "-C", self.engine, "rev-parse", "HEAD")))
        engine_status = self.text(self.run("source", ("git", "-C", self.engine, "status", "--porcelain")))
        require(head == self.revision and not status, "Expected the selected clean Samples commit.")
        require(engine_head == ENGINE and not engine_status, "Expected the pinned clean Engine checkout.")
        directories = (HERE, APP)
        files = [path for directory in directories for path in sorted(directory.glob("*.*")) if path.is_file()]
        files.extend((BROKER_SUPPORT, ROOT / "global.json", ROOT / "NuGet.Config"))
        return {path.relative_to(ROOT).as_posix(): digest(path) for path in files}

    def build_replay(self):
        require(platform.system() == "Linux" and platform.machine() == "x86_64", "Expected Linux x86_64.")
        context = self.text(self.docker("context", "context", "inspect", "default",
                                        "--format", "{{.Endpoints.docker.Host}}"))
        require(context == "unix:///var/run/docker.sock", "Expected a local default Docker socket.")
        docker = self.text(self.docker("docker-info", "info", "--format",
                                      "{{.ServerVersion}} {{.OSType}} {{.Architecture}}"))
        require(docker.endswith(" linux x86_64"), "Expected a Linux amd64 Docker daemon.")
        sdk = self.text(self.run("sdk", (self.dotnet, "--version")))
        require(sdk == broker.SDK == read(ROOT / "global.json")["sdk"]["version"], "Expected SDK 11.0.100.")
        self.report.update(sdk=sdk, runtime="11.0.0", docker=docker, host=platform.platform(), source=self.source_snapshot())
        project = APP / "OrderReplay.Consumer.csproj"
        artifacts = self.out / "artifacts"
        arguments = ("--artifacts-path", artifacts, f"-p:EngineRoot={self.engine}")
        self.run("restore", (self.dotnet, "restore", project, "--configfile", ROOT / "NuGet.Config",
                             "--locked-mode", *arguments), timeout=180)
        self.run("build", (self.dotnet, "build", project, "-c", "Release", "--no-restore",
                           *arguments, "-warnaserror"), timeout=180)
        binaries = artifacts / "bin/OrderReplay.Consumer/release"
        self.report["execution_artifacts"] = {
            path.name: digest(path) for path in sorted(binaries.iterdir()) if path.suffix in {".dll", ".json"}
        }
        return binaries / "OrderReplay.Consumer.dll"

    def start_postgres(self):
        fields = "{{.Id}} {{.Os}} {{.Architecture}}"
        image = self.docker("pg-image", "image", "inspect", "--format", fields, PG_IMAGE, check=False)
        if image.returncode != 0:
            self.docker("pg-pull", "pull", "--platform", "linux/amd64", PG_IMAGE, timeout=180)
            image = self.docker("pg-image", "image", "inspect", "--format", fields, PG_IMAGE)
        require(self.text(image) == f"{PG_CONFIG} linux amd64", "Pinned PostgreSQL image identity differed.")
        label = f"{PG_LABEL}={self.pg_name}"
        self.docker("pg-volume", "volume", "create", "--label", label, self.pg_name)
        result = self.docker("pg-container", "container", "create", "--platform", "linux/amd64",
            "--name", self.pg_name, "--label", label, "--network", self.name,
            "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD",
            "--env", f"POSTGRES_DB={DATABASE}",
            "--mount", f"type=volume,source={self.pg_name},target=/var/lib/postgresql",
            PG_IMAGE, extra_env={"POSTGRES_PASSWORD": self.admin_value})
        self.pg_container = self.text(result)
        require(re.fullmatch("[a-f0-9]{64}", self.pg_container), "Expected the complete PostgreSQL container ID.")
        fields = "{{.Image}} " + '{{index .Config.Labels "' + PG_LABEL + '"}}'
        identity = self.text(self.docker("pg-ownership", "container", "inspect", "--format", fields, self.pg_container))
        mount = self.text(self.docker("pg-ownership", "container", "inspect", "--format",
            "{{range .Mounts}}{{println .Type .Name .Destination}}{{end}}", self.pg_container))
        require(identity == f"{PG_CONFIG} {self.pg_name}" and mount == f"volume {self.pg_name} /var/lib/postgresql",
                "Expected the owned PostgreSQL container and data volume.")
        self.docker("pg-start", "container", "start", self.pg_container)
        binding = self.text(self.docker("pg-listener", "container", "port", self.pg_container, "5432/tcp"))
        match = re.fullmatch(r"127\.0\.0\.1:([0-9]+)", binding)
        require(match is not None, "Expected exactly one PostgreSQL loopback listener.")
        self.pg_port = int(match[1])

        def version_probe():
            state = self.text(self.docker("pg-ready", "container", "inspect", "--format",
                                         "{{.State.Running}}", self.pg_container))
            require(state == "true", "The owned PostgreSQL container exited before readiness.")
            result = self.docker("pg-ready", "container", "exec", "--env", "PGPASSWORD", self.pg_container,
                "psql", "-XAt", "-h", "127.0.0.1", "-U", "postgres", "-d", DATABASE, "-c", "SHOW server_version_num",
                check=False, extra_env={"PGPASSWORD": self.admin_value})
            return self.text(result) if result.returncode == 0 and broker.port_open(self.pg_port) else None

        require(wait_until(version_probe, "PostgreSQL TCP query and published listener") == "180006",
                "Expected PostgreSQL 18.6.")
        self.report["postgresql"] = {"image": PG_IMAGE, "config_digest": PG_CONFIG,
                                     "platform": "linux/amd64", "server": "18.6"}

    def apply_sql(self, stage, user, statement, extra_env):
        # Explicit stdin keeps fixture values outside argument vectors and public receipts.
        environment = dict(self.environment, **extra_env)
        names = [part for key in extra_env for part in ("--env", key)]
        command = ("docker", "--context", "default", "container", "exec", "--interactive",
                   *names, self.pg_container, "psql", "-X", "-h", "127.0.0.1", "-U", user, "-d", DATABASE,
                   "--set", "ON_ERROR_STOP=1", "--single-transaction", "--file", "-")
        with (self.out / f"{stage}.log").open("xb") as log:
            subprocess.run(command, cwd=ROOT, env=environment, input=statement, timeout=35,
                           stdout=log, stderr=subprocess.STDOUT, check=True)

    def postgres_json(self, stage, statement):
        command = self.docker(stage, "container", "exec", "--env", "PGPASSWORD", self.pg_container,
            "psql", "-XAt", "-h", "127.0.0.1", "-U", "postgres", "-d", DATABASE, "-c", statement,
            extra_env={"PGPASSWORD": self.admin_value})
        return json.loads(command.stdout)

    def schema(self):
        self.apply_sql("pg-roles", "postgres", BOOTSTRAP.encode("ascii"), {
            "PGPASSWORD": self.admin_value,
            "CEPHALON_REPLAY_OWNER_VALUE": self.owner_value,
            "CEPHALON_REPLAY_RUNTIME_VALUE": self.runtime_value,
        })
        self.apply_sql("pg-schema", OWNER, (APP / "schema.sql").read_bytes(), {"PGPASSWORD": self.owner_value})
        roles = self.postgres_json("pg-role-check", ROLE_SNAPSHOT)
        expected = {
            "roles": [[name, True, False, False, False] for name in (OWNER, RUNTIME)],
            "runtime_is_owner_member": False, "runtime_can_create": False,
            "relations": [[table, OWNER, True, True] for table in ("inbox", "orders", "outbox", "stock")],
        }
        require(roles == expected, "Migration owner, runtime rights or forced row security differ.")
        self.report["postgresql"]["restricted_roles_and_force_rls"] = True

    def replay_queue(self, ready):
        expected = {"name": QUEUE, "type": "quorum", "durable": True,
                    "messages_ready": ready, "messages_unacknowledged": 0}

        def observe():
            result = self.docker("queue-state", "container", "exec", self.container, "rabbitmqctl", "-q",
                                 "list_queues", "--formatter", "json", *expected, check=False, timeout=20)
            rows = json.loads(result.stdout) if result.returncode == 0 else None
            return rows[0] if rows == [expected] else None

        return wait_until(observe, f"durable order queue with {ready} ready and zero unacknowledged")

    def checkpoint(self, phase, *, created, published=False, reserved=False, ready=None):
        actual = self.postgres_json("ledger", LEDGER)
        expected = ledger_expected(created=created, published=published, reserved=reserved)
        require(actual == expected, f"Independent PostgreSQL ledger mismatch at {phase}. See the private ledger log.")
        checked = {"ledger": actual}
        if ready is not None:
            checked["broker"] = self.replay_queue(ready)
        self.report["checkpoints"][phase] = checked

    def app(self, assembly, phase, port):
        expected_exit, expected_receipt = PHASES[phase]
        postgres = (f"Host=127.0.0.1;Port={self.pg_port};Database={DATABASE};Username={RUNTIME};"
                    f"Password={self.runtime_value};SSL Mode=Disable")
        amqp = f"amqp://cephalon_fixture:{quote(self.fixture_value, safe='')}@127.0.0.1:{port}/%2f"
        environment = {"CEPHALON_ORDER_REPLAY_POSTGRES": postgres, "CEPHALON_ORDER_REPLAY_AMQP": amqp}
        result = self.run(phase, (self.dotnet, assembly, phase), extra_env=environment, timeout=60, check=False)
        require(result.returncode == expected_exit and self.text(result) == expected_receipt and not result.stderr,
                f"Application exit or receipt differs at {phase}. See the private phase log.")
        self.report["phases"].append({"phase": phase, "exit": result.returncode, "receipt": expected_receipt})

    def matrix(self, assembly):
        port = self.start_fixture()
        self.start_postgres()
        self.schema()
        self.checkpoint("bootstrap", created=False)
        self.app(assembly, "create", port)
        self.checkpoint("order_and_outbox", created=True)
        self.app(assembly, "publish-confirm-only", port)
        self.checkpoint("confirmed_before_outbox_mark", created=True, ready=1)
        port = self.restart(self.disconnect(port))
        self.checkpoint("after_confirm_restart", created=True, ready=1)
        self.app(assembly, "publish", port)
        self.checkpoint("after_retry_mark", created=True, published=True, ready=2)
        self.app(assembly, "worker-exit-after-commit", port)
        self.checkpoint("committed_before_worker_ack", created=True, published=True, reserved=True, ready=2)
        port = self.restart(self.disconnect(port))
        self.checkpoint("after_worker_exit_restart", created=True, published=True, reserved=True, ready=2)
        self.app(assembly, "worker-replay", port)
        self.checkpoint("after_duplicate_acks", created=True, published=True, reserved=True, ready=0)
        port = self.restart(self.disconnect(port))
        self.app(assembly, "verify", port)
        self.checkpoint("verified_after_final_restart", created=True, published=True, reserved=True, ready=0)

    def cleanup_postgres(self):
        label = f"label={PG_LABEL}={self.pg_name}"
        args = ("container", "ls", "--all", "--quiet", "--no-trunc", "--filter", label)
        owned = self.text(self.docker("cleanup-pg", *args)).splitlines()
        require(len(owned) <= 1 and (self.pg_container is None or owned in ([], [self.pg_container])),
                "Expected unambiguous PostgreSQL container ownership.")
        for container in owned:
            require(re.fullmatch("[a-f0-9]{64}", container), "Expected full owned PostgreSQL container ID.")
            active = self.text(self.docker("cleanup-pg", "container", "inspect", "--format",
                                          "{{.State.Running}}", container))
            if active == "true":
                self.docker("cleanup-pg", "container", "stop", "--timeout", "30", container, timeout=40)
            self.docker("cleanup-pg", "container", "rm", container)
        args_volume = ("volume", "ls", "--filter", label, "--format", "{{.Name}}")
        volumes = self.text(self.docker("cleanup-pg", *args_volume)).splitlines()
        require(volumes in ([], [self.pg_name]), "Expected unambiguous PostgreSQL volume ownership.")
        if volumes:
            self.docker("cleanup-pg", "volume", "rm", self.pg_name)
        require(not self.text(self.docker("cleanup-pg", *args)) and
                not self.text(self.docker("cleanup-pg", *args_volume)), "An owned PostgreSQL resource remains.")
        if self.pg_port is not None:
            wait_until(lambda: True if not broker.port_open(self.pg_port) else None, "closed PostgreSQL listener", 15)
        self.report["postgresql_cleanup"] = {"container_gone": True, "volume_gone": True, "loopback_closed": True}

    def cleanup_fixtures(self):
        try:
            self.cleanup_postgres()
        finally:
            super().cleanup()
            self.report["rabbitmq_cleanup"] = self.report.pop("cleanup")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet", required=True, type=Path)
    parser.add_argument("--engine-root", required=True, type=Path)
    parser.add_argument("--samples-revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    out = (ROOT / args.output).resolve()
    private = (ROOT / ".local").resolve()
    require(out != private and out.is_relative_to(private), "Use a fresh Samples .local directory.")
    require(re.fullmatch("[a-f0-9]{40}", args.samples_revision), "Expected the exact Samples commit SHA.")
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    proof = ReplayProof(args.dotnet.resolve(strict=True), args.engine_root.resolve(strict=True), out,
                        args.samples_revision)
    proof.write()
    fixtures = False
    try:
        assembly = proof.build_replay()
        fixtures = True
        proof.matrix(assembly)
        require(proof.source_snapshot() == proof.report["source"], "Tracked source changed during the proof.")
        proof.report["status"] = "passed"
    except Exception as error:
        proof.report.update(status="failed", failure=str(error))
        raise
    finally:
        try:
            if fixtures:
                try:
                    if proof.report["status"] == "failed":
                        for kind, container in (("postgresql", proof.pg_container), ("rabbitmq", proof.container)):
                            if container is not None:
                                proof.docker(kind + "-bootstrap-private", "container", "logs", container, check=False)
                finally:
                    proof.cleanup_fixtures()
        except Exception as error:
            proof.report.update(status="failed", cleanup_failure=str(error))
            raise
        finally:
            proof.write()


if __name__ == "__main__":
    main()
