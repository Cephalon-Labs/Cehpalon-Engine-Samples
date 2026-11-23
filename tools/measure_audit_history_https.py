"""Paired WSL/HTTPS audit history measurement with an owned PostgreSQL fixture."""
import argparse
from contextlib import closing
import hashlib
import http.client
import json
from pathlib import Path
import select
import ssl
import statistics
import subprocess
import time
import uuid

PAIRS = (("before", "after"), ("after", "before"), ("before", "after"), ("after", "before"))
WORKLOADS = (("http", 25), ("graphql", 25), ("http", 200), ("graphql", 200))
WARMUP, MEASURED, BOOKMARK = 20, 100, 8
FIELDS = ("title", "secret", "category", "count", "retained", "enabled", "comment", "rank")
SELECTION = """tenant entries {
  receiptId recordedAtUtc reportedAtUtc principalIssuer principalSubject authenticationScheme
  tenant operationId action resourceKind resourceId authorizationResourceVersion beforeEntityVersion
  afterEntityVersion kind mode capturedMode fields { name wasChanged before { kind text number boolean }
    after { kind text number boolean } } } nextCursor { tenant resourceKind resourceId afterReceiptId }"""


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def request_bytes(transport, tenant, limit, cursor_tenant=None):
    cursor = dict(tenant=cursor_tenant or tenant, resourceKind="entity", resourceId="shared",
                  afterReceiptId=str(uuid.UUID(int=BOOKMARK)))
    value = dict(tenant=tenant, resourceKind="entity", resourceId="shared", limit=limit, continuation=cursor)
    if transport == "http":
        return json.dumps(value).encode()
    return json.dumps({
        "query": "query($input:AuditResourceHistoryRequestInput!) { trailResourceHistory(input:$input) {"
                 + SELECTION + "} }",
        "variables": {"input": value},
    }).encode()


def send(client, transport, body, token):
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    path = "/audit/resources/history" if transport == "http" else "/graphql"
    t0 = time.perf_counter_ns()
    client.request("POST", path, body, headers)
    response = client.getresponse()
    data = response.read(4 * 1024 * 1024 + 1)
    latency = time.perf_counter_ns() - t0
    require(len(data) <= 4 * 1024 * 1024, "Response size exceeded fixture bound")
    return response.status, data, latency


def verify_page(transport, tenant, limit, status, body):
    require(status == 200, "Expected a successful audit read")
    root = json.loads(body)
    if transport == "graphql":
        require("errors" not in root, "Unexpected GraphQL error")
        root = root["data"]["trailResourceHistory"]
    require(root["tenant"] == tenant and len(root["entries"]) == limit, "Wrong response scope or page count")
    cursor = root["nextCursor"]
    require(cursor["tenant"] == tenant and cursor["resourceKind"] == "entity" and cursor["resourceId"] == "shared"
            and uuid.UUID(cursor["afterReceiptId"]).int == BOOKMARK + limit, "Wrong continuation")
    for key, record in enumerate(root["entries"], BOOKMARK + 1):
        require(uuid.UUID(record["receiptId"]).int == key and record["tenant"] == tenant
                and record["resourceKind"] == "entity" and record["resourceId"] == "shared"
                and record["mode"] == record["capturedMode"] == "BeforeAfterSnapshots", "Wrong row or receipt order")
        require(tuple(f["name"] for f in record["fields"]) == FIELDS, "Wrong field order or allowlist")
        for field in record["fields"]:
            name = field["name"]
            values = (field["before"], field["after"])
            require(field["wasChanged"], "Wrong recorded change flag")
            if name == "secret":
                require(all(value == dict(kind="Redacted", text=None, number=None, boolean=None) for value in values),
                        "Secret projection leaked fixture values")
            else:
                require(all(value["kind"] == "Text" and value["number"] is None and value["boolean"] is None
                            for value in values)
                        and values[0]["text"] == "before:" + name
                        and values[1]["text"] == f"after:{tenant}:{key}:{name}", "Wrong tenant field projection")
    return hashlib.sha256(json.dumps(root, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Server:
    def __init__(self, command, error_log):
        self.command = command
        self.error_log = error_log

    def __enter__(self):
        self.stderr = self.error_log.open("xb")
        try:
            self.process = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=self.stderr, bufsize=0)
        except BaseException:
            self.stderr.close()
            raise
        return self

    def read(self, expected):
        require(bool(select.select([self.process.stdout], [], [], 35)[0]), "Server control timed out")
        line = self.process.stdout.readline()
        require(bool(line), "Server ended before control response")
        result = json.loads(line)
        require(result["kind"] == expected, "Unexpected server control message")
        return result

    def control(self, verb, expected=None):
        self.process.stdin.write((verb + "\n").encode())
        return self.read(expected or verb)

    def stop(self):
        self.process.stdin.write(b"stop\n")
        require(self.process.wait(timeout=30) == 0, "Server exited unsuccessfully")

    def __exit__(self, *_):
        try:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=10)
        finally:
            self.process.stdin.close()
            self.process.stdout.close()
            self.stderr.close()


def checks(server, client, transport, credentials, emit):
    scenarios = (
        ("A-owner", "A", "a", None, None),
        ("B-owner", "B", "b", None, None),
        ("A-to-B", "B", "a", None, "access.denied"),
        ("B-to-A", "A", "b", None, "access.denied"),
        ("missing-grant", "A", "history_only", None, "access.denied"),
        ("anonymous", "A", None, None, "anonymous"),
        ("foreign-cursor", "A", "both", "B", "validation.failed"),
        ("membership-revoked", "A", "both", None, "access.denied"),
        ("membership-restored", "A", "both", None, None),
    )
    for name, tenant, token, foreign, error in scenarios:
        if name == "membership-revoked":
            server.control("revoke", "revoked")
        if name == "membership-restored":
            server.control("restore", "restored")
        before = server.control("snapshot")
        status, data, _ = send(client, transport, request_bytes(transport, tenant, 25, foreign),
                               credentials[token] if token else None)
        after = server.control("snapshot")
        delta = {key: after[key] - before[key] for key in ("queries", "handlers", "results")}
        require(all(v == (0 if error else 1) for v in delta.values()) and after["active"] == 0,
                "Unexpected work for correctness request: " + name)
        if error is None:
            verify_page(transport, tenant, 25, status, data)
        elif error == "anonymous":
            require(status == 401, "Expected authentication rejection")
        elif transport == "graphql":
            root = json.loads(data)
            require(status == 200 and [e["extensions"]["code"] for e in root["errors"]] == [error],
                    "Wrong GraphQL rejection: " + name)
            require(root.get("data") in (None, {"trailResourceHistory": None}), "Data leaked in denied response")
        else:
            require(status == (403 if error == "access.denied" else 400) and json.loads(data)["code"] == error,
                    "Wrong HTTP rejection: " + name)
        if error:
            require(b"fixture-writer" not in data and b"after:" not in data and b"entries" not in data,
                    "Denied request published fixture data")
        emit(dict(kind="control", transport=transport, name=name, status=status, **delta))


def measure_workload(server, credentials, ssl_context, transport, limit, pair, lane, canonical, emit):
    with closing(http.client.HTTPSConnection("127.0.0.1", credentials["port"], context=ssl_context, timeout=15)) as client:
        payloads = {tenant: request_bytes(transport, tenant, limit) for tenant in ("A", "B")}
        socket = None

        def one(index, measured):
            nonlocal socket
            tenant = "A" if index % 2 == 0 else "B"
            status, body, latency = send(client, transport, payloads[tenant], credentials["both"])
            if socket is None:
                socket = client.sock
                require(socket is not None and socket.version() in ("TLSv1.2", "TLSv1.3"), "HTTPS TLS not observed")
                emit(dict(kind="connection", transport=transport, limit=limit, tls=socket.version()))
            require(client.sock is socket, "HTTPS connection did not stay warm")
            digest = verify_page(transport, tenant, limit, status, body)
            require(canonical.setdefault((tenant, limit), digest) == digest, "Response differs across transport or revision")
            emit(dict(kind="request", transport=transport, limit=limit, index=index, tenant=tenant, measured=measured,
                      latency_ns=latency, bytes=len(body), digest=digest))
            return latency

        for index in range(WARMUP):
            one(index, False)
        before = server.control("snapshot")
        samples = [one(index, True) for index in range(MEASURED)]
        after = server.control("snapshot")
        require(before["active"] == after["active"] == 0 and
                all(after[k] - before[k] == MEASURED for k in ("queries", "handlers", "results")),
                "Expected one completed PostgreSQL read and handler per measured response")
        ordered = sorted(samples)
        result = dict(kind="batch", pair=pair, lane=lane, transport=transport, limit=limit, samples=MEASURED,
                      p50_ns=ordered[49], p95_ns=ordered[94], p99_ns=ordered[98],
                      allocated_bytes=after["allocated"] - before["allocated"],
                      gc_collections=[a - b for a, b in zip(after["collections"], before["collections"], strict=True)],
                      source_queries=after["queries"] - before["queries"], before=before, after=after)
        require(result["allocated_bytes"] > 0, "Invalid process allocation delta")
        emit(result)
        return result


def summarize(batches):
    def metrics(batch):
        return {label + "_ms": batch[label + "_ns"] / 1e6 for label in ("p50", "p95", "p99")} | {
            "bytes_per_request": batch["allocated_bytes"] / batch["samples"]}

    summary = []
    for transport, limit in WORKLOADS:
        pairs = []
        for number in range(1, len(PAIRS) + 1):
            indexed = {b["lane"]: metrics(b) for b in batches
                       if (b["pair"], b["transport"], b["limit"]) == (number, transport, limit)}
            old, new = indexed["before"], indexed["after"]
            pairs.append(dict(pair=number, before=old, after=new,
                              percent_change={k: (new[k] / old[k] - 1) * 100 for k in old}))
        summary.append(dict(transport=transport, limit=limit, pairs=pairs,
                            median_paired_percent={k: statistics.median(p["percent_change"][k] for p in pairs)
                                                   for k in pairs[0]["percent_change"]}))
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dotnet", required=True, type=Path)
    parser.add_argument("--before", required=True, type=Path)
    parser.add_argument("--after", required=True, type=Path)
    parser.add_argument("--connection-file", required=True, type=Path)
    parser.add_argument("--schema", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--compare-read-deadline", action="store_true",
                        help="Use one binary and compare null with a two-second Engine read deadline")
    args = parser.parse_args()
    if args.compare_read_deadline:
        require(args.before.resolve() == args.after.resolve(), "Deadline comparison requires the exact same binary")
    args.output.mkdir(parents=True, exist_ok=False)
    binaries = {"before": args.before, "after": args.after}
    timeouts = {"before": None, "after": 2000 if args.compare_read_deadline else None}

    def command(lane, mode):
        parts = [args.dotnet, binaries[lane], "--measure-audit-history", mode, args.connection_file, args.schema]
        if mode == "serve" and timeouts[lane] is not None:
            parts.append("deadline")
        return parts

    with (args.output / "seed.json").open("xb") as seed, (args.output / "seed.stderr.log").open("xb") as error:
        subprocess.run(command("before", "seed"), stdout=seed, stderr=error, check=True, timeout=180)
    fixture = json.loads((args.output / "seed.json").read_bytes())
    require(fixture["kind"] == "seeded" and fixture["resource_rows"] == 512 and fixture["distractor_rows"] == 128
            and fixture["settings"]["server_version"].startswith("PostgreSQL 18.7 "), "Unexpected PostgreSQL fixture")
    deadline_checks = []
    if args.preflight and args.compare_read_deadline:
        receipt = args.output / "deadline-controls.jsonl"
        with receipt.open("xb") as raw, (args.output / "deadline-controls.stderr.log").open("xb") as error:
            subprocess.run(command("before", "verify-deadline"), stdout=raw, stderr=error, check=True, timeout=240)
        deadline_checks = [json.loads(row) for row in receipt.read_bytes().splitlines()]
        expected = {(transport, scenario) for transport in ("http", "graphql") for scenario in (
            "deadline-elapses", "caller-with-deadline", "caller-without-deadline", "null-outlasts-deadline")}
        require(len(deadline_checks) == len(expected) and
                {(row["transport"], row["scenario"]) for row in deadline_checks} == expected and
                all(row["kind"] == "deadline_control" and row["lock_observed_before_signal"]
                    and row["joined_backend"] and row["successful_reuse"] for row in deadline_checks),
                "Incomplete live PostgreSQL deadline controls")
    canonical, batches = {}, []
    pairs = (PAIRS[0],) if args.preflight else PAIRS
    for pair, order in enumerate(pairs, 1):
        for lane in order:
            prefix = args.output / f"pair-{pair}-{lane}"
            with prefix.with_suffix(".jsonl").open("x") as raw, Server(command(lane, "serve"), prefix.with_suffix(".stderr.log")) as server:
                def emit(event):
                    raw.write(json.dumps(event, sort_keys=True) + "\n")
                    raw.flush()

                credentials = server.read("ready")
                require(credentials["read_timeout_ms"] == timeouts[lane], "Unexpected server read deadline")
                emit(dict(kind="read_deadline", read_timeout_ms=credentials["read_timeout_ms"]))
                context = ssl.create_default_context(cadata=credentials["ca"])
                require(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED, "TLS trust weakened")
                for transport in ("http", "graphql"):
                    with closing(http.client.HTTPSConnection("127.0.0.1", credentials["port"], context=context, timeout=15)) as client:
                        checks(server, client, transport, credentials, emit)
                if not args.preflight:
                    rotation = (pair - 1) % len(WORKLOADS)
                    for transport, limit in WORKLOADS[rotation:] + WORKLOADS[:rotation]:
                        batches.append(measure_workload(server, credentials, context, transport, limit,
                                                        pair, lane, canonical, emit))
                else:
                    for transport, limit in WORKLOADS:
                        with closing(http.client.HTTPSConnection("127.0.0.1", credentials["port"], context=context, timeout=15)) as client:
                            status, body, _ = send(client, transport, request_bytes(transport, "B", limit), credentials["both"])
                            digest = verify_page(transport, "B", limit, status, body)
                            require(canonical.setdefault(("B", limit), digest) == digest, "Preflight payload mismatch")
                            emit(dict(kind="preflight", transport=transport, limit=limit, digest=digest))
                server.stop()
            print(f"pair {pair} {lane}: verified", flush=True)

    (args.output / "summary.json").write_text(json.dumps(
        dict(status="passed", preflight=args.preflight, fixture=fixture, read_timeout_ms=timeouts,
             deadline_lock_controls=len(deadline_checks), measured_requests=len(batches) * MEASURED,
             controls=len(pairs) * 2 * 2 * 9, batches=batches, comparisons=[] if args.preflight else summarize(batches)),
        indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
