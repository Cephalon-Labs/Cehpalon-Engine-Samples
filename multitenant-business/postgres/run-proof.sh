#!/usr/bin/env bash
set -euo pipefail

if (( $# != 3 )); then
    echo 'Usage: bash run-proof.sh DOTNET ENGINE_ROOT NEW_EVIDENCE_DIRECTORY' >&2
    exit 2
fi
dotnet=$(realpath -- "$1")
engine=$(realpath -- "$2")
evidence=$(realpath -m -- "$3")
cd "$(dirname -- "${BASH_SOURCE[0]}")"
project_root=$PWD
sample=$(git -C "$project_root" rev-parse --show-toplevel)
expected_engine=6fe7254404cf6b148370bd95befe8331e8932354
image='registry-1.docker.io/library/postgres@sha256:9770878138a2e83abcb10856d30cc3f24dae0d317bb956db6ab9159de6c3c80d'
image_config='sha256:79061104669bb30919d015b549c764e2d8021a18ee39cb175581a2588fe90dbe'
project="$project_root/Business.Postgres.Consumer.csproj"
migration="$project_root/migrations/001_orders.sql"
sdk_pin=$(sed -n 's/^[[:space:]]*"version": "\([^"]*\)".*/\1/p' "$sample/global.json")

fail() {
    echo "$1" >&2
    exit 1
}

[[ -x "$dotnet" && -f "$project" && -f "$migration" ]] || fail 'Proof inputs are missing.'
[[ "$evidence" == "$sample/.local/"* ]] || fail 'Evidence directory must be inside Samples .local.'
mkdir -p -- "$(dirname -- "$evidence")"
mkdir -- "$evidence"
[[ "$(git -C "$engine" rev-parse HEAD)" == "$expected_engine" &&
    -z "$(git -C "$engine" status --porcelain)" ]] || fail 'Engine checkout differs from the pinned clean revision.'
[[ "$("$dotnet" --version)" == "$sdk_pin" ]] || fail 'SDK differs from Samples global.json.'
"$dotnet" --list-runtimes | grep -q '^Microsoft.NETCore.App 11\.0\.0 ' || fail 'The pinned .NET runtime is unavailable.'
proof_inputs=(Business.Postgres.Consumer.csproj Program.cs PostgresOrderStore.cs ConcurrentOrderChecks.cs
    migrations/001_orders.sql packages.lock.json run-proof.sh OVERLAP-PROTOCOL.md)
{
    printf 'Engine %s\n' "$expected_engine"
    printf 'Samples %s\n' "$(git -C "$sample" rev-parse HEAD)"
    if [[ -z "$(git -C "$sample" status --porcelain)" ]]; then
        echo 'Samples source is clean.'
    else
        echo 'Samples source has local changes. See input hashes.'
    fi
    printf 'SDK %s\n' "$sdk_pin"
    printf 'Host %s\n' "$(uname -smr)"
    printf 'Docker %s\n' "$(docker info --format '{{.ServerVersion}}')"
    sha256sum "${proof_inputs[@]}"
} >"$evidence/inputs-before.txt"
artifacts="$evidence/artifacts"
"$dotnet" restore "$project" --configfile "$sample/NuGet.Config" --locked-mode \
    --artifacts-path "$artifacts" "-p:EngineRoot=$engine" >"$evidence/restore.log" 2>&1
"$dotnet" build "$project" -c Release --no-restore --artifacts-path "$artifacts" \
    "-p:EngineRoot=$engine" -warnaserror >"$evidence/build.log" 2>&1

container=
port=
volume=
cleanup() {
    local status=$?
    trap - EXIT
    set +e
    if [[ -n "$container" ]]; then
        if ! docker rm --force --volumes "$container" >/dev/null ||
            docker container inspect "$container" >/dev/null 2>&1 ||
            { [[ -n "$volume" ]] && docker volume inspect "$volume" >/dev/null 2>&1; } ||
            { [[ -n "$port" ]] && ( : >"/dev/tcp/127.0.0.1/$port" ) 2>/dev/null; }; then
            echo 'Owned PostgreSQL cleanup could not be verified.' >&2
            status=1
        elif [[ -n "$volume" && -n "$port" ]]; then
            echo 'Owned container and volume removed; loopback port closed.'
        fi
    fi
    exit "$status"
}
trap cleanup EXIT
export POSTGRES_PASSWORD
POSTGRES_PASSWORD=$(tr -d '-' </proc/sys/kernel/random/uuid)
export MIGRATOR_PASSWORD RUNTIME_PASSWORD
MIGRATOR_PASSWORD=$(tr -d '-' </proc/sys/kernel/random/uuid)
RUNTIME_PASSWORD=$(tr -d '-' </proc/sys/kernel/random/uuid)
container=$(docker run --detach --platform linux/amd64 --publish '127.0.0.1::5432' \
    --env POSTGRES_PASSWORD --env POSTGRES_DB=cephalon_app_proof "$image")
unset POSTGRES_PASSWORD
binding=$(docker port "$container" 5432/tcp)
[[ "$binding" =~ ^127\.0\.0\.1:([0-9]+)$ ]] || fail 'Expected one PostgreSQL loopback port.'
port=${BASH_REMATCH[1]}
volume=$(docker inspect --format '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}{{end}}{{end}}' "$container")
[[ "$volume" =~ ^[a-f0-9]{64}$ ]] || fail 'Expected one owned PostgreSQL volume.'
[[ "$(docker inspect --format '{{.Image}}' "$container")" == "$image_config" ]] || fail 'PostgreSQL image configuration differs.'
printf 'PostgreSQL image %s\nPostgreSQL config %s\n' "$image" "$image_config"

for (( check=0; check<90; check++ )); do
    if docker exec "$container" pg_isready -h 127.0.0.1 -q -U postgres -d cephalon_app_proof; then
        break
    fi
    sleep 0.5
done
(( check < 90 )) || fail 'PostgreSQL TCP readiness timed out.'

admin() {
    docker exec -i "$container" psql -X -v ON_ERROR_STOP=1 -U postgres -d cephalon_app_proof "$@"
}
[[ "$(admin -Atc 'SHOW server_version_num')" == 180006 ]] || fail 'Expected PostgreSQL 18.6.'
echo 'PostgreSQL 18.6 ready on owned loopback.'
docker exec -i --env MIGRATOR_PASSWORD --env RUNTIME_PASSWORD "$container" \
    psql -X -v ON_ERROR_STOP=1 -U postgres -d cephalon_app_proof >"$evidence/bootstrap.log" 2>&1 <<'SQL'
\getenv migrator_password MIGRATOR_PASSWORD
\getenv runtime_password RUNTIME_PASSWORD
CREATE ROLE cephalon_orders_migrator LOGIN NOSUPERUSER NOCREATEROLE NOBYPASSRLS PASSWORD :'migrator_password';
CREATE ROLE cephalon_orders_runtime LOGIN NOSUPERUSER NOCREATEROLE NOBYPASSRLS PASSWORD :'runtime_password';
REVOKE ALL ON DATABASE cephalon_app_proof FROM PUBLIC;
GRANT CONNECT, CREATE ON DATABASE cephalon_app_proof TO cephalon_orders_migrator;
GRANT CONNECT ON DATABASE cephalon_app_proof TO cephalon_orders_runtime;
SQL

migrate() {
    PGPASSWORD="$MIGRATOR_PASSWORD" docker exec -i --env PGPASSWORD "$container" psql -X -v ON_ERROR_STOP=1 \
        -h 127.0.0.1 -U cephalon_orders_migrator -d cephalon_app_proof --single-transaction --file -
}

if { cat "$migration"; printf '\nSELECT 1 / 0;\n'; } | migrate >"$evidence/migration-rollback.log" 2>&1; then
    fail 'The intentionally failed migration returned success.'
fi
grep -q 'division by zero' "$evidence/migration-rollback.log" || fail 'The migration did not reach its intentional failure.'
[[ "$(admin -Atc "SELECT to_regnamespace('cephalon_orders') IS NULL")" == t ]] || fail 'Failed migration left a schema.'
migrate <"$migration" >"$evidence/migration-apply.log" 2>&1
[[ "$(admin -Atc "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'cephalon_orders.orders'::regclass")" == cephalon_orders_migrator ]] || fail 'Migrator does not own the order table.'
if migrate <"$migration" >"$evidence/migration-repeat.log" 2>&1; then
    fail 'The create-only migration accepted an unexpected replay.'
fi
grep -q 'already exists' "$evidence/migration-repeat.log" || fail 'The migration replay failed for an unexpected reason.'
unset MIGRATOR_PASSWORD
admin >"$evidence/seed.log" 2>&1 <<'SQL'
INSERT INTO cephalon_orders.orders (tenant_id, order_id, status, revision) VALUES
    ('A', 1, 'pending', 0),
    ('B', 1, 'review', 0),
    ('A', 2, 'pending', 0),
    ('B', 2, 'review', 0),
    ('A', 3, 'pending', 0),
    ('A', 4, 'pending', 0);
SQL
echo 'Migration rollback, explicit apply, owner and repeat refusal verified.'

assembly="$artifacts/bin/Business.Postgres.Consumer/release/Business.Postgres.Consumer.dll"
runtime_config="${assembly%.dll}.runtimeconfig.json"
sha256sum "$assembly" "$runtime_config" >"$evidence/binaries.sha256"
CEPHALON_ORDERS_RUNTIME="Host=127.0.0.1;Port=$port;Database=cephalon_app_proof;Username=cephalon_orders_runtime;Password=$RUNTIME_PASSWORD;SSL Mode=Disable" \
    "$dotnet" "$assembly" | tee "$evidence/results.log"
unset RUNTIME_PASSWORD
sha256sum --check <(tail -n "${#proof_inputs[@]}" "$evidence/inputs-before.txt")
[[ "$(git -C "$engine" rev-parse HEAD)" == "$expected_engine" &&
    -z "$(git -C "$engine" status --porcelain)" ]] || fail 'Pinned Engine worktree changed during proof.'
