# Sourced by run-proof.sh for the explicitly selected crash mode.

run_crash_proof() {
    local expected_storage expected_system expected_start actual_start
    local stop_deadline stopped exit_code stopped_at stage_process verify_process new_binding
    [[ "$container" =~ ^[a-f0-9]{64}$ ]] || fail 'Expected the exact owned container ID.'
    expect_owned_container
    expected_storage=$(docker volume inspect --format '{{.Driver}}|{{.CreatedAt}}' "$volume")
    expected_system=$(admin -Atc 'SELECT system_identifier FROM pg_control_system()')
    [[ "$expected_system" =~ ^[0-9]+$ ]] || fail 'Expected the fixture database system identifier.'
    expected_start=$(admin -Atc 'SELECT pg_postmaster_start_time()')
    require_durability

    admin >"$evidence/recovery-seed.log" 2>&1 <<'SQL'
INSERT INTO cephalon_orders.orders (tenant_id, order_id, status, revision) VALUES
    ('A', 5, 'pending', 0),
    ('B', 5, 'review', 0);
SQL

    stage_signal="$evidence/crash-stage.close"
    : >"$evidence/crash-stage.log"
    "$dotnet" "$assembly" --crash-stage "$stage_signal" >"$evidence/crash-stage.log" 2>&1 &
    stage_pid=$!
    stage_process=$stage_pid
    stop_deadline=$((SECONDS + 35))
    while ! grep -Fxq 'Crash stage ready with one acknowledged commit and one held update.' "$evidence/crash-stage.log"; do
        kill -0 "$stage_pid" 2>/dev/null || fail 'Crash stage stopped before its receipt.'
        (( SECONDS < stop_deadline )) || fail 'Crash stage receipt timed out.'
        sleep 0.05
    done
    kill -0 "$stage_pid" 2>/dev/null || fail 'Crash stage was absent at the crash boundary.'
    expect_owned_container
    [[ "$(docker inspect --format '{{.State.Running}}' "$container")" == true ]] || fail 'The owned PostgreSQL fixture was not running.'
    echo 'Crash stage ready with one acknowledged commit and one held update.'

    docker kill --signal KILL "$container" >"$evidence/crash-stop.log"
    IFS='|' read -r stopped exit_code stopped_at <<<"$(docker inspect --format '{{.State.Running}}|{{.State.ExitCode}}|{{.State.FinishedAt}}' "$container")"
    [[ "$stopped" == false && "$exit_code" == 137 && -n "$stopped_at" ]] || fail 'Expected the exact container to stop with exit 137.'
    echo 'Owned PostgreSQL received SIGKILL and exited with status 137.'

    : >"$stage_signal"
    if ! wait "$stage_pid"; then
        stage_pid=
        fail 'The stage process did not join after the fixture stop.'
    fi
    stage_pid=
    grep -Fxq 'Crash stage application joined after the stop signal.' "$evidence/crash-stage.log" ||
        fail 'The stage process did not acknowledge its close signal.'
    echo 'Crash stage application joined after the stop signal.'

    docker start "$container" >"$evidence/crash-start.log"
    expect_owned_container
    [[ "$(docker volume inspect --format '{{.Driver}}|{{.CreatedAt}}' "$volume")" == "$expected_storage" ]] ||
        fail 'The owned PostgreSQL volume changed during restart.'
    new_binding=$(docker port "$container" 5432/tcp)
    [[ "$new_binding" =~ ^127\.0\.0\.1:([0-9]+)$ ]] || fail 'Expected one PostgreSQL loopback port after restart.'
    port=${BASH_REMATCH[1]}
    wait_for_postgres
    [[ "$(admin -Atc 'SELECT system_identifier FROM pg_control_system()')" == "$expected_system" ]] ||
        fail 'The database system identifier changed during restart.'
    actual_start=$(admin -Atc 'SELECT pg_postmaster_start_time()')
    [[ -n "$actual_start" && "$actual_start" != "$expected_start" ]] || fail 'The postmaster start time did not change.'
    [[ "$(admin -Atc 'SELECT NOT pg_is_in_recovery()')" == t ]] || fail 'PostgreSQL had not completed recovery.'
    require_durability
    docker logs --since "$stopped_at" "$container" >"$evidence/postgresql-recovery.log" 2>&1
    grep -Fq 'automatic recovery in progress' "$evidence/postgresql-recovery.log" &&
        grep -Fq 'redo done at' "$evidence/postgresql-recovery.log" ||
        fail 'Expected fresh PostgreSQL crash recovery and completed redo markers.'
    echo 'Owned PostgreSQL restarted on the same storage and reported WAL recovery.'

    use_runtime_connection
    "$dotnet" "$assembly" --crash-verify >"$evidence/crash-verify.log" 2>&1 &
    verify_process=$!
    wait "$verify_process" || fail 'The fresh application failed its recovery assertions.'
    [[ "$verify_process" != "$stage_process" ]] || fail 'Expected a separate recovery application process.'
    grep -Fxq 'Fresh application saw only the acknowledged update and preserved tenant isolation after restart.' "$evidence/crash-verify.log" ||
        fail 'The recovery application did not publish its verification receipt.'
    echo 'Fresh application saw only the acknowledged update and preserved tenant isolation after restart.'
}

expect_owned_container() {
    local expected
    expected="$container|$image_config|$volume"
    [[ "$(docker inspect --format '{{.Id}}|{{.Image}}|{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}{{end}}{{end}}' "$container")" == "$expected" ]] ||
        fail 'The PostgreSQL container, image or volume differs from the owned fixture.'
}

require_durability() {
    [[ "$(admin -Atc "SELECT current_setting('fsync'), current_setting('synchronous_commit'), current_setting('full_page_writes')")" == 'on|on|on' ]] ||
        fail 'Expected fsync, synchronous_commit and full_page_writes.'
}
