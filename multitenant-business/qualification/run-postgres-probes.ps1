# Requires PowerShell 7, Docker, and the Samples-pinned .NET SDK.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$image = 'registry-1.docker.io/library/postgres@sha256:9770878138a2e83abcb10856d30cc3f24dae0d317bb956db6ab9159de6c3c80d'
$name = "cephalon-pg-probe-$([guid]::NewGuid().ToString('N'))"
$password = [guid]::NewGuid().ToString('N')
$priorConnection = [Environment]::GetEnvironmentVariable('CEPHALON_PROBE_POSTGRES')

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE." }
}

Invoke-Checked docker @('version', '--format', '{{.Server.Version}}')
$sdk = Invoke-Checked dotnet @('--version')
if ($sdk -ne '11.0.100-rc.3.26522.148') { throw 'Run from the Samples checkout using its pinned .NET SDK.' }
try {
    Invoke-Checked docker @('run', '--detach', '--name', $name, '--platform', 'linux/amd64',
        '--publish', '127.0.0.1::5432', '--env', "POSTGRES_PASSWORD=$password",
        '--env', 'POSTGRES_DB=cephalon_probe', $image)

    $deadline = [Diagnostics.Stopwatch]::StartNew()
    do {
        # TCP excludes the temporary socket-only initialization server.
        & docker exec $name pg_isready -h 127.0.0.1 -U postgres -d cephalon_probe -q
        if ($LASTEXITCODE -eq 0) { break }
        if ($deadline.Elapsed.TotalSeconds -ge 45) { throw 'PostgreSQL readiness timed out.' }
        Start-Sleep -Milliseconds 500
    } while ($true)

    $binding = Invoke-Checked docker @('port', $name, '5432/tcp')
    if ($binding -notmatch '^127\.0\.0\.1:(\d+)$') { throw 'Expected one loopback port binding.' }
    $port = $Matches[1]
    $version = Invoke-Checked docker @('exec', $name, 'psql', '-XAt', '-U', 'postgres',
        '-d', 'cephalon_probe', '-c', 'SHOW server_version_num')
    if ($version -ne '180006') { throw 'Expected PostgreSQL 18.6.' }

    Get-Content -Raw (Join-Path $PSScriptRoot 'postgres-rls-probe.sql') |
        docker exec -i $name psql -X -v ON_ERROR_STOP=1 -U postgres -d cephalon_probe
    if ($LASTEXITCODE -ne 0) { throw "SQL RLS probe failed with exit code $LASTEXITCODE." }

    $env:CEPHALON_PROBE_POSTGRES = "Host=127.0.0.1;Port=$port;Database=cephalon_probe;Username=postgres;Password=$password;SSL Mode=Disable"
    Invoke-Checked dotnet @('run', '--file', (Join-Path $PSScriptRoot 'PostgresPoolProbe.cs'))
}
finally {
    [Environment]::SetEnvironmentVariable('CEPHALON_PROBE_POSTGRES', $priorConnection)
    $owned = & docker container inspect --format '{{.Id}}' $name 2>$null
    if ($LASTEXITCODE -eq 0 -and $owned -match '^[0-9a-f]{64}$') {
        Invoke-Checked docker @('rm', '--force', '--volumes', $owned)
    } else {
        Write-Warning "Container cleanup could not be confirmed for $name."
    }
}
