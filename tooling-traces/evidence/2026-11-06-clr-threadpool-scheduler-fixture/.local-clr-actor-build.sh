#!/bin/sh
set -eu
root=/tmp/cehpalon-clr-actor-agent-01
mkdir "$root"
mkdir "$root/empty" "$root/src"
cp /mnt/d/Cephalon/.worktrees/clr-threadpool-actor/tooling-traces/ThreadPoolConformance/* "$root/src/"
cd "$root/src"
sdk=/home/tom/.local/share/cehpalon-benchmark-deployment/tuning-20261028/sdk/dotnet
export DOTNET_CLI_HOME="$root/cli" DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
"$sdk" --version
sha256sum Program.cs ThreadPoolConformance.csproj global.json packages.lock.json
"$sdk" restore --locked-mode --source "$root/empty"
"$sdk" build --no-restore -c Release -o "$root/out"
sha256sum "$root/out/ThreadPoolConformance.dll" "$root/out/ThreadPoolConformance.runtimeconfig.json" "$root/out/ThreadPoolConformance.deps.json"
