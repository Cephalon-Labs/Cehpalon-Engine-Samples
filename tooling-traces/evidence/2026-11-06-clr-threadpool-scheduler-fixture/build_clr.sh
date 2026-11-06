#!/bin/sh
set -eu
root=/tmp/cehpalon-clr-scheduler-20261106-01
source=/mnt/d/Cephalon/Cehpalon-Engine-Samples/tooling-traces/ThreadPoolConformance
host=/home/tom/.local/share/cehpalon-benchmark-deployment/tuning-20261028/sdk/dotnet
mkdir "$root"
mkdir "$root/empty" "$root/src"
for file in Program.cs ThreadPoolConformance.csproj global.json packages.lock.json; do
    cp "$source/$file" "$root/src/$file"
done
cd "$root/src"
export DOTNET_CLI_HOME="$root/cli"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_GENERATE_ASPNET_CERTIFICATE=false
"$host" --version
sha256sum Program.cs ThreadPoolConformance.csproj global.json packages.lock.json
"$host" restore --locked-mode --source "$root/empty" --disable-build-servers
"$host" build --no-restore -c Release -o "$root/out" --disable-build-servers
sha256sum "$root/out/ThreadPoolConformance.dll" "$root/out/ThreadPoolConformance.runtimeconfig.json" "$root/out/ThreadPoolConformance.deps.json"
sha256sum "$host" "$(dirname "$host")/shared/Microsoft.NETCore.App/11.0.0-rc.3.26522.148/libcoreclr.so"
