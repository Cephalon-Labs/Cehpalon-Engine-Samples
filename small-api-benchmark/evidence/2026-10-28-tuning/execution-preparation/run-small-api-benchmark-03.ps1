$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class CephalonBenchmarkExecutionState {
  [DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint state);
}
'@
$taskStarted = [DateTimeOffset]::UtcNow.ToString('o')
$taskHeld = [CephalonBenchmarkExecutionState]::SetThreadExecutionState(2147483649)
if ($taskHeld -eq 0) { throw 'Cannot hold task-owned idle-sleep guard.' }
$taskExit = -1
try {
    @{ startedAtUtc=$taskStarted; automaticIdleSleepInhibited=$true; persistentPowerPlanChanged=$false } | ConvertTo-Json | Set-Content -LiteralPath 'D:/Cephalon/Cehpalon-Engine-Samples/.local/benchmark-windows-launcher-03.json' -Encoding utf8
    & wsl -d Ubuntu --cd /mnt/d/Cephalon/Cehpalon-Engine-Samples python3 tools/benchmark_small_api.py --dotnet /home/tom/.local/share/cehpalon-benchmark-deployment/tuning-20261028/sdk/dotnet --assembly /home/tom/.local/share/cehpalon-benchmark-deployment/tuning-20261028/app-final-01/SmallApi.Benchmark.dll --server-working-directory /home/tom/.local/share/cehpalon-benchmark-deployment/tuning-20261028/app-final-01 --output /home/tom/.local/share/cehpalon-benchmark-runs/benchmark-observation-03
    $taskExit = $LASTEXITCODE
}
finally {
    $taskReleased = [CephalonBenchmarkExecutionState]::SetThreadExecutionState(2147483648)
    @{ startedAtUtc=$taskStarted; completedAtUtc=[DateTimeOffset]::UtcNow.ToString('o'); automaticIdleSleepInhibitedDuringRun=$true; guardReleased=($taskReleased -ne 0); persistentPowerPlanChanged=$false; exitCode=$taskExit } | ConvertTo-Json | Set-Content -LiteralPath 'D:/Cephalon/Cehpalon-Engine-Samples/.local/benchmark-windows-launcher-03.json' -Encoding utf8
}
exit $taskExit
