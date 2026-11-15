$ErrorActionPreference = 'Stop'
$root = 'D:/Cephalon/Cehpalon-Engine-Samples'
$capture = "$root/.local/roslyn-gc-callsite-capture01"
$manifest = Get-Content "$capture/manifest.json" -Raw | ConvertFrom-Json
if ($manifest.status -ne 'completed' -or $manifest.sample_threads -ne $false) {
    throw 'A completed allocation-omitted capture is required'
}
if (-not (Test-Path "$PSScriptRoot/source-parity.json")) { throw 'Source and binary parity is required' }
function Invoke-Replay($tool, $output, [string[]]$arguments) {
    python -B "$root/tools/$tool.py" @arguments --output "$capture/$output" *> "$PSScriptRoot/$output.txt"
    if ($LASTEXITCODE) {
        Get-Content "$PSScriptRoot/$output.txt" -Tail 20
        throw "$tool failed"
    }
}
Invoke-Replay 'analyze_roslyn_task_lineage' 'lineage' @('--folder', "$capture/generator")
Invoke-Replay 'analyze_roslyn_scheduler' 'scheduler-joins' @('--capture', $capture, '--lineage', "$capture/lineage")
Invoke-Replay 'analyze_roslyn_boundaries' 'boundary-joins' @('--capture', $capture, '--joins', "$capture/scheduler-joins")
Invoke-Replay 'analyze_roslyn_gc_episodes' 'gc-episodes' @('--capture', $capture)

