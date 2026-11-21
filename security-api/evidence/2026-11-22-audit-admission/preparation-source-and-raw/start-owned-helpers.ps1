$ErrorActionPreference='Stop'
$taskRoot='D:/Cephalon/.worktrees/ara-consumer/.local'
foreach($name in @('pg-wsl-anchor-owned-process.json','pg-proxy-owned-process.json','pg-wsl-anchor-windows-process.json','pg-proxy-windows-process.json','pg-proxy-native-listener-before.json')){if(Test-Path -LiteralPath (Join-Path $taskRoot $name)){throw "Retain prior helper attempt: $name"}}
$anchor=Start-Process -FilePath 'wsl.exe' -ArgumentList @('-d','Ubuntu','--','python3','-u','/mnt/d/Cephalon/.worktrees/ara-consumer/.local/pg-wsl-anchor.py') -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $taskRoot 'pg-wsl-anchor.stdout.txt') -RedirectStandardError (Join-Path $taskRoot 'pg-wsl-anchor.stderr.txt')
@{pid=$anchor.Id}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $taskRoot 'pg-wsl-anchor-windows-process.json') -Encoding utf8
for($index=0;$index -lt 100 -and !(Test-Path -LiteralPath (Join-Path $taskRoot 'pg-wsl-anchor-owned-process.json'));$index++){Start-Sleep -Milliseconds 100}
if(!(Test-Path -LiteralPath (Join-Path $taskRoot 'pg-wsl-anchor-owned-process.json'))){throw 'Owned anchor did not register'}
$pythonExe=(Get-Command python.exe).Source
$proxy=Start-Process -FilePath $pythonExe -ArgumentList @('-u',($taskRoot+'/pg-loopback-proxy.py')) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $taskRoot 'pg-proxy.stdout.txt') -RedirectStandardError (Join-Path $taskRoot 'pg-proxy.stderr.txt')
@{pid=$proxy.Id}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $taskRoot 'pg-proxy-windows-process.json') -Encoding utf8
for($index=0;$index -lt 100 -and !(Test-Path -LiteralPath (Join-Path $taskRoot 'pg-proxy-owned-process.json'));$index++){Start-Sleep -Milliseconds 100}
if(!(Test-Path -LiteralPath (Join-Path $taskRoot 'pg-proxy-owned-process.json'))){throw 'Owned proxy did not register'}
$owned=Get-Content -LiteralPath (Join-Path $taskRoot 'pg-proxy-owned-process.json') -Raw|ConvertFrom-Json
$ownedPort=[int]($owned.bind.Split(':')[-1])
$listeners=@([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()|Where-Object {$_.Port -eq $ownedPort})
@{method='Native IPGlobalProperties.GetActiveTcpListeners';port=$ownedPort;listener_count=$listeners.Count;status='observed'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $taskRoot 'pg-proxy-native-listener-before.json') -Encoding utf8
if($listeners.Count -ne 1){throw 'Owned native listener count must be one'}
Write-Output ('Owned helpers ready; OS assigned proxy port '+$ownedPort)
