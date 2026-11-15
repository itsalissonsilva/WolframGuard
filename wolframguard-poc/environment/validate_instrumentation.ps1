param([string]$RunId = 'preparation-001')
$ErrorActionPreference = 'Stop'
if ($RunId -notmatch '^[a-z0-9-]+$') { throw 'Invalid RunId' }
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskWork = Join-Path $taskRoot "results\$RunId"
if (Test-Path -LiteralPath $taskWork) { throw 'Refusing to overwrite an existing run. Use a new RunId.' }
New-Item -ItemType Directory -Path $taskWork | Out-Null
$taskImage = (& docker image inspect 'python:3.13-slim' --format '{{.Id}}')
if ($LASTEXITCODE -ne 0) { throw 'Cached python:3.13-slim image is required; no image is pulled.' }
$taskArgs = @('run','--rm','--pull=never','--network=none','--user=10001:10001',
  '--read-only','--cap-drop=ALL','--security-opt=no-new-privileges:true',
  '--pids-limit=64','--memory=256m','--cpus=1',
  '--tmpfs=/tmp:rw,noexec,nosuid,size=16m',
  '--mount',"type=bind,source=$taskRoot,target=/source,readonly",
  '--mount',"type=bind,source=$taskWork,target=/work",
  '--env=PYTHONDONTWRITEBYTECODE=1','--entrypoint=python',$taskImage,
  '/source/instrumentation/lab.py')
$taskOut = Join-Path $taskRoot "results\$RunId.json"
$taskErr = Join-Path $taskRoot "results\$RunId.stderr.txt"
[pscustomobject]@{ImageId=$taskImage;Arguments=$taskArgs;Kind='instrumentation validation only'} |
  ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $taskRoot "results\$RunId-launch.json")
& docker @taskArgs 2> $taskErr | Set-Content -LiteralPath $taskOut
if ($LASTEXITCODE -ne 0) { throw "Validation failed; inspect $taskErr" }
$taskResult = Get-Content -LiteralPath $taskOut -Raw | ConvertFrom-Json
if ($taskResult.agent_trial -ne $false -or $taskResult.read_only_count -ne 250 -or !$taskResult.receiver_selftest_ok) { throw 'Unexpected validation result' }
Write-Output "Verified isolated fixture and instrumentation preparation: $taskOut"
