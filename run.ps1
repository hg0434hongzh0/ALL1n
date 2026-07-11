$ErrorActionPreference = "Stop"
$projectDir = $PSScriptRoot
$exe = Join-Path $projectDir "bin\ALL1n.exe"
$buildScript = Join-Path $projectDir "build.ps1"

$needsBuild = -not (Test-Path $exe)
if (-not $needsBuild) {
    $exeTime = (Get-Item $exe).LastWriteTimeUtc
    $newerSource = Get-ChildItem $projectDir -File |
        Where-Object {
            ($_.Extension -eq ".go" -or $_.Name -in @("go.mod", "go.sum")) -and
            $_.LastWriteTimeUtc -gt $exeTime
        } |
        Select-Object -First 1
    $needsBuild = $null -ne $newerSource
}

if ($needsBuild) {
    & $buildScript
}

& $exe
