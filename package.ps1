$ErrorActionPreference = "Stop"
$projectDir = $PSScriptRoot
$versionSource = Get-Content (Join-Path $projectDir "report.go") -Raw
$match = [regex]::Match($versionSource, 'const appVersion = "([^"]+)"')
if (-not $match.Success) {
    throw "Unable to read appVersion from report.go"
}
$version = $match.Groups[1].Value

& (Join-Path $projectDir "build.ps1")

$distDir = Join-Path $projectDir "dist"
$stageDir = Join-Path $distDir "ALL1n-$version-windows-amd64"
$zipPath = "$stageDir.zip"
Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $stageDir | Out-Null

Copy-Item (Join-Path $projectDir "bin\ALL1n.exe") $stageDir
Copy-Item (Join-Path $projectDir "README.md") $stageDir
Copy-Item (Join-Path $projectDir "LICENSE") $stageDir
Copy-Item (Join-Path $projectDir "CHANGELOG.md") $stageDir
Copy-Item (Join-Path $projectDir "SECURITY.md") $stageDir
Compress-Archive -Path (Join-Path $stageDir "*") -DestinationPath $zipPath -CompressionLevel Optimal

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash.ToLowerInvariant()
Set-Content -Encoding ascii -LiteralPath "$zipPath.sha256" -Value "$hash  $(Split-Path $zipPath -Leaf)"
Write-Host "Release package: $zipPath"
Write-Host "SHA256: $hash"

