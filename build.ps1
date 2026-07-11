param(
    [switch]$DebugBuild,
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$projectDir = $PSScriptRoot
$outputDir = Join-Path $projectDir "bin"
$outputFile = Join-Path $outputDir "ALL1n.exe"

New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
Push-Location $projectDir
try {
    if (-not $SkipTests) {
        & go test ./...
        if ($LASTEXITCODE -ne 0) {
            throw "Tests failed with exit code $LASTEXITCODE"
        }
    }

    $arguments = @("build", "-buildvcs=false", "-trimpath", "-o", $outputFile)
    if (-not $DebugBuild) {
        $arguments += @("-ldflags", "-s -w -H=windowsgui")
    }
    $arguments += "."

    & go @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Go build failed with exit code $LASTEXITCODE"
    }
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $outputFile).Hash
    Write-Host "Build completed: $outputFile"
    Write-Host "SHA256: $hash"
} finally {
    Pop-Location
}
