<#
    Builds a release of SecHUD and packs it into a zip ready to upload to GitHub.

      1. reads the version from SecHUD.csproj
      2. builds the app and runs the tests (a failing test stops the release)
      3. writes release\SecHUD-v<version>.zip and its SHA-256

    It does not publish anything. Uploading is a separate step you do yourself.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

[xml]$project = Get-Content (Join-Path $root 'SecHUD.csproj')
$version = $project.Project.PropertyGroup | ForEach-Object { $_.Version } | Where-Object { $_ } | Select-Object -First 1
if (-not $version) { throw 'No <Version> found in SecHUD.csproj.' }
Write-Host "SecHUD $version" -ForegroundColor Red

$wasRunning = [bool](Get-Process -Name SecHUD -ErrorAction SilentlyContinue)
if ($wasRunning) {
    Write-Host 'Closing the running SecHUD so its exe can be rebuilt...'
    Get-Process -Name SecHUD | Stop-Process -Force
    Start-Sleep -Seconds 1
}

Write-Host 'Building the app...'
& dotnet build SecHUD.csproj -c Release -nologo > build-log.txt 2>&1
if ($LASTEXITCODE -ne 0) { throw 'The build failed. See build-log.txt.' }

Write-Host 'Running the tests...'
& dotnet build tests\SecHUD.Tests.csproj -c Release -nologo > tests\build-log.txt 2>&1
if ($LASTEXITCODE -ne 0) { throw 'The tests did not build. See tests\build-log.txt.' }
& tests\bin\Release\SecHUD.Tests.exe > tests\test-results.txt
if ($LASTEXITCODE -ne 0) {
    Get-Content tests\test-results.txt | Where-Object { $_ -like 'FAIL*' }
    throw 'A test failed, so no release was made. See tests\test-results.txt.'
}
Write-Host ('  ' + (Get-Content tests\test-results.txt | Select-Object -Last 1))

$out   = Join-Path $root 'release'
$stage = Join-Path $out "SecHUD-v$version"
$zip   = Join-Path $out "SecHUD-v$version.zip"
New-Item -ItemType Directory -Force $out | Out-Null
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
if (Test-Path $zip)   { Remove-Item $zip -Force }
New-Item -ItemType Directory $stage | Out-Null

Copy-Item 'bin\Release\SecHUD.exe' $stage
if (Test-Path 'bin\Release\SecHUD.exe.config') { Copy-Item 'bin\Release\SecHUD.exe.config' $stage }
Copy-Item 'README.md' $stage
if (Test-Path 'LICENSE') { Copy-Item 'LICENSE' $stage }

Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
Remove-Item $stage -Recurse -Force

$hash = (Get-FileHash $zip -Algorithm SHA256).Hash
"$hash  SecHUD-v$version.zip" | Set-Content (Join-Path $out "SecHUD-v$version.sha256.txt")

Write-Host ''
Write-Host "Made release\SecHUD-v$version.zip" -ForegroundColor Cyan
Write-Host "SHA-256: $hash"
Write-Host ''
Write-Host 'To publish it:' -ForegroundColor Yellow
Write-Host "  1. On github.com/sivadyt/SecHUD open Releases and choose Draft a new release."
Write-Host "  2. Set the tag to v$version (the app compares this tag with its own version)."
Write-Host '  3. Write what changed. Your friends see this text in the app.'
Write-Host "  4. Attach release\SecHUD-v$version.zip and publish."
Write-Host ''
Write-Host 'Everyone running an older version sees UPDATE AVAILABLE within a day.'

if ($wasRunning) { Start-Process 'bin\Release\SecHUD.exe' }
