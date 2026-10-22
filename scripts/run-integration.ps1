# run-integration.ps1 - driver-level integration suite for a Windows test host.
#
# Prerequisites: driver installed + STARTED (scripts/install.ps1); elevated.
# Runs the rdacli contract checks and prints a PASS/FAIL summary.

[CmdletBinding()]
param(
    [string]$Client = ".\bin\x64\Release\rdacli.exe",
    [int]$Disk = 0
)

$ErrorActionPreference = 'Continue'
$results = @()

function Invoke-Case([string]$name, [scriptblock]$body) {
    Write-Host "== $name"
    & $body
    if ($LASTEXITCODE -eq 0) { $script:results += @{ Name = $name; Ok = $true } }
    else { $script:results += @{ Name = $name; Ok = $false } }
}

Invoke-Case "info"     { & $Client info }
Invoke-Case "grammar"  { & $Client grammar $Disk }
Invoke-Case "ident"    { & $Client ident $PID }
Invoke-Case "read"     { & $Client read $Disk 0 512 }

Write-Host ""
$failed = @($results | Where-Object { -not $_.Ok })
if ($failed.Count -eq 0) { Write-Host "ALL INTEGRATION CASES PASSED"; exit 0 }
else {
    Write-Host "$($failed.Count) case(s) FAILED:"
    $failed | ForEach-Object { Write-Host "  - $($_.Name)" }
    exit 1
}
