# uninstall.ps1 - removes an RDA driver service.
#
# Exit-code contract (v0.2.3, the deployer parity batch):
#   0 = service + driver file removed (or nothing existed)
#   1 = not elevated
#   2 = sc.exe stop failed (SCM error)
#   3 = service did not reach STOPPED within the poll bound
#   4 = sc.exe delete failed (SCM error)
#   5 = service still registered after delete (SCM pending/marked)
#   6 = driver file delete failed (locked image, in use)
#
# Usage: .\uninstall.ps1 -ServiceName eprdtdrv
#
# Licensed under the MIT license. See LICENSE.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServiceName
)

$ErrorActionPreference = 'Stop'

# v0.2.3 (S-036): the old form chained static access through a type literal
# ([WindowsPrincipal]::[WindowsIdentity]) - invalid member syntax that
# resolves to null and dies as InvokeMethodOnNull on every stock host.
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must run elevated (Administrator)."
    exit 1
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        sc.exe stop $ServiceName | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Error "StopService failed! Error = $LASTEXITCODE"
            exit 2
        }
        # v0.2.3 (M-061): poll the state instead of a fixed 1s sleep - a
        # kernel driver with open handles sits in STOP_PENDING for as long
        # as the last handle lives; 10 x 500ms bounds the wait.
        $stopped = $false
        for ($i = 0; $i -lt 10; $i++) {
            Start-Sleep -Milliseconds 500
            $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($null -eq $svc) { $stopped = $true; break }
            if ($svc.Status -eq 'Stopped') { $stopped = $true; break }
        }
        if (-not $stopped) {
            Write-Error "Service '$ServiceName' did not reach STOPPED within 5s (state: $((Get-Service -Name $ServiceName -ErrorAction SilentlyContinue).Status)); close all \\.\ handles and retry."
            exit 3
        }
    }
    sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "DeleteService failed! Error = $LASTEXITCODE"
        exit 4
    }
    # verify the registration is gone (SCM marks for deletion when handles
    # remain - that is NOT a completed uninstall)
    Start-Sleep -Milliseconds 300
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Error "Service '$ServiceName' is still registered after delete (marked for deletion; a handle is open). Re-run after reboot or close the clients."
        exit 5
    }
    Write-Host "Service '$ServiceName' deleted."
} else {
    Write-Warning "Service '$ServiceName' not found."
}

# --- driver file ------------------------------------------------------------
$destPath = Join-Path $env:SystemRoot "System32\drivers\$ServiceName.sys"
if (Test-Path $destPath) {
    # v0.2.3 (M-061): loud failure - the old script swallowed Remove-Item
    # errors and printed "Removed" unconditionally (a lie while the locked
    # image stayed on disk).
    Remove-Item $destPath -Force -ErrorAction Stop
    if (Test-Path $destPath) {
        Write-Error "Driver image '$destPath' is still present after Remove-Item."
        exit 6
    }
    Write-Host "Removed $destPath"
} else {
    Write-Host "Driver image '$destPath' not present (already clean)."
}
exit 0
