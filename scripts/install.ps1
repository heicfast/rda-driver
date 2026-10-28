# install.ps1 - RDA service installer (raw-access deployment profile).
#
# Installs rda.sys as a kernel driver service under a caller-chosen service
# name. The driver derives its \Device\ + \DosDevices\ names from the service
# name at load time (reference parity), so:
#
#   -ServiceName eprdtdrv   -> \Device\EPRDTDRV  (DRW Device.mo drop-in)
#   -ServiceName ebrntdrv   -> \Device\EBRNTDRV  (WinPE spare instance)
#   -ServiceName rda        -> \Device\RDA       (neutral default)
#
# REQUIRES: elevated PowerShell; a signed driver (test-signing enabled) or a
# test certificate provisioned for this driver on the target machine.
#
# Exit-code contract (v0.2.3, the deployer parity batch):
#   0 = installed (+ started, unless -NoStart)
#   1 = not elevated
#   2 = service name already exists
#   3 = driver copy failed
#   4 = CreateService failed (SCM, per-call error)
#   5 = Parameters registry write-back verification failed
#   6 = StartService failed (signature rejection, missing dep, etc.)
#   7 = the service did not reach RUNNING after start
#
# Usage:
#   .\install.ps1 -ServiceName eprdtdrv -Source .\bin\x64\Release\rda.sys
#
# Licensed under the MIT license. See LICENSE.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_]+$')]
    [string]$ServiceName,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$Source,

    [int]$IoctlBase = 0,
    [int]$MaxDisks = 200,
    [int]$DebugLevel = 1,
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'

# --- elevation guard ---------------------------------------------------------
# v0.2.3 (S-036): the old form chained static access through a type literal
# ([WindowsPrincipal]::[WindowsIdentity]) - invalid member syntax that
# resolves to null and dies as InvokeMethodOnNull on every stock host. The
# principal is now constructed explicitly.
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must run elevated (Administrator)."
    exit 1
}

# --- preflight ----------------------------------------------------------------
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    Write-Error "Service '$ServiceName' already exists. Remove it first (uninstall.ps1) or pick another name."
    exit 2
}

$sourcePath = (Resolve-Path $Source).Path
$destDir = Join-Path $env:SystemRoot 'System32\drivers'
$destPath = Join-Path $destDir "$ServiceName.sys"

Write-Host "Installing '$sourcePath' as service '$ServiceName' -> $destPath"
Copy-Item $sourcePath $destPath -Force
if (-not (Test-Path $destPath)) {
    Write-Error "Copy failed: '$destPath' is not present after Copy-Item."
    exit 3
}

# --- service + parameters ------------------------------------------------------
sc.exe create $ServiceName binPath= "$destPath" type= kernel start= demand error= normal group= "Boot File System" | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "CreateService failed! Error = $LASTEXITCODE"
    exit 4
}

$paramKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName\Parameters"
New-Item -Path $paramKey -Force | Out-Null
Set-ItemProperty -Path $paramKey -Name 'IoctlBase' -Value $IoctlBase -Type DWord
Set-ItemProperty -Path $paramKey -Name 'MaxDisks' -Value $MaxDisks -Type DWord
Set-ItemProperty -Path $paramKey -Name 'DebugLevel' -Value $DebugLevel -Type DWord
Set-ItemProperty -Path $paramKey -Name 'SessionsEnabled' -Value 1 -Type DWord

# v0.2.3 (M-064, the deployer's write+verify contract): read back every
# written value and fail loudly on mismatch - a half-written Parameters
# key is a silently misconfigured driver otherwise.
$verify = @{
    'IoctlBase'       = $IoctlBase
    'MaxDisks'        = $MaxDisks
    'DebugLevel'     = $DebugLevel
    'SessionsEnabled' = 1
}
foreach ($name in $verify.Keys) {
    $actual = (Get-ItemProperty -Path $paramKey -Name $name -ErrorAction Stop).$name
    if ($actual -ne $verify[$name]) {
        Write-Error "Parameters verification failed: $name expected $($verify[$name]), read back $actual."
        exit 5
    }
}

# --- start --------------------------------------------------------------------
if (-not $NoStart) {
    sc.exe start $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        # v0.2.3 (M-062): start failure is FATAL (exit 6) - the canonical dev
        # failure is code-signing rejection and exit 0 made every caller
        # blind to it. The service is left installed-but-stopped for
        # diagnosis (sc.exe query / the System event log).
        Write-Error ("StartService failed! Error = $LASTEXITCODE - check code-signing " +
                        "policy (testsigning), driver signature, and the System event log.")
        exit 6
    }
    # confirm RUNNING (the SCM accepts the start but the load may still fail)
    Start-Sleep -Milliseconds 500
    $state = (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue).Status
    if ($state -ne 'Running') {
        Write-Error "Service '$ServiceName' is '$state' after start (expected Running); check the System event log."
        exit 7
    }
    Write-Host "Service '$ServiceName' started."
} else {
    Write-Host "Service '$ServiceName' installed (not started, -NoStart)."
}

# --- verify the control device appeared ---------------------------------------
$expected = "\Device\" + $ServiceName.ToUpperInvariant()
$dosName = "\\.\$($ServiceName.ToUpperInvariant())"
Write-Host "Expected control device: $expected"
Write-Host "User-mode path:          $dosName\<pid-token>\<disk>\<part>"
Write-Host ""
Write-Host "Next: .\bin\x64\Release\rdacli.exe grammar 0"
exit 0
