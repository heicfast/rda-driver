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
$identity = [Security.Principal.WindowsPrincipal]::[Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must run elevated (Administrator)."
}

# --- preflight ----------------------------------------------------------------
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    Write-Error "Service '$ServiceName' already exists. Remove it first (uninstall.ps1) or pick another name."
}

$sourcePath = (Resolve-Path $Source).Path
$destDir = Join-Path $env:SystemRoot 'System32\drivers'
$destPath = Join-Path $destDir "$ServiceName.sys"

Write-Host "Installing '$sourcePath' as service '$ServiceName' -> $destPath"
Copy-Item $sourcePath $destPath -Force

# --- service + parameters ------------------------------------------------------
sc.exe.exe create $ServiceName binPath= "$destPath" type= kernel start= demand error= normal group= "Boot File System" | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Error "CreateService failed ($LASTEXITCODE)" }

$paramKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName\Parameters"
New-Item -Path $paramKey -Force | Out-Null
Set-ItemProperty -Path $paramKey -Name 'IoctlBase' -Value $IoctlBase -Type DWord
Set-ItemProperty -Path $paramKey -Name 'MaxDisks' -Value $MaxDisks -Type DWord
Set-ItemProperty -Path $paramKey -Name 'DebugLevel' -Value $DebugLevel -Type DWord
Set-ItemProperty -Path $paramKey -Name 'SessionsEnabled' -Value 1 -Type DWord

# --- start --------------------------------------------------------------------
if (-not $NoStart) {
    sc.exe.exe start $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "StartService failed ($LASTEXITCODE). Check code-signing policy " +
                      "(testsigning), driver signature, and the System event log."
    } else {
        Write-Host "Service '$ServiceName' started."
    }
}

# --- verify the control device appeared ---------------------------------------
$expected = "\Device\" + $ServiceName.ToUpperInvariant()
$dosName = "\\.\$($ServiceName.ToUpperInvariant())"
Write-Host "Expected control device: $expected"
Write-Host "User-mode path:          $dosName\<pid-token>\<disk>\<part>"
Write-Host ""
Write-Host "Next: .\bin\x64\Release\rdacli.exe grammar 0"
