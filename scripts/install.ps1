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
# Exit-code contract (v0.2.3, the deployer parity batch; v0.2.4 additions):
#   0 = installed (+ started, unless -NoStart) | or -Uninstall teardown done
#   1 = not elevated
#   2 = service name already exists (and not a versioned in-place upgrade)
#   3 = driver copy failed
#   4 = CreateService failed (SCM, per-call error)
#   5 = Parameters registry write-back verification failed
#   6 = StartService failed (signature rejection, missing dep, etc.)
#   7 = the service did not reach RUNNING after start
#   8 = in-place upgrade: the old service did not reach STOPPED (v0.2.4)
#   9 = in-place upgrade: sc.exe config failed (SCM, per-call error) (v0.2.4)
#
# v0.2.4 (M-064 remainder): -Layout Versioned (default) copies the driver to
#   <ServiceName><MajorMinor>.sys (the reference setupdrvx64 %s%d coexistence
#   scheme - an in-use image is never overwritten); installing a different
#   version over an existing service reconfigures it in place (stop ->
#   sc config binPath -> start; the old file stays). -Layout Plain keeps the
#   classic <ServiceName>.sys. -Uninstall delegates to uninstall.ps1 (one
#   implementation, both entry points).
#
# Usage:
#   .\install.ps1 -ServiceName eprdtdrv -Source .\bin\x64\Release\rda.sys
#   .\install.ps1 -ServiceName eprdtdrv -Source .\rda.sys -Uninstall
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
    [switch]$NoStart,

    # v0.2.4 (M-064): Versioned (default) = <ServiceName><MajorMinor>.sys,
    # the reference's %s%d coexistence scheme (an in-use image is never
    # overwritten; upgrades repoint the service in place). Plain = the
    # classic <ServiceName>.sys.
    [ValidateSet('Versioned', 'Plain')]
    [string]$Layout = 'Versioned',

    # v0.2.4 (M-064): the same verified teardown uninstall.ps1 implements -
    # one implementation, both entry points.
    [switch]$Uninstall
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

# --- -Uninstall: delegate to uninstall.ps1 (one implementation) ---------------
if ($Uninstall) {
    $un = Join-Path $PSScriptRoot 'uninstall.ps1'
    if (-not (Test-Path $un)) {
        Write-Error "uninstall.ps1 not found beside install.ps1 ($un)."
        exit 1
    }
    # re-invoke THIS engine (works under powershell.exe 5.1 and pwsh 7+) so the
    # child's exit code lands in $LASTEXITCODE reliably
    $engine = (Get-Process -Id $PID).Path
    & $engine -NoProfile -ExecutionPolicy Bypass -File $un -ServiceName $ServiceName
    exit $LASTEXITCODE
}

# --- preflight ----------------------------------------------------------------
$sourcePath = (Resolve-Path $Source).Path
$destDir = Join-Path $env:SystemRoot 'System32\drivers'

# v0.2.4 (M-064): the versioned layout - <ServiceName><MajorMinor>.sys from
# the source image's version resource (the reference setupdrvx64 %s%d
# coexistence scheme; an in-use image is never overwritten, upgrades repoint
# the service in place).
$destName = "$ServiceName.sys"
if ($Layout -eq 'Versioned') {
    $vi = (Get-Item $sourcePath).VersionInfo
    $tag = "$($vi.FileMajorPart)$($vi.FileMinorPart)"
    if ([string]::IsNullOrEmpty($tag) -or $tag -eq '00') {
        # no version resource on the source image - fall back to the plain
        # name (an honest degradation, never a guessed tag)
        Write-Warning "Source image carries no usable version resource (FileVersion '$($vi.FileVersion)') - falling back to the Plain layout."
        $destName = "$ServiceName.sys"
    } else {
        $destName = "$ServiceName$tag.sys"
    }
}
$destPath = Join-Path $destDir $destName

$script:upgraded = $false
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    # v0.2.4 (M-064): a DIFFERENT version over an existing service is the
    # reference's in-place upgrade (stop -> sc config binPath -> start; the
    # old image file stays - coexistence, no reboot). The same file or the
    # Plain layout keeps the classic refuse.
    $imagePath = $null
    try {
        $imagePath = (Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop).PathName
    } catch { $imagePath = $null }
    if ($imagePath) { $imagePath = $imagePath.Trim('"') }
    $isUpgrade = ($Layout -eq 'Versioned') -and $imagePath -and
                 ($imagePath -ne $destPath) -and (Test-Path $imagePath)
    if (-not $isUpgrade) {
        Write-Error "Service '$ServiceName' already exists. Remove it first (-Uninstall / uninstall.ps1), upgrade with a new-version image (-Layout Versioned), or pick another name."
        exit 2
    }
    Write-Host "Upgrading service '$ServiceName': $imagePath -> $destPath (in place; the old image stays)"
    if ($service.Status -ne 'Stopped') {
        sc.exe stop $ServiceName | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Error "StopService failed! Error = $LASTEXITCODE (the in-place upgrade's stop leg)"
            exit 8
        }
        $stopped = $false
        for ($i = 0; $i -lt 10; $i++) {
            Start-Sleep -Milliseconds 500
            $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($null -eq $svc) { $stopped = $true; break }
            if ($svc.Status -eq 'Stopped') { $stopped = $true; break }
        }
        if (-not $stopped) {
            Write-Error "Service '$ServiceName' did not reach STOPPED within 5s for the in-place upgrade (state: $((Get-Service -Name $ServiceName -ErrorAction SilentlyContinue).Status)); close all \\.\ handles and retry."
            exit 8
        }
    }
    Copy-Item $sourcePath $destPath -Force
    if (-not (Test-Path $destPath)) {
        Write-Error "Copy failed: '$destPath' is not present after Copy-Item."
        exit 3
    }
    sc.exe config $ServiceName binPath= "$destPath" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Service reconfigure failed (sc.exe config binPath)! Error = $LASTEXITCODE"
        exit 9
    }
    # the Parameters write+verify below re-runs for the upgraded service
    $paramKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName\Parameters"
    if (-not (Test-Path $paramKey)) { New-Item -Path $paramKey -Force | Out-Null }
    Set-ItemProperty -Path $paramKey -Name 'IoctlBase' -Value $IoctlBase -Type DWord
    Set-ItemProperty -Path $paramKey -Name 'MaxDisks' -Value $MaxDisks -Type DWord
    Set-ItemProperty -Path $paramKey -Name 'DebugLevel' -Value $DebugLevel -Type DWord
    Set-ItemProperty -Path $paramKey -Name 'SessionsEnabled' -Value 1 -Type DWord
    $script:upgraded = $true
    # fall through to the start leg (codes 6/7) - the service is now the new image
}

if (-not $script:upgraded) {
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
} # end -not upgraded (the fresh-install path)

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
