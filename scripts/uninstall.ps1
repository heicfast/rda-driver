# uninstall.ps1 - removes an RDA driver service.
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

$identity = [Security.Principal.WindowsPrincipal]::[Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must run elevated (Administrator)."
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        sc.exe.exe stop $ServiceName | Out-Null
        Start-Sleep -Seconds 1
    }
    sc.exe.exe delete $ServiceName | Out-Null
    Write-Host "Service '$ServiceName' deleted."
} else {
    Write-Warning "Service '$ServiceName' not found."
}

$destPath = Join-Path $env:SystemRoot "System32\drivers\$ServiceName.sys"
if (Test-Path $destPath) {
    Remove-Item $destPath -Force -ErrorAction SilentlyContinue
    Write-Host "Removed $destPath"
}
