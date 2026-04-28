
$global:filter = ""

function Get-ParentMap {
    $map = @{}
    Get-CimInstance Win32_Process | ForEach-Object {
        $map[$_.ProcessId] = $_.ParentProcessId
    }
    return $map
}

# -------------------------
# DLL DETECTION (NEW)
# -------------------------
function Get-SuspiciousDLLs {

    $suspicious = @()

    $java = Get-Process javaw -ErrorAction SilentlyContinue

    foreach ($j in $java) {
        try {
            $j.Modules | ForEach-Object {

                $path = $_.FileName
                if (-not $path) { return }

                $p = $path.ToLower()

                if (
                    $p -match "temp|appdata|downloads|inject|hack|cheat" -or
                    -not $p.Contains("windows") -or
                    -not $p.Contains("program files")
                ) {
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

function Get-Processes {
    $parents = Get-ParentMap

    Get-Process | ForEach-Object {

        $cpu = 0
        try { $cpu = $_.CPU } catch {}

        $path = ""
        try { $path = $_.Path } catch {}

        [PSCustomObject]@{
            Name   = $_.ProcessName
            PID    = $_.Id
            Parent = $parents[$_.Id]
            CPU    = [math]::Round($cpu,2)
            RAMMB  = [math]::Round($_.WorkingSet64 / 1MB,2)
            Path   = $path
        }
    }
}

function Render {
    Clear-Host

    Write-Host "=== LIVE PROCESS DASHBOARD ===" -ForegroundColor Cyan
    Write-Host "Filter: $global:filter"
    Write-Host ""

    $list = Get-Processes

    if ($global:filter -ne "") {
        $list = $list | Where-Object { $_.Name -like "*$global:filter*" }
    }

    $dlls = Get-SuspiciousDLLs

    Write-Host "=== SUSPICIOUS JAVA DLLS ===" -ForegroundColor Yellow
    if ($dlls.Count -eq 0) {
        Write-Host "None detected"
    } else {
        foreach ($d in $dlls) {
            Write-Host "$($d.Process) -> $($d.DLL)" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "=== TOP PROCESSES ===" -ForegroundColor Cyan

    foreach ($p in $list | Sort-Object CPU -Descending | Select-Object -First 25) {

        $color = "White"

        if (
            $p.CPU -gt 50 -or
            $p.Path -match "temp|appdata|downloads"
        ) {
            $color = "Red"
        }

        Write-Host (
            "{0,-20} PID:{1,-6} CPU:{2,-6} RAM:{3,-6}MB Parent:{4}" -f
            $p.Name, $p.PID, $p.CPU, $p.RAMMB, $p.Parent
        ) -ForegroundColor $color
    }

    Write-Host ""
    Write-Host "[F]ilter | [E]xport | [Q]uit"
}

function Export {
    $path = "$env:USERPROFILE\Desktop\process_report.csv"
    Get-Processes | Export-Csv $path -NoTypeInformation
    Write-Host "Exported to Desktop" -ForegroundColor Green
}

# -------------------------
# MAIN LOOP
# -------------------------
while ($true) {

    Render

    if ([console]::KeyAvailable) {
        $key = [console]::ReadKey($true).Key

        switch ($key) {
            "F" {
                $global:filter = Read-Host "Enter filter"
            }
            "E" {
                Export
            }
            "Q" {
                break
            }
        }
    }

    Start-Sleep -Seconds 1
}
