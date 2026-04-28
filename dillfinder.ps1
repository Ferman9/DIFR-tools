# Run as Admin recommended

function Hash($p) {
    try { return (Get-FileHash $p -Algorithm SHA256).Hash }
    catch { return "" }
}

function Sig($p) {
    try { return (Get-AuthenticodeSignature $p).Status }
    catch { return "Unknown" }
}

function BadPath($p) {
    if (-not $p) { return $false }
    $p = $p.ToLower()
    return ($p -match "appdata|temp|downloads|desktop")
}

$results = @()

Write-Host "[*] Starting scan..." -ForegroundColor Cyan

# -----------------------------
# Scan javaw modules (DLLs)
# -----------------------------
Get-Process javaw -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        $_.Modules | ForEach-Object {

            $p = $_.FileName
            if (-not $p) { return }

            $sig = Sig $p

            if (($sig -ne "Valid") -or (BadPath $p)) {
                $results += [PSCustomObject]@{
                    Type = "DLL"
                    Name = $_.ModuleName
                    Path = $p
                    Sig  = $sig
                    Hash = Hash $p
                }
            }
        }
    }
    catch {}
}

# -----------------------------
# Process monitor (WMI)
# -----------------------------
try {
    Register-WmiEvent -Class Win32_ProcessStartTrace -SourceIdentifier "procMon" -ErrorAction Stop | Out-Null
}
catch {
    Write-Host "[!] WMI event failed to register" -ForegroundColor Red
    return
}

Write-Host "[*] Monitoring processes... (Ctrl+C to stop)" -ForegroundColor Green

$lastPopup = Get-Date "2000-01-01"

try {
    while ($true) {

        $e = Wait-Event -SourceIdentifier "procMon" -Timeout 5
        if (-not $e) { continue }

        $name = $e.SourceEventArgs.NewEvent.ProcessName
        $pid  = $e.SourceEventArgs.NewEvent.ProcessID

        if ($name -like "*.exe") {

            $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$pid" -ErrorAction SilentlyContinue
            $path = $proc.ExecutablePath

            if ($path) {
                $sig = Sig $path

                if (($sig -ne "Valid") -or (BadPath $path)) {

                    $obj = [PSCustomObject]@{
                        Type = "Process"
                        Name = $name
                        Path = $path
                        Sig  = $sig
                        Hash = Hash $path
                    }

                    $results += $obj

                    # throttle popup spam (max once every 5 seconds)
                    if ((Get-Date) - $lastPopup -gt (New-TimeSpan -Seconds 5)) {
                        $results | Out-GridView -Title "Live Detection"
                        $lastPopup = Get-Date
                    }
                }
            }
        }

        Remove-Event -EventIdentifier $e.EventIdentifier -ErrorAction SilentlyContinue
    }
}
finally {
    Write-Host "`n[*] Cleaning up..." -ForegroundColor Yellow
    Unregister-Event -SourceIdentifier "procMon" -ErrorAction SilentlyContinue
}
