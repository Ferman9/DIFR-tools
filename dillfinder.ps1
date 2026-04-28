# Run as Admin

function Hash($p) {
try { return (Get-FileHash $p -Algorithm SHA256).Hash } catch { return "" }
}

function Sig($p) {
try { return (Get-AuthenticodeSignature $p).Status } catch { return "Unknown" }
}

function BadPath($p) {
if (-not $p) { return $false }
$p = $p.ToLower()
return ($p -match 'appdata|temp|downloads|desktop')
}

$results = @()

# --- Scan javaw modules (DLL injection traces)

Get-Process javaw -ErrorAction SilentlyContinue | ForEach-Object {
try {
$*.Modules | ForEach-Object {
$p = $*.FileName
if (-not $p) { return }

```
        $sig = Sig $p
        if ($sig -ne "Valid" -or BadPath $p) {
            $results += [PSCustomObject]@{
                Type = "DLL"
                Name = $_.ModuleName
                Path = $p
                Sig  = $sig
                Hash = Hash $p
            }
        }
    }
} catch {}
```

}

# --- Real-time process monitor (WMI)

Register-WmiEvent -Class Win32_ProcessStartTrace -SourceIdentifier "procMon" | Out-Null

Write-Host "Monitoring started... open Minecraft now."

while ($true) {
$e = Wait-Event -SourceIdentifier "procMon"
$name = $e.SourceEventArgs.NewEvent.ProcessName

```
if ($name -like "*.exe") {
    $proc = Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -eq $e.SourceEventArgs.NewEvent.ProcessID }
    $path = $proc.ExecutablePath

    if ($path) {
        $sig = Sig $path

        if ($sig -ne "Valid" -or BadPath $path) {
            $results += [PSCustomObject]@{
                Type = "Process"
                Name = $name
                Path = $path
                Sig  = $sig
                Hash = Hash $path
            }

            $results | Out-GridView -Title "Live Detection"
        }
    }
}

Remove-Event -EventIdentifier $e.EventIdentifier
```

}
