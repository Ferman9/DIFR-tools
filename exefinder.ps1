# Run as Administrator

$bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
Write-Host "Last Boot Time: $bootTime"

$events = Get-WinEvent -FilterHashtable @{
LogName = 'Security'
Id = 4688
StartTime = $bootTime
} -ErrorAction SilentlyContinue

$results = @()

foreach ($event in $events) {
if ($event.Message -match "New Process Name:\s+(.+.exe)") {
$exePath = $matches[1].Trim()

```
    if (Test-Path $exePath) {
        $sig = Get-AuthenticodeSignature $exePath

        if ($sig.Status -ne "Valid") {
            $results += [PSCustomObject]@{
                Time = $event.TimeCreated
                Path = $exePath
                Signature = $sig.Status
            }
        }
    }
}
```

}

$results | Sort-Object Path -Unique | Format-Table -AutoSize
