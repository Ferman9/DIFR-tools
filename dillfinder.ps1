# Process Audit Logger (Safe Version)

$logPath = "$env:USERPROFILE\Desktop\proc_log.csv"
$results = @()

function Get-Hash($p) {
    try { (Get-FileHash $p -Algorithm SHA256).Hash } catch { "" }
}

function Get-Signature($p) {
    try { (Get-AuthenticodeSignature $p).Status } catch { "Unknown" }
}

# Create log file header
if (!(Test-Path $logPath)) {
    "Time,PID,ParentPID,Name,Path,Signature,Hash" | Out-File $logPath
}

# Track processes
Register-WmiEvent -Class Win32_ProcessStartTrace -SourceIdentifier "procStart" | Out-Null

Write-Host "Process audit started..."

while ($true) {
    $event = Wait-Event -SourceIdentifier "procStart"

    $pid = $event.SourceEventArgs.NewEvent.ProcessID
    $ppid = $event.SourceEventArgs.NewEvent.ParentProcessID
    $name = $event.SourceEventArgs.NewEvent.ProcessName

    $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$pid"

    if ($proc) {
        $path = $proc.ExecutablePath
        $sig = Get-Signature $path
        $hash = Get-Hash $path

        $entry = [PSCustomObject]@{
            Time = Get-Date
            PID = $pid
            ParentPID = $ppid
            Name = $name
            Path = $path
            Signature = $sig
            Hash = $hash
        }

        $results += $entry

        # append to CSV
        "$($entry.Time),$pid,$ppid,$name,$path,$sig,$hash" | Add-Content $logPath
    }

    Remove-Event -EventIdentifier $event.EventIdentifier
}
