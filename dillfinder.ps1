
# =========================
# PROCESS / DLL MONITOR + UI
# =========================

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

# -------------------------
# Helpers
# -------------------------

function Hash($p) {
    try { (Get-FileHash $p -Algorithm SHA256).Hash } catch { "" }
}

function Sig($p) {
    try { (Get-AuthenticodeSignature $p).Status } catch { "Unknown" }
}

function BadPath($p) {
    if (-not $p) { return $false }
    $p = $p.ToLower()
    return ($p -match "appdata|temp|downloads|desktop")
}

# -------------------------
# Data storage
# -------------------------
$results = New-Object System.Collections.ObjectModel.ObservableCollection[Object]

# -------------------------
# UI (WPF Dashboard)
# -------------------------

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Process Monitor Dashboard"
        Height="600"
        Width="900"
        Background="#1E1E1E"
        WindowStartupLocation="CenterScreen">

    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="40"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <TextBlock Text="Live Process / DLL Monitor"
                   Foreground="White"
                   FontSize="16"
                   VerticalAlignment="Center"
                   Margin="10"/>

        <DataGrid Grid.Row="1"
                  Name="Grid"
                  AutoGenerateColumns="True"
                  IsReadOnly="True"
                  Background="#252526"
                  Foreground="White"
                  BorderThickness="0"/>
    </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

$grid = $window.FindName("Grid")
$grid.ItemsSource = $results

# -------------------------
# Add entry function
# -------------------------
function Add-Result($type, $name, $path, $sig) {
    $results.Add([PSCustomObject]@{
        Type = $type
        Name = $name
        Path = $path
        Sig  = $sig
        Hash = Hash $path
    })
}

# -------------------------
# DLL Scan (javaw modules)
# -------------------------
Get-Process javaw -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        $_.Modules | ForEach-Object {

            $p = $_.FileName
            if (-not $p) { return }

            $sig = Sig $p

            if (($sig -ne "Valid") -or (BadPath $p)) {
                Add-Result "DLL" $_.ModuleName $p $sig
            }
        }
    } catch {}
}

# -------------------------
# Process monitoring
# -------------------------
try {
    Register-WmiEvent -Class Win32_ProcessStartTrace -SourceIdentifier "procMon" -ErrorAction Stop | Out-Null
} catch {
    [System.Windows.MessageBox]::Show("WMI Event failed to start")
    exit
}

# -------------------------
# Background loop
# -------------------------
$job = Start-Job -ScriptBlock {

    Register-WmiEvent -Class Win32_ProcessStartTrace -SourceIdentifier "procMon" | Out-Null

    while ($true) {
        $e = Wait-Event -SourceIdentifier "procMon" -Timeout 5
        if (-not $e) { continue }

        $name = $e.SourceEventArgs.NewEvent.ProcessName
        $processId = $e.SourceEventArgs.NewEvent.ProcessID

        $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$processId" -ErrorAction SilentlyContinue
        $path = $proc.ExecutablePath

        if ($path) {
            [PSCustomObject]@{
                Type = "Process"
                Name = $name
                Path = $path
                Sig  = (try { (Get-AuthenticodeSignature $path).Status } catch { "Unknown" })
                Hash = ""
            }
        }

        Remove-Event -EventIdentifier $e.EventIdentifier -ErrorAction SilentlyContinue
    }
}

# -------------------------
# UI update timer
# -------------------------
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(2)

$timer.Add_Tick({
    if ($job -and $job.State -eq "Running") {
        $output = Receive-Job $job -Keep -ErrorAction SilentlyContinue

        foreach ($item in $output) {
            if ($item) {
                $results.Add($item)
            }
        }
    }
})

$timer.Start()

# -------------------------
# Start UI
# -------------------------
$window.Add_Closing({
    Stop-Job $job -ErrorAction SilentlyContinue
    Remove-Job $job -ErrorAction SilentlyContinue
})

$window.ShowDialog()
