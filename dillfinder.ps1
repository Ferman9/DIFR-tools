
# =========================
# PROCESS / DLL MONITOR + UI + PROGRESS
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
# Data
# -------------------------
$results = New-Object System.Collections.ObjectModel.ObservableCollection[Object]

# -------------------------
# UI (WPF)
# -------------------------

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Process Monitor Dashboard"
        Height="650"
        Width="950"
        Background="#1E1E1E"
        WindowStartupLocation="CenterScreen">

    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="25"/>
            <RowDefinition Height="25"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <!-- STATUS -->
        <TextBlock Name="StatusText"
                   Foreground="LightGray"
                   FontSize="14"
                   Text="Initializing..."
                   VerticalAlignment="Center"/>

        <!-- PROGRESS BAR -->
        <ProgressBar Name="ProgressBar"
                     Grid.Row="1"
                     Height="18"
                     Minimum="0"
                     Maximum="100"
                     Value="0"/>

        <!-- TABLE -->
        <DataGrid Grid.Row="2"
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
$statusText = $window.FindName("StatusText")
$progressBar = $window.FindName("ProgressBar")

$grid.ItemsSource = $results

# -------------------------
# Add result helper
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
# PROGRESS SYSTEM
# -------------------------
$global:progress = 0
$global:stage = "Starting..."

function Set-Progress($value, $text) {
    $global:progress = $value
    $global:stage = $text

    $window.Dispatcher.Invoke([action]{
        $progressBar.Value = $global:progress
        $statusText.Text = "$($global:stage) ($($global:progress)%)"
    })
}

# -------------------------
# STAGE 1: DLL SCAN
# -------------------------
Set-Progress 5 "Scanning DLL modules"

$java = Get-Process javaw -ErrorAction SilentlyContinue
$total = ($java | Measure-Object).Count
$current = 0

foreach ($proc in $java) {
    $current++

    try {
        $proc.Modules | ForEach-Object {

            $p = $_.FileName
            if (-not $p) { return }

            $sig = Sig $p

            if (($sig -ne "Valid") -or (BadPath $p)) {
                Add-Result "DLL" $_.ModuleName $p $sig
            }
        }
    } catch {}

    $percent = 5 + [math]::Round(($current / [math]::Max($total,1)) * 25)
    Set-Progress $percent "Scanning Java modules"
}

# -------------------------
# STAGE 2: PROCESS MONITOR INIT
# -------------------------
Set-Progress 35 "Starting process monitor"

try {
    Register-WmiEvent -Class Win32_ProcessStartTrace -SourceIdentifier "procMon" -ErrorAction Stop | Out-Null
} catch {
    [System.Windows.MessageBox]::Show("WMI Event failed")
    exit
}

# -------------------------
# BACKGROUND PROCESS LOOP
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
# UI UPDATE LOOP
# -------------------------
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(1)

$timer.Add_Tick({

    if ($job.State -eq "Running") {

        Set-Progress ([math]::Min($global:progress + 1, 100)) $global:stage

        $output = Receive-Job $job -Keep -ErrorAction SilentlyContinue

        foreach ($item in $output) {
            if ($item) {
                $results.Add($item)
            }
        }

        if ($global:progress -ge 100) {
            Set-Progress 100 "Monitoring active"
        }
    }
})

$timer.Start()

# -------------------------
# CLEAN EXIT
# -------------------------
$window.Add_Closing({
    Stop-Job $job -ErrorAction SilentlyContinue
    Remove-Job $job -ErrorAction SilentlyContinue
})

# -------------------------
# SHOW UI
# -------------------------
Set-Progress 100 "Ready"
$window.ShowDialog()
