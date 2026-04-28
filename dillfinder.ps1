
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

# -------------------------
# DATA
# -------------------------
$queue = New-Object System.Collections.Concurrent.ConcurrentQueue[object]

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
# UI
# -------------------------
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Live Monitor"
        Height="650"
        Width="950"
        Background="#1E1E1E">

    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="25"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <TextBlock Name="Status"
                   Foreground="LightGreen"
                   Text="Starting..."
                   FontSize="14"/>

        <DataGrid Grid.Row="1"
                  Name="Grid"
                  AutoGenerateColumns="True"
                  Background="#252526"
                  Foreground="White"/>
    </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

$grid = $window.FindName("Grid")
$status = $window.FindName("Status")

$results = New-Object System.Collections.ObjectModel.ObservableCollection[object]
$grid.ItemsSource = $results

# -------------------------
# ADD FUNCTION
# -------------------------
function Add-Item($type, $name, $path) {
    $results.Add([PSCustomObject]@{
        Type = $type
        Name = $name
        Path = $path
        Sig  = Sig $path
        Hash = Hash $path
    })
}

# -------------------------
# INITIAL SCAN (GUARANTEED OUTPUT)
# -------------------------
$status.Text = "Scanning DLLs..."

Get-Process javaw -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        $_.Modules | ForEach-Object {

            $p = $_.FileName
            if (-not $p) { return }

            $sig = Sig $p

            if (($sig -ne "Valid") -or (BadPath $p)) {
                Add-Item "DLL" $_.ModuleName $p
            }
        }
    } catch {}
}

$status.Text = "Starting process monitor..."

# -------------------------
# PROPER EVENT HANDLER (FIX)
# -------------------------
Register-ObjectEvent -InputObject ([System.Diagnostics.Process]) -EventName "Start" -Action {} | Out-Null

Register-WmiEvent -Class Win32_ProcessStartTrace -SourceIdentifier "procMon" | Out-Null

Register-EngineEvent -SourceIdentifier "procMon" -Action {

    $name = $Event.SourceEventArgs.NewEvent.ProcessName
    $pid  = $Event.SourceEventArgs.NewEvent.ProcessID

    $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$pid" -ErrorAction SilentlyContinue
    $path = $proc.ExecutablePath

    if ($path) {
        $global:queue.Enqueue([PSCustomObject]@{
            Type = "Process"
            Name = $name
            Path = $path
            Sig  = ""
            Hash = ""
        })
    }
} | Out-Null

# -------------------------
# UI LOOP (WORKING)
# -------------------------
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromMilliseconds(250)

$timer.Add_Tick({

    while ($queue.TryDequeue([ref]$item)) {
        if ($item) {
            $item.Sig = (Sig $item.Path)
            $item.Hash = (Hash $item.Path)
            $results.Add($item)
        }
    }

    $status.Text = "Running... Items: $($results.Count)"
})

$timer.Start()

# -------------------------
# CLEAN EXIT
# -------------------------
$window.Add_Closing({
    Unregister-Event -SourceIdentifier "procMon" -ErrorAction SilentlyContinue
})

# -------------------------
# SHOW UI
# -------------------------
$window.ShowDialog()
