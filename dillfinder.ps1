
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

# -------------------------
# THREAD-SAFE QUEUE
# -------------------------
$queue = New-Object System.Collections.Concurrent.ConcurrentQueue[object]

# -------------------------
# HELPERS
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
                   Text="Running..."
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
# ADD RESULT
# -------------------------
function Push-Result($obj) {
    $queue.Enqueue($obj)
}

# -------------------------
# INITIAL DLL SCAN
# -------------------------
$status.Text = "Scanning DLLs..."

Get-Process javaw -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        $_.Modules | ForEach-Object {

            $p = $_.FileName
            if (-not $p) { return }

            $sig = Sig $p

            if (($sig -ne "Valid") -or (BadPath $p)) {
                Push-Result ([PSCustomObject]@{
                    Type = "DLL"
                    Name = $_.ModuleName
                    Path = $p
                    Sig  = $sig
                    Hash = Hash $p
                })
            }
        }
    } catch {}
}

# -------------------------
# WMI EVENT MONITOR (FIXED)
# -------------------------
try {
    Register-WmiEvent -Class Win32_ProcessStartTrace -SourceIdentifier "procMon" -ErrorAction Stop | Out-Null
} catch {
    [System.Windows.MessageBox]::Show("Failed to start WMI monitoring")
    exit
}

$status.Text = "Monitoring processes..."

# -------------------------
# UI LOOP (REAL TIME FIX)
# -------------------------
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromMilliseconds(300)

$timer.Add_Tick({

    # drain queue → UI
    while ($queue.TryDequeue([ref]$item)) {
        if ($item) {
            $results.Add($item)
        }
    }

    # process events
    $e = Get-Event -SourceIdentifier "procMon" -ErrorAction SilentlyContinue
    if ($e) {

        $name = $e.SourceEventArgs.NewEvent.ProcessName
        $pid  = $e.SourceEventArgs.NewEvent.ProcessID

        $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$pid" -ErrorAction SilentlyContinue
        $path = $proc.ExecutablePath

        if ($path) {
            Push-Result ([PSCustomObject]@{
                Type = "Process"
                Name = $name
                Path = $path
                Sig  = (Sig $path)
                Hash = ""
            })
        }

        Remove-Event -EventIdentifier $e.EventIdentifier -ErrorAction SilentlyContinue
    }

})

$timer.Start()

# -------------------------
# CLEAN EXIT
# -------------------------
$window.Add_Closing({
    Unregister-Event -SourceIdentifier "procMon" -ErrorAction SilentlyContinue
})

# -------------------------
# RUN UI
# -------------------------
$window.ShowDialog()
