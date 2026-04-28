
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

# -------------------------
# DATA
# -------------------------
$view = New-Object System.Collections.ObjectModel.ObservableCollection[object]

# -------------------------
# SUSPICION RULES
# -------------------------
function Is-SuspiciousDLL($path, $sig) {

    if (-not $path) { return $false }

    $p = $path.ToLower()

    return (
        $sig -ne "Valid" -or
        $p -match "temp|appdata|downloads|inject|hack|cheat" -or
        $p -notmatch "windows\\system32|program files"
    )
}

# -------------------------
# UI
# -------------------------
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Javaw DLL Monitor"
        Height="700"
        Width="1100"
        Background="#1E1E1E">

    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="30"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <TextBlock Name="Status"
                   Foreground="LightGreen"
                   Text="Monitoring javaw..."
                   FontSize="14"/>

        <DataGrid Name="Grid"
                  Grid.Row="1"
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

$grid.ItemsSource = $view

# -------------------------
# SCAN FUNCTION
# -------------------------
function Scan-JavawDLL {

    $view.Clear()

    $java = Get-Process javaw -ErrorAction SilentlyContinue

    if (-not $java) {
        $status.Text = "javaw not running"
        return
    }

    foreach ($j in $java) {

        try {
            $j.Modules | ForEach-Object {

                $path = $_.FileName
                if (-not $path) { return }

                $sig = try {
                    (Get-AuthenticodeSignature $path).Status
                } catch {
                    "Unknown"
                }

                $suspicious = Is-SuspiciousDLL $path $sig

                $view.Add([PSCustomObject]@{
                    Process = "javaw"
                    DLL     = $_.ModuleName
                    Path    = $path
                    Sig     = $sig
                    Flag    = if ($suspicious) { "SUSPICIOUS" } else { "OK" }
                })
            }
        }
        catch {}
    }
}

# -------------------------
# LIVE TIMER
# -------------------------
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(2)

$timer.Add_Tick({
    Scan-JavawDLL
})

$timer.Start()

# -------------------------
# SHOW UI
# -------------------------
$window.ShowDialog()
