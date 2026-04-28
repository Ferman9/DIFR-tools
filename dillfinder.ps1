
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

# -------------------------
# CACHE (IMPORTANT FIX)
# -------------------------
$cache = @{}
$view = New-Object System.Collections.ObjectModel.ObservableCollection[object]

# -------------------------
# UI
# -------------------------
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="TRUE Live Dashboard"
        Height="700"
        Width="1100"
        Background="#1E1E1E">

    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="35"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <TextBox Name="Filter"
                 Background="#2D2D30"
                 Foreground="White"
                 Height="25"/>

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
$filter = $window.FindName("Filter")

$grid.ItemsSource = $view

# -------------------------
# PROCESS FETCH
# -------------------------
function Get-State($p) {

    $ram = [math]::Round($p.WorkingSet64 / 1MB,2)

    $flag = $false

    if ($ram -gt 500) { $flag = $true }
    if ($p.ProcessName -match "temp|inject|hack") { $flag = $true }

    return @{
        Name = $p.ProcessName
        PID  = $p.Id
        CPU  = $p.CPU
        RAM  = $ram
        Flag = $flag
    }
}

# -------------------------
# UPDATE LOOP (FIXED)
# -------------------------
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(1)

$timer.Add_Tick({

    $current = Get-Process

    foreach ($p in $current) {

        $key = $p.Id

        if (-not $cache.ContainsKey($key)) {

            $state = Get-State $p
            $cache[$key] = $state

            $view.Add($state)
        }
    }

    # remove dead processes
    $alive = $current.Id
    foreach ($k in @($cache.Keys)) {
        if ($alive -notcontains $k) {
            $cache.Remove($k) | Out-Null
        }
    }

})

$timer.Start()

# -------------------------
# SHOW
# -------------------------
$window.ShowDialog()
