
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

# -------------------------
# DATA
# -------------------------
$allProcesses = New-Object System.Collections.ObjectModel.ObservableCollection[object]
$viewData = New-Object System.Collections.ObjectModel.ObservableCollection[object]

# -------------------------
# HELPERS
# -------------------------
function Get-ParentMap {
    $map = @{}
    Get-CimInstance Win32_Process | ForEach-Object {
        $map[$_.ProcessId] = $_.ParentProcessId
    }
    return $map
}

function Is-Suspicious($p) {
    $path = $p.Path.ToLower()

    return (
        $path -match "temp|appdata|downloads|desktop" -or
        $p.CPU -gt 80
    )
}

# -------------------------
# UI (WPF)
# -------------------------
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Live Process Dashboard"
        Height="700"
        Width="1100"
        Background="#1E1E1E">

    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="35"/>
            <RowDefinition Height="35"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <!-- SEARCH -->
        <TextBox Name="SearchBox"
                 Grid.Row="0"
                 Height="25"
                 Background="#2D2D30"
                 Foreground="White"
                 Text=""/>

        <!-- BUTTONS -->
        <StackPanel Grid.Row="1" Orientation="Horizontal">

            <Button Name="ExportBtn"
                    Content="Export CSV"
                    Width="120"
                    Margin="0,0,10,0"/>

        </StackPanel>

        <!-- GRID -->
        <DataGrid Name="Grid"
                  Grid.Row="2"
                  AutoGenerateColumns="True"
                  Background="#252526"
                  Foreground="White"
                  IsReadOnly="True"/>

    </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

$grid = $window.FindName("Grid")
$search = $window.FindName("SearchBox")
$exportBtn = $window.FindName("ExportBtn")

$grid.ItemsSource = $viewData

# -------------------------
# LOAD LOOP (REAL WORKING)
# -------------------------
function Refresh-Processes {

    $parentMap = Get-ParentMap

    $processes = Get-Process | ForEach-Object {

        $cpu = 0
        try { $cpu = $_.CPU } catch {}

        $path = ""
        try { $path = $_.Path } catch {}

        [PSCustomObject]@{
            Name   = $_.ProcessName
            PID    = $_.Id
            Parent = $parentMap[$_.Id]
            CPU    = [math]::Round($cpu,2)
            RAM    = [math]::Round($_.WorkingSet64 / 1MB,2)
            Path   = $path
            Flag   = ""
        }
    }

    $viewData.Clear()

    foreach ($p in $processes) {

        $flag = Is-Suspicious $p
        $p.Flag = if ($flag) { "RED" } else { "OK" }

        $viewData.Add($p)
    }
}

# -------------------------
# SEARCH FILTER
# -------------------------
$search.Add_TextChanged({
    $text = $search.Text.ToLower()

    $viewData.Clear()

    Get-Process | ForEach-Object {

        $cpu = $_.CPU
        $path = $_.Path

        $obj = [PSCustomObject]@{
            Name = $_.ProcessName
            PID  = $_.Id
            CPU  = [math]::Round($cpu,2)
            RAM  = [math]::Round($_.WorkingSet64 / 1MB,2)
            Path = $path
            Flag = ""
        }

        if ($obj.Name.ToLower().Contains($text)) {
            $viewData.Add($obj)
        }
    }
})

# -------------------------
# EXPORT BUTTON
# -------------------------
$exportBtn.Add_Click({
    $path = "$env:USERPROFILE\Desktop\process_report.csv"
    $viewData | Export-Csv -Path $path -NoTypeInformation
    [System.Windows.MessageBox]::Show("Exported to Desktop")
})

# -------------------------
# LIVE TIMER
# -------------------------
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(1)

$timer.Add_Tick({
    Refresh-Processes
})

$timer.Start()

# -------------------------
# SHOW UI
# -------------------------
$window.ShowDialog()
