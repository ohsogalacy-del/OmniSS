# OmniSS Screenshare One-Liner Execution Script
# Usage in CMD / Run:
# powershell -ep bypass -c "irm https://raw.githubusercontent.com/ohsogalacy-del/OmniSS/main/run.ps1 | iex"

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  OmniSS Screenshare & Anti-Cheat Diagnostic Initializer  " -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan

# Check if running locally with omniss.exe in same directory
$localExe = ""
if (![string]::IsNullOrEmpty($PSScriptRoot)) {
    $candidate = "$PSScriptRoot\omniss.exe"
    if (Test-Path $candidate) {
        $localExe = $candidate
    }
}

if ($localExe -ne "") {
    Write-Host "[*] Launching local OmniSS binary..." -ForegroundColor Green
    & $localExe
} else {
    $destPath = "$env:TEMP\OmniSS.exe"
    $downloadUrl = "https://raw.githubusercontent.com/ohsogalacy-del/OmniSS/main/omniss.exe"
    
    Write-Host "[*] Fetching OmniSS scanner from GitHub..." -ForegroundColor Cyan
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($downloadUrl, $destPath)
        Write-Host "[+] Download complete. Starting scan..." -ForegroundColor Green
        & $destPath
    } catch {
        Write-Host "[!] Failed to fetch scanner binary: $_" -ForegroundColor Red
        Pause
    }
}
