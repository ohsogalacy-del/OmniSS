# OmniSS Screenshare One-Liner Execution Script
# Usage in CMD / Run:
# powershell -ep bypass -c "irm https://raw.githubusercontent.com/YOUR_USERNAME/OmniSS/main/run.ps1 | iex"

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  OmniSS Screenshare & Anti-Cheat Diagnostic Initializer  " -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan

# Check for Administrator elevation
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Administrative privileges required. Elevating..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-ep bypass -NoExit -Command `"irm '$($MyInvocation.MyCommand.Definition)' | iex`""
    exit
}

$destPath = "$env:TEMP\OmniSS.exe"
$localExe = Join-Path $PSScriptRoot "omniss.exe"

if (Test-Path $localExe) {
    Write-Host "[*] Launching local OmniSS binary..." -ForegroundColor Green
    & $localExe
} else {
    # Replace URL below with your GitHub release or raw direct binary link
    $downloadUrl = "https://github.com/YOUR_USERNAME/OmniSS/releases/latest/download/omniss.exe"
    
    Write-Host "[*] Fetching OmniSS scanner..." -ForegroundColor Cyan
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        Invoke-WebRequest -Uri $downloadUrl -OutFile $destPath -UseBasicParsing
        Write-Host "[+] Download complete. Commencing forensic scan..." -ForegroundColor Green
        & $destPath
    } catch {
        Write-Host "[!] Failed to download binary from GitHub release URL." -ForegroundColor Red
        Write-Host "    Please ensure you have built and uploaded 'omniss.exe' to your GitHub Releases." -ForegroundColor Yellow
        Pause
    }
}
