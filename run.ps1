# OmniSS Screenshare One-Liner Execution Script
# Usage in CMD / Run:
# powershell -ep bypass -c "irm https://raw.githubusercontent.com/ohsogalacy-del/OmniSS/main/run.ps1 | iex"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  OmniSS Screenshare & Anti-Cheat Diagnostic Initializer  " -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan

# Check for Administrator elevation gracefully
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[*] Requesting Administrator privileges for full kernel/USN audit..." -ForegroundColor Yellow
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-ep bypass -NoExit -Command `"irm https://raw.githubusercontent.com/ohsogalacy-del/OmniSS/main/run.ps1 | iex`"" -ErrorAction Stop
        exit
    } catch {
        Write-Host "[-] Elevation declined or unavailable. Continuing in standard user mode..." -ForegroundColor Yellow
    }
}

$destPath = "$env:TEMP\OmniSS.exe"
$localExe = Join-Path $PSScriptRoot "omniss.exe"

if (Test-Path $localExe) {
    Write-Host "[*] Launching local OmniSS binary..." -ForegroundColor Green
    & $localExe
} else {
    # Direct binary link from GitHub repo main branch
    $downloadUrl = "https://raw.githubusercontent.com/ohsogalacy-del/OmniSS/main/omniss.exe"
    
    Write-Host "[*] Fetching OmniSS scanner from GitHub..." -ForegroundColor Cyan
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        Invoke-WebRequest -Uri $downloadUrl -OutFile $destPath -UseBasicParsing
        Write-Host "[+] Download complete. Commencing forensic scan..." -ForegroundColor Green
        & $destPath
    } catch {
        Write-Host "[!] Failed to download binary from GitHub." -ForegroundColor Red
        Write-Host "    Error: $_" -ForegroundColor Yellow
        Pause
    }
}
