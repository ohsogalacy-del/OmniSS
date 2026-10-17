@echo off
title OmniSS - Minecraft Forensic Scanner
cd /d "%~dp0"

:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

if exist "omni.exe" (
    "omni.exe"
) else if exist "target\release\omni.exe" (
    "target\release\omni.exe"
) else if exist "omniss.exe" (
    "omniss.exe"
) else (
    echo [*] Binary not found. Building OmniSS from source...
    cargo build --release --bin omni
    if %errorLevel% equ 0 (
        "target\release\omni.exe"
    ) else (
        echo [!] Build failed. Please verify Rust is installed.
        pause
    )
)
