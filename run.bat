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

:: Run pre-compiled binary if available, otherwise build
if exist "target\release\omniss.exe" (
    "target\release\omniss.exe"
) else if exist "omniss.exe" (
    "omniss.exe"
) else (
    echo [*] Binary not found. Building OmniSS from source...
    cargo build --release
    if %errorLevel% equ 0 (
        "target\release\omniss.exe"
    ) else (
        echo [!] Build failed. Please verify Rust is installed.
        pause
    )
)
