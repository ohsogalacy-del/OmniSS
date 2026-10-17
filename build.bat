@echo off
title OmniSS Build System
echo [*] Building OmniSS in optimized release mode...
cargo build --release
if %errorLevel% equ 0 (
    copy /Y "target\release\omniss.exe" "omniss.exe" >nul
    echo [+] Successfully built: omniss.exe
    echo [*] Ready for standalone distribution!
) else (
    echo [!] Build failed. Verify Rust / MSVC compiler is installed.
)
pause
