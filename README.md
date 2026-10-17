# OmniSS — Next-Gen Minecraft Screenshare & Memory Forensic Scanner

[![Minecraft](https://img.shields.io/badge/Minecraft-1.7%20--%201.21+-brightgreen.svg)](#)
[![Fabric & Forge](https://img.shields.io/badge/Loaders-Fabric%20%7C%20Forge%20%7C%20Vanilla-blue.svg)](#)
[![AI Studio Ready](https://img.shields.io/badge/AI%20Studio-Gemini%20Prompts%20Included-orange.svg)](#)
[![Rust](https://img.shields.io/badge/Engine-Rust%201.97-red.svg)](#)

**OmniSS** is an industrial-strength, zero-dependency Windows screensharing (SS) and forensic scanner engineered to outperform legacy tools (Ocean, Echo, Paladin).

It detects the entire spectrum of Minecraft cheats across legacy (1.7/1.8.9) and modern (1.20–1.21+) versions—even after the user has executed **self-destruct panic keys, string nullers, USN wipers, or batch cleaners**.

---

## 📌 Features & Detection Capabilities

* **Modern 1.20–1.21+ Exploits & Argon:** Argon Client (CPvP, AimAssist, Hitbox, AutoCrystal, AutoTotem), Krypton (DonutSMP), Phantom (AutoMace), Boze, Mio, Meteor.
* **PreLaunch HWID Remote Droppers:** Auto-scans Modrinth (`ModrinthApp/profiles/*/mods`) and `.minecraft` for hidden `PreLaunchEntrypoint` loaders utilizing OSHI/JNA hardware ID queries and dynamic in-memory class injection (`defineClass`).
* **Trojanized Libraries:** Automatically flags legitimate JARs (like `cloth-config`) injected with foreign cheat packages (`com.papack.maceattackassistance`).
* **The "Render-Only" Invariant:** Zero false positives on verified visual/HUD mods like `combat-hitbox` (F3+B debug visualizer) and GUI components (`AccordionHeaderHitbox`).
* **Injected Ghost Clients:** Vape V4, Vape Lite, Drip Lite, Slinky, Prestige, Entropy, Breeze, Karma, Crypt, Dream, Whiteout, Sloth, Doomsday.
* **External Autoclickers & Drivers:** Mango, Koid, Itami, FastClicker, Interception-driver clickers (`keyboard.sys`/`mouse.sys`), Logitech G-Hub LUA scripts, Razer Synapse macro databases.
* **Anti-Forensics & Cleaners:** USN journal wipers (`fsutil usn deletejournal`), event log clearers (Event ID 1102), Process Hacker / System Informer live memory tools, timestompers, and recent USB drive disconnections.

---

## 🧠 AI Studio Prompts & Rules Suite

This repository includes battle-tested system instructions for **Google AI Studio** and LLMs:

- **[`prompts/argon_ai_studio_system_prompt.md`](prompts/argon_ai_studio_system_prompt.md):** System prompt focused on detecting Argon Client, its modules, dangling Mixin artifacts, and self-destruct traces.
- **[`prompts/general_ss_forensics_prompt.md`](prompts/general_ss_forensics_prompt.md):** Broad screenshare forensic auditor prompt.
- **[`prompts/dropper_trojan_hunter_prompt.md`](prompts/dropper_trojan_hunter_prompt.md):** Decompilation and reverse-engineering guide for HWID droppers and memory loaders.
- **[`rules/signatures.json`](rules/signatures.json):** Machine-readable signature database.
- **[`rules/render_only_invariant.md`](rules/render_only_invariant.md):** Technical documentation proving why `combat-hitbox` is 100% clean.
- **[`tools/argon_scanner.py`](tools/argon_scanner.py):** Standalone, dependency-free Python 3 CLI scanner.

---

## 🚀 Screenshare Staff: How to Run on a Suspect's PC

When you freeze a suspected player on Discord or in-game, give them **one** of these options:

### Option 1: The Fast PowerShell One-Liner (Recommended)
Tell the player to open **CMD** or **PowerShell** as Administrator and run:

```powershell
powershell -ep bypass -c "irm https://raw.githubusercontent.com/ohsogalacy-del/OmniSS/main/run.ps1 | iex"
```

### Option 2: Run Locally / via Discord
1. Send them the `OmniSS` folder or `run.bat`.
2. Tell them to double-click `run.bat` (it automatically requests Administrator elevation).

---

## 🔒 Scan Results & Report Verification

At the end of the scan:
1. An interactive, dark-themed HTML report is automatically generated: `OmniSS_Report_<timestamp>.html`.
2. The report opens automatically in the default browser.
3. **Cryptographic Verification Seal (SHA-256):** Every report is sealed with an SHA-256 hash printed directly in CMD and at the bottom of the HTML page. 
   - If a player attempts to edit the HTML file in Notepad to say "CLEAN", the cryptographic seal is broken and staff can immediately flag them for report tampering.

---

## 🛠️ Architecture & Detection Modules

1. **`src/mod_scanner.rs`**: Traverses `.minecraft/mods` and `ModrinthApp/profiles/*/mods`, analyzes bytecode strings, catches PreLaunch entrypoints, OSHI hardware ID stealing, Trojan packages, and enforces the render-only invariant for `combat-hitbox`.
2. **`src/jvm.rs`**: Scans `javaw.exe` memory for unbacked executable pages (`MEM_PRIVATE` + `PAGE_EXECUTE_READWRITE`), stream-proof overlays (`WDA_EXCLUDEFROMCAPTURE`), and 30+ signature patterns.
3. **`src/cleaner.rs`**: Audits the NTFS USN Journal and Windows Event Logs for wiper scripts and running memory manipulation tools.
4. **`src/artifacts.rs`**: Traverses the BAM registry (`SYSTEM\CurrentControlSet\Services\bam`) and Prefetch for deleted cheat loaders.
5. **`src/network.rs`**: Dumps the Windows DNS resolver cache for query traces to cheat licensing servers.
6. **`src/input.rs`**: Detects kernel filter drivers (Interception) and rapid-click macro profiles.
7. **`src/report.rs`**: Generates the tamper-evident HTML report.

---

## 🔨 Building from Source

Build an optimized standalone binary anytime by running:

```cmd
build.bat
```
or via Cargo:
```cmd
cargo build --release
```
The output executable is located at `omniss.exe`.
