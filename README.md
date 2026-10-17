# OmniSS — Next-Gen Minecraft Screenshare & Memory Forensic Scanner

**OmniSS** is an industrial-strength, zero-dependency Windows screensharing (SS) and forensic scanner engineered to outperform legacy tools (Ocean, Echo, Paladin).

It detects the entire spectrum of Minecraft cheats across legacy (1.7/1.8.9) and modern (1.20–1.21+) versions—even after the user has executed **self-destruct panic keys, string nullers, USN wipers, or batch cleaners**.

---

## What OmniSS Detects

* **Injected Ghost Clients:** Vape V4, Vape Lite, Drip Lite, Slinky, Prestige, Entropy, Breeze, Karma, Crypt, Dream, Whiteout, Sloth, Doomsday, Antic, Spook, Kurium.
* **Forge, Fabric & Weave Mods:** Raven (B+, B++, XD, Weave), Haru, Crow, Skilled (v1–v3), CatLean, disguised JARs (OptiFine/Sodium payloads).
* **Modern 1.20–1.21+ Exploits:** Krypton (DonutSMP), Phantom (AutoMace), Boze, Mio, Meteor (+ Orion, Blackout, Tanuki, TrouserStreak).
* **Blatant & Hybrid Clients:** Rise, Novoline, Augustus, Tenacity, Astolfo, Moon, Flux, Exhibition, LiquidBounce, Thunderhack.
* **External Autoclickers & Drivers:** Mango, Koid, Itami, FastClicker, Interception-driver clickers (`keyboard.sys`/`mouse.sys`), Logitech G-Hub LUA scripts, Razer Synapse macro databases.
* **Anti-Forensics & Cleaners:** USN journal wipers (`fsutil usn deletejournal`), event log clearers (Event ID 1102), Process Hacker / System Informer live memory tools, timestompers, and recent USB drive disconnections.

---

## How to Upload to GitHub

Open **Command Prompt (CMD)** or **PowerShell** inside the `OmniSS` folder and run:

```cmd
git init
git add .
git commit -m "Initial commit of OmniSS Forensic Scanner"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/OmniSS.git
git push -u origin main
```

### Making the One-Liner Work:
1. Go to your GitHub repository: `https://github.com/YOUR_USERNAME/OmniSS/releases/new`
2. Create a tag named `v1.0.0` or `latest`.
3. Upload `omniss.exe` as an asset to the release.
4. Update line 23 in `run.ps1` with your GitHub username:
   ```powershell
   $downloadUrl = "https://github.com/YOUR_USERNAME/OmniSS/releases/latest/download/omniss.exe"
   ```

---

## Screenshare Staff: How to Run on a Suspect's PC

When you freeze a suspected player on Discord or in-game, give them **one** of these options:

### Option 1: The Fast PowerShell One-Liner (Recommended)
Tell the player to open **CMD** or **PowerShell** as Administrator and run:

```powershell
powershell -ep bypass -c "irm https://raw.githubusercontent.com/YOUR_USERNAME/OmniSS/main/run.ps1 | iex"
```

### Option 2: Run Locally / via Discord
1. Send them the `OmniSS` folder or `run.bat`.
2. Tell them to double-click `run.bat` (it automatically requests Administrator elevation).

---

## Scan Results & Report Verification

At the end of the scan:
1. An interactive, dark-themed HTML report is automatically generated: `OmniSS_Report_<timestamp>.html`.
2. The report opens automatically in the default browser.
3. **Cryptographic Verification Seal (SHA-256):** Every report is sealed with an SHA-256 hash printed directly in CMD and at the bottom of the HTML page. 
   - If a player attempts to edit the HTML file in Notepad to say "CLEAN", the cryptographic seal is broken and staff can immediately flag them for report tampering.

---

## Architecture & Detection Modules

1. **`jvm.rs`**: Scans `javaw.exe` memory for unbacked executable pages (`MEM_PRIVATE` + `PAGE_EXECUTE_READWRITE`), stream-proof overlays (`WDA_EXCLUDEFROMCAPTURE`), and 30+ signature patterns.
2. **`cleaner.rs`**: Audits the NTFS USN Journal and Windows Event Logs for wiper scripts and running memory manipulation tools.
3. **`artifacts.rs`**: Traverses the BAM registry (`SYSTEM\CurrentControlSet\Services\bam`) and Prefetch for deleted cheat loaders.
4. **`network.rs`**: Dumps the Windows DNS resolver cache for query traces to cheat licensing servers.
5. **`input.rs`**: Detects kernel filter drivers (Interception) and rapid-click macro profiles.
6. **`report.rs`**: Generates the tamper-evident HTML report.

---

## Building from Source

If you modify the scanner code, build an optimized standalone binary anytime by running:

```cmd
build.bat
```
or via Cargo:
```cmd
cargo build --release
```
The output executable is located at `omniss.exe`.
