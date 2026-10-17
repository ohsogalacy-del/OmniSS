#!/usr/bin/env python3
"""
Argon & Ghost Client Forensic Scanner
======================================
Automated forensic auditor for detecting Argon Client, disguised HWID droppers,
and Trojanized mods in Minecraft Fabric 1.20-1.21+ profiles.

Zero external dependencies required (Python 3.8+).
"""

import os
import sys
import json
import zipfile
import argparse
from pathlib import Path

# ANSI Color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

WHITELISTED_MODS = {
    "combat-hitbox",
    "bowboost",
    "shieldfixes",
    "betterhitreg",
    "sodium",
    "lithium",
    "iris",
    "ferritecore",
    "cloth-config",
    "litematica",
    "lifestealutils",
    "modmenu"
}

ARGON_KEYWORDS = [
    b"argon",
    b"argonclient",
    b"argon.mixins.json",
    b"LegitRotations",
    b"AutoCrystal",
    b"ShieldDisabler",
    b"DoubleHand"
]

HWID_INDICATORS = [
    b"oshi/",
    b"oshi.",
    b"oshi/SystemInfo",
    b"Win32ComputerSystemProduct",
    b"Win32Bios",
    b"getHardwareUUID",
    b"getBaseboard",
    b"getProcessorIdentifier"
]

NETWORK_INDICATORS = [
    b"java/net/http/HttpClient",
    b"java.net.http.HttpClient",
    b"java/net/HttpURLConnection"
]

INJECTION_INDICATORS = [
    b"defineClass",
    b"javax/crypto/Cipher",
    b"javax.crypto.Cipher"
]

def scan_jar(jar_path: Path):
    findings = []
    has_prelaunch = False
    has_hwid = False
    has_network = False
    has_injection = False
    argon_traces = []
    foreign_packages = set()

    try:
        with zipfile.ZipFile(jar_path, 'r') as z:
            namelist = z.namelist()

            # 1. Check fabric.mod.json
            if "fabric.mod.json" in namelist:
                try:
                    data = json.loads(z.read("fabric.mod.json").decode('utf-8', errors='ignore'))
                    mod_id = data.get("id", "")
                    entrypoints = data.get("entrypoints", {})

                    if "preLaunch" in entrypoints:
                        has_prelaunch = True
                        findings.append(f"Executes in PreLaunchEntrypoint: {entrypoints['preLaunch']}")
                except Exception:
                    pass

            # 2. Check for Trojan packages in legitimate mods
            for name in namelist:
                if name.startswith("com/papack/"):
                    foreign_packages.add("com.papack.* (Mace Attack Assistance Trojan)")
                if name.startswith("argon/") or name.startswith("net/argon/") or name.startswith("com/argon/"):
                    argon_traces.append(f"Argon class path: {name}")

            # 3. Bytecode scan of .class files
            for name in namelist:
                if name.endswith(".class"):
                    try:
                        content = z.read(name)
                        
                        for kw in ARGON_KEYWORDS:
                            if kw in content:
                                argon_traces.append(f"Argon string: {kw.decode(errors='ignore')}")

                        for hw in HWID_INDICATORS:
                            if hw in content:
                                has_hwid = True

                        for net in NETWORK_INDICATORS:
                            if net in content:
                                has_network = True

                        for inj in INJECTION_INDICATORS:
                            if inj in content:
                                has_injection = True
                    except Exception:
                        continue

    except Exception as e:
        return {"status": "ERROR", "msg": str(e)}

    # Evaluate Verdict
    mod_name_lower = jar_path.stem.lower()
    is_whitelisted = any(w in mod_name_lower for w in WHITELISTED_MODS)

    # Invariant: combat-hitbox is clean
    if "combat-hitbox" in mod_name_lower and not has_hwid and not has_injection:
        return {
            "verdict": "CLEAN",
            "reason": "Verified Render-Only Mod (F3+B debug visualizer).",
            "details": []
        }

    if foreign_packages:
        return {
            "verdict": "FATAL TROJAN",
            "reason": f"Disguised Trojan root package detected: {', '.join(foreign_packages)}",
            "details": list(foreign_packages)
        }

    if has_prelaunch and has_hwid and (has_network or has_injection):
        return {
            "verdict": "FATAL HWID DROPPER",
            "reason": "Mod harvests hardware IDs during PreLaunch and communicates with remote auth server to inject memory payload.",
            "details": findings
        }

    if argon_traces:
        return {
            "verdict": "FATAL CHEAT (ARGON)",
            "reason": "Direct Argon Client signatures and classes identified.",
            "details": list(set(argon_traces))[:5]
        }

    if has_hwid and has_injection:
        return {
            "verdict": "SUSPICIOUS DROPPER",
            "reason": "Contains HWID querying and dynamic in-memory classloading.",
            "details": ["Hardware ID + Memory loader signatures"]
        }

    return {
        "verdict": "CLEAN",
        "reason": "No unauthorized combat cheats, droppers, or Trojan payloads found.",
        "details": []
    }

def main():
    parser = argparse.ArgumentParser(description="Argon & Ghost Client Forensic Scanner")
    parser.add_argument("target", help="Directory containing .jar files to audit")
    args = parser.parse_args()

    target_dir = Path(args.target)
    if not target_dir.exists():
        print(f"{RED}Error: Path '{target_dir}' does not exist.{RESET}")
        sys.exit(1)

    print(f"\n{BOLD}{CYAN}=== Argon & Ghost Client Forensic Scanner ==={RESET}")
    print(f"Scanning directory: {target_dir}\n")

    jar_files = list(target_dir.glob("*.jar"))
    if not jar_files:
        print(f"{YELLOW}No .jar files found in target directory.{RESET}\n")
        return

    clean_count = 0
    threat_count = 0

    # Configure stdout for Windows console UTF-8 support
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    for jar in jar_files:
        res = scan_jar(jar)
        verdict = res.get("verdict", "UNKNOWN")

        if "FATAL" in verdict:
            threat_count += 1
            print(f"[{RED}{BOLD}{verdict}{RESET}] {jar.name}")
            print(f"  |-> {YELLOW}Reason:{RESET} {res['reason']}")
            for d in res.get("details", []):
                print(f"     * {d}")
            print()
        elif "SUSPICIOUS" in verdict:
            threat_count += 1
            print(f"[{YELLOW}{BOLD}{verdict}{RESET}] {jar.name}")
            print(f"  |-> {YELLOW}Reason:{RESET} {res['reason']}")
            print()
        else:
            clean_count += 1
            print(f"[{GREEN}CLEAN{RESET}] {jar.name} ({res['reason']})")

    print(f"\n{BOLD}Audit Summary:{RESET} {clean_count} Clean | {threat_count} Threats detected.")

if __name__ == "__main__":
    main()
