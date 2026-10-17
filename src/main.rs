mod artifacts;
mod cleaner;
mod input;
mod jvm;
mod mod_scanner;
mod network;
mod report;
mod winapi;

use std::process::Command;
use std::time::SystemTime;

fn get_current_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", now)
}

fn main() {
    winapi::enable_ansi_support();

    println!("\x1b[36m======================================================================\x1b[0m");
    println!("\x1b[1;36m  ██████╗ ███╗   ███╗███╗   ██╗██╗███████╗███████╗\x1b[0m");
    println!("\x1b[1;36m ██╔═══██╗████╗ ████║████╗  ██║██║██╔════╝██╔════╝\x1b[0m");
    println!("\x1b[1;36m ██║   ██║██╔████╔██║██╔██╗ ██║██║███████╗███████╗\x1b[0m");
    println!("\x1b[1;36m ██║   ██║██║╚██╔╝██║██║╚██╗██║██║╚════██║╚════██║\x1b[0m");
    println!("\x1b[1;36m ╚██████╔╝██║ ╚═╝ ██║██║ ╚████║██║███████║███████║\x1b[0m");
    println!("\x1b[1;36m  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝╚══════╝╚══════╝\x1b[0m");
    println!("\x1b[33m Industrial Minecraft Screenshare & Memory Forensic Scanner v1.0\x1b[0m");
    println!("\x1b[36m======================================================================\x1b[0m\n");

    let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "UnknownHost".to_string());
    let username = std::env::var("USERNAME").unwrap_or_else(|_| "UnknownUser".to_string());
    let timestamp = get_current_timestamp();

    println!("\x1b[34m[*] Target Host:\x1b[0m {}", hostname);
    println!("\x1b[34m[*] User Account:\x1b[0m {}", username);
    println!("\x1b[34m[*] Scan Mode:\x1b[0m High-Depth Forensic Audit\n");

    // 1. Process & Memory Forensics (JVM)
    println!("\x1b[35m[1/5] Auditing Minecraft Process & Injected Memory...\x1b[0m");
    let mc_procs = jvm::find_minecraft_processes();
    let mut jvm_results = Vec::new();

    if mc_procs.is_empty() {
        println!("  \x1b[33m[-] No active Minecraft process found (javaw.exe).\x1b[0m");
    } else {
        for (pid, name) in mc_procs {
            println!("  \x1b[32m[+] Discovered Minecraft Target: {} (PID: {})\x1b[0m", name, pid);
            let res = jvm::scan_jvm_memory(pid, &name);
            println!("      -> Unbacked executable pages: {}", res.unbacked_exec_regions.len());
            println!("      -> Cheat signature matches: {}", res.signature_hits.len());
            println!("      -> Stream-proof windows: {}", res.stream_proof_windows.len());
            jvm_results.push(res);
        }
    }

    // 2. Anti-Forensics & Cleaner Audit
    println!("\n\x1b[35m[2/5] Auditing Anti-Forensics, USN Journal & Cleaner Tools...\x1b[0m");
    let cleaner_hits = cleaner::audit_anti_forensics_and_cleaners();
    if cleaner_hits.is_empty() {
        println!("  \x1b[32m[+] USN Journal is active. Event logs intact. No cleaner tools running.\x1b[0m");
    } else {
        for hit in &cleaner_hits {
            println!("  \x1b[1;31m[!] {} : {}\x1b[0m", hit.check_name, hit.details);
        }
    }

    // 3. Execution Artifacts (BAM / Prefetch / Downloads)
    println!("\n\x1b[35m[3/5] Auditing BAM Registry, Prefetch & Historical Executions...\x1b[0m");
    let mut artifacts = Vec::new();
    let bam_hits = artifacts::scan_bam_registry();
    println!("  -> BAM registry records checked: {} suspicious hits.", bam_hits.len());
    artifacts.extend(bam_hits);

    let prefetch_hits = artifacts::scan_prefetch();
    println!("  -> Prefetch files checked: {} suspicious hits.", prefetch_hits.len());
    artifacts.extend(prefetch_hits);

    let temp_hits = artifacts::scan_temp_and_downloads();
    println!("  -> Temp & Downloads checked: {} suspicious hits.", temp_hits.len());
    artifacts.extend(temp_hits);

    let usb_hits = artifacts::scan_usb_disconnections();
    println!("  -> USB Storage devices audited: {} external drive traces.", usb_hits.len());
    artifacts.extend(usb_hits);

    for a in &artifacts {
        if a.severity.contains("FATAL") {
            println!("  \x1b[1;31m[!] [{}] {}\x1b[0m ({})", a.source, a.detected_item, a.details);
        } else {
            println!("  \x1b[33m[-] [{}] {}\x1b[0m ({})", a.source, a.detected_item, a.details);
        }
    }

    // 4. Network & DNS Cache Telemetry
    println!("\n\x1b[35m[4/5] Auditing Windows DNS Cache for Cheat Licensing Telemetry...\x1b[0m");
    let dns_hits = network::audit_dns_cache();
    if dns_hits.is_empty() {
        println!("  \x1b[32m[+] Zero DNS cache hits to known cheat authentication domains.\x1b[0m");
    } else {
        for hit in &dns_hits {
            println!("  \x1b[1;31m[!] CHEAT DOMAIN RESOLVED: {} ({})\x1b[0m", hit.domain, hit.cheat_association);
        }
    }

    // 5. Input Subsystem & Hardware Clickers
    println!("\n\x1b[35m[5/5] Auditing Input Subsystem, Filter Drivers & Macro Profiles...\x1b[0m");
    let input_hits = input::audit_input_and_macros();
    if input_hits.is_empty() {
        println!("  \x1b[32m[+] No Interception drivers, Logitech clickers, or Razer macros found.\x1b[0m");
    } else {
        for hit in &input_hits {
            println!("  \x1b[1;31m[!] [{}] {}\x1b[0m", hit.category, hit.description);
        }
    }

    // 6. Minecraft Mods (.jar) Heuristic Audit (Mace Core, Cart Core, Click Spoofing)
    println!("\n\x1b[35m[6/6] Auditing Minecraft Mods (.jar) for Combat Cores & Macros...\x1b[0m");
    let mod_results = mod_scanner::scan_mods_directory();
    let suspicious_mods: Vec<_> = mod_results.iter().filter(|m| m.suspicion_score > 0).collect();

    if suspicious_mods.is_empty() {
        println!("  \x1b[32m[+] No suspicious Mace/Cart cores or macro mods found in mods directory.\x1b[0m");
    } else {
        for m in suspicious_mods {
            if m.suspicion_score >= 80 {
                println!("  \x1b[1;31m[!] FATAL COMBAT CORE ({}% SUSPICIOUS): {}\x1b[0m", m.suspicion_score, m.jar_name);
            } else if m.suspicion_score >= 50 {
                println!("  \x1b[1;33m[-] HIGH SUSPICION ({}% SUSPICIOUS): {}\x1b[0m", m.suspicion_score, m.jar_name);
            } else {
                println!("  \x1b[36m[+] Utility Mod ({}% Suspicion): {}\x1b[0m", m.suspicion_score, m.jar_name);
            }

            for h in &m.matched_heuristics {
                println!("      -> [{}] {}", h.category, h.description);
            }
        }
    }

    // Generate Final Signed Report
    let report_data = report::ScanReportData {
        timestamp,
        hostname,
        username,
        jvm_results,
        artifacts,
        cleaner_hits,
        dns_hits,
        input_hits,
        mod_results,
    };

    println!("\n\x1b[36m======================================================================\x1b[0m");
    println!("\x1b[1;36m                      FINAL AUDIT VERDICT                             \x1b[0m");
    println!("\x1b[36m======================================================================\x1b[0m");

    let (report_path, seal) = report::generate_html_report(&report_data);

    let fatal_total = report_data.cleaner_hits.iter().filter(|h| h.severity.contains("FATAL")).count()
        + report_data.jvm_results.iter().map(|j| j.unbacked_exec_regions.len() + j.signature_hits.len() + j.stream_proof_windows.len()).sum::<usize>()
        + report_data.artifacts.iter().filter(|a| a.severity.contains("FATAL")).count()
        + report_data.dns_hits.len()
        + report_data.input_hits.iter().filter(|i| i.severity.contains("FATAL")).count()
        + report_data.mod_results.iter().filter(|m| m.suspicion_score >= 80).count();

    if fatal_total > 0 {
        println!("\x1b[1;41;37m                                                                      \x1b[0m");
        println!("\x1b[1;41;37m   >>> VERDICT: CHEAT / CLEANER DETECTED (FATAL VIOLATIONS) <<<      \x1b[0m");
        println!("\x1b[1;41;37m                                                                      \x1b[0m");
    } else if !report_data.artifacts.is_empty() || !report_data.input_hits.is_empty() {
        println!("\x1b[1;43;30m                                                                      \x1b[0m");
        println!("\x1b[1;43;30m   >>> VERDICT: SUSPICIOUS ACTIVITY (MANUAL REVIEW REQUIRED) <<<     \x1b[0m");
        println!("\x1b[1;43;30m                                                                      \x1b[0m");
    } else {
        println!("\x1b[1;42;37m                                                                      \x1b[0m");
        println!("\x1b[1;42;37m   >>> VERDICT: VERIFIED CLEAN (NO CHEAT TRACES DETECTED) <<<        \x1b[0m");
        println!("\x1b[1;42;37m                                                                      \x1b[0m");
    }

    println!("\n\x1b[32m[+] Report Generated:\x1b[0m {}", report_path.display());
    println!("\x1b[32m[+] Integrity Seal (SHA-256):\x1b[0m {}", seal);

    // Launch report in default browser
    let _ = Command::new("cmd")
        .args(["/C", "start", "", &report_path.to_string_lossy()])
        .spawn();

    println!("\n\x1b[33mPress Enter to close OmniSS...\x1b[0m");
    let mut dummy = String::new();
    let _ = std::io::stdin().read_line(&mut dummy);
}
