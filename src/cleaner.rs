use std::process::Command;

#[derive(Debug, Clone)]
pub struct CleanerHit {
    pub check_name: String,
    pub details: String,
    pub severity: String,
}

pub fn audit_anti_forensics_and_cleaners() -> Vec<CleanerHit> {
    let mut hits = Vec::new();

    // 1. Audit USN Journal Integrity
    let usn_query = Command::new("fsutil")
        .args(["usn", "queryjournal", "C:"])
        .output();

    if let Ok(out) = usn_query {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let combined = format!("{} {}", stdout, stderr).to_lowercase();

        if combined.contains("error") || combined.contains("is not active") || combined.contains("deleted") {
            hits.push(CleanerHit {
                check_name: "NTFS USN Journal Status".to_string(),
                details: "USN Journal is inactive or recently deleted (fsutil usn deletejournal detected)".to_string(),
                severity: "FATAL (Active Cleaner / Anti-Forensics)".to_string(),
            });
        }
    }

    // 2. Audit Security / System Event Logs for Clearing (Event ID 1102 / 104)
    let event_check = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 5 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty TimeCreated",
        ])
        .output();

    if let Ok(out) = event_check {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if !stdout.trim().is_empty() {
            hits.push(CleanerHit {
                check_name: "Windows Event Logs Cleared".to_string(),
                details: format!("Audit log clear events (Event ID 1102) detected: {}", stdout.trim()),
                severity: "FATAL (Log Wiping Detected)".to_string(),
            });
        }
    }

    // 3. Scan for active cleaner tools / memory editors
    let task_check = Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .output();

    if let Ok(out) = task_check {
        let stdout = String::from_utf8_lossy(&out.stdout).to_lowercase();
        let suspicious_tasks = &[
            ("processhacker.exe", "Process Hacker (Direct Memory Modifier)"),
            ("systeminformer.exe", "System Informer (Direct Memory Modifier)"),
            ("cheatengine.exe", "Cheat Engine"),
            ("x64dbg.exe", "x64dbg Debugger"),
            ("cutter.exe", "Cutter Disassembler"),
            ("echo_cleaner.exe", "Echo Cleaner"),
            ("viper_cleaner.exe", "Viper Cleaner"),
        ];

        for &(proc_name, desc) in suspicious_tasks {
            if stdout.contains(proc_name) {
                hits.push(CleanerHit {
                    check_name: "Running Anti-Forensic Process".to_string(),
                    details: format!("Detected active process: {} ({})", proc_name, desc),
                    severity: "FATAL (Live Memory Tool Running)".to_string(),
                });
            }
        }
    }

    hits
}
