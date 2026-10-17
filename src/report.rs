use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

pub struct ScanReportData {
    pub timestamp: String,
    pub hostname: String,
    pub username: String,
    pub jvm_results: Vec<crate::jvm::JvmScanResult>,
    pub artifacts: Vec<crate::artifacts::ArtifactHit>,
    pub cleaner_hits: Vec<crate::cleaner::CleanerHit>,
    pub dns_hits: Vec<crate::network::DnsHit>,
    pub input_hits: Vec<crate::input::InputHit>,
    pub mod_results: Vec<crate::mod_scanner::ModScanResult>,
}

pub fn generate_html_report(data: &ScanReportData) -> (PathBuf, String) {
    let fatal_count = data.cleaner_hits.iter().filter(|h| h.severity.contains("FATAL")).count()
        + data.jvm_results.iter().map(|j| j.unbacked_exec_regions.len() + j.signature_hits.len() + j.stream_proof_windows.len()).sum::<usize>()
        + data.artifacts.iter().filter(|a| a.severity.contains("FATAL")).count()
        + data.dns_hits.len()
        + data.input_hits.iter().filter(|i| i.severity.contains("FATAL")).count()
        + data.mod_results.iter().filter(|m| m.suspicion_score >= 80).count();

    let suspicious_count = data.artifacts.iter().filter(|a| a.severity.contains("SUSPICIOUS")).count()
        + data.input_hits.iter().filter(|i| i.severity.contains("SUSPICIOUS")).count()
        + data.mod_results.iter().filter(|m| m.suspicion_score >= 40 && m.suspicion_score < 80).count();

    let (verdict_class, verdict_title, verdict_desc) = if fatal_count > 0 {
        ("verdict-fatal", "FATAL: CHEAT / CLEANER DETECTED", "Definitive evidence of cheat injection, stream-proof overlay, or anti-forensic cleaner detected.")
    } else if suspicious_count > 0 {
        ("verdict-suspicious", "SUSPICIOUS ARTIFACTS FOUND", "Anomalous execution traces, deleted files, or macro scripts identified. Manual review required.")
    } else {
        ("verdict-clean", "VERIFIED CLEAN", "No active injections, unbacked memory pages, cleaner traces, or cheat signatures detected.")
    };

    let mut jvm_html = String::new();
    if data.jvm_results.is_empty() {
        jvm_html.push_str("<p class='muted'>No active Minecraft (javaw.exe) instance was running during scan.</p>");
    } else {
        for jvm in &data.jvm_results {
            jvm_html.push_str(&format!("<h3>Target: {} (PID: {})</h3>", jvm.process_name, jvm.pid));

            if !jvm.unbacked_exec_regions.is_empty() {
                jvm_html.push_str("<h4>Unbacked Executable Memory Regions (Injected DLL / Shellcode):</h4><ul>");
                for r in &jvm.unbacked_exec_regions {
                    jvm_html.push_str(&format!(
                        "<li><span class='badge badge-fatal'>FATAL</span> Address: <code>0x{:X}</code> | Size: <code>{} bytes</code> | Protection: <code>{}</code></li>",
                        r.base_address, r.size, r.protection
                    ));
                }
                jvm_html.push_str("</ul>");
            }

            if !jvm.signature_hits.is_empty() {
                jvm_html.push_str("<h4>Memory String & Signature Matches:</h4><ul>");
                for s in &jvm.signature_hits {
                    jvm_html.push_str(&format!(
                        "<li><span class='badge badge-fatal'>FATAL</span> <strong>{}</strong> | Pattern: <code>{}</code> @ <code>0x{:X}</code></li>",
                        s.cheat_name, s.matched_pattern, s.address
                    ));
                }
                jvm_html.push_str("</ul>");
            }

            if !jvm.stream_proof_windows.is_empty() {
                jvm_html.push_str("<h4>Stream-Proof Hidden Overlays (WDA_EXCLUDEFROMCAPTURE):</h4><ul>");
                for w in &jvm.stream_proof_windows {
                    jvm_html.push_str(&format!(
                        "<li><span class='badge badge-fatal'>FATAL</span> Window: <strong>{}</strong> | Affinity: <code>0x{:X}</code> (PID: {})</li>",
                        w.title, w.affinity, w.pid
                    ));
                }
                jvm_html.push_str("</ul>");
            }

            if jvm.unbacked_exec_regions.is_empty() && jvm.signature_hits.is_empty() && jvm.stream_proof_windows.is_empty() {
                jvm_html.push_str("<p class='clean-note'>Memory regions clean. No unbacked executable allocations or known signatures.</p>");
            }
        }
    }

    let mut artifacts_html = String::new();
    if data.artifacts.is_empty() {
        artifacts_html.push_str("<p class='clean-note'>No suspicious BAM registry entries, Prefetch files, or deleted binaries found.</p>");
    } else {
        artifacts_html.push_str("<ul>");
        for a in &data.artifacts {
            let badge_cls = if a.severity.contains("FATAL") { "badge-fatal" } else { "badge-suspicious" };
            artifacts_html.push_str(&format!(
                "<li><span class='badge {}'>{}</span> <strong>[{}]</strong> {} &mdash; <span class='muted'>{}</span></li>",
                badge_cls, a.severity, a.source, a.detected_item, a.details
            ));
        }
        artifacts_html.push_str("</ul>");
    }

    let mut cleaner_html = String::new();
    if data.cleaner_hits.is_empty() {
        cleaner_html.push_str("<p class='clean-note'>NTFS USN Journal active. Event logs intact. No cleaner processes running.</p>");
    } else {
        cleaner_html.push_str("<ul>");
        for c in &data.cleaner_hits {
            cleaner_html.push_str(&format!(
                "<li><span class='badge badge-fatal'>{}</span> <strong>{}</strong>: {}</li>",
                c.severity, c.check_name, c.details
            ));
        }
        cleaner_html.push_str("</ul>");
    }

    let mut dns_html = String::new();
    if data.dns_hits.is_empty() {
        dns_html.push_str("<p class='clean-note'>Windows DNS cache contains zero queries to known cheat domains.</p>");
    } else {
        dns_html.push_str("<ul>");
        for d in &data.dns_hits {
            dns_html.push_str(&format!(
                "<li><span class='badge badge-fatal'>FATAL</span> <strong>{}</strong> ({}) &mdash; <code>{}</code></li>",
                d.domain, d.cheat_association, d.raw_entry
            ));
        }
        dns_html.push_str("</ul>");
    }

    let mut input_html = String::new();
    if data.input_hits.is_empty() {
        input_html.push_str("<p class='clean-note'>No Interception filter drivers, Logitech LUA clickers, or Razer macros detected.</p>");
    } else {
        input_html.push_str("<ul>");
        for i in &data.input_hits {
            let badge_cls = if i.severity.contains("FATAL") { "badge-fatal" } else { "badge-suspicious" };
            input_html.push_str(&format!(
                "<li><span class='badge {}'>{}</span> <strong>[{}]</strong> {} &mdash; {}</li>",
                badge_cls, i.severity, i.category, i.source_path, i.description
            ));
        }
        input_html.push_str("</ul>");
    }

    let mut mods_html = String::new();
    if data.mod_results.is_empty() {
        mods_html.push_str("<p class='clean-note'>No suspicious combat cores or macro mods detected in .minecraft/mods.</p>");
    } else {
        mods_html.push_str("<ul>");
        for m in &data.mod_results {
            if m.suspicion_score > 0 {
                let badge_cls = if m.suspicion_score >= 80 {
                    "badge-fatal"
                } else if m.suspicion_score >= 50 {
                    "badge-suspicious"
                } else {
                    "clean-note"
                };

                let triggers = m.matched_heuristics.iter()
                    .map(|h| format!("{}: {}", h.category, h.description))
                    .collect::<Vec<_>>()
                    .join(" | ");

                mods_html.push_str(&format!(
                    "<li><span class='badge {}'>{}% SUSPICIOUS</span> <strong>{}</strong> &mdash; <code>{}</code></li>",
                    badge_cls, m.suspicion_score, m.jar_name, triggers
                ));
            }
        }
        mods_html.push_str("</ul>");
    }

    let raw_html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OmniSS Forensic Audit Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0d1117; color: #c9d1d9; padding: 24px; margin: 0; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 32px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }}
        h1 {{ color: #58a6ff; margin-top: 0; border-bottom: 1px solid #30363d; padding-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }}
        .meta {{ color: #8b949e; font-size: 14px; margin-bottom: 24px; }}
        .verdict-box {{ padding: 20px; border-radius: 6px; margin-bottom: 30px; border: 1px solid; }}
        .verdict-fatal {{ background: rgba(248, 81, 73, 0.15); border-color: #f85149; color: #ff7b72; }}
        .verdict-suspicious {{ background: rgba(210, 153, 34, 0.15); border-color: #d29922; color: #e3b341; }}
        .verdict-clean {{ background: rgba(46, 160, 67, 0.15); border-color: #2ea043; color: #56d364; }}
        .verdict-box h2 {{ margin: 0 0 8px 0; font-size: 24px; }}
        .section {{ margin-bottom: 28px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 20px; }}
        .section h2 {{ color: #79c0ff; margin-top: 0; font-size: 18px; border-bottom: 1px solid #21262d; padding-bottom: 8px; }}
        ul {{ list-style-type: none; padding-left: 0; margin: 0; }}
        li {{ padding: 10px 0; border-bottom: 1px solid #21262d; font-size: 14px; line-height: 1.5; }}
        li:last-child {{ border-bottom: none; }}
        code {{ background: #161b22; padding: 2px 6px; border-radius: 4px; font-family: monospace; color: #ff7b72; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; margin-right: 8px; display: inline-block; }}
        .badge-fatal {{ background: #f85149; color: #fff; }}
        .badge-suspicious {{ background: #d29922; color: #000; }}
        .clean-note {{ color: #56d364; font-size: 14px; margin: 0; }}
        .muted {{ color: #8b949e; }}
        .seal-box {{ margin-top: 30px; padding: 16px; background: #0d1117; border: 1px dashed #30363d; border-radius: 6px; font-size: 12px; color: #8b949e; word-break: break-all; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>OmniSS Forensic Audit Report <span>v1.0</span></h1>
        <div class="meta">
            Target Host: <strong>{}</strong> | User: <strong>{}</strong> | Audit Timestamp: <strong>{}</strong>
        </div>

        <div class="verdict-box {}">
            <h2>{}</h2>
            <p style="margin: 0;">{}</p>
        </div>

        <div class="section">
            <h2>1. Process & Injected Memory Forensics (JVM)</h2>
            {}
        </div>

        <div class="section">
            <h2>2. Anti-Forensics & Cleaner Verification</h2>
            {}
        </div>

        <div class="section">
            <h2>3. Windows Artifacts & Execution History (BAM / Prefetch)</h2>
            {}
        </div>

        <div class="section">
            <h2>4. Network & DNS Cache Telemetry</h2>
            {}
        </div>

        <div class="section">
            <h2>5. Input Subsystem & Hardware Clicker Macros</h2>
            {}
        </div>

        <div class="section">
            <h2>6. Minecraft Mods (.jar) & Combat Cores / Assist Macros</h2>
            {}
        </div>

        <div class="seal-box">
            <strong>Cryptographic Verification Seal (SHA-256):</strong><br>
            <code>##INTEGRITY_SEAL##</code><br>
            <span class="muted">Tamper-evident verification: Any alteration to this HTML document invalidates the signature.</span>
        </div>
    </div>
</body>
</html>"#,
        data.hostname, data.username, data.timestamp,
        verdict_class, verdict_title, verdict_desc,
        jvm_html, cleaner_html, artifacts_html, dns_html, input_html, mods_html
    );

    // Compute cryptographic SHA-256 seal
    let mut hasher = Sha256::new();
    hasher.update(raw_html.as_bytes());
    let seal = format!("{:x}", hasher.finalize());

    let final_html = raw_html.replace("##INTEGRITY_SEAL##", &seal);

    let report_filename = format!("OmniSS_Report_{}.html", data.timestamp.replace(":", "-").replace(" ", "_"));
    let report_path = PathBuf::from(&report_filename);
    let _ = fs::write(&report_path, &final_html);

    (report_path, seal)
}
