use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct InputHit {
    pub category: String,
    pub source_path: String,
    pub description: String,
    pub severity: String,
}

pub fn audit_input_and_macros() -> Vec<InputHit> {
    let mut hits = Vec::new();

    // 1. Check for Interception driver (Used by hardware-level autoclickers like Oblivion)
    let interception_driver = Path::new("C:\\Windows\\System32\\drivers\\interception.sys");
    if interception_driver.exists() {
        hits.push(InputHit {
            category: "Kernel Filter Driver".to_string(),
            source_path: "C:\\Windows\\System32\\drivers\\interception.sys".to_string(),
            description: "Interception driver detected (hardware-level input spoofing)".to_string(),
            severity: "FATAL (Driver Autoclicker)".to_string(),
        });
    }

    // 2. Scan Logitech G-Hub LUA Macro scripts for clicker loops
    if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
        let lghub_scripts = PathBuf::from(local_appdata).join("LGHUB\\scripts");
        if lghub_scripts.exists() {
            if let Ok(entries) = fs::read_dir(&lghub_scripts) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("lua") {
                        if let Ok(content) = fs::read_to_string(&path) {
                            let lower = content.to_lowercase();
                            if (lower.contains("pressmousebutton") || lower.contains("click"))
                                && lower.contains("sleep")
                                && (lower.contains("while") || lower.contains("repeat"))
                            {
                                hits.push(InputHit {
                                    category: "Hardware Macro (Logitech G-Hub)".to_string(),
                                    source_path: path.to_string_lossy().to_string(),
                                    description: "Automated rapid-fire mouse click loop found in LUA script".to_string(),
                                    severity: "SUSPICIOUS (Hardware Macro Clicker)".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. Scan Razer Synapse Macro directories
    if let Ok(program_data) = std::env::var("ProgramData") {
        let razer_macros = PathBuf::from(program_data).join("Razer\\Synapse3\\Macros");
        if razer_macros.exists() {
            if let Ok(entries) = fs::read_dir(&razer_macros) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Ok(content) = fs::read_to_string(&path) {
                        let lower = content.to_lowercase();
                        if lower.contains("leftclick") || lower.contains("mousebutton1") {
                            hits.push(InputHit {
                                category: "Hardware Macro (Razer Synapse)".to_string(),
                                source_path: path.to_string_lossy().to_string(),
                                description: "Configured rapid mouse macro detected in Razer Synapse database".to_string(),
                                severity: "SUSPICIOUS (Macro Profile)".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    hits
}
