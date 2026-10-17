use crate::winapi::*;
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ArtifactHit {
    pub source: String,       // "BAM Registry", "Prefetch (.pf)", "USBSTOR (Flash Drive)", "Temp/Downloads"
    pub detected_item: String,
    pub details: String,
    pub severity: String,     // "FATAL", "SUSPICIOUS"
}

pub fn scan_usb_disconnections() -> Vec<ArtifactHit> {
    let mut hits = Vec::new();
    let root_path = to_wide_null("SYSTEM\\CurrentControlSet\\Enum\\USBSTOR");

    unsafe {
        let mut h_root: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, root_path.as_ptr(), 0, KEY_READ, &mut h_root) == 0 {
            let mut subkey_idx = 0;
            let mut subkey_name = [0u16; 256];

            loop {
                let mut name_len = 256 as DWORD;
                let status = RegEnumKeyExW(
                    h_root,
                    subkey_idx,
                    subkey_name.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );

                if status != 0 {
                    break;
                }

                let usb_device = OsString::from_wide(&subkey_name[..name_len as usize])
                    .to_string_lossy()
                    .to_string();

                hits.push(ArtifactHit {
                    source: "Hardware USBSTOR (External Storage Trace)".to_string(),
                    detected_item: usb_device.clone(),
                    details: "External flash drive hardware footprint recorded in system registry".to_string(),
                    severity: "SUSPICIOUS (Audit External Device Usage)".to_string(),
                });

                subkey_idx += 1;
            }

            RegCloseKey(h_root);
        }
    }

    hits
}

// Suspicious cheat keywords
const SUSPICIOUS_KEYWORDS: &[&str] = &[
    "vape", "drip", "slinky", "prestige", "breeze", "karma", "entropy",
    "whiteout", "sloth", "doomsday", "koid", "itami", "mango", "haru",
    "raven", "liquidbounce", "rise", "novoline", "tenacity", "augustus",
    "future", "rusherhack", "boze", "meteor", "wurst", "aristois",
    "cyemer", "imnotcheatinn", "vengeance", "meowclient", "meowclientfucker",
    "rust_loader", "capcom", "kdmapper", "processhacker", "kprocesshacker", "cheatengine",
    "autoclicker", "fastclicker", "cleaner", "usn_clean", "journal_wipe",
    "maceattackassistance", "cartcore", "pearl-catcher", "instantshield"
];

fn to_wide_null(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub fn scan_bam_registry() -> Vec<ArtifactHit> {
    let mut hits = Vec::new();
    let root_path = to_wide_null("SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings");

    unsafe {
        let mut h_root: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, root_path.as_ptr(), 0, KEY_READ, &mut h_root) == 0 {
            let mut subkey_idx = 0;
            let mut subkey_name = [0u16; 256];

            loop {
                let mut name_len = 256 as DWORD;
                let status = RegEnumKeyExW(
                    h_root,
                    subkey_idx,
                    subkey_name.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );

                if status != 0 {
                    break;
                }

                // Open each User SID key
                let mut h_user: HKEY = std::ptr::null_mut();
                if RegOpenKeyExW(h_root, subkey_name.as_ptr(), 0, KEY_READ, &mut h_user) == 0 {
                    let mut val_idx = 0;
                    let mut val_name = [0u16; 1024];

                    loop {
                        let mut val_len = 1024 as DWORD;
                        let mut val_type: DWORD = 0;

                        let val_status = RegEnumValueW(
                            h_user,
                            val_idx,
                            val_name.as_mut_ptr(),
                            &mut val_len,
                            std::ptr::null_mut(),
                            &mut val_type,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                        );

                        if val_status != 0 {
                            break;
                        }

                        let exec_path = OsString::from_wide(&val_name[..val_len as usize])
                            .to_string_lossy()
                            .to_string();

                        let lower = exec_path.to_lowercase();
                        for &kw in SUSPICIOUS_KEYWORDS {
                            if lower.contains(kw) {
                                let severity = if kw.contains("cleaner") || kw.contains("vape") || kw.contains("drip") || kw.contains("slinky") || kw.contains("prestige") {
                                    "FATAL".to_string()
                                } else {
                                    "SUSPICIOUS".to_string()
                                };

                                hits.push(ArtifactHit {
                                    source: "BAM Registry (Execution History)".to_string(),
                                    detected_item: exec_path.clone(),
                                    details: format!("Matched cheat/cleaner keyword: '{}'", kw),
                                    severity,
                                });
                                break;
                            }
                        }

                        val_idx += 1;
                    }
                    RegCloseKey(h_user);
                }

                subkey_idx += 1;
            }

            RegCloseKey(h_root);
        }
    }

    hits
}

pub fn scan_prefetch() -> Vec<ArtifactHit> {
    let mut hits = Vec::new();
    let prefetch_dir = Path::new("C:\\Windows\\Prefetch");

    if let Ok(entries) = fs::read_dir(prefetch_dir) {
        for entry in entries.flatten() {
            let filename = entry.file_name().to_string_lossy().to_string();
            let lower = filename.to_lowercase();

            for &kw in SUSPICIOUS_KEYWORDS {
                if lower.contains(kw) && lower.ends_with(".pf") {
                    let severity = if kw == "fsutil" {
                        "SUSPICIOUS (Possible USN Journal Wipe)".to_string()
                    } else if kw.contains("cleaner") || kw.contains("vape") || kw.contains("drip") || kw.contains("slinky") || kw.contains("prestige") {
                        "FATAL".to_string()
                    } else {
                        "SUSPICIOUS".to_string()
                    };

                    hits.push(ArtifactHit {
                        source: "Windows Prefetch (.pf)".to_string(),
                        detected_item: filename.clone(),
                        details: format!("Prefetch evidence found for: '{}'", kw),
                        severity,
                    });
                    break;
                }
            }
        }
    }

    hits
}

fn inspect_pe_file(path: &Path) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let mut buffer = [0u8; 4096];
    let n = file.read(&mut buffer).ok()?;
    if n < 0x40 || buffer[0] != b'M' || buffer[1] != b'Z' {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(buffer[0x3C..0x40].try_into().ok()?) as usize;
    if e_lfanew + 24 >= n || &buffer[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let num_sections = u16::from_le_bytes(buffer[e_lfanew + 6..e_lfanew + 8].try_into().ok()?) as usize;
    let opt_hdr_size = u16::from_le_bytes(buffer[e_lfanew + 20..e_lfanew + 22].try_into().ok()?) as usize;
    let sec_table_offset = e_lfanew + 24 + opt_hdr_size;

    let mut has_zero_raw_code = false;
    let mut non_standard_sections = Vec::new();

    for i in 0..num_sections {
        let sec_offset = sec_table_offset + i * 40;
        if sec_offset + 40 > n {
            break;
        }
        let name_bytes = &buffer[sec_offset..sec_offset + 8];
        let name = String::from_utf8_lossy(name_bytes).trim_matches('\0').to_string();
        let raw_size = u32::from_le_bytes(buffer[sec_offset + 16..sec_offset + 20].try_into().ok()?);

        if (name == ".text" || name == ".rdata") && raw_size == 0 {
            has_zero_raw_code = true;
        }
        if name.contains('&') || name.contains('\\') || name.contains('"') || name.starts_with(".vmp") || name.starts_with(".themida") {
            non_standard_sections.push(name);
        }
    }

    if has_zero_raw_code || !non_standard_sections.is_empty() {
        return Some(format!(
            "VMProtect/Themida Crypter Signature (Zero-raw standard code: {}, Packed non-standard sections: {:?})",
            has_zero_raw_code, non_standard_sections
        ));
    }
    None
}

pub fn scan_temp_and_downloads() -> Vec<ArtifactHit> {
    let mut hits = Vec::new();

    let mut paths_to_check = Vec::new();
    if let Ok(temp) = std::env::var("TEMP") {
        paths_to_check.push(PathBuf::from(temp));
    }
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        paths_to_check.push(PathBuf::from(userprofile).join("Downloads"));
    }

    for dir in paths_to_check {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                let lower = name.to_lowercase();

                if path.is_file() {
                    let is_target_ext = lower.ends_with(".jar")
                        || lower.ends_with(".exe")
                        || lower.ends_with(".dll")
                        || lower.ends_with(".bat")
                        || lower.ends_with(".ps1");

                    if is_target_ext {
                        for &kw in SUSPICIOUS_KEYWORDS {
                            if lower.contains(kw) {
                                hits.push(ArtifactHit {
                                    source: format!("File System: {:?}", dir),
                                    detected_item: name.clone(),
                                    details: format!("Matched keyword '{}' in executable/script", kw),
                                    severity: "SUSPICIOUS".to_string(),
                                });
                                break;
                            }
                        }

                        // Inspect PE Header for commercial crypter / VMProtect / Themida packing
                        if lower.ends_with(".exe") || lower.ends_with(".dll") {
                            if let Some(crypter_details) = inspect_pe_file(&path) {
                                hits.push(ArtifactHit {
                                    source: format!("Forensics: {:?}", dir),
                                    detected_item: name.clone(),
                                    details: crypter_details,
                                    severity: "FATAL: Obfuscated Cheat Binary".to_string(),
                                });
                            }
                        }
                    }
                } else if path.is_dir() {
                    // Check for cheat loader directories (e.g. loader/map.exe, imgui.ini)
                    if lower.contains("loader") || lower.contains("cheat") {
                        let map_exe = path.join("loader\\map.exe");
                        let imgui = path.join("loader\\usermode\\imgui.ini");
                        if map_exe.exists() || imgui.exists() {
                            hits.push(ArtifactHit {
                                source: format!("Cheat Suite Folder: {:?}", dir),
                                detected_item: name.clone(),
                                details: "Kernel/Usermode cheat suite (map.exe driver mapper + ImGui overlay configuration)".to_string(),
                                severity: "FATAL: Cheat Loader Suite".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    hits
}
