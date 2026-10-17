use crate::winapi::*;
use std::ffi::{c_void, OsString};
use std::os::windows::ffi::OsStringExt;
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct JvmScanResult {
    pub pid: DWORD,
    pub process_name: String,
    pub unbacked_exec_regions: Vec<UnbackedRegion>,
    pub signature_hits: Vec<SignatureHit>,
    pub stream_proof_windows: Vec<StreamProofWindow>,
}

#[derive(Debug, Clone)]
pub struct UnbackedRegion {
    pub base_address: usize,
    pub size: usize,
    pub protection: String,
}

#[derive(Debug, Clone)]
pub struct SignatureHit {
    pub address: usize,
    pub cheat_name: String,
    pub matched_pattern: String,
}

#[derive(Debug, Clone)]
pub struct StreamProofWindow {
    pub title: String,
    pub affinity: u32,
    pub pid: u32,
}

// Cheat signatures to scan in committed memory
const SIGNATURE_PATTERNS: &[(&str, &str)] = &[
    ("Vape V4 / Lite", "vape.gg"),
    ("Vape V4 / Lite", "manthe"),
    ("Vape Lite", "vape_lite"),
    ("Drip Lite", "drip.gg"),
    ("Drip Lite", "driplite"),
    ("Drip Lite", "dripclient"),
    ("Slinky", "slinky.gg"),
    ("Slinky", "slinky_client"),
    ("Prestige", "prestigeclient.vip"),
    ("Prestige", "prestige_client"),
    ("Breeze", "breezemc.com"),
    ("Breeze", "breezestore"),
    ("Karma", "karma.rip"),
    ("Karma", "karmaclient"),
    ("Entropy", "entropy.club"),
    ("Whiteout", "whiteout.gg"),
    ("Raven Ghost", "ravenbplus"),
    ("Raven Ghost", "raven_xd"),
    ("Raven Ghost", "raven_bplus"),
    ("Haru Ghost", "haru_client"),
    ("Haru Ghost", "haru_reborn"),
    ("Doomsday", "doomsdayclient"),
    ("Crypt Client", "cryptclient"),
    ("Dream Client", "dreamclient.net"),
    ("Meteor Client", "meteor-client"),
    ("Future Client", "futureclient.net"),
    ("RusherHack", "rusherhack"),
    ("LiquidBounce", "liquidbounce"),
    ("Rise Client", "riseclient.com"),
    ("Novoline", "novoline.lol"),
    ("Tenacity", "tenacity.dev"),
    ("Augustus", "augustus_client"),
    ("Krypton Client", "kryptonclient"),
];

static FOUND_WINDOWS: Mutex<Vec<StreamProofWindow>> = Mutex::new(Vec::new());

unsafe extern "system" fn enum_windows_proc(hwnd: HWND, _lparam: isize) -> BOOL {
    if IsWindowVisible(hwnd) != 0 {
        let mut affinity: DWORD = 0;
        if GetWindowDisplayAffinity(hwnd, &mut affinity) != 0 {
            // WDA_MONITOR = 0x01, WDA_EXCLUDEFROMCAPTURE = 0x11
            if affinity == WDA_EXCLUDEFROMCAPTURE || affinity == WDA_MONITOR {
                let mut title_buf = [0u16; 512];
                let len = GetWindowTextW(hwnd, title_buf.as_mut_ptr(), 512);
                let title = if len > 0 {
                    OsString::from_wide(&title_buf[..len as usize])
                        .to_string_lossy()
                        .to_string()
                } else {
                    "<No Title / Hidden Overlay>".to_string()
                };

                let mut pid: DWORD = 0;
                GetWindowThreadProcessId(hwnd, &mut pid);

                if let Ok(mut list) = FOUND_WINDOWS.lock() {
                    list.push(StreamProofWindow {
                        title,
                        affinity,
                        pid,
                    });
                }
            }
        }
    }
    1
}

pub fn check_stream_proof_windows() -> Vec<StreamProofWindow> {
    if let Ok(mut list) = FOUND_WINDOWS.lock() {
        list.clear();
    }
    unsafe {
        EnumWindows(enum_windows_proc, 0);
    }
    if let Ok(list) = FOUND_WINDOWS.lock() {
        list.clone()
    } else {
        Vec::new()
    }
}

pub fn find_minecraft_processes() -> Vec<(DWORD, String)> {
    let mut targets = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(0x00000002, 0); // TH32CS_SNAPPROCESS = 2
        if snapshot.is_null() || snapshot == (-1isize as HANDLE) {
            return targets;
        }

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as DWORD,
            cntUsage: 0,
            th32ProcessID: 0,
            th32DefaultHeapID: 0,
            th32ModuleID: 0,
            cntThreads: 0,
            th32ParentProcessID: 0,
            pcPriClassBase: 0,
            dwFlags: 0,
            szExeFile: [0u16; 260],
        };

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                let exe_name = OsString::from_wide(&entry.szExeFile[..len])
                    .to_string_lossy()
                    .to_lowercase();

                if exe_name == "javaw.exe" || exe_name == "java.exe" {
                    targets.push((entry.th32ProcessID, exe_name));
                }

                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }
    targets
}

pub fn scan_jvm_memory(pid: DWORD, process_name: &str) -> JvmScanResult {
    let mut unbacked = Vec::new();
    let mut sig_hits = Vec::new();

    unsafe {
        let h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if !h_process.is_null() {
            let mut address: usize = 0;
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

            while VirtualQueryEx(
                h_process,
                address as *const c_void,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) != 0
            {
                // Inspect committed memory
                if mbi.State == MEM_COMMIT {
                    let is_executable = mbi.Protect == PAGE_EXECUTE
                        || mbi.Protect == PAGE_EXECUTE_READ
                        || mbi.Protect == PAGE_EXECUTE_READWRITE;

                    // Detect unbacked executable memory (MEM_PRIVATE + executable)
                    // Legitimate DLLs are MEM_IMAGE. Cheats manual-mapped in private memory are MEM_PRIVATE.
                    if is_executable && mbi.Type == MEM_PRIVATE {
                        let prot_str = match mbi.Protect {
                            PAGE_EXECUTE => "PAGE_EXECUTE",
                            PAGE_EXECUTE_READ => "PAGE_EXECUTE_READ",
                            PAGE_EXECUTE_READWRITE => "PAGE_EXECUTE_READWRITE (CRITICAL)",
                            _ => "EXECUTABLE",
                        };

                        unbacked.push(UnbackedRegion {
                            base_address: mbi.BaseAddress as usize,
                            size: mbi.RegionSize,
                            protection: prot_str.to_string(),
                        });
                    }

                    // Only scan memory pages likely to contain injected cheat payloads (executable pages or small private allocations)
                    // Skip multi-gigabyte Java Garbage Collector heap arrays for maximum speed
                    let should_scan_strings = is_executable || (mbi.Type == MEM_PRIVATE && mbi.RegionSize <= 2 * 1024 * 1024);

                    if should_scan_strings {
                        let read_size = mbi.RegionSize.min(1024 * 1024);
                        let mut buffer: Vec<u8> = vec![0u8; read_size];
                        let mut bytes_read: SIZE_T = 0;

                        if ReadProcessMemory(
                            h_process,
                            mbi.BaseAddress,
                            buffer.as_mut_ptr() as *mut c_void,
                            read_size,
                            &mut bytes_read,
                        ) != 0 && bytes_read > 0 {
                            let slice = &buffer[..bytes_read];
                            for &(cheat, pattern) in SIGNATURE_PATTERNS {
                                let pat_bytes = pattern.as_bytes();
                                if slice.windows(pat_bytes.len()).any(|w| w == pat_bytes) {
                                    sig_hits.push(SignatureHit {
                                        address: mbi.BaseAddress as usize,
                                        cheat_name: cheat.to_string(),
                                        matched_pattern: pattern.to_string(),
                                    });
                                }
                            }
                        }
                    }
                }

                // Advance to next region
                address = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
                if mbi.RegionSize == 0 || address == 0 {
                    break;
                }
            }

            CloseHandle(h_process);
        }
    }

    let stream_proof = check_stream_proof_windows();

    JvmScanResult {
        pid,
        process_name: process_name.to_string(),
        unbacked_exec_regions: unbacked,
        signature_hits: sig_hits,
        stream_proof_windows: stream_proof,
    }
}
