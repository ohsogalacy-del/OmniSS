// Windows Native API Declarations (Zero external dependency bloat)
#![allow(non_snake_case, non_camel_case_types, dead_code)]
use std::ffi::c_void;

pub type HANDLE = *mut c_void;
pub type HKEY = *mut c_void;
pub type BOOL = i32;
pub type DWORD = u32;
pub type SIZE_T = usize;
pub type LPCWSTR = *const u16;
pub type LPWSTR = *mut u16;
pub type LPCSTR = *const i8;
pub type LPSTR = *mut i8;
pub type HWND = *mut c_void;

pub const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;
pub const PROCESS_VM_READ: DWORD = 0x0010;
pub const PROCESS_ALL_ACCESS: DWORD = 0x1F0FFF;

pub const MEM_COMMIT: DWORD = 0x1000;
pub const MEM_PRIVATE: DWORD = 0x20000;
pub const MEM_IMAGE: DWORD = 0x1000000;

pub const PAGE_NOACCESS: DWORD = 0x01;
pub const PAGE_READONLY: DWORD = 0x02;
pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_EXECUTE: DWORD = 0x10;
pub const PAGE_EXECUTE_READ: DWORD = 0x20;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
pub const PAGE_GUARD: DWORD = 0x100;

pub const HKEY_LOCAL_MACHINE: HKEY = 0x80000002usize as HKEY;
pub const HKEY_CURRENT_USER: HKEY = 0x80000001usize as HKEY;
pub const KEY_READ: DWORD = 0x20019;

pub const WDA_NONE: DWORD = 0x00000000;
pub const WDA_MONITOR: DWORD = 0x00000001;
pub const WDA_EXCLUDEFROMCAPTURE: DWORD = 0x00000011;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct MEMORY_BASIC_INFORMATION {
    pub BaseAddress: *mut c_void,
    pub AllocationBase: *mut c_void,
    pub AllocationProtect: DWORD,
    pub PartitionId: u16,
    pub RegionSize: SIZE_T,
    pub State: DWORD,
    pub Protect: DWORD,
    pub Type: DWORD,
}

#[repr(C)]
pub struct PROCESSENTRY32W {
    pub dwSize: DWORD,
    pub cntUsage: DWORD,
    pub th32ProcessID: DWORD,
    pub th32DefaultHeapID: usize,
    pub th32ModuleID: DWORD,
    pub cntThreads: DWORD,
    pub th32ParentProcessID: DWORD,
    pub pcPriClassBase: i32,
    pub dwFlags: DWORD,
    pub szExeFile: [u16; 260],
}

pub type WNDENUMPROC = unsafe extern "system" fn(hwnd: HWND, lparam: isize) -> BOOL;

#[link(name = "kernel32")]
extern "system" {
    pub fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) -> HANDLE;
    pub fn CloseHandle(hObject: HANDLE) -> BOOL;
    pub fn VirtualQueryEx(
        hProcess: HANDLE,
        lpAddress: *const c_void,
        lpBuffer: *mut MEMORY_BASIC_INFORMATION,
        dwLength: SIZE_T,
    ) -> SIZE_T;
    pub fn ReadProcessMemory(
        hProcess: HANDLE,
        lpBaseAddress: *const c_void,
        lpBuffer: *mut c_void,
        nSize: SIZE_T,
        lpNumberOfBytesRead: *mut SIZE_T,
    ) -> BOOL;
    pub fn CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD) -> HANDLE;
    pub fn Process32FirstW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
    pub fn Process32NextW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
    pub fn GetStdHandle(nStdHandle: DWORD) -> HANDLE;
    pub fn GetConsoleMode(hConsoleHandle: HANDLE, lpMode: *mut DWORD) -> BOOL;
    pub fn SetConsoleMode(hConsoleHandle: HANDLE, dwMode: DWORD) -> BOOL;
    pub fn GetLastError() -> DWORD;
}

#[link(name = "advapi32")]
extern "system" {
    pub fn RegOpenKeyExW(
        hKey: HKEY,
        lpSubKey: LPCWSTR,
        ulOptions: DWORD,
        samDesired: DWORD,
        phkResult: *mut HKEY,
    ) -> i32;
    pub fn RegCloseKey(hKey: HKEY) -> i32;
    pub fn RegEnumKeyExW(
        hKey: HKEY,
        dwIndex: DWORD,
        lpName: LPWSTR,
        lpcchName: *mut DWORD,
        lpReserved: *mut DWORD,
        lpClass: LPWSTR,
        lpcchClass: *mut DWORD,
        lpftLastWriteTime: *mut c_void,
    ) -> i32;
    pub fn RegEnumValueW(
        hKey: HKEY,
        dwIndex: DWORD,
        lpValueName: LPWSTR,
        lpcchValueName: *mut DWORD,
        lpReserved: *mut DWORD,
        lpType: *mut DWORD,
        lpData: *mut u8,
        lpcbData: *mut DWORD,
    ) -> i32;
}

#[link(name = "user32")]
extern "system" {
    pub fn EnumWindows(lpEnumFunc: WNDENUMPROC, lParam: isize) -> BOOL;
    pub fn GetWindowDisplayAffinity(hWnd: HWND, pdwAffinity: *mut DWORD) -> BOOL;
    pub fn GetWindowTextW(hWnd: HWND, lpString: LPWSTR, nMaxCount: i32) -> i32;
    pub fn IsWindowVisible(hWnd: HWND) -> BOOL;
    pub fn GetWindowThreadProcessId(hWnd: HWND, lpdwProcessId: *mut DWORD) -> DWORD;
}

pub fn enable_ansi_support() {
    unsafe {
        let handle = GetStdHandle(0xFFFFFFF5); // STD_OUTPUT_HANDLE = ((DWORD)-11)
        if !handle.is_null() && handle != (-1isize as HANDLE) {
            let mut mode: DWORD = 0;
            if GetConsoleMode(handle, &mut mode) != 0 {
                // ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                SetConsoleMode(handle, mode | 0x0004);
            }
        }
    }
}
