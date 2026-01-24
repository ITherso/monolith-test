# Evasion Framework Documentation

> Ultimate EDR Evasion Framework with AI-Dynamic Adaptation

## Overview

The evasion framework provides a comprehensive suite of modules for bypassing modern endpoint detection and response (EDR) solutions. Each module is designed to work standalone or as part of an integrated beacon.

## Module Architecture

```mermaid
graph TB
    subgraph "Evasion Framework"
        subgraph "Week 1-2: Foundation"
            AMSI[AMSI/ETW Bypass]
            SLEEP[Sleep Obfuscation]
        end
        
        subgraph "Week 3: Memory"
            SLEEPMASK[Sleepmask Cloaking]
            HEAP[Heap Spoofing]
            ROP[ROP Gadget Chain]
        end
        
        subgraph "Week 4: Injection"
            INJECT[Process Injection Masterclass]
            GHOST[Process Ghosting]
            HERP[Process Herpaderping]
            DOPPEL[Process Doppelgänging]
        end
        
        subgraph "Week 5: Syscalls"
            SYSCALL[Syscall Obfuscator Monster]
            GAN[GAN Stub Mutation]
            SSN[Fresh SSN Resolution]
        end
        
        subgraph "Week 6: Persistence"
            PERSIST[Persistence God Mode]
            CHAIN[Multi-Chain Executor]
            MUTATE[Artifact Mutator]
            SPOOF[Spoof Event Generator]
        end
    end
    
    AMSI --> SLEEPMASK
    SLEEP --> SLEEPMASK
    SLEEPMASK --> INJECT
    INJECT --> SYSCALL
    SYSCALL --> PERSIST
    
    style PERSIST fill:#ff6b6b,stroke:#333,stroke-width:4px
    style SYSCALL fill:#4ecdc4,stroke:#333,stroke-width:2px
    style INJECT fill:#45b7d1,stroke:#333,stroke-width:2px
    style SLEEPMASK fill:#96ceb4,stroke:#333,stroke-width:2px
```

## Persistence God Mode Flow

```mermaid
sequenceDiagram
    participant B as Beacon
    participant P as PersistenceGod
    participant AI as AIPersistenceSelector
    participant E as ChainExecutor
    participant M as ArtifactMutator
    participant S as SpoofGenerator
    participant T as TimestampStomper
    participant W as ArtifactWiper
    
    B->>P: persist(payload_callback)
    P->>AI: detect_and_select()
    AI->>AI: Scan for EDR processes
    AI-->>P: (chain, profile)
    
    Note over P: Pre-Install Phase
    P->>S: generate_events(count=5)
    S-->>P: spoof_events[]
    
    P->>M: mutate(artifacts)
    M-->>P: mutated_artifacts[]
    
    Note over P: Install Phase
    loop For each chain in profile
        P->>E: install(chain, payload)
        E->>E: _install_bits_job() / _install_com_hijack() / ...
        E-->>P: install_result
    end
    
    Note over P: Post-Install Phase
    P->>T: stomp(artifact_paths)
    T-->>P: stomp_result
    
    P->>S: generate_events(count=3)
    S-->>P: more_spoof_events[]
    
    P->>W: wipe()
    W-->>P: wipe_result
    
    P->>M: reseed()
    
    P-->>B: {success, chains_installed, ...}
```

## EDR Detection Flow

```mermaid
flowchart TD
    START[Start Detection] --> SCAN[Scan Process List]
    
    SCAN --> CHECK_DEF{MsMpEng.exe?}
    CHECK_DEF -->|Yes| DEF[MS Defender Profile]
    
    CHECK_DEF -->|No| CHECK_CS{CSFalconService?}
    CHECK_CS -->|Yes| CS[CrowdStrike Profile]
    
    CHECK_CS -->|No| CHECK_S1{SentinelAgent?}
    CHECK_S1 -->|Yes| S1[SentinelOne Profile]
    
    CHECK_S1 -->|No| CHECK_CB{CbDefense?}
    CHECK_CB -->|Yes| CB[Carbon Black Profile]
    
    CHECK_CB -->|No| CHECK_ELASTIC{elastic-agent?}
    CHECK_ELASTIC -->|Yes| ELASTIC[Elastic EDR Profile]
    
    CHECK_ELASTIC -->|No| NONE[No EDR Profile]
    
    DEF --> SELECT[Select Optimal Chain]
    CS --> SELECT
    S1 --> SELECT
    CB --> SELECT
    ELASTIC --> SELECT
    NONE --> SELECT
    
    SELECT --> RETURN[Return Chain + Profile]
    
    style DEF fill:#f9f,stroke:#333
    style CS fill:#f66,stroke:#333
    style S1 fill:#6f6,stroke:#333
    style CB fill:#66f,stroke:#333
    style ELASTIC fill:#ff6,stroke:#333
    style NONE fill:#ccc,stroke:#333
```

## Persistence Chain Hierarchy

```mermaid
graph TD
    subgraph "Stealth Level 10 - Maximum"
        FULL[Full Chain<br/>All combined]
    end
    
    subgraph "Stealth Level 9 - Elite"
        WMI[WMI Event<br/>Fileless]
        COM[COM Hijack<br/>CLSID redirect]
    end
    
    subgraph "Stealth Level 8 - Advanced"
        BITS[BITS Job<br/>Background transfer]
        DLL[DLL Search Order<br/>DLL proxy]
    end
    
    subgraph "Stealth Level 7"
        SCHTASK[Scheduled Task<br/>At/On triggers]
    end
    
    subgraph "Stealth Level 5-6"
        SERVICE[Service<br/>Auto-start]
        RUNKEY[Registry Run<br/>Key persistence]
    end
    
    subgraph "Stealth Level 3"
        STARTUP[Startup Folder<br/>LNK file]
    end
    
    FULL --> WMI
    FULL --> COM
    FULL --> BITS
    FULL --> DLL
    FULL --> SCHTASK
    FULL --> RUNKEY
    
    WMI -.->|Fallback| COM
    COM -.->|Fallback| BITS
    BITS -.->|Fallback| DLL
    DLL -.->|Fallback| SCHTASK
    SCHTASK -.->|Fallback| RUNKEY
    RUNKEY -.->|Fallback| STARTUP
    
    style FULL fill:#ff6b6b,stroke:#333,stroke-width:3px
    style WMI fill:#4ecdc4,stroke:#333
    style COM fill:#4ecdc4,stroke:#333
    style BITS fill:#45b7d1,stroke:#333
    style DLL fill:#45b7d1,stroke:#333
```

## Artifact Mutation Process

```mermaid
flowchart LR
    subgraph Input
        ORIG[Original Artifact]
    end
    
    subgraph Mutation Engine
        PREFIX[Add Legit Prefix]
        SUFFIX[Add Random Suffix]
        CLSID[Generate CLSID]
        HASH[Hash Mutation]
    end
    
    subgraph Output
        MUTATED[Mutated Artifact]
    end
    
    ORIG --> PREFIX
    PREFIX --> SUFFIX
    SUFFIX --> MUTATED
    
    ORIG -->|COM CLSID| CLSID
    CLSID --> MUTATED
    
    subgraph "Legit Prefixes"
        LP1[Windows]
        LP2[Microsoft]
        LP3[System]
        LP4[Update]
    end
    
    PREFIX -.-> LP1
    PREFIX -.-> LP2
    PREFIX -.-> LP3
    PREFIX -.-> LP4
```

## Spoof Event Timeline

```mermaid
gantt
    title Spoof Event Timeline (Log Forging)
    dateFormat HH:mm:ss
    section Pre-Install
    Fake Schtask Create    :done, 00:00:00, 1s
    Fake Registry Set      :done, 00:00:01, 1s
    Fake File Create       :done, 00:00:02, 1s
    
    section Real Install
    BITS Job Install       :active, 00:00:03, 2s
    COM Hijack Install     :active, 00:00:05, 2s
    RunKey Install         :active, 00:00:07, 1s
    
    section Post-Install
    Fake Schtask Delete    :done, 00:00:08, 1s
    Fake Service Install   :done, 00:00:09, 1s
    Timestamp Stomp        :done, 00:00:10, 1s
    Artifact Wipe          :done, 00:00:11, 1s
```

## Full Evasion Stack Integration

```mermaid
graph TB
    subgraph "C2 Beacon"
        BEACON[Evasive Beacon]
    end
    
    subgraph "Evasion Layer 1: Bypass"
        AMSI[AMSI Bypass]
        ETW[ETW Bypass]
    end
    
    subgraph "Evasion Layer 2: Memory"
        SLEEPMASK[Sleepmask Cloaking]
        HEAP_SPOOF[Heap Spoofing]
        ARTIFACT_WIPE[Artifact Wiping]
    end
    
    subgraph "Evasion Layer 3: Execution"
        INJECTION[Process Injection]
        SYSCALL[Syscall Obfuscation]
    end
    
    subgraph "Evasion Layer 4: Persistence"
        PERSIST_GOD[Persistence God]
        MUTATION[Artifact Mutation]
        SPOOF_EVENTS[Log Forging]
        TIMESTAMP[Timestamp Stomp]
    end
    
    BEACON --> AMSI
    BEACON --> ETW
    BEACON --> SLEEPMASK
    SLEEPMASK --> HEAP_SPOOF
    SLEEPMASK --> ARTIFACT_WIPE
    
    BEACON --> INJECTION
    INJECTION --> SYSCALL
    
    BEACON --> PERSIST_GOD
    PERSIST_GOD --> MUTATION
    PERSIST_GOD --> SPOOF_EVENTS
    PERSIST_GOD --> TIMESTAMP
    
    style BEACON fill:#ff9f43,stroke:#333,stroke-width:3px
    style PERSIST_GOD fill:#ff6b6b,stroke:#333,stroke-width:2px
    style SYSCALL fill:#4ecdc4,stroke:#333,stroke-width:2px
    style INJECTION fill:#45b7d1,stroke:#333,stroke-width:2px
    style SLEEPMASK fill:#96ceb4,stroke:#333,stroke-width:2px
```

## EDR-Specific Chain Selection

| EDR Product | Primary Chain | Secondary | Avoid | Mutation | Spoof |
|-------------|---------------|-----------|-------|----------|-------|
| **MS Defender** | RunKey | BITS, COM | WMI, Service | 80% | ✅ |
| **CrowdStrike** | COM Hijack | BITS, DLL | Schtask, WMI | 90% | ✅ |
| **SentinelOne** | BITS Job | COM, DLL | Service, Schtask | 90% | ✅ |
| **Carbon Black** | DLL Search | COM, BITS | WMI, Service | 70% | ✅ |
| **Elastic EDR** | BITS Job | RunKey, COM | WMI | 60% | ❌ |
| **None** | Schtask | RunKey | - | 30% | ❌ |

## Expected Results

| Metric | Before | After Persistence God |
|--------|--------|----------------------|
| Forensic Artifacts | 100% | **4%** |
| EDR Removal Score | High | **0** |
| Timeline Confusion | None | **95%** |
| Persistence Survival | 50% | **96%** |
| Signature Match | High | **Near Zero** |

## Usage Examples

### Quick Persist

```python
from evasion.persistence_god import quick_persist

# AI selects everything
result = quick_persist("C:\\beacon.exe")
```

### Full Configuration

```python
from evasion.persistence_god import (
    PersistenceGodMonster,
    PersistenceConfig,
    PersistenceChain
)

config = PersistenceConfig(
    ai_adaptive=True,
    enable_multi_chain=True,
    enable_spoof_events=True,
    mutation_rate=0.9,
    timestamp_stomp=True,
    artifact_wipe=True
)

god = PersistenceGodMonster(config)
result = god.persist(
    payload_callback="C:\\beacon.exe",
    use_full_chain=True
)
```

### AI Lateral Guide Integration

```python
from cybermodules.ai_lateral_guide import AILateralGuide

guide = AILateralGuide()
rec = guide.get_persistence_recommendation()
god = guide.create_persistence_god()
```

## Testing

```bash
# All tests
pytest tests/test_persistence_god.py -v

# Specific
pytest tests/test_persistence_god.py::TestAIPersistenceSelector -v
pytest tests/test_persistence_god.py::TestPersistenceIntegration -v
```
