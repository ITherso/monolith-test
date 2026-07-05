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

---

## Report Generator Pro Flow

```mermaid
sequenceDiagram
    participant B as Beacon/Chain
    participant R as ReportGenerator
    participant M as MITREMapper
    participant A as AISummaryGenerator
    participant S as SigmaRuleGenerator
    participant H as HTMLReportGenerator
    participant AN as DataAnonymizer
    
    B->>R: generate_report(chain_log)
    
    Note over R: Phase 1: MITRE Mapping
    R->>M: map_chain_log(chain_log)
    M->>M: Match techniques to tactics
    M->>M: Calculate coverage scores
    M-->>R: mitre_coverage{}
    
    Note over R: Phase 2: AI Summary
    R->>A: generate_summary(chain_log, coverage)
    A->>A: Calculate stats (bypass %, success %)
    A->>A: Apply executive template
    A-->>R: ai_summary
    
    Note over R: Phase 3: Detection Rules
    R->>S: generate_rules(chain_log, coverage)
    S->>S: Per-tactic rule templates
    S->>S: Inject artifacts into rules
    S-->>R: sigma_rules[]
    
    Note over R: Phase 4: OPSEC Anonymization
    R->>AN: anonymize_chain_log(chain_log)
    AN->>AN: Replace IPs → format-preserved
    AN->>AN: Replace hostnames
    AN->>AN: Replace usernames
    AN-->>R: safe_chain_log
    
    Note over R: Phase 5: Report Generation
    R->>H: generate_report(all_data)
    H->>H: Build tabs (Summary, MITRE, Sigma)
    H->>H: Generate Mermaid diagrams
    H->>H: Apply theme CSS
    H-->>R: html_content
    
    R-->>B: ReportResult{paths, rules, summary}
```

## MITRE ATT&CK Heatmap Data Flow

```mermaid
flowchart TD
    subgraph "Input"
        CL[Chain Log Entries]
    end
    
    subgraph "Processing"
        TECH[Extract Techniques]
        MAP[Map to MITRE Tactics]
        SCORE[Calculate Scores]
        AGG[Aggregate by Tactic]
    end
    
    subgraph "Output"
        HEAT[Heatmap Data]
        MERMAID[Mermaid Diagram]
        JSON[JSON Export]
    end
    
    CL --> TECH
    TECH --> MAP
    MAP --> SCORE
    SCORE --> AGG
    
    AGG --> HEAT
    AGG --> MERMAID
    AGG --> JSON
    
    style CL fill:#4ecdc4,stroke:#333
    style HEAT fill:#ff6b6b,stroke:#333
    style MERMAID fill:#45b7d1,stroke:#333
    style JSON fill:#96ceb4,stroke:#333
```

## Sigma Rule Generation Flow

```mermaid
flowchart LR
    subgraph "Input"
        TECH[Technique ID]
        ART[Artifacts]
    end
    
    subgraph "Template Selection"
        T1[Process Injection?]
        T2[Persistence?]
        T3[Credential Access?]
        T4[Lateral Movement?]
        T5[Defense Evasion?]
    end
    
    subgraph "Rule Building"
        LOG[Logsource Config]
        DET[Detection Logic]
        META[Metadata Tags]
    end
    
    subgraph "Output"
        YAML[Sigma YAML]
    end
    
    TECH --> T1
    TECH --> T2
    TECH --> T3
    TECH --> T4
    TECH --> T5
    
    T1 --> LOG
    T2 --> LOG
    T3 --> LOG
    T4 --> LOG
    T5 --> LOG
    
    LOG --> DET
    ART --> DET
    DET --> META
    META --> YAML
    
    style TECH fill:#4ecdc4
    style ART fill:#4ecdc4
    style YAML fill:#ff6b6b
```

## Report Generator Usage

```python
from tools.report_generator import (
    ReportGenerator,
    ReportConfig,
    ReportFormat,
    create_sample_chain_log,
)

# Create report generator
config = ReportConfig(
    enable_ai_summary=True,
    enable_mitre_map=True,
    enable_sigma_generate=True,
    format=ReportFormat.HTML,
    output_dir="reports",
    anonymize_data=True,
    theme="hacker",
)

generator = ReportGenerator(config)

# Generate report from chain log
chain_log = create_sample_chain_log()
result = generator.generate_report(chain_log)

print(f"Report: {result.report_path}")
print(f"Sigma Rules: {len(result.sigma_rules)}")
print(f"MITRE Coverage: {len(result.mitre_coverage)} techniques")
```

### AI Lateral Guide Report Integration

```python
from cybermodules.ai_lateral_guide import AILateralGuide

guide = AILateralGuide()

# Full report generation
result = guide.generate_chain_report(
    format="html",
    include_sigma=True,
    include_mitre=True,
)

# Quick AI summary
summary = guide.get_ai_report_summary(style="executive")

# Get MITRE heatmap data
heatmap = guide.get_mitre_heatmap_data()

# Generate Twitter thread for demo
thread = guide.generate_twitter_thread()
for tweet in thread:
    print(tweet)
```

## Testing

```bash
# Report generator tests
pytest tests/test_report_generator.py -v

# Specific components
pytest tests/test_report_generator.py::TestMITREMapper -v
pytest tests/test_report_generator.py::TestSigmaRuleGenerator -v
pytest tests/test_report_generator.py::TestAISummaryGenerator -v
pytest tests/test_report_generator.py::TestDataAnonymizer -v
```
