# 05 - Detection Engineering
## SIEM, Sigma, YARA, Alert Design, False Positive Reduction

---

## Detection Engineering Principles

```
DETECTION PYRAMID (Prioritization):
         ▲
        /|\  TTP-Based Detections (Most valuable, hardest to evade)
       / | \   - Behavioral patterns
      /  |  \  - Attack chain detection
     /   |   \
    /    |    \ Tool-Based Detections
   /     |     \  - Mimikatz, Cobalt Strike signatures
  /      |      \ - Known malware hashes
 /       |       \
/________|________\ IOC-Based Detections (Easiest to evade)
                    - IPs, domains, hashes

DETECTION ENGINEERING LIFECYCLE:
Requirements → Research → Design → Implement → Test → Tune → Maintain
```

---

## Sigma Rules (Universal Detection Language)

### Sigma Structure

```yaml
title: Suspicious PowerShell Download Cradle
id: 3b6ab547-8ec3-4b36-a2f5-d4a10d2f08b5
status: stable
description: Detects PowerShell download cradles commonly used by attackers
author: Your Name
date: 2026/02/23
modified: 2026/02/23
references:
    - https://attack.mitre.org/techniques/T1059/001/
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'IEX'
            - 'Invoke-Expression'
            - 'DownloadString'
            - 'Net.WebClient'
            - 'Invoke-WebRequest'
            - 'iwr'
            - 'curl'
            - 'wget'
    condition: selection
falsepositives:
    - Legitimate admin scripts
    - Software installers
level: high
tags:
    - attack.execution
    - attack.t1059.001
```

### Sigma Modifiers (Quick Reference)

```yaml
# String Modifiers
contains        # Substring match
startswith      # Starts with
endswith        # Ends with
re              # Regex match
all             # All values must match
base64          # Base64 decode before matching
base64offset    # Base64 with offset variations

# Numeric Modifiers
gt              # Greater than
gte             # Greater than or equal
lt              # Less than
lte             # Less than or equal

# Field Modifiers
exists          # Field exists
cidr            # CIDR notation IP matching

# Examples
CommandLine|contains|all:
    - 'powershell'
    - '-enc'
TargetFilename|endswith:
    - '.exe'
    - '.dll'
DestinationIp|cidr: '10.0.0.0/8'
```

### Sigma to SIEM Conversion

```bash
# Install sigmac (legacy) or sigma-cli (current)
pip install sigma-cli

# Convert to Splunk
sigma convert -t splunk -p sysmon rule.yml

# Convert to Elastic
sigma convert -t elasticsearch -p ecs_windows rule.yml

# Convert to Microsoft Sentinel
sigma convert -t azure_monitor rule.yml

# Batch conversion
sigma convert -t splunk -p sysmon rules/*.yml > splunk_rules.spl
```

---

## YARA Rules (File/Memory Detection)

### YARA Structure

```yara
rule CobaltStrike_Beacon
{
    meta:
        description = "Detects Cobalt Strike Beacon"
        author = "Your Name"
        date = "2026-02-23"
        reference = "https://..."
        hash = "abc123..."

    strings:
        $s1 = "beacon.dll" ascii wide
        $s2 = "ReflectiveLoader" ascii
        $s3 = { 4D 5A 90 00 03 00 00 00 }  // MZ header
        $s4 = /https?:\/\/[^\s]+\.dll/     // Regex
        $pdb = "c:\\Users\\admin\\beacon" nocase

        // XOR'd strings
        $xor1 = "beacon" xor(0x00-0xff)

    condition:
        uint16(0) == 0x5A4D and  // MZ header
        filesize < 1MB and
        (3 of ($s*) or $pdb or $xor1)
}

rule Ransomware_Generic
{
    strings:
        $ransom1 = "Your files have been encrypted"
        $ransom2 = "bitcoin" nocase
        $ransom3 = "decrypt" nocase
        $ext1 = ".locked"
        $ext2 = ".encrypted"

    condition:
        2 of ($ransom*) or 2 of ($ext*)
}
```

### YARA Operators & Conditions

```yara
// String count
#s1 > 5                    // More than 5 occurrences

// String position
$s1 at 0                   // At offset 0
$s1 in (0..100)           // Within first 100 bytes

// File properties
uint16(0) == 0x5A4D       // MZ header (PE file)
uint32(0) == 0x464C457F   // ELF header

// Combinations
all of them               // All strings must match
any of them               // At least one string
3 of ($s*)                // 3 or more strings starting with $s
for any of ($s*) : (# > 2) // Any string appears more than twice

// PE module (requires pe module import)
import "pe"
pe.number_of_sections > 5
pe.imports("kernel32.dll", "VirtualAlloc")
pe.exports("ReflectiveLoader")
```

---

## Alert Design Best Practices

### Alert Anatomy

```
┌─────────────────────────────────────────────────────────────────────┐
│ ALERT: LSASS Memory Access Detected                                │
├─────────────────────────────────────────────────────────────────────┤
│ Severity: CRITICAL                                                  │
│ Confidence: HIGH                                                    │
│ MITRE: T1003.001 (OS Credential Dumping: LSASS Memory)             │
├─────────────────────────────────────────────────────────────────────┤
│ Summary: Process accessed LSASS memory with suspicious permissions │
├─────────────────────────────────────────────────────────────────────┤
│ Evidence:                                                          │
│   Source Process: C:\Temp\updater.exe                              │
│   Target Process: C:\Windows\System32\lsass.exe                    │
│   Access Rights: 0x1FFFFF (PROCESS_ALL_ACCESS)                     │
│   User: DOMAIN\compromised_user                                    │
│   Host: WORKSTATION-42                                             │
│   Time: 2026-02-23 14:35:22 UTC                                    │
├─────────────────────────────────────────────────────────────────────┤
│ Context (Auto-enriched):                                           │
│   User Risk Score: 85/100 (elevated)                               │
│   Host Risk Score: 72/100 (elevated)                               │
│   Similar alerts (24h): 0                                          │
│   Source hash VT score: 45/70                                      │
├─────────────────────────────────────────────────────────────────────┤
│ Recommended Actions:                                               │
│   1. Isolate host immediately                                      │
│   2. Force password reset for user                                 │
│   3. Acquire memory dump for forensics                             │
│   4. Check for lateral movement                                    │
└─────────────────────────────────────────────────────────────────────┘
```

### Severity Matrix

```
┌─────────────────────────────────────────────────────────────────────┐
│ Severity │ Confidence │ Response SLA │ Examples                    │
├──────────┼────────────┼──────────────┼─────────────────────────────┤
│ CRITICAL │ HIGH       │ 15 min       │ Ransomware staging, Domain  │
│          │            │              │ Admin compromise, Active    │
│          │            │              │ C2 beacon                   │
├──────────┼────────────┼──────────────┼─────────────────────────────┤
│ HIGH     │ HIGH       │ 1 hour       │ Credential dumping,         │
│          │            │              │ Lateral movement,           │
│          │            │              │ Data exfiltration           │
├──────────┼────────────┼──────────────┼─────────────────────────────┤
│ MEDIUM   │ MEDIUM     │ 4 hours      │ Suspicious PowerShell,      │
│          │            │              │ Unusual service creation,   │
│          │            │              │ Policy violations           │
├──────────┼────────────┼──────────────┼─────────────────────────────┤
│ LOW      │ LOW        │ 24 hours     │ Reconnaissance, Info        │
│          │            │              │ disclosure, Minor policy    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## False Positive Reduction

### Baselining Approach

```python
# Pseudo-code for behavioral baseline
def create_baseline(entity, behavior, timeframe="30d"):
    """
    Create behavioral baseline for entity
    """
    historical_data = query_siem(
        entity=entity,
        behavior=behavior,
        time_range=timeframe
    )

    baseline = {
        "mean": mean(historical_data),
        "std_dev": std_dev(historical_data),
        "percentile_95": percentile(historical_data, 95),
        "typical_hours": get_typical_hours(historical_data),
        "typical_sources": get_typical_sources(historical_data)
    }

    return baseline

def is_anomalous(current_value, baseline):
    """
    Z-score based anomaly detection
    """
    z_score = (current_value - baseline["mean"]) / baseline["std_dev"]
    return abs(z_score) > 3  # 3 standard deviations
```

### Whitelist Strategies

```yaml
# Sigma with whitelisting
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: 'DownloadString'
    filter_legitimate:
        User|contains:
            - 'svc_automation'
            - 'SYSTEM'
        ParentImage|endswith:
            - '\SCCM\ccmexec.exe'
            - '\chef-client\bin\ruby.exe'
    condition: selection and not filter_legitimate
```

### Tuning Process

```
DETECTION TUNING WORKFLOW:

1. DEPLOY DETECTION (silent mode)
   └── Log but don't alert for 7-14 days

2. ANALYZE FALSE POSITIVES
   ├── Group by user, host, application
   ├── Identify legitimate patterns
   └── Document business justification

3. REFINE DETECTION
   ├── Add exclusions with documentation
   ├── Tighten scope if too broad
   └── Add context requirements

4. TEST REFINED DETECTION
   ├── Purple team validation
   ├── Replay historical attacks
   └── Verify FP reduction

5. PRODUCTION DEPLOYMENT
   └── Monitor for 7 days post-deployment

6. CONTINUOUS REVIEW
   └── Monthly review of exclusions
```

---

## Log Sources Priority

```
CRITICAL (Must Have):
├── Windows Security Events (Domain Controllers)
├── Sysmon (Endpoints)
├── EDR Telemetry
├── Authentication Logs (Okta, Azure AD)
├── VPN/Remote Access Logs
└── Firewall/Proxy Logs

HIGH (Should Have):
├── DNS Query Logs
├── Email Gateway Logs
├── Cloud Audit Logs (CloudTrail, Azure Activity)
├── Database Access Logs
└── Web Application Logs

MEDIUM (Nice to Have):
├── DHCP Logs
├── NetFlow/Traffic Analysis
├── Badge Access Logs
├── DLP Logs
└── Container/K8s Audit Logs
```

---

## Detection Metrics

```
COVERAGE METRICS:
├── ATT&CK Technique Coverage: % of techniques with detections
├── Detection Gap Analysis: Techniques without coverage
└── Asset Coverage: % of assets with logging/monitoring

QUALITY METRICS:
├── True Positive Rate (TPR): TP / (TP + FN)
├── False Positive Rate (FPR): FP / (FP + TN)
├── Precision: TP / (TP + FP)
├── Alert Fatigue Index: FP alerts / Total alerts
└── Mean Time to Tune: Days from deploy to stable

OPERATIONAL METRICS:
├── MTTD (Mean Time to Detect)
├── MTTR (Mean Time to Respond)
├── Alert Volume by Severity
├── Alert Aging (unhandled alerts)
└── Detection Rule Health (errors, performance)

TARGET BENCHMARKS:
├── False Positive Rate: <5% for critical alerts
├── ATT&CK Coverage: >60% of applicable techniques
├── MTTD for critical: <15 minutes
└── Detection Rule Uptime: >99%
```

---

## Interview Questions - Detection Engineering

1. **How do you measure detection effectiveness?**
   - TPR, FPR, Precision, ATT&CK coverage
   - Purple team validation
   - MTTD metrics
   - False positive rate

2. **How do you reduce false positives without missing attacks?**
   - Behavioral baselining
   - Context enrichment
   - Whitelist with documentation
   - Multi-condition detections
   - Confidence scoring

3. **Explain your detection engineering workflow**
   - Requirements from threat intel
   - Research attack mechanics
   - Design detection logic
   - Test with atomic red team
   - Silent mode deployment
   - Tune, then production

4. **How do you prioritize detection development?**
   - Threat intelligence (what's targeting us)
   - ATT&CK gap analysis
   - Crown jewel protection
   - Incident-driven (missed detections)

---

**Next: [06_INCIDENT_RESPONSE.md](./06_INCIDENT_RESPONSE.md) →**
