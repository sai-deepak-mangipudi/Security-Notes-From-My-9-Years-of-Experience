# Security Reference Guide - Master Index
## Interview Prep for Threat Hunter, Detection Engineer, Incident Responder

---

## Quick Navigation

| # | Topic | Key Focus Areas |
|---|-------|-----------------|
| [01](./01_FUNDAMENTALS.md) | Network Fundamentals | OSI, TCP/IP, DNS, HTTP/S |
| [02](./02_CRYPTOGRAPHY.md) | Cryptography | Symmetric/Asymmetric, PKI, TLS |
| [03](./03_AUTH_IDENTITY.md) | Authentication & Identity | OAuth, OIDC, SAML, Kerberos |
| [04](./04_MITRE_ATTACK.md) | MITRE ATT&CK | All 14 Tactics, 200+ Techniques |
| [05](./05_DETECTION_ENGINEERING.md) | Detection Engineering | Sigma, YARA, Alert Design |
| [06](./06_INCIDENT_RESPONSE.md) | Incident Response | IR Frameworks, Forensics, Playbooks |
| [07](./07_THREAT_HUNTING.md) | Threat Hunting | Hypotheses, Queries, Methodologies |
| [08](./08_MALWARE_RANSOMWARE.md) | Malware & Ransomware | Analysis, Families, Response |
| [09](./09_WINDOWS_SECURITY.md) | Windows Security | AD, Kerberos, Events, LOLBins |
| [10](./10_LINUX_SECURITY.md) | Linux Security | PrivEsc, Persistence, Hardening |
| [11](./11_CLOUD_SECURITY.md) | Cloud Security | AWS/Azure/GCP, K8s, Serverless, Forensics |
| [12](./12_WEB_API_SECURITY.md) | Web & API Security | OWASP Top 10, Injection, XSS |
| [13](./13_AI_ML_SECURITY.md) | AI/ML Security | LLM Attacks, Adversarial ML |
| [14](./14_TOOLS_REFERENCE.md) | Tools Reference | EDR, SIEM, Forensics, Pentest |
| [15](./15_INTERVIEW_QUESTIONS.md) | Interview Questions | Technical, Scenario, Behavioral |
| [16](./16_PYTHON_AUTOMATION.md) | Python Automation | Parsing, APIs, Forensics Scripts |

---

## Role-Specific Focus Areas

### Threat Hunter
**Primary:** 04, 07, 09, 10, 11
**Secondary:** 05, 06, 08
```
Core Skills:
├── Hypothesis development and testing
├── Advanced query writing (Splunk, KQL, Sigma)
├── ATT&CK technique deep knowledge
├── Network and endpoint telemetry analysis
├── Behavioral pattern recognition
└── Threat intelligence application
```

### Detection & Response Engineer
**Primary:** 04, 05, 06, 09, 10
**Secondary:** 07, 08, 11
```
Core Skills:
├── Detection rule development (Sigma, YARA)
├── Alert tuning and false positive reduction
├── SIEM administration and query optimization
├── Log source management
├── ATT&CK coverage mapping
├── Purple team collaboration
└── Metrics and reporting
```

### Incident Responder
**Primary:** 06, 08, 09, 10, 11
**Secondary:** 04, 05, 07
```
Core Skills:
├── Forensics (memory, disk, network)
├── Evidence handling and chain of custody
├── Containment and eradication
├── Root cause analysis
├── Incident documentation
├── Playbook development
└── Crisis communication
```

---

## Study Plan

### Week 1: Foundations
```
Day 1-2: Network Fundamentals (01) + Cryptography (02)
Day 3-4: Authentication & Identity (03)
Day 5-7: MITRE ATT&CK Framework (04) - Critical section
```

### Week 2: Detection & Response
```
Day 1-2: Detection Engineering (05)
Day 3-4: Incident Response (06)
Day 5-7: Threat Hunting (07)
```

### Week 3: Platforms & Malware
```
Day 1-2: Windows Security (09)
Day 3-4: Linux Security (10)
Day 5-7: Malware & Ransomware (08)
```

### Week 4: Cloud & Advanced Topics
```
Day 1-3: Cloud Security + Forensics (11)
Day 4-5: Web/API Security (12) + AI/ML Security (13)
Day 6-7: Tools Reference (14) + Interview Questions (15)
```

---

## Critical Events Quick Reference

### Windows Security Events
```
Authentication:
├── 4624 - Successful logon
├── 4625 - Failed logon
├── 4648 - Explicit credential use
├── 4672 - Admin logon (special privileges)
├── 4768 - TGT requested (Kerberos)
├── 4769 - TGS requested
└── 4776 - NTLM credential validation

Persistence & Execution:
├── 4688 - Process creation
├── 4697 - Service installed
├── 4698 - Scheduled task created
├── 7045 - Service installed (System log)
└── 1102 - Audit log cleared

Sysmon (Critical):
├── 1  - Process Create
├── 3  - Network Connection
├── 7  - Image Loaded (DLL)
├── 8  - CreateRemoteThread
├── 10 - ProcessAccess (LSASS)
├── 11 - FileCreate
├── 13 - Registry Value Set
└── 22 - DNS Query
```

### ATT&CK Priority Techniques
```
Initial Access:
├── T1566 - Phishing
├── T1190 - Exploit Public-Facing App
└── T1078 - Valid Accounts

Execution:
├── T1059.001 - PowerShell
├── T1047 - WMI
└── T1053.005 - Scheduled Task

Persistence:
├── T1547.001 - Registry Run Keys
├── T1543.003 - Windows Service
└── T1505.003 - Web Shell

Credential Access:
├── T1003.001 - LSASS Memory
├── T1003.006 - DCSync
├── T1558.003 - Kerberoasting
└── T1555 - Credentials from Password Stores

Defense Evasion:
├── T1055 - Process Injection
├── T1070.001 - Clear Event Logs
└── T1562.001 - Disable Security Tools

Lateral Movement:
├── T1021.001 - RDP
├── T1021.002 - SMB/Windows Admin Shares
└── T1021.006 - WinRM

Impact:
├── T1486 - Data Encrypted (Ransomware)
└── T1490 - Inhibit System Recovery
```

---

## Key Metrics

### Detection Engineering
```
├── ATT&CK Coverage: % techniques with detections
├── False Positive Rate: <5% for critical alerts
├── MTTD (Mean Time to Detect): <15 min critical
├── Detection Rule Health: >99% uptime
└── Alert Aging: % unhandled >24 hours
```

### Incident Response
```
├── MTTD: Compromise to Detection
├── MTTC: Detection to Containment
├── MTTR: Detection to Recovery
├── Dwell Time: Industry avg ~10 days
└── Incidents per Month by Category
```

### Threat Hunting
```
├── Hunts Completed per Month: 4+
├── Detections Created from Hunts: 50%+
├── Incidents Discovered: Track quarterly
├── Hunt Coverage: % of critical TTPs
└── Hypothesis Validation Rate
```

---

## Interview Preparation Checklist

### Technical Deep-Dive Questions
- [ ] Explain Kerberos authentication flow and attacks
- [ ] Walk through investigating LSASS access
- [ ] Design a detection for lateral movement
- [ ] Explain your approach to reducing false positives
- [ ] How do you prioritize threat hunting hypotheses?
- [ ] Walk through memory forensics workflow

### Scenario-Based Questions
- [ ] Ransomware incident response (3 AM page)
- [ ] Domain admin compromise
- [ ] Suspected nation-state intrusion
- [ ] Insider threat investigation
- [ ] Cloud credential compromise

### Behavioral Questions (STAR Method)
- [ ] Most complex incident you've handled
- [ ] Time you improved a process/detection
- [ ] Conflict resolution with stakeholders
- [ ] Mentoring/leadership example
- [ ] Failed project and lessons learned

### Questions to Ask Them
- [ ] Team structure and size
- [ ] Tech stack (SIEM, EDR, SOAR)
- [ ] Threat hunting cadence
- [ ] Detection engineering process
- [ ] Career growth opportunities

---

## Salary Reference (2026 US Market)

```
Detection Engineer:
├── Mid-Level: $140K - $180K
├── Senior: $180K - $240K
└── Staff/Principal: $220K - $300K

Threat Hunter:
├── Mid-Level: $150K - $190K
├── Senior: $180K - $260K
└── Staff/Principal: $240K - $320K

Incident Responder:
├── Mid-Level: $130K - $170K
├── Senior: $170K - $230K
└── Lead/Manager: $200K - $280K

Multipliers:
├── FAANG/Big Tech: +20-40%
├── Remote (HCOL company, LCOL location): +effective 30%
├── Specialized skills (cloud, ML): +10-20%
└── Management track: +15-25%
```

---

## Quick Study Cards

### Authentication Protocols
```
Kerberos: Ticket-based, port 88, uses KRBTGT
NTLM: Challenge-response, legacy, Pass-the-Hash vulnerable
OAuth 2.0: Authorization framework, access tokens
OIDC: Authentication layer on OAuth, ID tokens
SAML: XML-based SSO, enterprise federated auth
```

### Encryption Quick Facts
```
Symmetric: AES (128/256), same key encrypt/decrypt
Asymmetric: RSA (2048+), public/private key pairs
Hashing: SHA-256, one-way, integrity verification
Password Storage: bcrypt, scrypt, Argon2 (with salt)
TLS 1.3: AEAD only, removed RSA key exchange
```

### Cloud Security Essentials
```
AWS: IAM policies, CloudTrail, GuardDuty, Security Hub
Azure: Entra ID, Activity Logs, Defender for Cloud
GCP: IAM, Audit Logs, Security Command Center
K8s: RBAC, Network Policies, Pod Security Standards
```

---

**Start with [01_FUNDAMENTALS.md](./01_FUNDAMENTALS.md) or jump to your priority section.**

*Last Updated: February 2026*
