# 06 - Incident Response
## IR Frameworks, Forensics, Memory Analysis, Evidence Handling, Playbooks

---

## IR Frameworks Comparison

```
NIST SP 800-61 (4 Phases):
┌──────────────┬───────────────┬──────────────┬───────────────────┐
│ Preparation  │ Detection &   │ Containment, │ Post-Incident     │
│              │ Analysis      │ Eradication, │ Activity          │
│              │               │ Recovery     │                   │
└──────────────┴───────────────┴──────────────┴───────────────────┘

SANS PICERL (6 Phases):
┌────────────┬────────────┬─────────────┬────────────┬──────────┬─────────┐
│ Preparation│ Identifica-│ Containment │ Eradication│ Recovery │ Lessons │
│            │ tion       │             │            │          │ Learned │
└────────────┴────────────┴─────────────┴────────────┴──────────┴─────────┘

MITRE D3FEND (Defensive Techniques):
├── Detect: Network Analysis, Platform Monitoring, Process Analysis
├── Deny: Credential Hardening, Application Hardening, Message Hardening
├── Disrupt: Execution Isolation, Network Isolation
├── Degrade: Decoy Environment
├── Deceive: Decoy Object
└── Evict: Credential Eviction, Process Eviction, File Eviction

CISA INCIDENT HANDLING:
Preparation → Detection → Analysis → Containment → Eradication →
Recovery → Post-Incident Activity → Coordination (throughout)
```

---

## Incident Classification & Severity

```
INCIDENT CATEGORIES:
┌─────────────────────────────────────────────────────────────────────────────┐
│ Category                │ Examples                                          │
├─────────────────────────┼───────────────────────────────────────────────────┤
│ Malware                 │ Ransomware, trojan, worm, cryptominer             │
│ Unauthorized Access     │ Compromised credentials, privilege escalation     │
│ Denial of Service       │ DDoS, resource exhaustion                         │
│ Insider Threat          │ Data theft, sabotage, policy violations           │
│ Social Engineering      │ Phishing, vishing, business email compromise      │
│ Data Breach             │ PII exposure, IP theft, regulatory data           │
│ Web Application         │ SQLi, XSS, defacement                             │
│ APT/Nation-State        │ Persistent targeted intrusion                     │
│ Supply Chain            │ Compromised vendor, malicious update              │
│ Physical Security       │ Theft, unauthorized physical access               │
└─────────────────────────┴───────────────────────────────────────────────────┘

SEVERITY MATRIX:
┌──────────┬─────────────────────────────────────────────────────────────────┐
│ SEV-1    │ CRITICAL: Active breach with ongoing damage                     │
│ (P1)     │ Examples: Active ransomware, data exfiltration in progress,    │
│          │ domain admin compromise, critical system unavailable            │
│          │ Response: 15 min, Exec bridge, 24/7 staffing, all-hands        │
│          │ Actions: Immediate containment, preserve evidence               │
├──────────┼─────────────────────────────────────────────────────────────────┤
│ SEV-2    │ HIGH: Confirmed compromise requiring urgent response            │
│ (P2)     │ Examples: Credential theft confirmed, lateral movement,         │
│          │ malware on multiple systems, sensitive data access              │
│          │ Response: 1 hour, Senior analyst + team lead                    │
│          │ Actions: Scope assessment, targeted containment                 │
├──────────┼─────────────────────────────────────────────────────────────────┤
│ SEV-3    │ MEDIUM: Suspicious activity requiring investigation             │
│ (P3)     │ Examples: Potential malware, policy violation, single system   │
│          │ compromise, phishing campaign                                   │
│          │ Response: 4 hours, Analyst handles                              │
│          │ Actions: Investigation, monitoring                              │
├──────────┼─────────────────────────────────────────────────────────────────┤
│ SEV-4    │ LOW: Minor security event, informational                        │
│ (P4)     │ Examples: Reconnaissance, minor policy violation, false        │
│          │ positive investigation                                          │
│          │ Response: 24 hours, Queue-based                                 │
│          │ Actions: Log, review, close                                     │
└──────────┴─────────────────────────────────────────────────────────────────┘

ESCALATION CRITERIA:
├── Scope expansion (more systems/users affected)
├── Sensitive data involved (PII, PHI, financial)
├── Critical systems affected
├── Evidence of advanced adversary
├── Containment failing
├── Legal/regulatory implications
├── Media attention likely
└── Executive interest
```

---

## Evidence Collection - Order of Volatility

```
MOST VOLATILE → LEAST VOLATILE:
┌─────┬────────────────────────────┬───────────────────────────────────┐
│ 1   │ CPU Registers, Cache       │ Nanoseconds (rarely collectible)  │
├─────┼────────────────────────────┼───────────────────────────────────┤
│ 2   │ Memory (RAM)               │ Power-dependent, collect FIRST    │
│     │                            │ Contains: processes, network      │
│     │                            │ connections, encryption keys,     │
│     │                            │ malware in memory-only            │
├─────┼────────────────────────────┼───────────────────────────────────┤
│ 3   │ Network State              │ Connections, routing tables, ARP  │
│     │                            │ cache, DNS cache                  │
├─────┼────────────────────────────┼───────────────────────────────────┤
│ 4   │ Running Processes          │ Process list, handles, threads,   │
│     │                            │ loaded DLLs, open files           │
├─────┼────────────────────────────┼───────────────────────────────────┤
│ 5   │ Disk (Non-volatile)        │ Files, registry, logs, deleted    │
│     │                            │ files, slack space                │
├─────┼────────────────────────────┼───────────────────────────────────┤
│ 6   │ Remote Logging             │ SIEM, syslog servers, CloudTrail  │
├─────┼────────────────────────────┼───────────────────────────────────┤
│ 7   │ Physical Evidence          │ Hardware, network taps, photos    │
├─────┼────────────────────────────┼───────────────────────────────────┤
│ 8   │ Archival Data              │ Backups, offline storage          │
└─────┴────────────────────────────┴───────────────────────────────────┘

WINDOWS EVIDENCE COLLECTION:

# Memory acquisition
winpmem_mini_x64.exe memory.raw
# OR using Magnet RAM Capture, Belkasoft RAM Capturer, DumpIt

# Network state
netstat -ano > netstat.txt
ipconfig /all > ipconfig.txt
arp -a > arp.txt
route print > routes.txt
Get-NetTCPConnection | Export-Csv connections.csv
Get-DnsClientCache | Export-Csv dns_cache.csv

# Process information
tasklist /v > processes.txt
wmic process get processid,parentprocessid,commandline > process_cmdline.txt
Get-Process | Select-Object * | Export-Csv processes_full.csv

# Service information
sc query > services.txt
Get-Service | Export-Csv services.csv

# Scheduled tasks
schtasks /query /fo CSV /v > scheduled_tasks.csv

# User sessions
query user > user_sessions.txt
net session > net_sessions.txt

# Registry persistence
reg export HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run run_hklm.reg
reg export HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run run_hkcu.reg

# Event logs (export critical logs)
wevtutil epl Security security.evtx
wevtutil epl System system.evtx
wevtutil epl Application application.evtx
wevtutil epl "Microsoft-Windows-PowerShell/Operational" powershell.evtx
wevtutil epl "Microsoft-Windows-Sysmon/Operational" sysmon.evtx

LINUX EVIDENCE COLLECTION:

# Memory acquisition
sudo insmod /path/to/lime.ko "path=/tmp/memory.lime format=lime"
# OR using AVML (Amazon Volatility Memory Lime)

# Network state
netstat -tulpn > netstat.txt
ss -tulpn > ss.txt
ip addr > ip_addr.txt
ip route > ip_route.txt
arp -a > arp.txt
cat /etc/hosts > hosts.txt
cat /etc/resolv.conf > resolv.txt

# Process information
ps auxf > processes.txt
pstree -p > process_tree.txt
ls -la /proc/*/exe 2>/dev/null > proc_exe.txt
ls -la /proc/*/fd 2>/dev/null > proc_fd.txt

# User information
w > logged_in_users.txt
last > last_logins.txt
lastb > failed_logins.txt
cat /etc/passwd > passwd.txt
cat /etc/shadow > shadow.txt (if accessible)

# Cron jobs
cat /etc/crontab > crontab.txt
ls -la /etc/cron.d/ > cron_d.txt
for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null; done > user_crontabs.txt

# System logs
cp -r /var/log/ ./evidence_logs/

# Persistence locations
ls -la /etc/init.d/ > init_d.txt
systemctl list-unit-files > systemd_units.txt
cat /etc/rc.local > rc_local.txt (if exists)

# File system timestamps
find / -mtime -7 -type f 2>/dev/null > files_modified_7d.txt
find / -ctime -7 -type f 2>/dev/null > files_changed_7d.txt
```

---

## Memory Forensics (Volatility 3)

```bash
# Identify profile (automatic in Vol3)
vol -f memory.raw windows.info

# PROCESS ANALYSIS
vol -f memory.raw windows.pslist           # Running processes
vol -f memory.raw windows.pstree           # Process tree (hierarchy)
vol -f memory.raw windows.psscan           # Hidden/terminated processes
vol -f memory.raw windows.cmdline          # Command lines
vol -f memory.raw windows.handles          # Open handles
vol -f memory.raw windows.getsids          # Process SIDs

# NETWORK ANALYSIS
vol -f memory.raw windows.netstat          # Active connections
vol -f memory.raw windows.netscan          # Comprehensive network artifacts

# CODE INJECTION DETECTION
vol -f memory.raw windows.malfind          # Injected code, hollowing
vol -f memory.raw windows.hollowfind       # Process hollowing
vol -f memory.raw windows.ldrmodules       # Hidden/unlinked DLLs
vol -f memory.raw windows.vadinfo          # VAD tree analysis

# DLL ANALYSIS
vol -f memory.raw windows.dlllist          # Loaded DLLs per process
vol -f memory.raw windows.modules          # Loaded kernel modules

# CREDENTIAL EXTRACTION
vol -f memory.raw windows.hashdump         # SAM hashes
vol -f memory.raw windows.lsadump          # LSA secrets
vol -f memory.raw windows.cachedump        # Domain cached creds

# REGISTRY ANALYSIS
vol -f memory.raw windows.registry.hivelist    # Registry hives
vol -f memory.raw windows.registry.printkey    # Print specific key
vol -f memory.raw windows.registry.userassist  # UserAssist data

# FILE EXTRACTION
vol -f memory.raw windows.filescan         # Find files in memory
vol -f memory.raw windows.dumpfiles --pid 1234  # Dump files for PID
vol -f memory.raw windows.memmap --pid 1234 --dump  # Dump process memory

# KERNEL ANALYSIS
vol -f memory.raw windows.ssdt             # System Service Descriptor Table
vol -f memory.raw windows.callbacks        # Kernel callbacks
vol -f memory.raw windows.driverscan       # Loaded drivers

# TIMELINE
vol -f memory.raw windows.mftscan          # MFT entries
vol -f memory.raw timeliner                # Create timeline

KEY MEMORY ARTIFACTS:

LSASS.EXE:
├── Contains: Plaintext passwords, NTLM hashes, Kerberos tickets
├── Attack: Mimikatz, procdump, comsvcs.dll
├── Red flags: Unusual access patterns (Sysmon Event 10)
├── Expected: Low PID, parent is wininit.exe
└── Analyze with: vol windows.lsadump, mimikatz on memory dump

SVCHOST.EXE:
├── Expected: Multiple instances, all from C:\Windows\System32
├── Parent: services.exe
├── Red flags: Wrong path, wrong parent, network to external IPs
└── Each should have -k parameter with service group

CSRSS.EXE:
├── Expected: Session 0 and Session 1 instances only
├── Parent: smss.exe (but parent terminates, so will show none)
├── Red flags: More than 2 instances, has parent, wrong path
└── Critical system process

SMSS.EXE:
├── Expected: One instance, Session 0
├── Parent: System (PID 4)
├── Red flags: Multiple instances, wrong parent, wrong path
└── First user-mode process

EXPLORER.EXE:
├── Expected: One per logged-in user session
├── Parent: userinit.exe (but terminates, so shows none)
├── Red flags: Multiple per session, unusual child processes
└── Common injection target

WINLOGON.EXE:
├── Expected: One per session
├── Parent: smss.exe
├── Red flags: Multiple per session, suspicious modules
└── Handles authentication

SERVICES.EXE:
├── Expected: One instance, Session 0
├── Parent: wininit.exe
├── Red flags: Multiple instances, wrong parent
└── Parent of all service processes
```

---

## Disk Forensics

### Windows Artifacts

```
REGISTRY HIVES:
C:\Windows\System32\config\
├── SAM          - Local user accounts, hashes
├── SECURITY     - Security policies, LSA secrets
├── SYSTEM       - System config, services, mounted devices
├── SOFTWARE     - Installed software, Run keys, uninstall
├── DEFAULT      - Default user profile template
├── DRIVERS      - Device drivers
└── BCD-Template - Boot configuration data

USER HIVES (per user):
C:\Users\<user>\NTUSER.DAT        - User preferences, recent files
C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat - COM class info

PERSISTENCE LOCATIONS:
├── HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
├── HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
├── HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices
├── HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
├── HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
├── HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
├── HKLM\SYSTEM\CurrentControlSet\Services
├── HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon (Shell, Userinit)
├── HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
├── HKLM\SYSTEM\CurrentControlSet\Control\Session Manager (BootExecute)
├── C:\Windows\System32\Tasks\
├── C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
└── C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup

EVIDENCE OF EXECUTION:
├── Prefetch: C:\Windows\Prefetch\*.pf
│   └── Contains: Execution count, timestamps, loaded files
│   └── Tool: PECmd.exe (Eric Zimmerman)
│
├── AmCache: C:\Windows\AppCompat\Programs\Amcache.hve
│   └── Contains: File path, hash, size, publisher, compile time
│   └── Tool: AmcacheParser.exe
│
├── ShimCache: SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
│   └── Contains: File path, size, last modified (not executed time)
│   └── Tool: ShimCacheParser.py, AppCompatCacheParser.exe
│
├── SRUM: C:\Windows\System32\sru\SRUDB.dat
│   └── Contains: App usage, network usage, energy usage
│   └── Tool: srum-dump, SrumECmd.exe
│
├── BAM/DAM: SYSTEM\CurrentControlSet\Services\bam\State\UserSettings
│   └── Contains: Execution path, timestamp (Windows 10+)
│   └── Tool: Registry Explorer
│
├── UserAssist: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
│   └── Contains: GUI program execution, ROT13 encoded
│   └── Tool: Registry Explorer, UserAssist.exe
│
└── RecentApps: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps
    └── Contains: Recent application launches

FILE KNOWLEDGE:
├── MRU Lists: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\*MRU*
├── LNK Files: C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\*.lnk
│   └── Contains: Target path, MAC times, volume info, network path
│   └── Tool: LECmd.exe
├── Jump Lists: C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations
│   └── Contains: Recent files per application
│   └── Tool: JLECmd.exe
├── Shellbags: NTUSER.DAT + UsrClass.dat
│   └── Contains: Folder access history, even deleted folders
│   └── Tool: ShellBagsExplorer.exe
└── Open/Save MRU: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32

USB/EXTERNAL DEVICE FORENSICS:
├── SYSTEM\CurrentControlSet\Enum\USB
├── SYSTEM\CurrentControlSet\Enum\USBSTOR
├── SYSTEM\CurrentControlSet\Enum\SCSI
├── SYSTEM\MountedDevices
├── SOFTWARE\Microsoft\Windows Portable Devices\Devices
├── SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt
├── NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
└── setupapi.dev.log (C:\Windows\INF\setupapi.dev.log)

BROWSER FORENSICS:
Chrome:
├── History: %LocalAppData%\Google\Chrome\User Data\Default\History (SQLite)
├── Cookies: %LocalAppData%\Google\Chrome\User Data\Default\Cookies
├── Cache: %LocalAppData%\Google\Chrome\User Data\Default\Cache
├── Downloads: History database
└── Login Data: %LocalAppData%\Google\Chrome\User Data\Default\Login Data

Firefox:
├── History: %AppData%\Mozilla\Firefox\Profiles\<profile>\places.sqlite
├── Cookies: cookies.sqlite
├── Cache: cache2/entries
└── Logins: logins.json + key4.db

Edge (Chromium):
├── Same structure as Chrome
└── Location: %LocalAppData%\Microsoft\Edge\User Data\Default\

NTFS ARTIFACTS:
├── $MFT: Master File Table - file metadata for all files
├── $UsnJrnl: Change journal - file operations log
├── $LogFile: Transaction log
├── $I30 (INDEX_ALLOCATION): Directory indexes
└── Alternate Data Streams: Hidden data streams
```

### Timeline Analysis

```bash
# PLASO/LOG2TIMELINE:
# Create timeline from disk image
log2timeline.py --storage-file timeline.plaso /path/to/image.E01

# With specific parsers
log2timeline.py --storage-file timeline.plaso --parsers "win7,win7_slow" /path/to/image.E01

# Process timeline
psort.py -o l2tcsv timeline.plaso -w timeline.csv

# Filter by date range
psort.py -o l2tcsv timeline.plaso "date > '2026-02-01' AND date < '2026-02-24'" -w filtered.csv

# ERIC ZIMMERMAN TOOLS TIMELINE:
# MFTECmd - Parse MFT
MFTECmd.exe -f '$MFT' --csv C:\output --csvf mft_output.csv

# PECmd - Parse Prefetch
PECmd.exe -d C:\Windows\Prefetch --csv C:\output --csvf prefetch.csv

# LECmd - Parse LNK files
LECmd.exe -d "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent" --csv C:\output

# JLECmd - Parse Jump Lists
JLECmd.exe -d "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv C:\output

# ShellBagsExplorer - GUI for shellbags
# Registry Explorer - GUI for registry analysis

# Timeline Explorer - View CSVs with filtering and sorting

KEY TIMELINE PIVOTS:
1. Start from known-bad indicator (IOC, alert)
2. Identify first occurrence in timeline
3. Work backward: How did it get there?
   └── Process creation, file download, email attachment
4. Work forward: What happened after?
   └── Persistence, lateral movement, data access
5. Correlate with network logs, SIEM
6. Build attack narrative with timestamps
```

---

## Containment Strategies

```
NETWORK CONTAINMENT:
┌─────────────────────────────────────┬─────────────────────────────────────┐
│ Method                              │ Use Case                            │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ EDR Isolation                       │ Preferred - maintains management    │
│                                     │ access, blocks network traffic      │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ VLAN Quarantine                     │ Move to isolated network segment    │
│                                     │ Allows controlled investigation     │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Firewall Block (Surgical)           │ Block specific IPs/ports            │
│                                     │ Targeted containment                │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Switch Port Disable                 │ Aggressive - complete network       │
│                                     │ isolation, loses remote access      │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Physical Disconnect                 │ Last resort - pull cable            │
│                                     │ Use when other methods fail         │
└─────────────────────────────────────┴─────────────────────────────────────┘

ACCOUNT CONTAINMENT:
├── Disable account (don't delete - preserve evidence)
├── Force password reset (after disabling to prevent race)
├── Revoke active sessions/tokens
├── Revoke MFA devices (if compromised)
├── Revoke VPN certificates
├── Block at identity provider (Azure AD, Okta)
├── Add to blocked users list
└── Monitor for re-compromise attempts

SCOPE-BASED CONTAINMENT:
┌─────────────────────────────────────┬─────────────────────────────────────┐
│ Scope                               │ Actions                             │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Single Host                         │ EDR isolate, collect evidence       │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Multiple Hosts                      │ Segment network, block lateral      │
│                                     │ movement paths (SMB, RDP, WMI)      │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Domain Admin Compromise             │ Assume all domain creds compromised │
│                                     │ Block DC access, prepare KRBTGT     │
│                                     │ reset, segment critical systems     │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Cloud Account Compromise            │ Revoke sessions, rotate keys        │
│                                     │ Review IAM, quarantine resources    │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Ransomware Active                   │ Aggressive isolation, stop shares   │
│                                     │ Block C2, preserve clean systems    │
└─────────────────────────────────────┴─────────────────────────────────────┘

CONTAINMENT DECISION TREE:
                    ┌─────────────────────┐
                    │ Incident Detected   │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Is data exfiltration│
                    │ or destruction      │───YES───► Immediate isolation
                    │ in progress?        │
                    └──────────┬──────────┘
                               │ NO
                    ┌──────────▼──────────┐
                    │ Is lateral movement │
                    │ detected?           │───YES───► Segment network
                    └──────────┬──────────┘           Block SMB/RDP/WMI
                               │ NO
                    ┌──────────▼──────────┐
                    │ Are credentials     │
                    │ compromised?        │───YES───► Reset credentials
                    └──────────┬──────────┘           Revoke sessions
                               │ NO
                    ┌──────────▼──────────┐
                    │ Single host         │───YES───► EDR isolation
                    │ affected?           │           Collect evidence
                    └──────────┬──────────┘
                               │ NO
                    ┌──────────▼──────────┐
                    │ Staged containment  │
                    │ Prioritize by risk  │
                    └─────────────────────┘
```

---

## Eradication & Recovery

### Eradication Checklist

```
PRE-ERADICATION REQUIREMENTS:
□ Incident fully scoped (all affected systems identified)
□ All persistence mechanisms identified
□ Root cause determined
□ Initial access vector closed
□ All IOCs extracted and documented
□ Clean backup verified (or rebuild plan ready)
□ Eradication plan reviewed and approved

ERADICATION ACTIONS:
□ Remove malware/attacker tools
□ Delete persistence mechanisms
│   ├── Registry run keys
│   ├── Scheduled tasks
│   ├── Services
│   ├── WMI subscriptions
│   ├── Startup items
│   └── Cron jobs (Linux)
□ Remove unauthorized user accounts
□ Remove unauthorized SSH keys
□ Revoke compromised certificates
□ Reset compromised credentials
│   ├── User passwords
│   ├── Service account passwords
│   ├── Local admin passwords
│   └── KRBTGT (if domain compromise)
□ Patch exploited vulnerabilities
□ Update firewall rules
□ Block IOCs at perimeter
│   ├── C2 domains
│   ├── C2 IP addresses
│   ├── File hashes
│   └── Email indicators
□ Update AV/EDR signatures
□ Remove unauthorized software
□ Correct security misconfigurations

VERIFICATION:
□ Re-scan with updated signatures
□ Threat hunt for variants/related activity
□ Verify logging captures new activity
□ Test detection rules
□ Confirm no active C2 communication
□ Monitor for re-compromise indicators

KRBTGT RESET PROCEDURE (Domain Compromise):
1. First KRBTGT reset
   └── Invalidates all current Kerberos tickets
2. Wait 10+ hours (TGT lifetime)
   └── Allows legitimate tickets to renew
3. Second KRBTGT reset
   └── Invalidates any golden tickets created
4. Monitor for:
   ├── Authentication failures (expected temporarily)
   ├── Service account issues
   └── Application connectivity problems
5. Document and communicate timeline
```

### Recovery Procedures

```
RECOVERY PRIORITIES:
┌─────┬────────────────────────────────────────────────────────────────────┐
│  1  │ Security Infrastructure (logging, monitoring, alerting)           │
├─────┼────────────────────────────────────────────────────────────────────┤
│  2  │ Identity Infrastructure (Active Directory, IdP)                   │
├─────┼────────────────────────────────────────────────────────────────────┤
│  3  │ Business-Critical Systems (production, revenue-generating)        │
├─────┼────────────────────────────────────────────────────────────────────┤
│  4  │ Core Services (DNS, DHCP, email)                                 │
├─────┼────────────────────────────────────────────────────────────────────┤
│  5  │ User Workstations                                                 │
├─────┼────────────────────────────────────────────────────────────────────┤
│  6  │ Non-Critical Systems                                              │
└─────┴────────────────────────────────────────────────────────────────────┘

RECOVERY METHODS:
┌─────────────────────────────────────┬─────────────────────────────────────┐
│ Method                              │ When to Use                         │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Clean and Restore                   │ Minor compromise, known-clean       │
│                                     │ backup available, quick recovery    │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Rebuild from Scratch                │ Deep compromise, no trusted backup  │
│                                     │ Rootkit suspected, full wipe needed │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Staged Recovery                     │ Large environment, phased approach  │
│                                     │ Recovery during business continuity │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Parallel Build                      │ Critical systems, can't have        │
│                                     │ downtime, build new alongside       │
└─────────────────────────────────────┴─────────────────────────────────────┘

CREDENTIAL RESET SCOPE:
┌─────────────────────────────────────┬─────────────────────────────────────┐
│ Compromise Level                    │ Reset Scope                         │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Single User Account                 │ That user account                   │
│                                     │ Any shared passwords                │
│                                     │ API keys/tokens owned by user       │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Admin Account                       │ All admin accounts                  │
│                                     │ Service accounts on affected systems│
│                                     │ Local admin passwords (LAPS reset)  │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Domain Admin                        │ KRBTGT (twice with delay)           │
│                                     │ All privileged accounts             │
│                                     │ All service accounts                │
│                                     │ Azure AD Connect (if used)          │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Full Domain Compromise              │ Everything above                    │
│ (Golden Ticket confirmed)           │ Consider domain rebuild             │
│                                     │ All trust relationships             │
└─────────────────────────────────────┴─────────────────────────────────────┘

RECOVERY VALIDATION:
□ System restored and functional
□ Security controls re-enabled
□ Logging and monitoring active
□ Baseline established for anomaly detection
□ Enhanced monitoring in place (30+ days)
□ Users notified and briefed
□ Documentation updated
```

---

## Incident Playbooks

### Ransomware Playbook

```
SEVERITY: CRITICAL (SEV-1)
RESPONSE SLA: 15 minutes

PHASE 1: IMMEDIATE RESPONSE (0-15 min)
□ Join/establish incident bridge
□ Confirm ransomware (note, extension, behavior)
□ Identify scope: How many systems affected?
□ Check: Is encryption still active?
□ Network isolate affected systems (EDR or manual)
□ Stop file shares to limit spread
□ Identify ransomware variant:
│   └── Ransom note filename
│   └── File extension
│   └── Email addresses in note
│   └── Check ID Ransomware (id-ransomware.malwarehunterteam.com)

PHASE 2: ASSESS & CONTAIN (15-60 min)
□ Check No More Ransom (nomoreransom.org) for decryptor
□ Identify patient zero (first encrypted files, timestamps)
□ Preserve evidence (don't reboot - volatile memory)
□ Capture memory if possible on key systems
□ Check backup status:
│   └── When was last backup?
│   └── Is backup clean (not encrypted)?
│   └── Test restore capability
□ Hunt for staging indicators on clean systems:
│   └── Shadow copy deletion commands
│   └── Backup deletion
│   └── Security tool disabling
□ Check for data exfiltration (double extortion):
│   └── Large outbound transfers
│   └── Cloud storage uploads
│   └── Unusual DNS traffic
□ Block C2 domains/IPs at firewall
□ Disable compromised accounts
□ Block lateral movement (restrict SMB, RDP)

PHASE 3: INVESTIGATION (1-4 hours)
□ Identify initial access vector:
│   └── Phishing email
│   └── Exposed RDP
│   └── VPN vulnerability
│   └── Supply chain
□ Map lateral movement path
□ Identify all compromised credentials
□ Determine dwell time (how long was attacker in)
□ Document all IOCs
□ Assess business impact

PHASE 4: ERADICATION & RECOVERY (4+ hours)
□ Confirm no active attacker presence
□ Remove all persistence mechanisms
□ Restore from clean backups
│   └── Verify backup integrity before restore
│   └── Scan restored systems
□ If no backup: Negotiate (with legal approval) or rebuild
□ Reset all compromised credentials
□ Patch vulnerability that allowed initial access
□ Enhanced monitoring for 30+ days

COMMUNICATION:
□ Notify CISO/Executive leadership (within 1 hour)
□ Notify legal counsel
□ Consider cyber insurance carrier notification
□ Prepare internal communications
□ Consider law enforcement notification (FBI)
□ Do NOT contact attackers without executive/legal approval

DO NOT:
× Pay ransom immediately (negotiate timeline, legal review)
× Reboot encrypted systems (lose volatile evidence)
× Delete ransom notes (needed for identification)
× Use encrypted systems for forensics
× Communicate recovery plans over compromised network
× Rush recovery without confirming clean state
```

### Compromised Credentials Playbook

```
SEVERITY: HIGH (SEV-2) to CRITICAL (SEV-1 if privileged)
RESPONSE SLA: 1 hour

IDENTIFICATION:
□ Source of alert (SIEM, identity provider, threat intel)
□ Which credential is compromised (user, service account, API key)
□ How was it compromised (phishing, breach database, logs)
□ When was it compromised (time bound the exposure)

IMMEDIATE ACTIONS:
□ Disable the account (don't reset password yet)
□ Kill all active sessions:
│   └── Azure AD: Revoke-AzureADUserAllRefreshToken
│   └── AWS: Invalidate active sessions via IAM
│   └── On-prem: klist purge on all logged-in systems
□ Revoke API keys/tokens
□ Block known attacker IPs at firewall

SCOPE ASSESSMENT:
□ Where did this credential authenticate in the last 30 days?
│   └── AD logs (4624, 4625)
│   └── VPN logs
│   └── Cloud provider logs (CloudTrail, Azure Sign-in)
│   └── Application logs
□ Was there any suspicious activity from this account?
│   └── Unusual hours
│   └── Unusual locations
│   └── Unusual systems accessed
│   └── Data access patterns
□ What permissions did this account have?
□ What data could have been accessed?

CONTAINMENT:
□ If admin account: Assume elevated compromise
□ Check for persistence created by attacker
□ Check for new accounts created
□ Check for permission changes
□ Check for data exfiltration

ERADICATION:
□ Reset password (strong, unique)
□ Re-enroll MFA
□ Review and revoke unnecessary permissions
□ Remove any attacker persistence
□ Update detection rules

RECOVERY:
□ Re-enable account after verification
□ Brief user on what happened
□ Monitor account closely for 30 days
□ Consider additional authentication requirements
```

### Domain Admin Compromise Playbook

```
SEVERITY: CRITICAL (SEV-1)
RESPONSE SLA: 15 minutes (immediate)

ASSUME COMPLETE COMPROMISE

IMMEDIATE ACTIONS (0-30 min):
□ Do NOT tip off attacker (covert response if possible)
□ Disable compromised DA account
□ Isolate known compromised systems
□ Block lateral movement:
│   └── Restrict SMB/RDP between segments
│   └── Consider isolating DCs
□ Engage senior leadership and legal

SCOPE ASSESSMENT:
□ How was DA obtained?
│   └── Kerberoasting
│   └── DCSync
│   └── LSASS dumping
│   └── Mimikatz on DC
│   └── Golden ticket
□ Check DA authentication history (30 days):
│   └── 4624 on all DCs
│   └── 4648 (explicit credentials)
│   └── 4672 (special privileges assigned)
□ Check for DCSync activity:
│   └── Event 4662 with replication GUIDs
│   └── Non-DC requesting replication
□ Check for other persistence:
│   └── New DA accounts
│   └── AdminSDHolder modifications
│   └── GPO modifications
│   └── Scheduled tasks on DCs
│   └── New services on DCs

ERADICATION DECISION:

IF KRBTGT COMPROMISED (Golden Ticket possible):
□ Plan KRBTGT double reset
□ First reset: Invalidate current tickets
□ Wait 10+ hours (TGT lifetime)
□ Second reset: Kill any golden tickets
□ Reset ALL privileged accounts
□ Reset ALL service accounts
□ Reset Azure AD Connect accounts
□ Consider domain rebuild for severe cases

IF KRBTGT NOT COMPROMISED:
□ Reset compromised DA account
□ Reset all DA accounts (precaution)
□ Reset local admin passwords (LAPS)
□ Check and clean any persistence

RECOVERY:
□ Staged recovery of critical systems
□ Enhanced monitoring on DCs
□ Deploy advanced credential protection:
│   └── Credential Guard
│   └── Protected Users group
│   └── Tiered admin model
□ 30+ day heightened monitoring
□ Conduct thorough post-incident review
```

---

## Chain of Custody

```
EVIDENCE HANDLING REQUIREMENTS:
┌─────────────────────────────────────────────────────────────────────────────┐
│ Field                  │ Description                                        │
├────────────────────────┼────────────────────────────────────────────────────┤
│ Evidence ID            │ Unique identifier for this evidence item          │
│ Description            │ Detailed description (make/model/serial)          │
│ Date/Time Collected    │ UTC timestamp of collection                       │
│ Location Collected     │ Physical/logical location                         │
│ Collected By           │ Name, title, organization                         │
│ Collection Method      │ Tool/procedure used                               │
│ Hash Values            │ MD5 + SHA256 of evidence                          │
│ Storage Location       │ Physical location of evidence                     │
│ Access Log             │ Who accessed, when, why                           │
│ Transfer Record        │ Each handoff documented                           │
│ Analysis Record        │ What analysis was performed                       │
└────────────────────────┴────────────────────────────────────────────────────┘

CHAIN OF CUSTODY FORM:

EVIDENCE CHAIN OF CUSTODY RECORD
═══════════════════════════════════════════════════════════════════════════════
Case Number: ____________  Evidence ID: ____________  Page ___ of ___

ITEM DESCRIPTION:
┌─────────────────────────────────────────────────────────────────────────────┐
│ Device Type:                                                                │
│ Make/Model:                                                                 │
│ Serial Number:                                                              │
│ Evidence Description:                                                       │
└─────────────────────────────────────────────────────────────────────────────┘

HASH VALUES:
MD5:     ___________________________________
SHA256:  ___________________________________

COLLECTION INFORMATION:
┌─────────────────────────────────────────────────────────────────────────────┐
│ Collected By:                              Date/Time (UTC):                 │
│ Location:                                                                   │
│ Collection Tool:                           Version:                         │
│ Witness:                                                                    │
│ Notes:                                                                      │
└─────────────────────────────────────────────────────────────────────────────┘

TRANSFER RECORD:
┌───────────────────────────────────────────────────────────────────────────┐
│ Released By    │ Received By    │ Date/Time  │ Purpose      │ Signature  │
├────────────────┼────────────────┼────────────┼──────────────┼────────────┤
│                │                │            │              │            │
├────────────────┼────────────────┼────────────┼──────────────┼────────────┤
│                │                │            │              │            │
└────────────────┴────────────────┴────────────┴──────────────┴────────────┘

BEST PRACTICES:
├── Use write blockers for disk imaging
├── Work on forensic copies, never originals
├── Document all tools with versions
├── Photograph physical evidence
├── Store in tamper-evident containers
├── Secure storage with access controls
├── Regular integrity verification (re-hash)
└── Legal review for preservation requirements
```

---

## Post-Incident Activities

```
LESSONS LEARNED MEETING:
├── Schedule within 2 weeks of incident closure
├── Include all participants (IR, IT, affected business units)
├── Blameless culture - focus on process improvement
├── Document outcomes and action items

TOPICS TO COVER:
1. Incident Timeline
   └── What happened, when, how long each phase

2. What Went Well
   └── Effective controls, quick response, good communication

3. What Could Be Improved
   └── Gaps, delays, miscommunication

4. Detection Questions
   └── How was it detected?
   └── Could we detect it earlier?
   └── What logs/alerts did we use?
   └── What was missing?

5. Response Questions
   └── Were playbooks followed?
   └── Were playbooks adequate?
   └── What tools/access were missing?
   └── How was communication?

6. Prevention Questions
   └── How did attacker get in?
   └── What control failed?
   └── Can we prevent recurrence?

7. Action Items
   └── Specific, assigned, deadlines

METRICS TO TRACK:
┌─────────────────────────────────────┬─────────────────────────────────────┐
│ Metric                              │ Description                         │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Time to Detect (TTD)                │ Compromise → Detection              │
│ Time to Contain (TTC)               │ Detection → Containment complete    │
│ Time to Eradicate (TTE)             │ Containment → Eradication complete  │
│ Time to Recover (TTR)               │ Eradication → Full recovery         │
│ Total Incident Duration             │ Detection → Closure                 │
│ Dwell Time                          │ Initial compromise → Detection      │
│ Business Impact (hours)             │ Downtime, productivity loss         │
│ Business Impact ($)                 │ Recovery cost, revenue loss         │
│ Number of Systems Affected          │ Scope of compromise                 │
│ Root Cause Category                 │ Phishing, vuln, misconfig, etc.     │
└─────────────────────────────────────┴─────────────────────────────────────┘

REPORTING:
├── Executive Summary (1 page, business impact)
├── Technical Report (detailed timeline, TTPs, IOCs)
├── Lessons Learned Document
├── Updated Playbooks/Runbooks
└── Threat Intelligence Report (share IOCs with community)
```

---

## Interview Questions - Incident Response

1. **Walk me through your first 30 minutes of a ransomware incident**
   - Establish communication (incident bridge)
   - Confirm and identify ransomware variant
   - Assess scope (how many systems)
   - Check if encryption is still active
   - Isolate affected systems immediately
   - Identify patient zero if possible
   - Check backup status

2. **How do you determine the scope of a breach?**
   - Authentication logs: Where did attacker authenticate
   - Network logs: What did they touch/access
   - EDR: Process execution, file access
   - Lateral movement indicators
   - Data access logs
   - Timeline correlation across sources

3. **When would you NOT isolate a compromised system?**
   - Active intelligence collection (law enforcement coordinated)
   - Critical system where staged containment is better
   - Evidence collection in progress (memory capture)
   - Coordinated takedown required
   - System is honeypot/decoy

4. **How do you handle evidence for potential legal action?**
   - Strict chain of custody documentation
   - Hash all evidence immediately
   - Work only on forensic copies
   - Use write blockers
   - Document all tools and actions
   - Secure storage with access controls
   - Engage legal counsel early
   - Consider law enforcement involvement

5. **Explain your credential reset strategy after a domain compromise**
   - If KRBTGT compromised: Double reset with 10+ hour delay
   - Reset all DA and privileged accounts
   - Reset service accounts
   - Reset local admin via LAPS
   - Consider Azure AD Connect accounts
   - Revoke all sessions/tokens
   - Re-enroll MFA

---

**Next: [07_THREAT_HUNTING.md](./07_THREAT_HUNTING.md) →**
