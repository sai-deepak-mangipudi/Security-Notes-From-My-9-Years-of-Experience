# 15 - Interview Questions
## Technical Deep-Dive, Scenario-Based, Behavioral Questions

---

## Technical Deep-Dive Questions

### Detection Engineering

```
Q: How do you detect lateral movement in a Windows environment?

A: Multi-layered approach:

Network-Based:
├── Event 4624 Type 3 (Network) + Type 10 (RDP) correlations
├── Same credentials from multiple source IPs (impossible)
├── Unusual source-destination pairs (baseline deviation)
├── SMB traffic patterns to admin shares (C$, ADMIN$)
└── WinRM/PSRemoting detection (5985/5986)

Endpoint-Based:
├── Sysmon Event 3: Network connections from LOLBins
├── PsExec indicators: Service creation (7045) + named pipes
├── WMI: WmiPrvSe.exe spawning cmd/powershell
├── DCOM: MMC20.Application, ShellBrowserWindow objects
└── Pass-the-Hash: NTLM auth from unusual sources (no 4648 prior)

Query (Splunk):
index=windows EventCode=4624 LogonType IN (3,10)
| eval is_admin_share = if(match(ShareName, "C\$|ADMIN\$"), 1, 0)
| stats dc(SourceNetworkAddress) as source_count,
        values(SourceNetworkAddress) as sources by TargetUserName
| where source_count > 2
| lookup user_baseline TargetUserName OUTPUT baseline_sources
| where NOT match(sources, baseline_sources)
```

```
Q: Design a detection for ransomware staging (T1490).

A:
Indicators:
├── Shadow copy deletion (vssadmin, wmic, powershell)
├── Backup deletion (wbadmin)
├── Recovery mode disabled (bcdedit)
├── Security tool disabling
└── Batch encryption file discovery

Detection Logic:
rule Ransomware_Staging_Commands:
    process_create where
        (process.name == "vssadmin.exe" and commandline contains "delete shadows") or
        (process.name == "wmic.exe" and commandline contains "shadowcopy delete") or
        (process.name == "bcdedit.exe" and commandline contains "recoveryenabled") or
        (process.name == "wbadmin.exe" and commandline contains "delete")

Sigma:
title: Ransomware Staging - System Recovery Inhibited
logsource:
    product: windows
    category: process_creation
detection:
    selection_vss:
        Image|endswith: '\vssadmin.exe'
        CommandLine|contains|all:
            - 'delete'
            - 'shadows'
    selection_wmic:
        Image|endswith: '\wmic.exe'
        CommandLine|contains: 'shadowcopy delete'
    selection_bcdedit:
        Image|endswith: '\bcdedit.exe'
        CommandLine|contains:
            - 'recoveryenabled'
            - 'bootstatuspolicy'
    selection_wbadmin:
        Image|endswith: '\wbadmin.exe'
        CommandLine|contains: 'delete'
    condition: selection_vss or selection_wmic or selection_bcdedit or selection_wbadmin
level: critical
tags:
    - attack.impact
    - attack.t1490

Response: AUTO-ISOLATE (this is pre-ransomware with 24-48hr window)
False Positives: IT backup operations (rare, whitelist by user/host/time)
```

```
Q: How do you detect Kerberoasting vs normal Kerberos activity?

A:
Kerberoasting Indicators:
├── Event 4769 with RC4 encryption (0x17)
├── Single user requests TGS for many different SPNs
├── Requests for service accounts (not computer accounts)
├── Unusual timing (off-hours, bulk requests in short window)
├── Requests from non-standard workstations

Normal Activity:
├── AES encryption (0x12, 0x11)
├── Application servers requesting expected services
├── Distributed across time
├── Consistent with user's job function

Detection Query:
index=windows EventCode=4769 TicketEncryptionType="0x17"
| bucket span=5m _time
| stats dc(ServiceName) as unique_services,
        count as total_requests,
        values(ServiceName) as services
    by TargetUserName, IpAddress, _time
| where unique_services > 5 OR total_requests > 10
| eval risk_score = unique_services * 2 + total_requests
| where risk_score > 20

Additional Context:
├── Check if target services have old passwords
├── Correlate with password cracking activity
├── Check for follow-up authentication as service account
```

```
Q: How do you reduce false positives without missing attacks?

A:
Framework:

1. Behavioral Baselining
   ├── Establish normal patterns per user/host/application
   ├── Use statistical thresholds (z-score, percentile)
   ├── Time-based patterns (business hours, weekends)
   └── Peer group comparison

2. Context Enrichment
   ├── User risk scores
   ├── Asset criticality
   ├── Threat intelligence
   ├── Recent activity patterns
   └── Related alerts

3. Whitelist Strategies
   ├── Hash-based (specific file/tool)
   ├── Path-based (signed location)
   ├── User-based (service accounts, admins)
   ├── Process chain (expected parent-child)
   └── Time-based (maintenance windows)

4. Multi-Condition Detections
   ├── Require multiple indicators
   ├── Time correlation between events
   ├── Sequence-based detection
   └── Anomaly + signature combination

5. Tuning Process
   ├── Deploy in silent mode first (7-14 days)
   ├── Analyze FP patterns
   ├── Add exclusions with documentation
   ├── Purple team validation
   └── Monthly exclusion review

Example - Tuned PowerShell Detection:
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'DownloadString'
            - 'IEX'
            - 'Invoke-Expression'
    filter_legitimate:
        User|contains:
            - 'svc_sccm'
            - 'SYSTEM'
        ParentImage|endswith:
            - '\ccmexec.exe'
            - '\chef-client.exe'
            - '\ansible.exe'
    condition: selection and not filter_legitimate
```

### Incident Response

```
Q: Walk me through investigating a potential domain admin compromise.

A:
PHASE 1: IMMEDIATE CONTAINMENT (0-30 min)
├── Disable the DA account (don't reset password yet)
├── Kill active sessions across all systems
├── Isolate known compromised systems
├── Block lateral movement (segment DCs if possible)
├── Engage senior leadership (potential full domain compromise)

PHASE 2: SCOPE ASSESSMENT (30 min - 2 hours)
├── Check DA authentication history (30 days minimum):
│   ├── 4624 on ALL DCs (centralized log search)
│   ├── 4648 (explicit credential use)
│   ├── 4672 (special privileges assigned - confirms admin)
│   └── VPN/remote access logs
├── Every system DA authenticated to is potentially compromised
├── Check for Kerberos ticket anomalies (4768, 4769)
└── Look for DCSync indicators (4662 with replication rights)

PHASE 3: ATTACK PATH ANALYSIS
├── How did they get DA?
│   ├── Kerberoasting → Check 4769 with RC4
│   ├── DCSync → Check 4662 replication events
│   ├── LSASS dumping → Check Sysmon 10 for LSASS access
│   ├── Mimikatz on DC → Check for suspicious processes on DCs
│   ├── Group Policy abuse → Check GPO modifications
│   └── ADCS abuse → Check certificate requests
├── When did compromise occur? (establish timeline)
└── What was accessed after compromise?

PHASE 4: HUNT FOR PERSISTENCE
├── Golden Ticket indicators:
│   ├── TGT with unusual lifetime
│   ├── Forged PAC data
│   └── KRBTGT needs double reset if suspected
├── Scheduled tasks on DCs
├── New admin accounts (4720, 4728)
├── AdminSDHolder modifications
├── GPO-based persistence
├── Computer account abuse
└── Azure AD Connect compromise (if hybrid)

PHASE 5: ERADICATION
├── If KRBTGT compromised:
│   ├── First reset KRBTGT
│   ├── Wait 10+ hours (TGT lifetime)
│   ├── Second reset KRBTGT
│   └── Reset ALL privileged accounts
├── If KRBTGT not compromised:
│   ├── Reset compromised DA account
│   ├── Reset all DA accounts as precaution
│   └── Reset service accounts that were exposed
├── Remove all identified persistence
└── Patch initial access vector

PHASE 6: RECOVERY
├── Staged recovery starting with DCs
├── Enhanced monitoring (30+ days)
├── Implement tiered admin model
├── Deploy Credential Guard
├── Add privileged accounts to Protected Users group
└── Conduct full post-incident review
```

```
Q: You see LSASS access from an unknown process. What's your playbook?

A:
SEVERITY: CRITICAL - Assume credential theft

FIRST 15 MINUTES:
1. Alert screenshot/documentation
2. Identify the process:
   ├── Full path
   ├── Hash (check VT immediately)
   ├── Parent process
   ├── Command line
   ├── User context
   └── Digital signature
3. Isolate endpoint (EDR isolation preferred)
4. DO NOT reboot (preserve memory)

BLAST RADIUS ASSESSMENT:
1. Which accounts authenticated to this host in last 30 days?
   └── Those credentials are ALL potentially compromised
2. Query:
   index=windows EventCode=4624 Computer="COMPROMISED-HOST"
   | where LogonType IN (2,3,10)
   | stats values(TargetUserName) as compromised_accounts,
           values(SourceNetworkAddress) as source_ips
3. Check for lateral movement FROM this host
4. Prioritize by privilege level (DA > admin > user)

EVIDENCE COLLECTION:
1. Memory dump BEFORE remediation
2. Disk image if extended investigation needed
3. Export Sysmon logs, Security logs
4. Network captures if available

CONTAINMENT:
1. Force password reset for ALL accounts that touched this host
2. Revoke Kerberos tickets (klist purge everywhere)
3. Block process hash at EDR
4. Block any identified C2

INVESTIGATION:
1. Initial access vector (how did malware get there?)
2. Dwell time (first evidence of compromise)
3. What else did attacker do after credential theft?
4. Are credentials already used elsewhere?
```

### Threat Hunting

```
Q: Give me a threat hunting hypothesis and how you'd test it.

A:
Hypothesis: "Attackers are using valid credentials during off-business-hours
from geographic locations inconsistent with our workforce to avoid detection."

Rationale:
├── APT actors often operate during their business hours (different timezone)
├── Legitimate users have predictable patterns
├── Stolen credentials may be used from unexpected locations

Data Sources:
├── Windows Security 4624 (successful logons)
├── VPN authentication logs
├── Cloud authentication logs (Azure AD, Okta)
├── Badge access data (physical location correlation)

Query:
index=windows EventCode=4624 LogonType IN (3,10)
| eval hour = strftime(_time, "%H")
| eval day = strftime(_time, "%A")
| eval is_offhours = if((hour >= 0 AND hour <= 5) OR
                        (hour >= 22) OR
                        day IN ("Saturday", "Sunday"), 1, 0)
| where is_offhours = 1
| iplocation IpAddress
| stats count,
        values(Country) as countries,
        values(hour) as hours,
        values(day) as days
    by TargetUserName, IpAddress
| where count > 3
| lookup hr_data TargetUserName OUTPUT expected_location, department
| where NOT match(Country, expected_location)

Investigation Steps:
1. Cross-reference with HR data (travel, remote workers, PTO)
2. Check if VPN IP is from expected provider
3. Correlate with badge data (was user in office?)
4. Look at what was accessed after authentication
5. Check for MFA fatigue/bypass indicators
6. Timeline analysis of the session

Expected Outcomes:
├── True Positive: Unauthorized access from compromised credentials
├── True Positive: Insider sharing credentials
├── False Positive: Legitimate travel not in HR system
├── False Positive: VPN exit node in unexpected country
└── Benign: Night-shift workers, on-call personnel

Detection Creation:
If pattern found, create detection rule with:
├── Off-hours authentication
├── Location anomaly
├── Combined with: sensitive data access or privilege use
```

```
Q: How would you hunt for C2 beaconing?

A:
Indicators:
├── Regular interval connections (jitter analysis)
├── Consistent byte sizes (heartbeat packets)
├── Long-duration TCP sessions
├── Connections to young/rare domains
├── High DNS query volume to single domain
├── Non-standard ports with HTTP/S traffic
├── Unusual user-agent strings
└── JA3/JA3S hash anomalies

Query - Beaconing Detection:
index=proxy
| bucket span=5m _time
| stats count, avg(bytes_out) as avg_bytes, stdev(bytes_out) as bytes_stdev
    by src_ip, dest_domain, _time
| eventstats stdev(count) as interval_stdev,
             avg(count) as avg_connections
    by src_ip, dest_domain
| where interval_stdev < 2 AND avg_connections > 0
| stats count,
        avg(avg_bytes) as overall_avg_bytes,
        values(interval_stdev) as jitter
    by src_ip, dest_domain
| where count > 50 AND jitter < 1.5
| lookup domain_age dest_domain OUTPUT domain_age_days
| where domain_age_days < 30 OR isnull(domain_age_days)
| lookup alexa_top1m dest_domain OUTPUT alexa_rank
| where isnull(alexa_rank) OR alexa_rank > 100000

DNS-Based Beaconing:
index=dns query_type=A
| bucket span=10m _time
| stats count by src_ip, query, _time
| eventstats stdev(count) as query_stdev by src_ip, query
| where query_stdev < 1
| stats count, values(query_stdev) as jitter by src_ip, query
| where count > 100
| eval suspicious = if(len(query) > 50 OR match(query, "^[a-z0-9]{20,}\."), 1, 0)
| where suspicious = 1

Packet Size Analysis:
index=firewall
| where bytes_sent < 1000 AND bytes_sent > 0
| bucket span=1m _time
| stats count, stdev(bytes_sent) as size_stdev by src_ip, dest_ip, _time
| where size_stdev < 10
| stats count by src_ip, dest_ip
| where count > 1000
```

---

## Scenario-Based Questions

### Scenario 1: Ransomware Incident

```
Q: It's 3 AM. You get paged that multiple file servers are showing
mass file encryption. Walk me through your response.

A:
MINUTE 0-5: ASSESSMENT
├── Join incident bridge / establish communication
├── Gather initial information:
│   ├── How many servers affected?
│   ├── Which business units impacted?
│   ├── Is encryption still active or complete?
│   ├── Any ransom notes visible?
│   └── Who reported it?

MINUTE 5-15: IMMEDIATE CONTAINMENT
├── ISOLATE affected systems (EDR isolation or network)
├── DISABLE file shares to prevent spread
├── IDENTIFY ransomware variant (note filename, extension, email)
├── Check ID Ransomware / No More Ransom for decryptor
├── DO NOT REBOOT affected systems (preserve memory)

MINUTE 15-30: SCOPE DETERMINATION
├── How many systems show encryption indicators?
├── Hunt for staging indicators on OTHER systems:
│   └── vssadmin, wbadmin, bcdedit commands
├── If found → those systems about to be encrypted → isolate immediately
├── Check backup status:
│   ├── When was last successful backup?
│   ├── Are backups also encrypted?
│   └── Can we test restore?

MINUTE 30-60: INVESTIGATION START
├── Identify patient zero:
│   ├── First encrypted files (timestamps)
│   ├── First system affected
│   ├── How did it get there?
├── Check for data exfiltration (double extortion):
│   ├── Large outbound transfers
│   ├── Cloud storage uploads (Mega, Dropbox)
│   ├── Unusual DNS traffic
│   └── New cloud accounts created
├── Block C2 domains/IPs at firewall
├── Disable any compromised accounts

HOUR 1-4: EXPANDED RESPONSE
├── Identify initial access vector:
│   ├── Phishing email (check mail logs)
│   ├── Exposed RDP
│   ├── VPN vulnerability
│   ├── Supply chain
├── Map lateral movement path
├── Identify ALL compromised credentials
├── Document IOCs

COMMUNICATION (Throughout):
├── Notify CISO/Executive (within 1 hour)
├── Notify Legal
├── Consider cyber insurance notification
├── Prepare internal comms
├── Consider law enforcement (FBI)
├── DO NOT contact attackers without approval

RECOVERY (After Investigation):
├── Restore from verified clean backups
├── Rebuild if backups unavailable
├── Credential reset for all affected users
├── Patch initial access vulnerability
├── Enhanced monitoring 30+ days
```

### Scenario 2: Suspected Nation-State Intrusion

```
Q: Threat intel indicates your organization is being targeted by APT29.
What proactive steps do you take?

A:
PHASE 1: IMMEDIATE THREAT HUNT (Day 1-2)

Review APT29 TTPs (MITRE ATT&CK):
├── T1566.001 - Spearphishing Attachment
├── T1566.002 - Spearphishing Link
├── T1059.001 - PowerShell
├── T1078 - Valid Accounts
├── T1003.001 - LSASS Memory Dumping
├── T1021.002 - SMB/Windows Admin Shares
├── T1071.001 - Web Protocols (C2)
├── T1567 - Exfiltration Over Web Service

Hunt for Historical Activity:
├── PowerShell with encoded commands:
│   index=sysmon EventCode=1 Image="*powershell*"
│   | where match(CommandLine, "-[eE][nN][cC]")
├── LSASS access from unusual processes:
│   index=sysmon EventCode=10 TargetImage="*lsass.exe"
│   | where NOT match(SourceImage, "csrss|wininit|MsMpEng")
├── Authentication anomalies:
│   - Multiple failed then success
│   - Off-hours from unusual IPs
│   - Impossible travel
├── DNS queries to known APT29 infrastructure
├── WellMess/WellMail malware signatures

Check Email for Targeted Phishing:
├── Emails from spoofed government/partner domains
├── COVID/health-themed lures (APT29 favorite)
├── Links to attacker infrastructure
├── Attachments with macros

PHASE 2: HARDENING (Day 2-5)

Immediate:
├── Enable MFA everywhere (especially VPN, cloud)
├── Implement Credential Guard on sensitive systems
├── Block known APT29 IOCs at perimeter
├── Reduce attack surface (disable legacy protocols)
├── Segment network (limit lateral movement paths)
├── Increase logging verbosity

Detection Deployment:
├── Deploy APT29-specific detections
├── Enable real-time LSASS protection alerts
├── Monitor for known tooling (Mimikatz, Cobalt Strike)
├── Behavioral analytics for credential abuse
├── DNS monitoring for DGA/tunneling

PHASE 3: PREPARE (Day 5-7)

Response Readiness:
├── Update IR playbooks with APT29 specifics
├── Brief SOC on APT29 indicators and TTPs
├── Tabletop exercise simulating APT29 intrusion
├── Ensure forensic readiness (disk space, tools, credentials)
├── Test backup restoration capability
├── Verify out-of-band communication methods

Ongoing:
├── Daily threat intel review
├── Proactive threat hunting schedule
├── Enhanced monitoring for 90+ days
├── Regular stakeholder updates
```

### Scenario 3: Insider Threat

```
Q: HR reports an employee gave 2-week notice. They have access to
trade secrets. What do you do?

A:
GUIDING PRINCIPLE: Covert monitoring until evidence obtained

IMMEDIATE ACTIONS (Day 1):
├── Enable enhanced monitoring WITHOUT alerting user:
│   ├── DLP: Large file downloads/copies
│   ├── Email: Forwarding to personal, large attachments
│   ├── Cloud: Dropbox, Google Drive, OneDrive uploads
│   ├── USB: Mass file copies to removable media
│   └── Print: Unusual print jobs
├── Obtain legal approval for monitoring
├── Coordinate with HR on timeline and approach

BASELINE ANALYSIS:
├── What data does this user normally access?
├── What's their normal working pattern?
├── What crown jewels do they have access to?
├── Who are their regular contacts?
└── What projects are they working on?

ACTIVE HUNTING:
Look for (last 30-60 days):
├── Large downloads from file servers/SharePoint
├── Access to data outside normal job function
├── After-hours access
├── Email forwarding rules to personal email
├── Recent access to sensitive repositories
├── Cloud storage account creation/access
├── Files renamed or added to archive
├── Searches for sensitive terms

Detection Query:
index=dlp user="SUBJECT"
| eval is_sensitive = if(match(file_path, "trade_secret|confidential|proprietary"), 1, 0)
| stats sum(bytes) as total_bytes, count as file_count by action, is_sensitive
| where total_bytes > 100000000 OR file_count > 100

Email Analysis:
index=email src_user="SUBJECT"
| where dest_email != "*@company.com"
| stats count, sum(attachment_size) by dest_email
| sort - attachment_size

IF EXFILTRATION DETECTED:
1. Preserve ALL evidence before any action
   ├── Forensic image of workstation
   ├── Email mailbox export
   ├── Cloud account activity logs
   ├── Badge access records
   └── Phone records if company device
2. Legal review of evidence
3. HR decision on immediate termination vs. complete notice period
4. If terminated:
   ├── Revoke all access simultaneously
   ├── Collect company devices
   ├── Brief on legal obligations (NDA, etc.)
5. Consider legal action if significant theft
6. Post-incident: Review access controls for departing employees
```

---

## Behavioral Questions (STAR Method)

```
STAR FORMAT:
├── Situation: Set the context (what, when, where)
├── Task: What was YOUR responsibility
├── Action: What YOU specifically did (not the team)
├── Result: Quantifiable outcome
```

### Sample Stories

```
1. MOST COMPLEX INCIDENT YOU'VE HANDLED

SITUATION:
Our organization was targeted by a suspected nation-state actor.
Initial detection was an anomalous outbound connection to rare domain
from a developer workstation.

TASK:
As lead investigator, I was responsible for scoping the breach,
coordinating the response team, and driving the investigation to
root cause.

ACTION:
├── Established incident command structure and communication channels
├── Led forensic analysis of initial compromised system
├── Identified novel malware using fileless persistence via WMI
├── Traced lateral movement across 50+ systems through AD logs
├── Discovered initial access was spearphishing targeting dev team
├── Found data exfiltration to cloud storage totaling 5GB
├── Coordinated with FBI and third-party IR firm
├── Developed custom YARA rules and Sigma detections
├── Led eradication effort including KRBTGT double reset

RESULT:
├── Contained breach within 3 weeks (vs 200+ day industry average)
├── Prevented ongoing exfiltration saving estimated $20M IP
├── Created 15 new detections that caught 2 follow-up attempts
├── Published anonymized threat intel to help sector
├── Improved dwell time detection by 60%
```

```
2. TIME YOU REDUCED FALSE POSITIVES

SITUATION:
Our LSASS access detection was generating 200+ alerts per day,
causing severe alert fatigue and being ignored by the SOC.

TASK:
Reduce false positives while maintaining detection capability
for actual credential theft.

ACTION:
├── Analyzed 2 weeks of alert data (3,000+ events)
├── Grouped by source process and identified patterns:
│   ├── 70% from AV/EDR legitimate scanning
│   ├── 15% from system processes (csrss, wininit)
│   ├── 10% from IT tools (SCCM, vulnerability scanners)
│   └── 5% required investigation
├── Created tiered detection approach:
│   ├── Tier 1: Known-bad processes → Auto-isolate
│   ├── Tier 2: Unknown processes → High priority alert
│   ├── Tier 3: Known-good with anomaly → Low priority
├── Added context requirements (access rights, user, time)
├── Implemented allow-list with documentation requirements
├── Created weekly review process for exclusions

RESULT:
├── Reduced from 200/day to 5/day (97.5% reduction)
├── Zero missed true positives in following 6 months
├── SOC engagement with alert increased from 10% to 95%
├── Time to investigate remaining alerts: 5min avg vs 30min
├── Model replicated for 10 other high-volume detections
```

```
3. CONFLICT WITH STAKEHOLDER

SITUATION:
Engineering team wanted to disable security logging on production
servers citing 15% performance impact during peak hours.

TASK:
Find solution that balanced security visibility with performance
requirements without compromising our detection capability.

ACTION:
├── Met with engineering to understand specific bottleneck
├── Analyzed log volume - identified 60% was debug-level noise
├── Proposed solution:
│   ├── Filter debug logs at source (keep security-relevant)
│   ├── Implement async log forwarding
│   ├── Sample high-volume events during peak (80% sampling)
│   ├── Maintain full fidelity for security-critical events
├── Built proof of concept in staging
├── Worked with engineering to test during load testing
├── Created monitoring dashboard for log health

RESULT:
├── Maintained full security visibility for critical events
├── Reduced performance impact from 15% to 3%
├── Actually improved log quality by removing noise
├── Engineering team became security advocates
├── Process adopted as standard for future deployments
```

```
4. MENTORING/LEADERSHIP EXAMPLE

SITUATION:
Junior analyst was struggling with alert triage, taking 2+ hours
per alert and missing key indicators.

TASK:
Develop their capabilities so they could handle Tier 2 alerts
independently within 3 months.

ACTION:
├── Created structured training program:
│   ├── Week 1-2: Alert anatomy and triage framework
│   ├── Week 3-4: Log analysis deep dive
│   ├── Week 5-6: Investigation methodology
│   ├── Week 7-8: Common attack patterns
├── Paired hunting sessions (showed my process)
├── Weekly 1:1s for questions and feedback
├── Gradually increased complexity of assigned alerts
├── Created decision trees for common scenarios
├── Had them document investigations (reinforced learning)
├── Shadow sessions where they led, I observed

RESULT:
├── Analyst handling Tier 2 alerts independently in 2.5 months
├── Alert handling time reduced to 20 minutes average
├── Promoted to Tier 2 analyst within year
├── They're now mentoring new hires themselves
├── Training materials became team standard
```

---

## Quick-Fire Technical Questions

```
NETWORKING:
Q: What port is Kerberos?          A: 88
Q: What port is LDAP/LDAPS?        A: 389/636
Q: What port is SMB?               A: 445 (also 139)
Q: What port is RDP?               A: 3389
Q: What port is WinRM?             A: 5985 (HTTP) / 5986 (HTTPS)
Q: What port is DNS?               A: 53
Q: Difference between TCP and UDP? A: TCP=reliable/ordered, UDP=fast/no guarantees

WINDOWS EVENTS:
Q: What event is successful logon?  A: 4624
Q: What event is failed logon?      A: 4625
Q: What event is admin logon?       A: 4672 (special privileges)
Q: What event is service install?   A: 7045 (System), 4697 (Security)
Q: What event is scheduled task?    A: 4698 (created), 4702 (updated)
Q: What event is TGT request?       A: 4768
Q: What event is TGS request?       A: 4769

SYSMON:
Q: What Sysmon event is process create?    A: 1
Q: What Sysmon event is network?           A: 3
Q: What Sysmon event is CreateRemoteThread?A: 8
Q: What Sysmon event is LSASS access?      A: 10
Q: What Sysmon event is file create?       A: 11
Q: What Sysmon event is registry?          A: 12, 13, 14
Q: What Sysmon event is DNS query?         A: 22

AUTHENTICATION:
Q: Difference between authentication and authorization?
A: AuthN=proving identity, AuthZ=what you can access
Q: What's a Golden Ticket?
A: Forged TGT using KRBTGT hash, full domain access
Q: What's a Silver Ticket?
A: Forged TGS using service account hash, specific service access
Q: What's Pass-the-Hash?
A: Using NTLM hash to authenticate without knowing password
Q: What's DCSync?
A: Replicating AD data including password hashes using replication protocol

CRYPTO:
Q: Why is MD5 insecure?
A: Collision attacks practical (~2^18 operations)
Q: What's PFS (Perfect Forward Secrecy)?
A: Compromised key doesn't expose past sessions
Q: Difference between encryption and hashing?
A: Encryption=reversible, Hashing=one-way

MITRE:
Q: What's T1003.001?    A: LSASS Memory Dumping
Q: What's T1490?        A: Inhibit System Recovery (ransomware staging)
Q: What's T1059.001?    A: PowerShell
Q: What's T1055?        A: Process Injection
Q: What's T1566?        A: Phishing

WEB:
Q: Difference between reflected and stored XSS?
A: Reflected=in URL immediate, Stored=in DB affects others
Q: What's SSRF?
A: Server-Side Request Forgery - making server request internal resources
Q: What's SQLi?
A: SQL Injection - injecting SQL into queries

FORENSICS:
Q: Where are prefetch files?
A: C:\Windows\Prefetch (*.pf)
Q: What's MFT?
A: Master File Table - NTFS file metadata
Q: What's the order of volatility?
A: CPU/Memory → Network → Process → Disk → Logs → Backups
```

---

## Questions to Ask the Interviewer

```
TEAM & CULTURE:
├── What does a typical day/week look like for this role?
├── How is the security team structured? (sizes, specializations)
├── What's the biggest challenge the team faces right now?
├── How do you measure success for this role?
├── What does on-call rotation look like?
├── What's the team's work-from-home policy?

TECHNICAL:
├── What's your SIEM platform? (Splunk, Sentinel, Elastic)
├── What EDR do you use?
├── What does your detection engineering pipeline look like?
├── How do you handle false positives?
├── What's your threat hunting cadence?
├── How do you prioritize detection development?
├── What's your ATT&CK coverage currently?

INCIDENT RESPONSE:
├── What types of incidents do you see most often?
├── What's your average time to detect/respond?
├── Do you have an IR retainer? Who?
├── How do you do post-incident review?

GROWTH:
├── How do you support professional development?
├── What does career progression look like?
├── What conferences/training do you support?
├── What certifications do you value?

RED FLAGS TO LISTEN FOR:
├── "We don't have time for threat hunting"
├── "We just respond to alerts"
├── "Security is an afterthought here"
├── "We don't have budget for training"
├── Vague answers about metrics or measurement
├── "We handle everything manually"
├── High turnover mentioned
├── No clear incident response process
```

---

## Salary Negotiation

```
MARKET DATA (2026, US):
┌─────────────────────────────────────┬────────────────────────────────────┐
│ Role                                │ Salary Range                       │
├─────────────────────────────────────┼────────────────────────────────────┤
│ Detection Engineer                  │ $140K - $200K                      │
│ Senior Detection Engineer           │ $180K - $240K                      │
│ Staff/Principal Detection Engineer  │ $220K - $300K                      │
├─────────────────────────────────────┼────────────────────────────────────┤
│ Threat Hunter                       │ $150K - $220K                      │
│ Senior Threat Hunter                │ $180K - $260K                      │
│ Principal Threat Hunter             │ $240K - $320K                      │
├─────────────────────────────────────┼────────────────────────────────────┤
│ Incident Responder                  │ $130K - $170K                      │
│ Senior Incident Responder           │ $170K - $230K                      │
│ IR Lead / Manager                   │ $200K - $280K                      │
└─────────────────────────────────────┴────────────────────────────────────┘

NEGOTIATION LEVERAGE:
├── GIAC certifications (GCIH, GCFA, GREM, GPEN)
├── OSCP/OSCE
├── Specific tool expertise (Splunk cert, etc.)
├── APT investigation experience
├── Detection engineering portfolio
├── Published research/conference talks
├── Leadership/management experience
├── Cloud security expertise (+15-20%)
├── AI/ML security knowledge (emerging premium)
├── Clearance (if applicable)

NEGOTIATION TIPS:
├── Research market rate before interview
├── Don't give a number first if possible
├── Consider total comp (base + bonus + equity)
├── Negotiate other benefits if salary capped:
│   ├── Sign-on bonus
│   ├── Additional equity
│   ├── Training budget
│   ├── Conference attendance
│   ├── Remote work flexibility
│   └── Extra PTO
├── Get offer in writing before accepting
├── It's okay to ask for time to consider
```

---

**Return to [00_INDEX.md](./00_INDEX.md) for complete navigation.**
