# 16 - Python for Security Operations
## Parsing, Automation, Log Analysis, API Integration, Forensics Scripts

---

## Core Libraries for Security

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Category            │ Libraries                   │ Use Case               │
├─────────────────────┼─────────────────────────────┼────────────────────────┤
│ Log Parsing         │ re, json, csv, xmltodict    │ Parse various formats  │
│ Network             │ scapy, socket, dpkt         │ Packet analysis        │
│ HTTP/API            │ requests, httpx, aiohttp    │ API integration        │
│ Forensics           │ volatility3, yara-python    │ Memory/file analysis   │
│ Data Analysis       │ pandas, numpy               │ Log aggregation        │
│ Threat Intel        │ OTXv2, MISP, stix2          │ IOC enrichment         │
│ Automation          │ paramiko, fabric, pywinrm   │ Remote execution       │
│ SIEM Integration    │ splunk-sdk, elasticsearch   │ Query/ingest data      │
│ Cloud               │ boto3, azure-mgmt, google   │ Cloud API access       │
│ Malware Analysis    │ pefile, oletools, yara      │ Static analysis        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Log Parsing Patterns

### JSON Log Parsing
```python
import json
from datetime import datetime
from collections import defaultdict

def parse_json_logs(filepath):
    """Parse JSON logs (one JSON object per line)"""
    events = []
    with open(filepath, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                event = json.loads(line.strip())
                events.append(event)
            except json.JSONDecodeError as e:
                print(f"Line {line_num}: Invalid JSON - {e}")
    return events

def parse_cloudtrail(filepath):
    """Parse AWS CloudTrail logs"""
    with open(filepath, 'r') as f:
        data = json.load(f)

    events = data.get('Records', [])

    # Extract key fields
    parsed = []
    for event in events:
        parsed.append({
            'timestamp': event.get('eventTime'),
            'event_name': event.get('eventName'),
            'event_source': event.get('eventSource'),
            'user_identity': event.get('userIdentity', {}).get('arn'),
            'source_ip': event.get('sourceIPAddress'),
            'user_agent': event.get('userAgent'),
            'error_code': event.get('errorCode'),
            'request_params': event.get('requestParameters')
        })
    return parsed

# Hunt for suspicious CloudTrail events
def hunt_cloudtrail(events):
    """Hunt for suspicious AWS activity"""
    suspicious = {
        'console_logins': [],
        'iam_changes': [],
        'security_group_changes': [],
        'failed_actions': []
    }

    for event in events:
        name = event.get('event_name', '')

        if name == 'ConsoleLogin':
            suspicious['console_logins'].append(event)
        elif name.startswith(('CreateUser', 'AttachPolicy', 'CreateAccessKey')):
            suspicious['iam_changes'].append(event)
        elif 'SecurityGroup' in name:
            suspicious['security_group_changes'].append(event)
        elif event.get('error_code'):
            suspicious['failed_actions'].append(event)

    return suspicious
```

### Windows Event Log Parsing
```python
import json
import xml.etree.ElementTree as ET
from datetime import datetime

def parse_evtx_xml(xml_string):
    """Parse Windows Event XML format"""
    ns = {
        'e': 'http://schemas.microsoft.com/win/2004/08/events/event'
    }

    root = ET.fromstring(xml_string)

    system = root.find('e:System', ns)
    event_data = root.find('e:EventData', ns)

    parsed = {
        'event_id': system.find('e:EventID', ns).text,
        'timestamp': system.find('e:TimeCreated', ns).get('SystemTime'),
        'computer': system.find('e:Computer', ns).text,
        'channel': system.find('e:Channel', ns).text,
    }

    # Extract EventData fields
    if event_data is not None:
        for data in event_data.findall('e:Data', ns):
            name = data.get('Name')
            if name:
                parsed[name] = data.text

    return parsed

def hunt_windows_auth(events):
    """Hunt for suspicious Windows authentication"""
    SUSPICIOUS_LOGON_TYPES = {'10': 'RemoteInteractive', '3': 'Network'}
    findings = []

    for event in events:
        event_id = event.get('event_id')

        # 4625 - Failed logon
        if event_id == '4625':
            findings.append({
                'type': 'failed_logon',
                'user': event.get('TargetUserName'),
                'source_ip': event.get('IpAddress'),
                'logon_type': event.get('LogonType'),
                'failure_reason': event.get('FailureReason'),
                'timestamp': event.get('timestamp')
            })

        # 4624 - Successful logon (focus on remote)
        elif event_id == '4624':
            logon_type = event.get('LogonType')
            if logon_type in SUSPICIOUS_LOGON_TYPES:
                findings.append({
                    'type': 'remote_logon',
                    'user': event.get('TargetUserName'),
                    'source_ip': event.get('IpAddress'),
                    'logon_type': SUSPICIOUS_LOGON_TYPES[logon_type],
                    'timestamp': event.get('timestamp')
                })

        # 4688 - Process creation
        elif event_id == '4688':
            cmd = event.get('CommandLine', '').lower()
            suspicious_cmds = ['mimikatz', 'procdump', 'sekurlsa',
                              'invoke-', 'powershell -e', 'certutil -decode']
            if any(s in cmd for s in suspicious_cmds):
                findings.append({
                    'type': 'suspicious_process',
                    'user': event.get('SubjectUserName'),
                    'process': event.get('NewProcessName'),
                    'command_line': event.get('CommandLine'),
                    'parent': event.get('ParentProcessName'),
                    'timestamp': event.get('timestamp')
                })

    return findings
```

### Syslog / CEF Parsing
```python
import re
from datetime import datetime

def parse_syslog(line):
    """Parse standard syslog format"""
    # RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
    pattern = r'^<(\d+)>(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+):\s*(.*)$'
    match = re.match(pattern, line)

    if match:
        pri, timestamp, hostname, tag, message = match.groups()
        facility = int(pri) >> 3
        severity = int(pri) & 0x07

        return {
            'priority': int(pri),
            'facility': facility,
            'severity': severity,
            'timestamp': timestamp,
            'hostname': hostname,
            'tag': tag,
            'message': message
        }
    return None

def parse_cef(line):
    """Parse Common Event Format (CEF)"""
    # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    cef_pattern = r'^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$'
    match = re.match(cef_pattern, line)

    if match:
        version, vendor, product, dev_version, sig_id, name, severity, extension = match.groups()

        # Parse extension key=value pairs
        ext_dict = {}
        ext_pattern = r'(\w+)=([^\s]+(?:\s+(?!\w+=)[^\s]+)*)'
        for key, value in re.findall(ext_pattern, extension):
            ext_dict[key] = value

        return {
            'cef_version': version,
            'vendor': vendor,
            'product': product,
            'device_version': dev_version,
            'signature_id': sig_id,
            'name': name,
            'severity': severity,
            'extension': ext_dict
        }
    return None

# Example: Parse firewall CEF logs
def analyze_firewall_cef(logs):
    """Analyze firewall CEF logs for suspicious activity"""
    blocked = []
    port_scan_candidates = defaultdict(set)

    for line in logs:
        event = parse_cef(line)
        if not event:
            continue

        ext = event.get('extension', {})
        action = ext.get('act', '')
        src_ip = ext.get('src', '')
        dst_port = ext.get('dpt', '')

        if action.lower() == 'block':
            blocked.append(event)
            port_scan_candidates[src_ip].add(dst_port)

    # Flag potential port scanners (>10 unique ports)
    scanners = {ip: ports for ip, ports in port_scan_candidates.items()
                if len(ports) > 10}

    return {'blocked': blocked, 'potential_scanners': scanners}
```

---

## Network Analysis

### Packet Capture Analysis with Scapy
```python
from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw
from collections import defaultdict

def analyze_pcap(filepath):
    """Analyze PCAP file for suspicious activity"""
    packets = rdpcap(filepath)

    analysis = {
        'total_packets': len(packets),
        'ip_conversations': defaultdict(int),
        'dns_queries': [],
        'http_requests': [],
        'suspicious_ports': [],
        'large_transfers': []
    }

    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            analysis['ip_conversations'][(src, dst)] += 1

            # DNS queries
            if DNS in pkt and pkt[DNS].qr == 0:  # Query
                query = pkt[DNS].qd.qname.decode() if pkt[DNS].qd else ''
                analysis['dns_queries'].append({
                    'src': src,
                    'query': query,
                    'type': pkt[DNS].qd.qtype if pkt[DNS].qd else 0
                })

            # Check for suspicious ports
            if TCP in pkt:
                dport = pkt[TCP].dport
                sport = pkt[TCP].sport
                suspicious = [4444, 5555, 6666, 1337, 31337, 8080, 9001]
                if dport in suspicious or sport in suspicious:
                    analysis['suspicious_ports'].append({
                        'src': src, 'dst': dst,
                        'sport': sport, 'dport': dport
                    })

            # HTTP requests
            if TCP in pkt and Raw in pkt:
                payload = pkt[Raw].load
                if payload.startswith(b'GET') or payload.startswith(b'POST'):
                    try:
                        analysis['http_requests'].append({
                            'src': src, 'dst': dst,
                            'request': payload[:200].decode('utf-8', errors='ignore')
                        })
                    except:
                        pass

    return analysis

def extract_dns_iocs(pcap_path):
    """Extract DNS IOCs from PCAP"""
    packets = rdpcap(pcap_path)

    domains = defaultdict(lambda: {'count': 0, 'ips': set(), 'sources': set()})

    for pkt in packets:
        if DNS in pkt:
            dns = pkt[DNS]

            # DNS Query
            if dns.qr == 0 and dns.qd:
                domain = dns.qd.qname.decode().rstrip('.')
                domains[domain]['count'] += 1
                if IP in pkt:
                    domains[domain]['sources'].add(pkt[IP].src)

            # DNS Response
            elif dns.qr == 1 and dns.an:
                for i in range(dns.ancount):
                    rr = dns.an[i]
                    if hasattr(rr, 'rdata'):
                        domain = rr.rrname.decode().rstrip('.')
                        domains[domain]['ips'].add(str(rr.rdata))

    # Flag suspicious domains
    suspicious = []
    for domain, info in domains.items():
        # High entropy (DGA-like)
        entropy = calculate_entropy(domain.split('.')[0])
        if entropy > 3.5 or len(domain.split('.')[0]) > 20:
            suspicious.append({
                'domain': domain,
                'entropy': entropy,
                'query_count': info['count'],
                'resolved_ips': list(info['ips'])
            })

    return suspicious

def calculate_entropy(s):
    """Calculate Shannon entropy of string"""
    from math import log2
    if not s:
        return 0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    entropy = 0
    for count in freq.values():
        p = count / len(s)
        entropy -= p * log2(p)
    return entropy
```

### Network Connection Analysis
```python
import socket
import subprocess
from collections import defaultdict

def get_network_connections():
    """Get current network connections (cross-platform)"""
    import platform

    connections = []

    if platform.system() == 'Windows':
        output = subprocess.check_output(['netstat', '-ano']).decode()
    else:
        output = subprocess.check_output(['netstat', '-tunapl']).decode()

    for line in output.split('\n'):
        parts = line.split()
        if len(parts) >= 4 and parts[0] in ('TCP', 'tcp', 'UDP', 'udp'):
            connections.append({
                'protocol': parts[0].upper(),
                'local': parts[1] if platform.system() != 'Windows' else parts[1],
                'remote': parts[2] if platform.system() != 'Windows' else parts[2],
                'state': parts[3] if len(parts) > 3 else 'N/A'
            })

    return connections

def detect_beaconing(connection_times, threshold_variance=0.1):
    """Detect beaconing behavior from connection timestamps"""
    if len(connection_times) < 5:
        return False, None

    # Calculate intervals
    intervals = []
    for i in range(1, len(connection_times)):
        intervals.append(connection_times[i] - connection_times[i-1])

    if not intervals:
        return False, None

    avg_interval = sum(intervals) / len(intervals)
    variance = sum((x - avg_interval)**2 for x in intervals) / len(intervals)
    std_dev = variance ** 0.5

    # Low variance = potential beaconing
    coefficient_of_variation = std_dev / avg_interval if avg_interval > 0 else float('inf')

    is_beaconing = coefficient_of_variation < threshold_variance

    return is_beaconing, {
        'avg_interval_seconds': avg_interval,
        'std_dev': std_dev,
        'coefficient_of_variation': coefficient_of_variation,
        'sample_count': len(intervals)
    }
```

---

## SIEM Integration

### Splunk SDK
```python
import splunklib.client as client
import splunklib.results as results

class SplunkConnector:
    def __init__(self, host, port, username, password):
        self.service = client.connect(
            host=host,
            port=port,
            username=username,
            password=password
        )

    def search(self, query, earliest='-24h', latest='now'):
        """Execute Splunk search and return results"""
        search_query = f'search {query}'

        job = self.service.jobs.create(
            search_query,
            earliest_time=earliest,
            latest_time=latest
        )

        while not job.is_done():
            import time
            time.sleep(0.5)

        result_list = []
        for result in results.JSONResultsReader(job.results(output_mode='json')):
            if isinstance(result, dict):
                result_list.append(result)

        return result_list

    def hunt_lateral_movement(self):
        """Hunt for lateral movement indicators"""
        queries = {
            'psexec': 'index=windows EventCode=7045 ServiceName="PSEXESVC"',
            'wmi_execution': 'index=windows EventCode=4688 CommandLine="*wmic*process*call*create*"',
            'remote_service': 'index=windows EventCode=7045 ServiceType="user mode service"',
            'rdp_connections': 'index=windows EventCode=4624 LogonType=10'
        }

        findings = {}
        for name, query in queries.items():
            results = self.search(query, earliest='-7d')
            if results:
                findings[name] = results

        return findings

    def create_alert(self, name, query, actions):
        """Create a saved search / alert"""
        self.service.saved_searches.create(
            name,
            search=query,
            **actions
        )
```

### Elasticsearch / OpenSearch
```python
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta

class ElasticConnector:
    def __init__(self, hosts, api_key=None, cloud_id=None):
        if cloud_id:
            self.es = Elasticsearch(cloud_id=cloud_id, api_key=api_key)
        else:
            self.es = Elasticsearch(hosts=hosts)

    def search(self, index, query, size=1000):
        """Execute Elasticsearch query"""
        response = self.es.search(
            index=index,
            body=query,
            size=size
        )
        return response['hits']['hits']

    def hunt_brute_force(self, index='winlogbeat-*', threshold=5, timeframe_minutes=5):
        """Hunt for brute force attacks"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.code": "4625"}},
                        {"range": {
                            "@timestamp": {
                                "gte": f"now-{timeframe_minutes}m",
                                "lte": "now"
                            }
                        }}
                    ]
                }
            },
            "aggs": {
                "by_source_ip": {
                    "terms": {"field": "source.ip", "size": 100},
                    "aggs": {
                        "target_users": {
                            "terms": {"field": "winlog.event_data.TargetUserName"}
                        }
                    }
                }
            }
        }

        response = self.es.search(index=index, body=query, size=0)

        brute_force_candidates = []
        for bucket in response['aggregations']['by_source_ip']['buckets']:
            if bucket['doc_count'] >= threshold:
                brute_force_candidates.append({
                    'source_ip': bucket['key'],
                    'failed_attempts': bucket['doc_count'],
                    'target_users': [u['key'] for u in bucket['target_users']['buckets']]
                })

        return brute_force_candidates

    def hunt_powershell_execution(self, index='winlogbeat-*'):
        """Hunt for suspicious PowerShell execution"""
        suspicious_patterns = [
            '*-EncodedCommand*', '*-enc*', '*IEX*', '*Invoke-Expression*',
            '*downloadstring*', '*Net.WebClient*', '*Start-Process*',
            '*bypass*', '*hidden*', '*-nop*'
        ]

        should_clauses = [
            {"wildcard": {"powershell.command.value": pattern}}
            for pattern in suspicious_patterns
        ]

        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.provider": "PowerShell"}}
                    ],
                    "should": should_clauses,
                    "minimum_should_match": 1
                }
            }
        }

        return self.search(index, query)
```

---

## API Integration

### VirusTotal
```python
import requests
import hashlib
import time

class VirusTotalClient:
    BASE_URL = 'https://www.virustotal.com/api/v3'

    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {'x-apikey': api_key}

    def get_file_report(self, file_hash):
        """Get file analysis report"""
        url = f'{self.BASE_URL}/files/{file_hash}'
        response = requests.get(url, headers=self.headers)
        return response.json()

    def scan_file(self, filepath):
        """Upload and scan a file"""
        url = f'{self.BASE_URL}/files'
        with open(filepath, 'rb') as f:
            files = {'file': f}
            response = requests.post(url, headers=self.headers, files=files)
        return response.json()

    def get_url_report(self, url_to_scan):
        """Get URL analysis report"""
        import base64
        url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip('=')
        url = f'{self.BASE_URL}/urls/{url_id}'
        response = requests.get(url, headers=self.headers)
        return response.json()

    def get_ip_report(self, ip):
        """Get IP address report"""
        url = f'{self.BASE_URL}/ip_addresses/{ip}'
        response = requests.get(url, headers=self.headers)
        return response.json()

    def get_domain_report(self, domain):
        """Get domain report"""
        url = f'{self.BASE_URL}/domains/{domain}'
        response = requests.get(url, headers=self.headers)
        return response.json()

    def bulk_ioc_check(self, iocs, ioc_type='hash'):
        """Check multiple IOCs with rate limiting"""
        results = []
        for ioc in iocs:
            try:
                if ioc_type == 'hash':
                    result = self.get_file_report(ioc)
                elif ioc_type == 'ip':
                    result = self.get_ip_report(ioc)
                elif ioc_type == 'domain':
                    result = self.get_domain_report(ioc)

                results.append({'ioc': ioc, 'result': result})
                time.sleep(0.25)  # Rate limiting (4 req/sec for standard API)
            except Exception as e:
                results.append({'ioc': ioc, 'error': str(e)})

        return results
```

### AbuseIPDB
```python
import requests

class AbuseIPDBClient:
    BASE_URL = 'https://api.abuseipdb.com/api/v2'

    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {'Key': api_key, 'Accept': 'application/json'}

    def check_ip(self, ip, max_age_days=90):
        """Check IP reputation"""
        url = f'{self.BASE_URL}/check'
        params = {'ipAddress': ip, 'maxAgeInDays': max_age_days}
        response = requests.get(url, headers=self.headers, params=params)
        return response.json()

    def check_ip_block(self, network):
        """Check IP block/CIDR"""
        url = f'{self.BASE_URL}/check-block'
        params = {'network': network}
        response = requests.get(url, headers=self.headers, params=params)
        return response.json()

    def report_ip(self, ip, categories, comment):
        """Report malicious IP"""
        url = f'{self.BASE_URL}/report'
        data = {
            'ip': ip,
            'categories': ','.join(map(str, categories)),
            'comment': comment
        }
        response = requests.post(url, headers=self.headers, data=data)
        return response.json()

    def bulk_check(self, ips):
        """Check multiple IPs"""
        results = []
        for ip in ips:
            try:
                result = self.check_ip(ip)
                data = result.get('data', {})
                results.append({
                    'ip': ip,
                    'abuse_confidence': data.get('abuseConfidenceScore', 0),
                    'country': data.get('countryCode'),
                    'isp': data.get('isp'),
                    'total_reports': data.get('totalReports', 0),
                    'is_tor': data.get('isTor', False)
                })
            except Exception as e:
                results.append({'ip': ip, 'error': str(e)})

        return results
```

### Shodan
```python
import shodan

class ShodanClient:
    def __init__(self, api_key):
        self.api = shodan.Shodan(api_key)

    def host_lookup(self, ip):
        """Get information about a host"""
        try:
            return self.api.host(ip)
        except shodan.APIError as e:
            return {'error': str(e)}

    def search(self, query, limit=100):
        """Search Shodan"""
        results = []
        try:
            for result in self.api.search_cursor(query):
                results.append(result)
                if len(results) >= limit:
                    break
        except shodan.APIError as e:
            return {'error': str(e)}
        return results

    def find_exposed_services(self, org_name):
        """Find exposed services for an organization"""
        queries = {
            'rdp': f'org:"{org_name}" port:3389',
            'ssh': f'org:"{org_name}" port:22',
            'smb': f'org:"{org_name}" port:445',
            'databases': f'org:"{org_name}" port:3306,5432,27017,6379',
            'web_admin': f'org:"{org_name}" http.title:"admin" OR http.title:"login"'
        }

        findings = {}
        for service, query in queries.items():
            results = self.search(query, limit=50)
            if results and 'error' not in results:
                findings[service] = [{
                    'ip': r.get('ip_str'),
                    'port': r.get('port'),
                    'product': r.get('product'),
                    'version': r.get('version'),
                    'hostnames': r.get('hostnames', [])
                } for r in results]

        return findings
```

---

## Cloud Security Automation

### AWS Security Automation
```python
import boto3
from datetime import datetime, timedelta

class AWSSecurityAutomation:
    def __init__(self, region='us-east-1'):
        self.session = boto3.Session(region_name=region)
        self.ec2 = self.session.client('ec2')
        self.iam = self.session.client('iam')
        self.cloudtrail = self.session.client('cloudtrail')
        self.guardduty = self.session.client('guardduty')

    def get_public_security_groups(self):
        """Find security groups with 0.0.0.0/0 ingress"""
        response = self.ec2.describe_security_groups()

        public_sgs = []
        for sg in response['SecurityGroups']:
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        public_sgs.append({
                            'group_id': sg['GroupId'],
                            'group_name': sg['GroupName'],
                            'vpc_id': sg.get('VpcId'),
                            'port_range': f"{rule.get('FromPort')}-{rule.get('ToPort')}",
                            'protocol': rule.get('IpProtocol')
                        })
        return public_sgs

    def get_unused_iam_keys(self, days_threshold=90):
        """Find IAM access keys not used in X days"""
        unused_keys = []

        users = self.iam.list_users()['Users']

        for user in users:
            keys = self.iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']

            for key in keys:
                last_used = self.iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                last_used_date = last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate')

                if last_used_date:
                    days_since_use = (datetime.now(last_used_date.tzinfo) - last_used_date).days
                    if days_since_use > days_threshold:
                        unused_keys.append({
                            'user': user['UserName'],
                            'key_id': key['AccessKeyId'],
                            'days_since_use': days_since_use,
                            'status': key['Status']
                        })
                else:
                    # Never used
                    unused_keys.append({
                        'user': user['UserName'],
                        'key_id': key['AccessKeyId'],
                        'days_since_use': 'Never used',
                        'status': key['Status']
                    })

        return unused_keys

    def query_cloudtrail(self, event_name=None, user_name=None, hours=24):
        """Query CloudTrail for specific events"""
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)

        lookup_attributes = []
        if event_name:
            lookup_attributes.append({'AttributeKey': 'EventName', 'AttributeValue': event_name})
        if user_name:
            lookup_attributes.append({'AttributeKey': 'Username', 'AttributeValue': user_name})

        events = []
        paginator = self.cloudtrail.get_paginator('lookup_events')

        for page in paginator.paginate(
            LookupAttributes=lookup_attributes,
            StartTime=start_time,
            EndTime=end_time
        ):
            events.extend(page['Events'])

        return events

    def get_guardduty_findings(self, severity_min=4):
        """Get GuardDuty findings above severity threshold"""
        detectors = self.guardduty.list_detectors()['DetectorIds']

        all_findings = []
        for detector_id in detectors:
            findings = self.guardduty.list_findings(
                DetectorId=detector_id,
                FindingCriteria={
                    'Criterion': {
                        'severity': {'Gte': severity_min}
                    }
                }
            )

            if findings['FindingIds']:
                details = self.guardduty.get_findings(
                    DetectorId=detector_id,
                    FindingIds=findings['FindingIds']
                )
                all_findings.extend(details['Findings'])

        return all_findings

    def isolate_instance(self, instance_id):
        """Isolate a compromised EC2 instance"""
        # Create isolation security group
        vpc_id = self.ec2.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]['VpcId']

        try:
            isolation_sg = self.ec2.create_security_group(
                GroupName=f'isolation-{instance_id}',
                Description='Isolation security group - no ingress/egress',
                VpcId=vpc_id
            )
            sg_id = isolation_sg['GroupId']

            # Remove default egress rule
            self.ec2.revoke_security_group_egress(
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': '-1',
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            )
        except Exception:
            # SG might already exist
            sg_id = self.ec2.describe_security_groups(
                Filters=[{'Name': 'group-name', 'Values': [f'isolation-{instance_id}']}]
            )['SecurityGroups'][0]['GroupId']

        # Apply isolation SG
        self.ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[sg_id]
        )

        # Create snapshot for forensics
        volumes = self.ec2.describe_volumes(
            Filters=[{'Name': 'attachment.instance-id', 'Values': [instance_id]}]
        )['Volumes']

        snapshots = []
        for vol in volumes:
            snapshot = self.ec2.create_snapshot(
                VolumeId=vol['VolumeId'],
                Description=f'Forensics snapshot - {instance_id}',
                TagSpecifications=[{
                    'ResourceType': 'snapshot',
                    'Tags': [{'Key': 'Forensics', 'Value': 'true'}]
                }]
            )
            snapshots.append(snapshot['SnapshotId'])

        return {
            'isolated': True,
            'isolation_sg': sg_id,
            'forensic_snapshots': snapshots
        }
```

### Azure Security Automation
```python
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.monitor import MonitorManagementClient

class AzureSecurityAutomation:
    def __init__(self, subscription_id):
        self.credential = DefaultAzureCredential()
        self.subscription_id = subscription_id
        self.compute = ComputeManagementClient(self.credential, subscription_id)
        self.network = NetworkManagementClient(self.credential, subscription_id)

    def get_public_ips(self):
        """Get all public IPs in subscription"""
        public_ips = []
        for ip in self.network.public_ip_addresses.list_all():
            public_ips.append({
                'name': ip.name,
                'resource_group': ip.id.split('/')[4],
                'ip_address': ip.ip_address,
                'allocation_method': ip.public_ip_allocation_method,
                'associated_resource': ip.ip_configuration.id if ip.ip_configuration else None
            })
        return public_ips

    def find_open_nsgs(self):
        """Find NSGs with 0.0.0.0/0 allow rules"""
        open_nsgs = []

        for nsg in self.network.network_security_groups.list_all():
            for rule in nsg.security_rules:
                if (rule.access == 'Allow' and
                    rule.direction == 'Inbound' and
                    ('*' in (rule.source_address_prefix or '') or
                     '0.0.0.0/0' in (rule.source_address_prefix or '') or
                     'Internet' in (rule.source_address_prefix or ''))):
                    open_nsgs.append({
                        'nsg_name': nsg.name,
                        'resource_group': nsg.id.split('/')[4],
                        'rule_name': rule.name,
                        'destination_port': rule.destination_port_range,
                        'protocol': rule.protocol,
                        'source': rule.source_address_prefix
                    })

        return open_nsgs
```

---

## Forensics Automation

### Hash Calculation
```python
import hashlib
import os

def calculate_hashes(filepath):
    """Calculate MD5, SHA1, SHA256 for a file"""
    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    hash_sha256 = hashlib.sha256()

    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            hash_md5.update(chunk)
            hash_sha1.update(chunk)
            hash_sha256.update(chunk)

    return {
        'md5': hash_md5.hexdigest(),
        'sha1': hash_sha1.hexdigest(),
        'sha256': hash_sha256.hexdigest(),
        'file_size': os.path.getsize(filepath)
    }

def hash_directory(directory, extensions=None):
    """Hash all files in a directory"""
    results = []

    for root, dirs, files in os.walk(directory):
        for filename in files:
            if extensions and not any(filename.endswith(ext) for ext in extensions):
                continue

            filepath = os.path.join(root, filename)
            try:
                hashes = calculate_hashes(filepath)
                hashes['filepath'] = filepath
                results.append(hashes)
            except Exception as e:
                results.append({'filepath': filepath, 'error': str(e)})

    return results
```

### PE File Analysis
```python
import pefile
import hashlib
from datetime import datetime

def analyze_pe(filepath):
    """Analyze PE file for suspicious indicators"""
    pe = pefile.PE(filepath)

    analysis = {
        'filepath': filepath,
        'hashes': calculate_hashes(filepath),
        'compile_time': datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat(),
        'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        'sections': [],
        'imports': [],
        'suspicious_indicators': []
    }

    # Section analysis
    for section in pe.sections:
        section_info = {
            'name': section.Name.decode().rstrip('\x00'),
            'virtual_size': section.Misc_VirtualSize,
            'raw_size': section.SizeOfRawData,
            'entropy': section.get_entropy(),
            'characteristics': hex(section.Characteristics)
        }
        analysis['sections'].append(section_info)

        # High entropy section (packed/encrypted)
        if section.get_entropy() > 7.0:
            analysis['suspicious_indicators'].append(
                f"High entropy section: {section_info['name']} ({section.get_entropy():.2f})"
            )

    # Import analysis
    suspicious_imports = [
        'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory',
        'CreateRemoteThread', 'LoadLibrary', 'GetProcAddress',
        'NtUnmapViewOfSection', 'WinExec', 'ShellExecute',
        'URLDownloadToFile', 'InternetOpen', 'HttpOpenRequest'
    ]

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode()
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode()
                    analysis['imports'].append(f"{dll_name}:{func_name}")

                    if func_name in suspicious_imports:
                        analysis['suspicious_indicators'].append(
                            f"Suspicious import: {dll_name}:{func_name}"
                        )

    # Check for packing indicators
    if pe.OPTIONAL_HEADER.SizeOfHeaders > 0x1000:
        analysis['suspicious_indicators'].append("Large headers (possible packer)")

    # Few imports (packed binaries often have minimal imports)
    if len(analysis['imports']) < 10:
        analysis['suspicious_indicators'].append("Very few imports (possible packing)")

    return analysis
```

### YARA Scanning
```python
import yara
import os

class YARAScanner:
    def __init__(self, rules_path):
        """Initialize with path to YARA rules directory"""
        self.rules = self._compile_rules(rules_path)

    def _compile_rules(self, rules_path):
        """Compile all YARA rules from directory"""
        rule_files = {}

        if os.path.isfile(rules_path):
            return yara.compile(filepath=rules_path)

        for root, dirs, files in os.walk(rules_path):
            for filename in files:
                if filename.endswith(('.yar', '.yara')):
                    filepath = os.path.join(root, filename)
                    rule_files[filename] = filepath

        return yara.compile(filepaths=rule_files)

    def scan_file(self, filepath):
        """Scan a single file"""
        matches = self.rules.match(filepath)
        return [{
            'rule': match.rule,
            'namespace': match.namespace,
            'tags': match.tags,
            'meta': match.meta,
            'strings': [(s[0], s[1], s[2].decode('utf-8', errors='ignore'))
                       for s in match.strings[:10]]  # Limit strings
        } for match in matches]

    def scan_directory(self, directory, extensions=None):
        """Scan all files in directory"""
        results = []

        for root, dirs, files in os.walk(directory):
            for filename in files:
                if extensions and not any(filename.endswith(ext) for ext in extensions):
                    continue

                filepath = os.path.join(root, filename)
                try:
                    matches = self.scan_file(filepath)
                    if matches:
                        results.append({
                            'filepath': filepath,
                            'matches': matches
                        })
                except Exception as e:
                    results.append({
                        'filepath': filepath,
                        'error': str(e)
                    })

        return results

    def scan_memory(self, pid):
        """Scan process memory"""
        matches = self.rules.match(pid=pid)
        return matches

# Sample YARA rule for detection
SAMPLE_RULE = '''
rule Suspicious_PowerShell_Download
{
    meta:
        description = "Detects PowerShell download cradles"
        author = "Security Team"
        severity = "medium"

    strings:
        $ps1 = "powershell" nocase
        $download1 = "DownloadString" nocase
        $download2 = "DownloadFile" nocase
        $download3 = "Invoke-WebRequest" nocase
        $download4 = "wget" nocase
        $download5 = "curl" nocase
        $iex = "IEX" nocase
        $invoke = "Invoke-Expression" nocase

    condition:
        $ps1 and (any of ($download*)) and (any of ($iex, $invoke))
}
'''
```

---

## Automation Scripts

### IOC Enrichment Pipeline
```python
import concurrent.futures
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class IOC:
    value: str
    ioc_type: str  # ip, domain, hash, url
    context: str = ''

class IOCEnricher:
    def __init__(self, vt_key=None, abuseipdb_key=None, shodan_key=None):
        self.clients = {}
        if vt_key:
            self.clients['virustotal'] = VirusTotalClient(vt_key)
        if abuseipdb_key:
            self.clients['abuseipdb'] = AbuseIPDBClient(abuseipdb_key)
        if shodan_key:
            self.clients['shodan'] = ShodanClient(shodan_key)

    def enrich_single(self, ioc: IOC) -> Dict[str, Any]:
        """Enrich a single IOC"""
        result = {'ioc': ioc.value, 'type': ioc.ioc_type, 'enrichment': {}}

        if ioc.ioc_type == 'ip':
            if 'virustotal' in self.clients:
                result['enrichment']['virustotal'] = self.clients['virustotal'].get_ip_report(ioc.value)
            if 'abuseipdb' in self.clients:
                result['enrichment']['abuseipdb'] = self.clients['abuseipdb'].check_ip(ioc.value)
            if 'shodan' in self.clients:
                result['enrichment']['shodan'] = self.clients['shodan'].host_lookup(ioc.value)

        elif ioc.ioc_type == 'domain':
            if 'virustotal' in self.clients:
                result['enrichment']['virustotal'] = self.clients['virustotal'].get_domain_report(ioc.value)

        elif ioc.ioc_type == 'hash':
            if 'virustotal' in self.clients:
                result['enrichment']['virustotal'] = self.clients['virustotal'].get_file_report(ioc.value)

        return result

    def enrich_batch(self, iocs: List[IOC], max_workers=5) -> List[Dict[str, Any]]:
        """Enrich multiple IOCs in parallel"""
        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ioc = {executor.submit(self.enrich_single, ioc): ioc for ioc in iocs}

            for future in concurrent.futures.as_completed(future_to_ioc):
                ioc = future_to_ioc[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append({
                        'ioc': ioc.value,
                        'type': ioc.ioc_type,
                        'error': str(e)
                    })

        return results

    def generate_report(self, enriched_iocs: List[Dict]) -> str:
        """Generate markdown report from enriched IOCs"""
        report = "# IOC Enrichment Report\n\n"
        report += f"**Generated:** {datetime.now().isoformat()}\n"
        report += f"**Total IOCs:** {len(enriched_iocs)}\n\n"

        for item in enriched_iocs:
            report += f"## {item['type'].upper()}: `{item['ioc']}`\n\n"

            if 'error' in item:
                report += f"**Error:** {item['error']}\n\n"
                continue

            for source, data in item.get('enrichment', {}).items():
                report += f"### {source.title()}\n"
                report += f"```json\n{json.dumps(data, indent=2, default=str)[:1000]}\n```\n\n"

        return report
```

### Automated Incident Response
```python
import json
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

class IncidentResponder:
    def __init__(self, config):
        self.config = config
        self.aws = AWSSecurityAutomation() if config.get('aws_enabled') else None
        self.siem = ElasticConnector(config.get('elastic_hosts', [])) if config.get('elastic_enabled') else None

    def handle_alert(self, alert):
        """Main alert handler - routes to appropriate playbook"""
        alert_type = alert.get('type', '').lower()

        playbooks = {
            'brute_force': self.playbook_brute_force,
            'malware_detected': self.playbook_malware,
            'data_exfiltration': self.playbook_exfiltration,
            'lateral_movement': self.playbook_lateral_movement,
            'privilege_escalation': self.playbook_privesc
        }

        playbook = playbooks.get(alert_type, self.playbook_generic)
        return playbook(alert)

    def playbook_brute_force(self, alert):
        """Brute force attack response playbook"""
        actions_taken = []
        source_ip = alert.get('source_ip')
        target_user = alert.get('target_user')

        # 1. Gather additional context
        context = self.gather_context(source_ip, target_user)
        actions_taken.append({'action': 'gathered_context', 'data': context})

        # 2. Check if attack was successful
        if context.get('successful_login_after_failures'):
            # Potential compromise - escalate
            actions_taken.append({'action': 'escalated', 'reason': 'Successful login after brute force'})
            self.escalate_to_analyst(alert, context)

        # 3. Block IP if threshold exceeded
        if context.get('failure_count', 0) > 20:
            if self.config.get('auto_block_enabled'):
                self.block_ip(source_ip)
                actions_taken.append({'action': 'blocked_ip', 'ip': source_ip})

        # 4. Reset user password if potentially compromised
        if context.get('successful_login_after_failures'):
            actions_taken.append({'action': 'password_reset_required', 'user': target_user})

        return {'alert_id': alert.get('id'), 'actions': actions_taken}

    def playbook_malware(self, alert):
        """Malware detection response playbook"""
        actions_taken = []
        host = alert.get('hostname')
        file_hash = alert.get('file_hash')
        instance_id = alert.get('instance_id')

        # 1. Enrich IOCs
        enrichment = self.enrich_iocs([{'type': 'hash', 'value': file_hash}])
        actions_taken.append({'action': 'enriched_iocs', 'data': enrichment})

        # 2. Isolate if high severity
        if alert.get('severity', 0) >= 7 and self.config.get('auto_isolate_enabled'):
            if self.aws and instance_id:
                isolation_result = self.aws.isolate_instance(instance_id)
                actions_taken.append({'action': 'isolated_instance', 'result': isolation_result})

        # 3. Collect forensic artifacts
        actions_taken.append({'action': 'collect_forensics', 'host': host})

        # 4. Search for lateral spread
        related = self.search_related_activity(file_hash, host)
        if related:
            actions_taken.append({'action': 'found_related_activity', 'hosts': related})

        return {'alert_id': alert.get('id'), 'actions': actions_taken}

    def gather_context(self, source_ip, target_user):
        """Gather additional context from SIEM"""
        context = {}

        if self.siem:
            # Check for successful logins from same IP
            # Check for other targets from same IP
            # Check for user's normal login patterns
            pass

        return context

    def escalate_to_analyst(self, alert, context):
        """Escalate to security analyst"""
        # Send email/Slack/PagerDuty
        pass

    def block_ip(self, ip):
        """Block IP at firewall/WAF"""
        # Implementation depends on firewall API
        pass

    def enrich_iocs(self, iocs):
        """Enrich IOCs with threat intel"""
        # Use IOCEnricher
        pass

    def search_related_activity(self, ioc, host):
        """Search for related activity in SIEM"""
        pass
```

---

## Utility Functions

### Data Parsing Helpers
```python
import re
import ipaddress
from urllib.parse import urlparse

def extract_iocs(text):
    """Extract IOCs from unstructured text"""
    iocs = {
        'ips': [],
        'domains': [],
        'urls': [],
        'hashes': {'md5': [], 'sha1': [], 'sha256': []},
        'emails': []
    }

    # IP addresses
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    for ip in re.findall(ip_pattern, text):
        try:
            ipaddress.ip_address(ip)
            if not ipaddress.ip_address(ip).is_private:
                iocs['ips'].append(ip)
        except:
            pass

    # URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    for url in re.findall(url_pattern, text):
        iocs['urls'].append(url)
        # Extract domain from URL
        parsed = urlparse(url)
        if parsed.netloc:
            iocs['domains'].append(parsed.netloc)

    # Domains (defanged and normal)
    text_cleaned = text.replace('[.]', '.').replace('hxxp', 'http')
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    for domain in re.findall(domain_pattern, text_cleaned):
        if domain not in iocs['domains']:
            iocs['domains'].append(domain)

    # MD5
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    iocs['hashes']['md5'] = list(set(re.findall(md5_pattern, text)))

    # SHA1
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    iocs['hashes']['sha1'] = list(set(re.findall(sha1_pattern, text)))

    # SHA256
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    iocs['hashes']['sha256'] = list(set(re.findall(sha256_pattern, text)))

    # Emails
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    iocs['emails'] = list(set(re.findall(email_pattern, text)))

    return iocs

def defang_ioc(ioc, ioc_type='auto'):
    """Defang IOC for safe sharing"""
    if ioc_type == 'auto':
        if re.match(r'^https?://', ioc):
            ioc_type = 'url'
        elif re.match(r'^\d+\.\d+\.\d+\.\d+$', ioc):
            ioc_type = 'ip'
        else:
            ioc_type = 'domain'

    if ioc_type == 'url':
        return ioc.replace('http', 'hxxp').replace('.', '[.]')
    elif ioc_type == 'ip':
        return ioc.replace('.', '[.]')
    elif ioc_type == 'domain':
        return ioc.replace('.', '[.]')

    return ioc

def refang_ioc(ioc):
    """Refang defanged IOC"""
    return ioc.replace('hxxp', 'http').replace('[.]', '.').replace('[:]', ':')

def is_internal_ip(ip):
    """Check if IP is internal/private"""
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False

def parse_timestamp(ts, formats=None):
    """Parse various timestamp formats"""
    if formats is None:
        formats = [
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%d %H:%M:%S',
            '%d/%b/%Y:%H:%M:%S %z',
            '%b %d %H:%M:%S',
            '%Y%m%d%H%M%S'
        ]

    for fmt in formats:
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue

    return None
```

### Reporting Helpers
```python
import csv
import json
from datetime import datetime

def export_to_csv(data, filepath, fields=None):
    """Export list of dicts to CSV"""
    if not data:
        return

    if fields is None:
        fields = data[0].keys()

    with open(filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(data)

def export_to_json(data, filepath, indent=2):
    """Export data to JSON"""
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=indent, default=str)

def generate_incident_report(incident_data):
    """Generate markdown incident report"""
    report = f"""# Incident Report

## Summary
- **Incident ID:** {incident_data.get('id', 'N/A')}
- **Date/Time Detected:** {incident_data.get('detected_at', 'N/A')}
- **Severity:** {incident_data.get('severity', 'N/A')}
- **Status:** {incident_data.get('status', 'Open')}

## Description
{incident_data.get('description', 'No description provided')}

## Affected Systems
{chr(10).join('- ' + system for system in incident_data.get('affected_systems', []))}

## IOCs
### IP Addresses
{chr(10).join('- `' + ip + '`' for ip in incident_data.get('iocs', {}).get('ips', []))}

### Domains
{chr(10).join('- `' + domain + '`' for domain in incident_data.get('iocs', {}).get('domains', []))}

### File Hashes
{chr(10).join('- `' + hash + '`' for hash in incident_data.get('iocs', {}).get('hashes', []))}

## Timeline
{chr(10).join('| ' + event.get('time', '') + ' | ' + event.get('description', '') + ' |' for event in incident_data.get('timeline', []))}

## Actions Taken
{chr(10).join('- ' + action for action in incident_data.get('actions', []))}

## Recommendations
{chr(10).join('- ' + rec for rec in incident_data.get('recommendations', []))}

---
*Report generated: {datetime.now().isoformat()}*
"""
    return report
```

---

## Interview Questions - Python Security

**Q: How would you parse Windows Event Logs in Python?**
```
Answer Framework:
- Use python-evtx library for raw .evtx files
- Parse XML structure with xml.etree.ElementTree
- Extract System and EventData sections
- Key fields: EventID, TimeCreated, Computer, EventData params
- For large files: use generators to avoid memory issues
```

**Q: Write a script to detect beaconing in network logs**
```
Answer Framework:
- Parse connection timestamps per destination
- Calculate intervals between connections
- Compute coefficient of variation (std_dev / mean)
- Low variance = consistent timing = potential beacon
- Threshold typically < 0.1-0.2 for beaconing
- Also check: jitter analysis, connection duration patterns
```

**Q: How do you handle API rate limiting in automation scripts?**
```
Answer Framework:
- Implement exponential backoff
- Use time.sleep() between requests
- Track rate limit headers (X-RateLimit-Remaining)
- Use asyncio for concurrent but throttled requests
- Cache results to reduce API calls
- Consider bulk endpoints where available
```

**Q: Design an IOC enrichment pipeline**
```
Answer Framework:
1. Input: Accept IOCs from multiple sources (file, API, SIEM)
2. Deduplication: Remove duplicate IOCs
3. Validation: Verify IOC format (valid IP, hash format)
4. Enrichment: Query multiple sources (VT, AbuseIPDB, Shodan)
5. Aggregation: Combine results, calculate risk score
6. Output: Generate report, update SIEM, block list
7. Considerations: Rate limiting, error handling, caching
```

---

**Next: [00_INDEX.md](./00_INDEX.md) →**
