# 01 - Fundamentals: Networking & Protocols
## Security Perspective on OSI, TCP/IP, DNS, HTTP/S

---

## OSI Model - Security Perspective

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│ LAYER │ NAME         │ PROTOCOLS      │ SECURITY CONCERNS           │ TOOLS    │
├───────┼──────────────┼────────────────┼─────────────────────────────┼──────────┤
│   7   │ Application  │ HTTP, DNS,     │ SQL Injection, XSS,         │ Burp,    │
│       │              │ SMTP, FTP      │ Command Injection, RCE      │ ZAP      │
├───────┼──────────────┼────────────────┼─────────────────────────────┼──────────┤
│   6   │ Presentation │ SSL/TLS,       │ Downgrade attacks, Weak     │ testssl, │
│       │              │ MIME, ASCII    │ ciphers, Certificate issues │ sslyze   │
├───────┼──────────────┼────────────────┼─────────────────────────────┼──────────┤
│   5   │ Session      │ NetBIOS,       │ Session hijacking,          │ Wireshark│
│       │              │ RPC, SMB       │ Token theft                 │          │
├───────┼──────────────┼────────────────┼─────────────────────────────┼──────────┤
│   4   │ Transport    │ TCP, UDP       │ SYN flood, Port scanning,   │ nmap,    │
│       │              │                │ Session hijacking           │ hping3   │
├───────┼──────────────┼────────────────┼─────────────────────────────┼──────────┤
│   3   │ Network      │ IP, ICMP,      │ IP spoofing, MITM,          │ Scapy,   │
│       │              │ IPSec          │ Routing attacks             │ tracert  │
├───────┼──────────────┼────────────────┼─────────────────────────────┼──────────┤
│   2   │ Data Link    │ Ethernet,      │ ARP spoofing, MAC flooding, │ arpspoof,│
│       │              │ ARP, PPP       │ VLAN hopping                │ macof    │
├───────┼──────────────┼────────────────┼─────────────────────────────┼──────────┤
│   1   │ Physical     │ Cables,        │ Wiretapping, Physical       │ N/A      │
│       │              │ Signals        │ access attacks              │          │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Layer 7 - Application Layer Attacks

**Common Attacks:**
1. **SQL Injection** - Manipulating database queries
2. **XSS (Cross-Site Scripting)** - Injecting malicious scripts
3. **Command Injection** - Executing OS commands
4. **Directory Traversal** - Accessing unauthorized files
5. **XXE (XML External Entity)** - Exploiting XML parsers

**Detection:**
- WAF logs showing blocked requests
- Unusual characters in HTTP parameters (`'`, `"`, `<script>`, `../`)
- Error messages in responses (SQL errors, stack traces)

### Layer 4 - Transport Layer Attacks

**TCP Three-Way Handshake:**
```
Client                    Server
   │                         │
   │ ──── SYN ─────────────► │  Client initiates
   │                         │
   │ ◄──── SYN-ACK ───────── │  Server acknowledges
   │                         │
   │ ──── ACK ─────────────► │  Connection established
   │                         │
```

**SYN Flood Attack:**
```
Attacker sends thousands of SYN packets with spoofed source IPs
Server allocates resources for each half-open connection
Server's connection table fills up → Denial of Service

Detection:
- High volume of SYN packets without ACK
- Many half-open connections
- Source IP diversity analysis
```

**Port Scanning Types:**
| Scan Type | TCP Flags | Detection | Stealth Level |
|-----------|-----------|-----------|---------------|
| TCP Connect | Full handshake | Easy (logged) | Low |
| SYN Scan | SYN only | Medium | Medium |
| FIN Scan | FIN only | Hard | High |
| XMAS Scan | FIN+PSH+URG | Hard | High |
| NULL Scan | No flags | Hard | High |
| ACK Scan | ACK only | Medium | Medium |

### Layer 3 - Network Layer Attacks

**IP Spoofing:**
- Attacker forges source IP address
- Used in DDoS amplification, evading IP-based controls
- Detection: Impossible source IPs, TTL anomalies

**ICMP Attacks:**
- **Ping of Death**: Oversized ICMP packets
- **Smurf Attack**: ICMP echo to broadcast address with spoofed source
- **ICMP Redirect**: Manipulate routing tables

### Layer 2 - Data Link Layer Attacks

**ARP Spoofing/Poisoning:**
```
Normal:
  Victim ARP Cache: Gateway MAC = AA:BB:CC:DD:EE:FF

After ARP Spoofing:
  Victim ARP Cache: Gateway MAC = [Attacker's MAC]

Result: All traffic routes through attacker (MITM)

Detection:
- Multiple MACs claiming same IP
- Gratuitous ARP floods
- ARP cache inconsistencies
```

**MAC Flooding:**
- Overwhelm switch CAM table
- Switch fails open → acts as hub
- Attacker can sniff all traffic

**VLAN Hopping:**
- **Switch Spoofing**: Attacker negotiates trunk link
- **Double Tagging**: Nested VLAN tags to reach other VLANs

---

## TCP/IP Deep Dive

### TCP Header Structure (Important Fields)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│          Source Port          │        Destination Port       │
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│                        Sequence Number                        │
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│                     Acknowledgment Number                     │
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│Offset │ Res │U│A│P│R│S│F│          Window Size               │
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│           Checksum            │        Urgent Pointer         │
└─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┘

TCP Flags:
U = URG (Urgent)
A = ACK (Acknowledgment)
P = PSH (Push)
R = RST (Reset)
S = SYN (Synchronize)
F = FIN (Finish)
```

### Common Port Numbers (Must Know)

| Port | Service | Security Relevance |
|------|---------|-------------------|
| 20/21 | FTP | Cleartext, anonymous access |
| 22 | SSH | Brute force target, key-based auth critical |
| 23 | Telnet | Cleartext - NEVER use |
| 25 | SMTP | Spam relay, email spoofing |
| 53 | DNS | DNS tunneling, amplification attacks |
| 80 | HTTP | Web attacks, cleartext |
| 88 | Kerberos | Golden/Silver ticket attacks |
| 110 | POP3 | Cleartext email |
| 135 | MS-RPC | Lateral movement, WMI |
| 137-139 | NetBIOS | Legacy Windows attacks |
| 143 | IMAP | Cleartext email |
| 389 | LDAP | Directory enumeration |
| 443 | HTTPS | Encrypted web, inspect for threats |
| 445 | SMB | EternalBlue, ransomware spread |
| 636 | LDAPS | Secure LDAP |
| 993 | IMAPS | Secure IMAP |
| 995 | POP3S | Secure POP3 |
| 1433 | MSSQL | Database attacks |
| 1521 | Oracle | Database attacks |
| 3306 | MySQL | Database attacks |
| 3389 | RDP | Brute force, BlueKeep |
| 5432 | PostgreSQL | Database attacks |
| 5900 | VNC | Remote access abuse |
| 5985/5986 | WinRM | PowerShell remoting attacks |
| 8080 | HTTP Proxy | Web proxy attacks |
| 8443 | HTTPS Alt | Alternative HTTPS |

---

## DNS - Domain Name System

### DNS Record Types

| Type | Purpose | Security Relevance |
|------|---------|-------------------|
| A | IPv4 address | Domain → IP mapping |
| AAAA | IPv6 address | IPv6 domain resolution |
| CNAME | Alias | Subdomain takeover if dangling |
| MX | Mail server | Email security, SPF/DMARC |
| TXT | Text records | SPF, DKIM, DMARC, domain verification |
| NS | Name server | DNS delegation |
| SOA | Start of Authority | Zone information |
| PTR | Reverse DNS | IP → Domain (verification) |
| SRV | Service location | Service discovery |
| CAA | Certificate Authority Auth | Certificate issuance control |

### DNS Security Records

**SPF (Sender Policy Framework):**
```
v=spf1 ip4:192.168.1.0/24 include:_spf.google.com -all

v=spf1      → SPF version 1
ip4:        → Allowed sending IPs
include:    → Include another domain's SPF
-all        → Hard fail (reject if not matched)
~all        → Soft fail (mark but deliver)
?all        → Neutral (no policy)
+all        → Pass all (BAD - allows spoofing)
```

**DKIM (DomainKeys Identified Mail):**
```
selector._domainkey.example.com TXT "v=DKIM1; k=rsa; p=[public_key]"

- Cryptographic signature on email headers/body
- Receiving server verifies signature against public key in DNS
- Proves email wasn't modified in transit
```

**DMARC (Domain-based Message Authentication):**
```
_dmarc.example.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"

p=none      → Monitor only (no action)
p=quarantine → Send to spam
p=reject    → Reject email

rua=        → Aggregate report destination
ruf=        → Forensic report destination
```

### DNS Attacks

**1. DNS Cache Poisoning:**
```
Attacker injects false DNS records into resolver cache
Victim queries for bank.com → Gets attacker's IP

Detection:
- TTL anomalies
- Multiple different answers for same query
- Answers from unexpected sources
```

**2. DNS Tunneling (Exfiltration):**
```
Attacker encodes data in DNS queries:
  base64data.attacker-domain.com

Detection:
- Long subdomain strings
- High volume of DNS queries to single domain
- High entropy in subdomain names
- TXT record queries with base64 data
- Unusual query patterns (timing, volume)

Detection Query (Splunk):
index=dns
| eval subdomain_length=len(mvindex(split(query,"."),0))
| where subdomain_length > 30
| stats count by query, src_ip
| where count > 100
```

**3. DNS Amplification DDoS:**
```
Attacker sends DNS queries with spoofed source IP (victim)
DNS servers respond to victim with large responses
Amplification factor: 28-54x

Detection:
- High volume of DNS responses without queries
- Large DNS response packets
- ANY query type (returns all records)
```

**4. DNS Rebinding:**
```
1. Victim visits attacker.com
2. Attacker DNS responds with attacker IP
3. JavaScript loads from attacker IP
4. Attacker changes DNS to internal IP (127.0.0.1 or 192.168.x.x)
5. Same-origin policy bypassed - JavaScript accesses internal resources

Mitigation:
- DNS pinning
- Private IP blocking in DNS resolvers
```

---

## HTTP/HTTPS Deep Dive

### HTTP Methods

| Method | Purpose | Security Considerations |
|--------|---------|------------------------|
| GET | Retrieve resource | Parameters in URL (logged, cached) |
| POST | Submit data | Body data, form submissions |
| PUT | Update/Create resource | Often disabled, file upload risks |
| DELETE | Remove resource | Dangerous if exposed |
| PATCH | Partial update | Similar to PUT |
| OPTIONS | Query supported methods | Information disclosure |
| HEAD | GET without body | Reconnaissance |
| TRACE | Echo request | XST (Cross-Site Tracing) if enabled |
| CONNECT | Tunnel connection | Proxy abuse |

### HTTP Response Codes

| Code | Meaning | Security Relevance |
|------|---------|-------------------|
| 200 | OK | Normal response |
| 201 | Created | Resource created |
| 301/302 | Redirect | Open redirect vulnerabilities |
| 400 | Bad Request | Input validation |
| 401 | Unauthorized | Authentication required |
| 403 | Forbidden | Authorization failed (resource exists) |
| 404 | Not Found | Resource doesn't exist |
| 405 | Method Not Allowed | Method restriction |
| 500 | Internal Server Error | Potential info disclosure |
| 502/503 | Bad Gateway/Unavailable | Backend issues |

### Important HTTP Headers (Security)

**Request Headers:**
```
Host: example.com                    # Target host (required in HTTP/1.1)
User-Agent: Mozilla/5.0...           # Client identification
Cookie: session=abc123               # Session management
Authorization: Bearer eyJ...         # Authentication token
Content-Type: application/json       # Request body format
Origin: https://example.com          # CORS - request origin
Referer: https://example.com/page    # Previous page (typo is intentional)
X-Forwarded-For: 192.168.1.1         # Original client IP (through proxy)
```

**Response Headers (Security):**
```
# Content Security Policy - Prevent XSS
Content-Security-Policy: default-src 'self'; script-src 'self'

# Prevent MIME sniffing
X-Content-Type-Options: nosniff

# Clickjacking protection
X-Frame-Options: DENY
# or
Content-Security-Policy: frame-ancestors 'none'

# XSS Filter (legacy)
X-XSS-Protection: 1; mode=block

# HTTPS enforcement
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

# Referrer control
Referrer-Policy: strict-origin-when-cross-origin

# Feature restrictions
Permissions-Policy: geolocation=(), camera=(), microphone=()

# Cookie security
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict
```

### HTTPS/TLS Handshake

```
Client                                          Server
   │                                               │
   │ ────── ClientHello ─────────────────────────► │
   │        (TLS versions, cipher suites,          │
   │         random, extensions)                   │
   │                                               │
   │ ◄────── ServerHello ───────────────────────── │
   │         (Selected TLS version, cipher,        │
   │          random, extensions)                  │
   │                                               │
   │ ◄────── Certificate ───────────────────────── │
   │         (Server's X.509 certificate)          │
   │                                               │
   │ ◄────── ServerKeyExchange ─────────────────── │
   │         (DH parameters if needed)             │
   │                                               │
   │ ◄────── ServerHelloDone ───────────────────── │
   │                                               │
   │ ────── ClientKeyExchange ──────────────────► │
   │        (Pre-master secret encrypted           │
   │         with server's public key)             │
   │                                               │
   │ ────── ChangeCipherSpec ───────────────────► │
   │        (Switching to encrypted comms)         │
   │                                               │
   │ ────── Finished ───────────────────────────► │
   │        (Encrypted verification)               │
   │                                               │
   │ ◄────── ChangeCipherSpec ─────────────────── │
   │                                               │
   │ ◄────── Finished ─────────────────────────── │
   │                                               │
   │ ◄═══════ Encrypted Application Data ════════► │
```

### TLS Versions & Security

| Version | Status | Notes |
|---------|--------|-------|
| SSL 2.0 | BROKEN | Multiple vulnerabilities |
| SSL 3.0 | BROKEN | POODLE attack |
| TLS 1.0 | DEPRECATED | BEAST, CRIME attacks |
| TLS 1.1 | DEPRECATED | Weak by modern standards |
| TLS 1.2 | SECURE | Minimum acceptable (with good ciphers) |
| TLS 1.3 | RECOMMENDED | Current standard, PFS by default |

**TLS 1.3 Improvements:**
- Removed weak algorithms (RSA key exchange, SHA-1, RC4, DES, 3DES)
- Perfect Forward Secrecy mandatory
- 1-RTT handshake (faster)
- 0-RTT resumption (with replay protection)
- Encrypted handshake (SNI still visible, ESNI/ECH addresses this)

---

## Network Segmentation & Architecture

### Defense in Depth Network Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              INTERNET                                    │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                              ┌─────┴─────┐
                              │ Firewall  │ ← Perimeter defense
                              │   (FW1)   │
                              └─────┬─────┘
                                    │
┌───────────────────────────────────┴───────────────────────────────────┐
│                              DMZ                                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │
│  │ Web Servers │  │ Mail Relay  │  │ DNS Server  │  │ VPN Gateway │  │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  │
└───────────────────────────────────┬───────────────────────────────────┘
                                    │
                              ┌─────┴─────┐
                              │ Firewall  │ ← Internal firewall
                              │   (FW2)   │
                              └─────┬─────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
┌───────┴───────┐           ┌───────┴───────┐           ┌───────┴───────┐
│  User Network │           │ Server Network│           │  Management   │
│  (VLAN 10)    │           │  (VLAN 20)    │           │  (VLAN 99)    │
│               │           │               │           │               │
│ Workstations  │           │ App Servers   │           │ Jump Hosts    │
│ Printers      │           │ DB Servers    │           │ SIEM          │
│               │           │ File Servers  │           │ Admin Tools   │
└───────────────┘           └───────────────┘           └───────────────┘
```

### Zero Trust Network Principles

```
Traditional: "Trust but verify" (inside = trusted)
Zero Trust:  "Never trust, always verify"

Core Principles:
1. Verify explicitly (every request authenticated & authorized)
2. Least privilege access (minimum required permissions)
3. Assume breach (limit blast radius, segment, encrypt)

Implementation:
- Micro-segmentation (application-level isolation)
- Identity-based access (not network location)
- MFA everywhere
- Continuous verification (not just at login)
- Encrypt all traffic (even internal)
```

---

## Interview Questions - Fundamentals

### Basic Questions

1. **Explain the OSI model and where common attacks occur**
   - Layer 2: ARP spoofing, MAC flooding
   - Layer 3: IP spoofing, ICMP attacks
   - Layer 4: SYN flood, port scanning
   - Layer 7: SQL injection, XSS, RCE

2. **What happens when you type google.com in a browser?**
   - DNS resolution (recursive query)
   - TCP connection (3-way handshake)
   - TLS handshake (if HTTPS)
   - HTTP request/response
   - HTML parsing and rendering

3. **Difference between TCP and UDP?**
   - TCP: Connection-oriented, reliable, ordered, slower
   - UDP: Connectionless, unreliable, faster, used for DNS/video/gaming

4. **How does ARP work and how can it be exploited?**
   - ARP maps IP to MAC addresses
   - ARP cache poisoning sends fake responses
   - Used for MITM attacks
   - Detection: Static ARP entries, DAI, monitoring tools

### Advanced Questions

5. **How would you detect DNS tunneling?**
   - Long subdomain strings (>30 chars)
   - High entropy in subdomains
   - High volume to single domain
   - TXT record queries with base64
   - Abnormal query patterns

6. **Explain a TLS MITM attack and how to prevent it**
   - Attacker intercepts TLS handshake
   - Presents own certificate to client
   - Decrypts, inspects, re-encrypts traffic
   - Prevention: Certificate pinning, HSTS, CAA records

7. **What is the difference between SPF, DKIM, and DMARC?**
   - SPF: Which IPs can send email for domain
   - DKIM: Cryptographic signature on emails
   - DMARC: Policy for SPF/DKIM failures + reporting

8. **How would you detect a SYN flood attack?**
   - High volume of SYN packets
   - Many half-open connections
   - Source IP diversity
   - SYN:ACK ratio anomaly
   - Server resource exhaustion

---

**Next: [02_CRYPTOGRAPHY.md](./02_CRYPTOGRAPHY.md) - Encryption, Hashing, PKI, TLS/SSL →**
