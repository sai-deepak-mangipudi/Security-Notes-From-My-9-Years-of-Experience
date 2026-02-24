# 03 - Authentication & Identity
## OAuth 2.0, OIDC, SAML, Kerberos, JWT, LDAP, MFA

---

## Authentication vs Authorization

```
AUTHENTICATION (AuthN): "Who are you?"
├── Verifies identity
├── Credentials: passwords, biometrics, tokens, certificates
└── Result: Identity confirmed or denied

AUTHORIZATION (AuthZ): "What can you do?"
├── Determines permissions
├── Based on roles, attributes, policies
└── Result: Access granted or denied

Example:
1. User logs in with username/password → AUTHENTICATION
2. User tries to access /admin page → AUTHORIZATION check
3. If user has admin role → Access granted
4. If user doesn't have admin role → 403 Forbidden
```

---

## OAuth 2.0

### OAuth 2.0 Overview

```
PURPOSE: Delegated authorization (NOT authentication)
- Allow third-party access to resources without sharing credentials
- User grants specific permissions to applications

KEY TERMS:
┌──────────────────────────────────────────────────────────────────────┐
│ Resource Owner    │ User who owns the data                          │
│ Client            │ Application requesting access                   │
│ Authorization     │ Server that authenticates user and issues       │
│ Server            │ tokens (Google, Okta, Azure AD)                 │
│ Resource Server   │ API that holds protected resources              │
│ Access Token      │ Credential to access resources                  │
│ Refresh Token     │ Long-lived token to get new access tokens       │
│ Scope             │ Permissions requested (read, write, profile)    │
└──────────────────────────────────────────────────────────────────────┘
```

### OAuth 2.0 Grant Types

#### 1. Authorization Code Flow (Most Secure for Web Apps)

```
User        Client App       Auth Server       Resource Server
 │              │                 │                   │
 │ ─── 1. Click "Login" ──────►  │                   │
 │              │                 │                   │
 │ ◄── 2. Redirect to Auth ─────  │                   │
 │              │                 │                   │
 │ ─── 3. Login + Consent ──────────────────────────► │
 │              │                 │                   │
 │ ◄── 4. Redirect with Code ────  │                   │
 │              │                 │                   │
 │              │ ── 5. Exchange Code + Secret ────►  │
 │              │                 │                   │
 │              │ ◄── 6. Access Token + Refresh ────  │
 │              │                 │                   │
 │              │ ── 7. API Request + Token ─────────────────────────►
 │              │                 │                   │
 │              │ ◄── 8. Protected Resource ──────────────────────────
 │              │                 │                   │

Security Features:
- Authorization code is short-lived
- Code exchanged for token via back-channel
- Client secret never exposed to browser
```

#### 2. Authorization Code Flow with PKCE (Mobile/SPA)

```
PKCE = Proof Key for Code Exchange

1. Client generates:
   - code_verifier: Random string (43-128 chars)
   - code_challenge: Base64URL(SHA256(code_verifier))

2. Authorization Request includes code_challenge
3. Token Request includes code_verifier
4. Auth Server verifies: SHA256(code_verifier) == code_challenge

Why PKCE?
- Mobile apps can't securely store client_secret
- SPAs can't hide client_secret in browser
- Prevents authorization code interception attacks
```

#### 3. Client Credentials Flow (Machine-to-Machine)

```
Client                           Auth Server
   │                                  │
   │ ── POST /token ─────────────────►│
   │    client_id=xxx                 │
   │    client_secret=xxx             │
   │    grant_type=client_credentials │
   │    scope=api.read                │
   │                                  │
   │ ◄── Access Token ────────────────│
   │                                  │

Use Case: Backend service calling another API
No user involved, just service-to-service auth
```

#### 4. Implicit Flow (DEPRECATED - Do Not Use)

```
Problems:
- Access token exposed in URL fragment
- No refresh tokens
- Vulnerable to token leakage
- Cannot be secured with PKCE

Migration: Use Authorization Code with PKCE instead
```

### OAuth 2.0 Security Vulnerabilities

```
1. AUTHORIZATION CODE INJECTION
   Attacker injects their code into victim's session
   Mitigation: Use PKCE, validate state parameter

2. REDIRECT URI MANIPULATION
   Attacker modifies redirect_uri to steal code/token
   Mitigation: Exact redirect_uri matching, no wildcards

3. ACCESS TOKEN LEAKAGE
   Token exposed via Referer header, logs, browser history
   Mitigation: Use Authorization Code flow, short token lifetime

4. CSRF ATTACKS
   Attacker tricks user into authorizing attacker's account
   Mitigation: Use state parameter, validate on callback

5. SCOPE MANIPULATION
   Application requests more permissions than needed
   Mitigation: Principle of least privilege, user consent review

6. TOKEN THEFT
   XSS can steal tokens from localStorage
   Mitigation: Store tokens in HttpOnly cookies, use refresh token rotation
```

---

## OpenID Connect (OIDC)

### OIDC vs OAuth 2.0

```
OAuth 2.0: Authorization (access to resources)
OIDC: Authentication (user identity) built on top of OAuth 2.0

OIDC Adds:
├── ID Token (JWT with user identity)
├── UserInfo Endpoint
├── Standard Scopes (openid, profile, email)
├── Standard Claims (sub, name, email, etc.)
└── Discovery Endpoint (.well-known/openid-configuration)
```

### ID Token Structure

```
ID Token is a JWT with specific claims:

HEADER:
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-id-123"
}

PAYLOAD:
{
  "iss": "https://auth.example.com",    // Issuer
  "sub": "user123",                      // Subject (user ID)
  "aud": "client-app-id",                // Audience (client)
  "exp": 1700000000,                     // Expiration
  "iat": 1699996400,                     // Issued At
  "auth_time": 1699996300,               // Authentication time
  "nonce": "random-nonce-value",         // Replay protection
  "acr": "urn:mace:incommon:iap:silver", // Auth context class
  "amr": ["pwd", "mfa"],                 // Auth methods used
  "azp": "client-app-id",                // Authorized party

  // Standard claims
  "name": "John Doe",
  "email": "john@example.com",
  "email_verified": true,
  "picture": "https://..."
}

SIGNATURE:
RS256(base64(header) + "." + base64(payload), private_key)
```

### OIDC Standard Scopes

| Scope | Claims Returned |
|-------|-----------------|
| openid | sub (required for OIDC) |
| profile | name, family_name, given_name, picture, etc. |
| email | email, email_verified |
| address | address (structured) |
| phone | phone_number, phone_number_verified |

---

## SAML (Security Assertion Markup Language)

### SAML Overview

```
PURPOSE: Enterprise SSO, federated identity
VERSION: SAML 2.0 (most common)

KEY TERMS:
┌──────────────────────────────────────────────────────────────────────┐
│ Identity Provider (IdP) │ Authenticates users (Okta, Azure AD)      │
│ Service Provider (SP)   │ Application relying on IdP                │
│ Assertion              │ XML document with identity claims          │
│ SAML Request           │ AuthnRequest from SP to IdP               │
│ SAML Response          │ Assertion from IdP to SP                  │
│ Metadata               │ Configuration exchange (XML)              │
│ Binding                │ How messages are sent (POST, Redirect)    │
└──────────────────────────────────────────────────────────────────────┘
```

### SAML Authentication Flow

```
User          Service Provider         Identity Provider
 │                   │                        │
 │ ── 1. Access App ──►                       │
 │                   │                        │
 │ ◄── 2. Redirect with AuthnRequest ──────────►
 │                   │                        │
 │ ── 3. Login to IdP ──────────────────────────►
 │                   │                        │
 │ ◄── 4. SAML Response with Assertion ─────────
 │                   │                        │
 │ ── 5. POST Assertion to SP ──►             │
 │                   │                        │
 │                   │ (Verify signature,     │
 │                   │  extract claims)       │
 │                   │                        │
 │ ◄── 6. Access Granted ────                 │
 │                   │                        │
```

### SAML Assertion Structure

```xml
<saml:Assertion>
  <saml:Issuer>https://idp.example.com</saml:Issuer>

  <ds:Signature>
    <!-- XML Digital Signature -->
  </ds:Signature>

  <saml:Subject>
    <saml:NameID>user@example.com</saml:NameID>
    <saml:SubjectConfirmation Method="bearer">
      <saml:SubjectConfirmationData
        NotOnOrAfter="2024-01-01T12:05:00Z"
        Recipient="https://sp.example.com/saml/acs"/>
    </saml:SubjectConfirmation>
  </saml:Subject>

  <saml:Conditions
    NotBefore="2024-01-01T12:00:00Z"
    NotOnOrAfter="2024-01-01T12:05:00Z">
    <saml:AudienceRestriction>
      <saml:Audience>https://sp.example.com</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>

  <saml:AuthnStatement AuthnInstant="2024-01-01T12:00:00Z">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>
        urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
      </saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>

  <saml:AttributeStatement>
    <saml:Attribute Name="email">
      <saml:AttributeValue>user@example.com</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="groups">
      <saml:AttributeValue>admins</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>
```

### SAML Security Vulnerabilities

```
1. XML SIGNATURE WRAPPING (XSW)
   Attacker moves signed content, adds malicious content
   SP verifies signature but processes attacker's content
   Mitigation: Strict XML parsing, reference validation

2. XML EXTERNAL ENTITY (XXE)
   Malicious XML references external entities
   Can lead to SSRF, file disclosure
   Mitigation: Disable external entity processing

3. SIGNATURE BYPASS
   Missing or improper signature validation
   Mitigation: Always verify signature, check signed elements

4. ASSERTION REPLAY
   Reusing captured SAML assertion
   Mitigation: Check NotOnOrAfter, use one-time tokens

5. GOLDEN SAML
   Attacker with IdP signing key forges any assertion
   Mitigation: Protect IdP signing keys (HSM), rotate regularly

Detection:
- SAML assertions with unusual attributes
- Assertions signed by unknown certificates
- Time-based anomalies (future timestamps, expired assertions)
```

---

## Kerberos

### Kerberos Overview

```
PURPOSE: Network authentication protocol (Windows Active Directory)
VERSION: Kerberos V5

KEY COMPONENTS:
┌──────────────────────────────────────────────────────────────────────┐
│ KDC (Key Distribution Center)                                       │
│   ├── AS (Authentication Service): Issues TGT                       │
│   └── TGS (Ticket Granting Service): Issues Service Tickets         │
│                                                                      │
│ Principal: User or service identity (user@REALM.COM)                │
│ TGT (Ticket Granting Ticket): "Passport" for requesting service tix │
│ Service Ticket: Access to specific service                          │
│ Realm: Administrative domain (usually AD domain)                    │
│ KRBTGT: KDC service account (critical!)                             │
└──────────────────────────────────────────────────────────────────────┘
```

### Kerberos Authentication Flow

```
User                   KDC (DC)                 Service
 │                        │                        │
 │ ─── AS-REQ ──────────► │                        │
 │     (username)         │                        │
 │                        │                        │
 │ ◄─── AS-REP ────────── │                        │
 │      (TGT encrypted    │                        │
 │       with KRBTGT key) │                        │
 │                        │                        │
 │ ─── TGS-REQ ─────────► │                        │
 │     (TGT + target SPN) │                        │
 │                        │                        │
 │ ◄─── TGS-REP ───────── │                        │
 │      (Service Ticket)  │                        │
 │                        │                        │
 │ ─── AP-REQ ───────────────────────────────────► │
 │     (Service Ticket)   │                        │
 │                        │                        │
 │ ◄─── AP-REP ─────────────────────────────────── │
 │      (Optional mutual  │                        │
 │       authentication)  │                        │

Windows Event IDs:
4768 - TGT requested (AS-REQ)
4769 - Service Ticket requested (TGS-REQ)
4770 - Service Ticket renewed
4771 - Kerberos pre-authentication failed
```

### Kerberos Attacks

#### 1. Kerberoasting

```
Attack: Request TGS for services, crack offline

Process:
1. Enumerate SPNs: Get-ADUser -Filter {ServicePrincipalName -ne "$null"}
2. Request TGS for each SPN (legitimate operation)
3. Extract ticket (encrypted with service account password hash)
4. Crack offline with hashcat/john

Detection:
- Event 4769 with encryption type 0x17 (RC4)
- Single user requesting many TGS tickets
- TGS requests for unusual SPNs
- Service accounts with weak passwords

Splunk Query:
index=windows EventCode=4769 TicketEncryptionType=0x17
| stats count dc(ServiceName) as unique_spns by TargetUserName
| where unique_spns > 10

Mitigation:
- Strong passwords for service accounts (25+ chars)
- Disable RC4 encryption
- Use group Managed Service Accounts (gMSA)
- Monitor for Kerberoasting patterns
```

#### 2. AS-REP Roasting

```
Attack: Target accounts without pre-authentication required

Process:
1. Find accounts with DONT_REQUIRE_PREAUTH flag
2. Request AS-REP (no password needed)
3. Extract encrypted portion
4. Crack offline

Detection:
- Event 4768 without prior 4771 failure
- Accounts with pre-auth disabled
- Multiple AS-REQ from single source

Mitigation:
- Enable pre-authentication for all accounts
- Monitor for DONT_REQUIRE_PREAUTH accounts
```

#### 3. Golden Ticket Attack

```
Attack: Forge TGT with KRBTGT hash (full domain compromise)

Requirements:
- KRBTGT password hash
- Domain SID

Process:
1. Compromise DC, extract KRBTGT hash (mimikatz: lsadump::dcsync /user:krbtgt)
2. Forge TGT for any user (including non-existent)
3. Use forged TGT to request service tickets

Detection:
- TGT with unusual lifetime (default 10 hours, Golden often 10 years)
- TGT for non-existent user
- TGS without corresponding AS-REQ
- SID history anomalies

Mitigation:
- Reset KRBTGT password twice
- Monitor Domain Admin account usage
- Use Protected Users group
- Enable Credential Guard
```

#### 4. Silver Ticket Attack

```
Attack: Forge Service Ticket with service account hash

Requirements:
- Service account password hash
- Service SPN
- Domain SID

Less powerful than Golden Ticket:
- Only access to specific service
- Doesn't touch KDC (harder to detect)

Detection:
- Service authentication without TGS-REQ to DC
- Anomalous service ticket properties
- PAC validation failures
```

#### 5. Pass-the-Ticket (PtT)

```
Attack: Use stolen Kerberos ticket for authentication

Process:
1. Extract tickets from memory (mimikatz: sekurlsa::tickets)
2. Inject into current session
3. Authenticate as ticket owner

Detection:
- Same ticket used from multiple IPs
- Ticket used after user logged off
- Anomalous ticket usage patterns
```

---

## JWT (JSON Web Token)

### JWT Structure

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJhZG1pbiI6dHJ1ZX0.
TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ

Three parts (base64url encoded):
1. HEADER: {"alg": "HS256", "typ": "JWT"}
2. PAYLOAD: {"sub": "1234567890", "name": "John", "admin": true}
3. SIGNATURE: HMAC-SHA256(header + "." + payload, secret)
```

### JWT Security Vulnerabilities

```
1. ALGORITHM CONFUSION (alg:none)
   Change algorithm to "none", signature not verified
   {"alg": "none", "typ": "JWT"}

   Mitigation: Always validate algorithm, whitelist allowed algorithms

2. RSA/HMAC CONFUSION
   Change RS256 to HS256, use public key as HMAC secret
   Server uses public key (known) as HMAC key

   Mitigation: Strict algorithm validation, separate key handling

3. WEAK SECRETS
   HMAC secret can be brute-forced

   Mitigation: Use strong secrets (256+ bits), prefer RSA/ECDSA

4. TOKEN INJECTION IN HEADER
   kid parameter can be exploited for injection
   {"alg": "HS256", "kid": "../../etc/passwd"}

   Mitigation: Sanitize kid parameter, use whitelist

5. JKU/X5U HEADER INJECTION
   Point to attacker-controlled key server

   Mitigation: Whitelist allowed key URLs

6. NO EXPIRATION
   Token valid forever if no exp claim

   Mitigation: Always include exp claim, validate server-side

7. TOKEN SIDEJACKING
   Token stolen via XSS

   Mitigation: HttpOnly cookies, short expiration, refresh tokens
```

### JWT Best Practices

```
1. Use asymmetric algorithms (RS256, ES256) for distributed systems
2. Use HMAC (HS256) only with strong secrets for single-service
3. Always validate: signature, exp, iss, aud
4. Keep tokens short-lived (15 min - 1 hour)
5. Use refresh tokens for longer sessions
6. Store in HttpOnly cookies (not localStorage)
7. Include minimum necessary claims
8. Never store sensitive data in payload (it's just base64)
```

---

## LDAP (Lightweight Directory Access Protocol)

### LDAP Structure

```
LDAP Directory (Tree Structure):
dc=example,dc=com
├── ou=Users
│   ├── cn=John Doe,ou=Users,dc=example,dc=com
│   └── cn=Jane Smith,ou=Users,dc=example,dc=com
├── ou=Groups
│   ├── cn=Admins,ou=Groups,dc=example,dc=com
│   └── cn=Developers,ou=Groups,dc=example,dc=com
└── ou=Computers
    └── cn=WKS001,ou=Computers,dc=example,dc=com

Common Attributes:
- cn: Common Name
- dn: Distinguished Name (full path)
- uid: User ID
- ou: Organizational Unit
- dc: Domain Component
- sAMAccountName: Windows logon name
- memberOf: Group membership
- userAccountControl: Account flags
```

### LDAP Injection

```
Vulnerable Query:
(&(uid={user_input})(password={password}))

Attack Input:
user_input = "*)(uid=*))(|(uid=*"

Resulting Query:
(&(uid=*)(uid=*))(|(uid=*)(password=anything))

Always returns results!

Mitigation:
- Input validation
- Use parameterized LDAP queries
- Escape special characters: * ( ) \ NUL
```

### LDAP Security

```
LDAP: Port 389 (cleartext)
LDAPS: Port 636 (TLS)
LDAP+STARTTLS: Port 389 → encrypted

Security Concerns:
1. Anonymous binds (information disclosure)
2. Cleartext passwords
3. LDAP injection
4. Privilege escalation via group manipulation

Detection:
- Unusual LDAP queries (enumeration)
- Anonymous bind attempts
- Queries for sensitive attributes (password hashes)
- Large result sets (data exfiltration)
```

---

## Multi-Factor Authentication (MFA)

### MFA Factors

```
SOMETHING YOU KNOW (Knowledge)
├── Password
├── PIN
└── Security questions

SOMETHING YOU HAVE (Possession)
├── Hardware token (YubiKey)
├── Software token (Authenticator app)
├── Smart card
├── Phone (SMS, push notification)
└── Email (one-time code)

SOMETHING YOU ARE (Inherence)
├── Fingerprint
├── Face recognition
├── Iris scan
├── Voice recognition
└── Behavioral biometrics
```

### MFA Methods Comparison

| Method | Security | Usability | Phishing Resistant |
|--------|----------|-----------|-------------------|
| SMS OTP | Low | High | No |
| Email OTP | Low | High | No |
| TOTP (Authenticator) | Medium | Medium | No |
| Push Notification | Medium | High | Partially |
| FIDO2/WebAuthn | High | High | Yes |
| Hardware Token | High | Low | Yes |
| Biometrics | High | High | Partially |

### MFA Attacks

```
1. SIM SWAPPING
   Attacker takes over victim's phone number
   Intercepts SMS OTP

2. REAL-TIME PHISHING (MFA Relay)
   Attacker proxies login in real-time
   Captures and uses MFA code immediately
   Tools: Evilginx2, Modlishka

3. MFA FATIGUE
   Repeatedly send push notifications
   User eventually approves out of frustration

4. SS7 EXPLOITATION
   Intercept SMS via SS7 network vulnerabilities

5. MFA BYPASS
   Exploit misconfigured MFA (legacy protocols, fallback methods)

6. SESSION HIJACKING
   Steal session cookie after MFA completion

Mitigation:
- Use phishing-resistant MFA (FIDO2/WebAuthn)
- Implement number matching for push
- Rate limit MFA attempts
- Monitor for MFA anomalies
- Disable legacy protocols
```

---

## Interview Questions - Authentication & Identity

### Basic Questions

1. **Explain OAuth 2.0 Authorization Code flow**
   - User clicks login → Redirect to auth server
   - User authenticates → Auth server issues code
   - App exchanges code for token (back-channel)
   - App uses token to access resources

2. **What's the difference between OAuth 2.0 and OIDC?**
   - OAuth 2.0: Authorization (access to resources)
   - OIDC: Authentication (user identity) + ID Token + UserInfo endpoint

3. **What is a Golden Ticket attack?**
   - Forge Kerberos TGT using KRBTGT hash
   - Full domain compromise
   - Impersonate any user
   - Detection: Unusual TGT lifetime, missing AS-REQ

4. **Why is SMS MFA considered weak?**
   - SIM swapping attacks
   - SS7 vulnerabilities
   - Social engineering
   - Not phishing-resistant

### Advanced Questions

5. **How would you detect Kerberoasting?**
   - Event 4769 with RC4 encryption (0x17)
   - Single user requesting many TGS tickets
   - Unusual SPN access patterns
   - Service accounts with recent password cracks

6. **Explain JWT algorithm confusion attack**
   - Change RS256 to HS256
   - Server verifies HMAC with RSA public key
   - Attacker signs with public key (known)
   - Mitigation: Validate algorithm explicitly

7. **How does PKCE protect OAuth flows?**
   - code_verifier: Random string generated by client
   - code_challenge: Hash of code_verifier
   - Auth server verifies on token exchange
   - Prevents code interception attacks

8. **What is a SAML Golden Ticket (Golden SAML)?**
   - Attacker compromises ADFS signing certificate
   - Forge SAML assertions for any user
   - Access all federated services
   - Detection: Monitor certificate usage, SAML anomalies

---

**Next: [04_MITRE_ATTACK.md](./04_MITRE_ATTACK.md) - Complete MITRE ATT&CK Framework Reference →**
