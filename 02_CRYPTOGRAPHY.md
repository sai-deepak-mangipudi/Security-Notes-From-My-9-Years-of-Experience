# 02 - Cryptography
## Encryption, Hashing, PKI, Digital Signatures, Common Attacks

---

## Cryptography Fundamentals

### Core Concepts

```
CRYPTOGRAPHY TYPES
├── Symmetric Encryption (Same key for encrypt/decrypt)
│   ├── Block Ciphers: AES, DES, 3DES, Blowfish
│   └── Stream Ciphers: RC4 (broken), ChaCha20
├── Asymmetric Encryption (Public/Private key pair)
│   ├── RSA (2048+ bits)
│   ├── ECC (Elliptic Curve: P-256, P-384)
│   └── Diffie-Hellman (Key exchange)
├── Hashing (One-way function)
│   ├── MD5 (broken), SHA-1 (broken)
│   ├── SHA-2 (SHA-256, SHA-384, SHA-512)
│   └── SHA-3, BLAKE2, BLAKE3
└── Digital Signatures (Authentication + Integrity)
    ├── RSA signatures
    ├── ECDSA (Elliptic Curve DSA)
    └── EdDSA (Ed25519)
```

---

## Symmetric Encryption

### How It Works

```
Plaintext ──► [ Encryption ] ──► Ciphertext
                   │
              [ Same Key ]
                   │
Ciphertext ──► [ Decryption ] ──► Plaintext
```

### AES (Advanced Encryption Standard)

```
Key Sizes:
- AES-128: 128-bit key, 10 rounds
- AES-192: 192-bit key, 12 rounds
- AES-256: 256-bit key, 14 rounds (recommended)

Block Size: 128 bits (16 bytes)

Modes of Operation:
┌────────────────────────────────────────────────────────────────┐
│ Mode    │ Description              │ Security Notes            │
├─────────┼──────────────────────────┼───────────────────────────┤
│ ECB     │ Electronic Codebook      │ NEVER USE - patterns leak │
│ CBC     │ Cipher Block Chaining    │ Needs random IV, padding  │
│ CTR     │ Counter Mode             │ Parallelizable, no padding│
│ GCM     │ Galois/Counter Mode      │ RECOMMENDED - auth + enc  │
│ CCM     │ Counter with CBC-MAC     │ Authenticated encryption  │
└────────────────────────────────────────────────────────────────┘
```

**ECB Mode Problem (Visual Example):**
```
Original Image:          ECB Encrypted:         CBC/GCM Encrypted:
┌──────────────┐         ┌──────────────┐       ┌──────────────┐
│  ████████    │         │  ████████    │       │ ░▒▓█▓▒░▓█▒░ │
│  ████████    │  ───►   │  ████████    │       │ ▓░▒█░▓▒█░▓█ │
│    ████      │         │    ████      │       │ █▓░▒▓█░▒▓░▒ │
│    ████      │         │    ████      │       │ ░▒▓█▒░▓█▓░▒ │
└──────────────┘         └──────────────┘       └──────────────┘
                         Pattern preserved!     Looks random!
```

### Symmetric Encryption Best Practices

1. **Always use AES-256-GCM** (authenticated encryption)
2. **Never reuse IV/nonce** (especially with CTR/GCM modes)
3. **Use secure random for key/IV generation**
4. **Derive keys from passwords using KDF** (PBKDF2, Argon2, scrypt)
5. **Rotate keys periodically**

---

## Asymmetric Encryption

### How It Works

```
KEY GENERATION:
┌─────────────────────────────────────────────┐
│ Generate Key Pair                           │
│   ├── Private Key (keep secret)             │
│   └── Public Key (share freely)             │
└─────────────────────────────────────────────┘

ENCRYPTION (Confidentiality):
Plaintext ──► [ Encrypt with Recipient's PUBLIC Key ] ──► Ciphertext
Ciphertext ──► [ Decrypt with Recipient's PRIVATE Key ] ──► Plaintext

DIGITAL SIGNATURE (Authentication):
Message ──► [ Sign with Sender's PRIVATE Key ] ──► Signature
Signature ──► [ Verify with Sender's PUBLIC Key ] ──► Valid/Invalid
```

### RSA (Rivest-Shamir-Adleman)

```
Key Sizes and Security:
- RSA-1024: BROKEN (factorable)
- RSA-2048: Minimum acceptable (equivalent to 112-bit symmetric)
- RSA-3072: Recommended (equivalent to 128-bit symmetric)
- RSA-4096: High security (equivalent to ~140-bit symmetric)

Mathematical Basis:
- Based on difficulty of factoring large prime numbers
- n = p × q (two large primes)
- Public key: (n, e) where e is typically 65537
- Private key: d (derived from p, q, e)

Encryption: c = m^e mod n
Decryption: m = c^d mod n
```

### Elliptic Curve Cryptography (ECC)

```
Advantages over RSA:
- Smaller key sizes for equivalent security
- Faster operations
- Less bandwidth/storage

Key Size Comparison:
┌──────────────┬─────────────┬──────────────────────┐
│ Symmetric    │ RSA         │ ECC (NIST curves)    │
├──────────────┼─────────────┼──────────────────────┤
│ 80-bit       │ 1024-bit    │ 160-bit (P-160)      │
│ 112-bit      │ 2048-bit    │ 224-bit (P-224)      │
│ 128-bit      │ 3072-bit    │ 256-bit (P-256)      │
│ 192-bit      │ 7680-bit    │ 384-bit (P-384)      │
│ 256-bit      │ 15360-bit   │ 521-bit (P-521)      │
└──────────────┴─────────────┴──────────────────────┘

Common Curves:
- P-256 (secp256r1): Most common, NIST approved
- P-384 (secp384r1): Higher security
- Curve25519: Modern, high-performance (used in Signal, WireGuard)
- secp256k1: Bitcoin curve
```

### Diffie-Hellman Key Exchange

```
Purpose: Establish shared secret over insecure channel

Alice                                   Bob
  │                                      │
  │ Choose private: a                    │ Choose private: b
  │ Calculate: A = g^a mod p             │ Calculate: B = g^b mod p
  │                                      │
  │ ─────────── Send A ────────────────► │
  │ ◄─────────── Send B ───────────────  │
  │                                      │
  │ Calculate: s = B^a mod p             │ Calculate: s = A^b mod p
  │                                      │
  │ Shared Secret: s = g^(ab) mod p      │ Shared Secret: s = g^(ab) mod p
  │                                      │

Attack: Man-in-the-Middle (without authentication)
Solution: Use authenticated DH (signed public values)
```

---

## Hashing

### Hash Function Properties

```
1. DETERMINISTIC
   Same input → Always same output

2. ONE-WAY (Pre-image Resistance)
   Given hash H, computationally infeasible to find M where hash(M) = H

3. COLLISION RESISTANCE
   Computationally infeasible to find M1 ≠ M2 where hash(M1) = hash(M2)

4. AVALANCHE EFFECT
   Small change in input → Completely different output

   Example:
   SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
   SHA-256("hello.") = a6fb9e92139acb80a1925e8a3f6d6defd85b356d6d30c2f5b943df23e6ffbdb8
```

### Hash Algorithms Comparison

| Algorithm | Output Size | Security Status | Use Cases |
|-----------|-------------|-----------------|-----------|
| MD5 | 128 bits | **BROKEN** | File verification (non-security) |
| SHA-1 | 160 bits | **BROKEN** | Legacy systems only |
| SHA-256 | 256 bits | Secure | General purpose, certificates |
| SHA-384 | 384 bits | Secure | High security applications |
| SHA-512 | 512 bits | Secure | High security applications |
| SHA-3 | Variable | Secure | Alternative to SHA-2 |
| BLAKE2 | Variable | Secure | Fast, modern alternative |
| BLAKE3 | Variable | Secure | Fastest, newest |

### Password Hashing (Different from Regular Hashing)

```
NEVER use regular hash functions for passwords!

Why? Regular hashes are TOO FAST:
- SHA-256 can compute billions of hashes/second
- Makes brute-force attacks practical

Password Hashing Functions (Slow by Design):
┌────────────────────────────────────────────────────────────────────┐
│ Function │ Memory Hard │ Parallelism Resistant │ Recommended      │
├──────────┼─────────────┼───────────────────────┼──────────────────┤
│ bcrypt   │ No          │ Yes                   │ Yes (legacy)     │
│ scrypt   │ Yes         │ Yes                   │ Yes              │
│ Argon2id │ Yes         │ Yes                   │ BEST CHOICE      │
│ PBKDF2   │ No          │ No                    │ Only if required │
└────────────────────────────────────────────────────────────────────┘

Argon2 Parameters:
- Memory: 64 MB minimum (more = better)
- Iterations: 3+ (time parameter)
- Parallelism: Number of threads
- Salt: Random, unique per password

Example (Python):
argon2.hash("password",
            time_cost=3,      # iterations
            memory_cost=65536, # 64MB
            parallelism=4,     # threads
            salt=os.urandom(16))
```

### HMAC (Hash-based Message Authentication Code)

```
Purpose: Verify message integrity AND authenticity

HMAC = Hash(Key || Hash(Key || Message))

Example:
HMAC-SHA256("key", "message") = ...

Properties:
- Requires shared secret key
- Verifies both integrity and authenticity
- Used in: JWT, API authentication, session tokens

Common Uses:
- JWT signatures (HS256 = HMAC-SHA256)
- AWS request signing (AWS Signature v4)
- Cookie signing
- API authentication
```

---

## Public Key Infrastructure (PKI)

### Certificate Structure (X.509)

```
┌─────────────────────────────────────────────────────────────────┐
│ X.509 Certificate v3                                            │
├─────────────────────────────────────────────────────────────────┤
│ Version: 3                                                      │
│ Serial Number: 0x01:02:03:...                                   │
│ Signature Algorithm: SHA256withRSA                              │
│ Issuer: CN=Example CA, O=Example Inc, C=US                      │
│ Validity:                                                       │
│   Not Before: Jan 1, 2024                                       │
│   Not After: Dec 31, 2025                                       │
│ Subject: CN=www.example.com, O=Example Inc, C=US                │
│ Subject Public Key Info:                                        │
│   Algorithm: RSA                                                │
│   Public Key: (2048 bits)                                       │
│ Extensions:                                                     │
│   Subject Alternative Name (SAN): www.example.com, example.com  │
│   Key Usage: Digital Signature, Key Encipherment                │
│   Extended Key Usage: Server Authentication                     │
│   Basic Constraints: CA=FALSE                                   │
│   Certificate Policies: ...                                     │
│   CRL Distribution Points: http://crl.example.com               │
│   OCSP Responder: http://ocsp.example.com                       │
├─────────────────────────────────────────────────────────────────┤
│ Signature (by Issuer's Private Key)                             │
└─────────────────────────────────────────────────────────────────┘
```

### Certificate Chain of Trust

```
┌───────────────────────────────────────────────────────────────────┐
│                     ROOT CA (Self-signed)                         │
│                     "Trust Anchor"                                │
│                     Stored in OS/Browser trust store              │
└───────────────────────────────┬───────────────────────────────────┘
                                │ Signs
                                ▼
┌───────────────────────────────────────────────────────────────────┐
│                     INTERMEDIATE CA                               │
│                     Signed by Root CA                             │
│                     Issues end-entity certificates                │
└───────────────────────────────┬───────────────────────────────────┘
                                │ Signs
                                ▼
┌───────────────────────────────────────────────────────────────────┐
│                     END-ENTITY CERTIFICATE                        │
│                     (Server certificate, www.example.com)         │
│                     Signed by Intermediate CA                     │
└───────────────────────────────────────────────────────────────────┘

Verification Process:
1. Server presents certificate + intermediate chain
2. Client verifies signature chain up to trusted root
3. Client checks validity dates
4. Client checks revocation (CRL/OCSP)
5. Client verifies hostname matches SAN/CN
```

### Certificate Validation

```
CLIENT CERTIFICATE VALIDATION STEPS:

1. SIGNATURE VERIFICATION
   └── Verify each cert signed by issuer's public key

2. VALIDITY PERIOD
   └── NotBefore < CurrentTime < NotAfter

3. REVOCATION CHECK
   ├── CRL (Certificate Revocation List): Download list, check serial
   └── OCSP (Online Certificate Status Protocol): Real-time query

4. HOSTNAME VERIFICATION
   └── Certificate CN or SAN matches requested hostname

5. KEY USAGE
   └── Certificate authorized for intended use (server auth, code signing)

6. CHAIN COMPLETENESS
   └── Full chain to trusted root available

Common Issues:
- Expired certificate
- Self-signed certificate (not in trust store)
- Hostname mismatch
- Revoked certificate
- Missing intermediate certificates
- Weak signature algorithm (SHA-1)
```

### Certificate Types

| Type | Validation Level | What's Verified | Visual Indicator |
|------|------------------|-----------------|------------------|
| DV (Domain Validation) | Low | Domain control only | Padlock |
| OV (Organization Validation) | Medium | Domain + Organization identity | Padlock |
| EV (Extended Validation) | High | Domain + Org + Legal existence | Green bar (legacy) |

---

## Digital Signatures

### How Digital Signatures Work

```
SIGNING PROCESS:
┌────────────────────────────────────────────────────────────────────┐
│ 1. Hash the message: H = Hash(Message)                            │
│ 2. Encrypt hash with signer's private key: Sig = Encrypt(H, Priv) │
│ 3. Attach signature to message: Message + Signature               │
└────────────────────────────────────────────────────────────────────┘

VERIFICATION PROCESS:
┌────────────────────────────────────────────────────────────────────┐
│ 1. Separate message and signature                                 │
│ 2. Hash the received message: H1 = Hash(Message)                  │
│ 3. Decrypt signature with signer's public key: H2 = Decrypt(Sig)  │
│ 4. Compare: If H1 == H2, signature is valid                       │
└────────────────────────────────────────────────────────────────────┘

Properties Provided:
✓ AUTHENTICATION - Proves message from claimed sender
✓ INTEGRITY - Proves message not modified
✓ NON-REPUDIATION - Signer cannot deny signing
```

### Common Signature Algorithms

| Algorithm | Based On | Key Size | Notes |
|-----------|----------|----------|-------|
| RSA-SHA256 | RSA | 2048+ bits | Traditional, widely supported |
| ECDSA | ECC | 256+ bits | Smaller signatures, faster |
| Ed25519 | Curve25519 | 256 bits | Modern, fast, secure |
| EdDSA | Edwards curves | Variable | Newer standard |

---

## Common Cryptographic Attacks

### Symmetric Encryption Attacks

```
1. BRUTE FORCE
   Try all possible keys
   Defense: Use 256-bit keys (2^256 combinations)

2. KNOWN PLAINTEXT ATTACK
   Attacker has plaintext-ciphertext pairs
   Defense: Use secure modes (GCM), don't reuse keys

3. CHOSEN PLAINTEXT ATTACK
   Attacker can encrypt arbitrary plaintexts
   Defense: Randomized encryption (IV/nonce)

4. PADDING ORACLE ATTACK
   Exploit error messages about padding
   Defense: Use authenticated encryption (GCM), constant-time comparison

5. IV/NONCE REUSE
   Reusing IV in CTR/GCM modes leaks plaintext XOR
   Defense: Never reuse nonces, use random IVs
```

### Asymmetric Encryption Attacks

```
1. FACTORING ATTACK (RSA)
   Factor n into p and q
   Defense: Use 2048+ bit keys

2. SMALL EXPONENT ATTACK
   Using e=3 with same message to multiple recipients
   Defense: Use proper padding (OAEP), e=65537

3. TIMING ATTACK
   Measure computation time to deduce key
   Defense: Constant-time implementations

4. BLEICHENBACHER ATTACK (RSA PKCS#1 v1.5)
   Exploit padding oracle in PKCS#1 v1.5
   Defense: Use OAEP padding, TLS 1.3
```

### Hash Attacks

```
1. COLLISION ATTACK
   Find two inputs with same hash
   MD5: 2^18 operations
   SHA-1: 2^63 operations (SHAttered, 2017)

2. LENGTH EXTENSION ATTACK
   Append data to message without knowing original
   Affects: MD5, SHA-1, SHA-256 (Merkle-Damgård)
   Defense: Use HMAC, SHA-3, or truncated SHA-512

3. RAINBOW TABLE ATTACK
   Precomputed hash → plaintext tables
   Defense: Always use salts

4. BIRTHDAY ATTACK
   Find any collision in 2^(n/2) operations
   128-bit hash → 2^64 operations (feasible)
   256-bit hash → 2^128 operations (infeasible)
```

### TLS/SSL Attacks

```
┌──────────────────────────────────────────────────────────────────────┐
│ Attack         │ Year │ Affects    │ Description                    │
├────────────────┼──────┼────────────┼────────────────────────────────┤
│ BEAST          │ 2011 │ TLS 1.0    │ CBC IV predictability          │
│ CRIME          │ 2012 │ TLS        │ Compression side-channel       │
│ BREACH         │ 2013 │ HTTP+TLS   │ HTTP compression side-channel  │
│ Heartbleed     │ 2014 │ OpenSSL    │ Memory disclosure              │
│ POODLE         │ 2014 │ SSL 3.0    │ CBC padding oracle             │
│ FREAK          │ 2015 │ TLS        │ Export cipher downgrade        │
│ Logjam         │ 2015 │ TLS        │ DH 512-bit downgrade           │
│ DROWN          │ 2016 │ SSLv2      │ Cross-protocol attack          │
│ ROBOT          │ 2017 │ TLS        │ RSA decryption oracle          │
│ ROCA           │ 2017 │ RSA keys   │ Weak key generation            │
└──────────────────────────────────────────────────────────────────────┘

Mitigations:
- Disable SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1
- Use TLS 1.2 with AEAD ciphers (GCM)
- Prefer TLS 1.3
- Disable compression
- Use ECDHE for key exchange (PFS)
```

---

## Cryptography in Practice

### Secure Cipher Suite Selection

```
TLS 1.3 Cipher Suites (All secure):
- TLS_AES_256_GCM_SHA384
- TLS_AES_128_GCM_SHA256
- TLS_CHACHA20_POLY1305_SHA256

TLS 1.2 Recommended:
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305

Avoid:
- Anything with RC4, DES, 3DES
- Anything with MD5, SHA-1 for signatures
- RSA key exchange (no PFS)
- Export ciphers
- Anonymous DH (ADH)
- NULL ciphers
```

### Key Management Best Practices

```
1. KEY GENERATION
   - Use cryptographically secure random number generator
   - Generate keys on secure system
   - Use appropriate key sizes

2. KEY STORAGE
   - Hardware Security Module (HSM) for critical keys
   - Encrypted key stores
   - Memory protection (don't leave keys in memory)
   - Access controls

3. KEY ROTATION
   - Rotate keys regularly (annually for most use cases)
   - Rotate immediately if compromise suspected
   - Support key versioning

4. KEY DESTRUCTION
   - Secure deletion when no longer needed
   - Cryptographic erasure for encrypted data

5. KEY DISTRIBUTION
   - Use secure channels for key exchange
   - Key wrapping for transport
   - Split keys for sensitive operations
```

---

## Interview Questions - Cryptography

### Basic Questions

1. **Difference between symmetric and asymmetric encryption?**
   - Symmetric: Same key for encrypt/decrypt, fast, key distribution problem
   - Asymmetric: Different keys, slower, solves key distribution

2. **Why can't you use MD5/SHA-1 for security purposes?**
   - Collision attacks are practical
   - MD5: ~2^18 operations for collision
   - SHA-1: SHAttered attack (2017)

3. **What is Perfect Forward Secrecy (PFS)?**
   - Compromised long-term key doesn't compromise past sessions
   - Each session uses ephemeral keys
   - Achieved with ECDHE/DHE key exchange

4. **How does HTTPS protect data?**
   - TLS handshake establishes secure channel
   - Server authentication via certificates
   - Symmetric encryption for data (AES-GCM typically)
   - Integrity via MAC

### Advanced Questions

5. **Explain a padding oracle attack**
   - Attacker can determine if padding is valid
   - Iteratively decrypt ciphertext byte by byte
   - Affects CBC mode with PKCS#7 padding
   - Mitigation: Use authenticated encryption, constant-time comparison

6. **What's the difference between encryption and signing?**
   - Encryption: Encrypt with recipient's public key (confidentiality)
   - Signing: Sign with sender's private key (authentication, integrity, non-repudiation)

7. **How would you securely store passwords?**
   - Use Argon2id (preferred), bcrypt, or scrypt
   - Never MD5/SHA-256 directly
   - Use unique salt per password
   - Use appropriate work factors
   - Never store plaintext or reversible encryption

8. **What is key stretching and why is it important?**
   - Converting low-entropy password to high-entropy key
   - PBKDF2, bcrypt, scrypt, Argon2
   - Makes brute-force attacks slower
   - Adjustable work factor for hardware improvements

9. **Explain certificate pinning and its pros/cons**
   - Pros: Prevents MITM even with compromised CA
   - Cons: Certificate rotation challenges, bricking apps
   - Alternatives: Certificate Transparency, CAA records

---

**Next: [03_AUTH_IDENTITY.md](./03_AUTH_IDENTITY.md) - OAuth 2.0, OIDC, SAML, Kerberos, JWT →**
