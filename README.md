# 🔐 GhostCache

### Production-Grade End-to-End Encrypted Messaging Architecture

GhostCache is a privacy-first secure messaging system implementing a modern cryptographic stack inspired by the design principles of Signal and the Signal Protocol.

The server never has access to plaintext messages or private keys.

---

# 📌 Overview

GhostCache implements:

* Forward Secrecy
* End-to-End Encryption (E2EE)
* Authenticated Key Exchange
* Authenticated Encryption
* Zero Plaintext Key Storage
* Secure Password Hashing

The server acts strictly as:

* Public key distributor
* Ciphertext relay
* Encrypted message storage

---

# 🏗 Architecture

```
Client A  <—— TLS 1.3 ——>  GhostCache Server  <—— TLS 1.3 ——>  Client B
              (End-to-End Encrypted Content)
```

Security is layered:

| Layer          | Responsibility           |
| -------------- | ------------------------ |
| TLS 1.3        | Transport security       |
| X25519         | Ephemeral key exchange   |
| HKDF (SHA-256) | Key derivation           |
| AES-256-GCM    | Authenticated encryption |
| Ed25519        | Identity verification    |
| Argon2id       | Password hashing         |

---

# 🔐 Cryptographic Stack

## 1️⃣ Password Hashing — Argon2id

* Memory-hard
* Resistant to GPU attacks
* RFC 9106 compliant

**Purpose:** Protect stored credentials from brute-force attacks.

---

## 2️⃣ Identity Keys — Ed25519

Each user generates:

* Long-term Identity Private Key (Ed25519)
* Identity Public Key (stored on server)

Private keys are never stored in plaintext.

Used for:

* Digital signatures
* Identity verification
* Preventing impersonation

---

## 3️⃣ Key Exchange — X25519 (ECDH)

Each user also generates:

* Ephemeral ECDH Private Key
* Public ECDH Key

When two users connect:

```
shared_secret = private_key.exchange(peer_public_key)
```

Provides:

* Forward secrecy
* Secure session key agreement

---

## 4️⃣ Key Derivation — HKDF (SHA-256)

From the shared secret:

* AES encryption key derived
* Additional context-separated keys supported

Prevents:

* Key reuse
* Cross-protocol attacks

---

## 5️⃣ Message Encryption — AES-256-GCM

* 256-bit symmetric key
* 12-byte random nonce per message
* Authenticated encryption (AEAD)

Each message:

```
nonce + ciphertext + auth_tag
```

If modified → decryption fails.

---

# 🔁 Secure Messaging Flow

### Registration

* Password hashed using Argon2id
* Ed25519 + X25519 keys generated
* Public keys stored
* Private keys encrypted locally

---

### Session Establishment

1. Fetch recipient public keys
2. Verify identity
3. Perform X25519 exchange
4. Derive symmetric AES key via HKDF

---

### Message Sending

1. Generate random nonce
2. Encrypt using AES-256-GCM
3. Send ciphertext to server

Server stores ciphertext only.

---

### Message Receiving

1. Perform same key derivation
2. Decrypt using nonce
3. Authentication verified

---

# 🗄 Database Security Model

Stored on server:

| Data                   | Stored? |
| ---------------------- | ------- |
| Username               | ✔       |
| Argon2id Password Hash | ✔       |
| Ed25519 Public Key     | ✔       |
| X25519 Public Key      | ✔       |
| Private Keys           | ❌       |
| Plaintext Messages     | ❌       |
| Symmetric Keys         | ❌       |

---

# 🌐 Transport Security

* TLS 1.3 enforced
* HTTPS-only deployment
* Recommended reverse proxy: NGINX
* Certificates: Let's Encrypt

---

# 🛡 Threat Model & Protections

| Threat            | Mitigation                     |
| ----------------- | ------------------------------ |
| Database breach   | No private keys stored         |
| Server compromise | Messages remain encrypted      |
| MITM attack       | TLS 1.3 + signature validation |
| Replay attack     | Unique nonces                  |
| Cipher tampering  | AES-GCM authentication         |
| Brute force       | Argon2id                       |

---

# 📦 Technology Stack

| Layer            | Technology            |
| ---------------- | --------------------- |
| Backend          | Flask                 |
| Database         | SQLite / PostgreSQL   |
| Crypto           | cryptography (Python) |
| Password Hashing | argon2-cffi           |
| WSGI             | Gunicorn              |
| Reverse Proxy    | NGINX                 |
| TLS              | Let's Encrypt         |
| Version Control  | Git & GitHub          |

---

# 🚀 Production Deployment (Recommended)

* Deploy on Linux VPS
* Use Gunicorn + NGINX
* Enforce HTTPS only
* Disable TLS 1.2 and below
* Enable firewall rules
* Use environment variables for secrets

---

# 📜 Cryptographic Standards

GhostCache aligns with:

* RFC 7748 — X25519
* RFC 8032 — Ed25519
* RFC 5869 — HKDF
* RFC 4106 — AES-GCM
* RFC 9106 — Argon2
* RFC 8446 — TLS 1.3

---

# 🔭 Future Enhancements

* Double Ratchet Implementation
* Perfect Forward Secrecy per message
* Secure group messaging
* Key rotation policy
* Device-based key separation
* Metadata minimization

---

# ⚠ Disclaimer

GhostCache is an educational and architectural security project.
It should undergo professional cryptographic audit before production deployment in real-world high-risk environments.

---

# 👩‍💻 Author
Prathamesh Lakeshri

Secure Messaging Architecture Project

