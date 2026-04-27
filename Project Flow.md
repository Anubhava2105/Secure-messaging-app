# Secure Messaging App — Complete Project Explanation

## Table of Contents

1. [Why This Project Exists](Project%20Flow.md#1-why-this-project-exists)
2. [The Problem It Solves](Project%20Flow.md#2-the-problem-it-solves)
3. [How It Is Useful](Project%20Flow.md#3-how-it-is-useful)
4. [High-Level Architecture](Project%20Flow.md#4-high-level-architecture)
5. [The Cryptographic Design](Project%20Flow.md#5-the-cryptographic-design)
6. [Key Exchange Protocol — Step by Step](Project%20Flow.md#6-key-exchange-protocol--step-by-step)
7. [Message Encryption Flow](Project%20Flow.md#7-message-encryption-flow)
8. [Double Ratchet & Forward Secrecy](Project%20Flow.md#8-double-ratchet--forward-secrecy)
9. [Trust & Identity Verification](Project%20Flow.md#9-trust--identity-verification)
10. [Server Design — Zero-Knowledge Relay](Project%20Flow.md#10-server-design--zero-knowledge-relay)
11. [Client Application](Project%20Flow.md#11-client-application)
12. [Electron Desktop Shell](Project%20Flow.md#12-electron-desktop-shell)
13. [Data Storage & Persistence](Project%20Flow.md#13-data-storage--persistence)
14. [Group Messaging](Project%20Flow.md#14-group-messaging)
15. [Real-Time Communication (WebSocket)](Project%20Flow.md#15-real-time-communication-websocket)
16. [Security Measures Summary](Project%20Flow.md#16-security-measures-summary)
17. [Technology Stack](Project%20Flow.md#17-technology-stack)
18. [Project Structure](Project%20Flow.md#18-project-structure)

---

## 1. Why This Project Exists

The world relies on encrypted messaging (WhatsApp, Signal, iMessage), but there is an emerging threat that most people don't think about: **quantum computers**.

Today's encryption (RSA, Elliptic Curve Cryptography) is mathematically secure against classical computers. But quantum computers, once sufficiently powerful, will be able to break these algorithms in polynomial time using Shor's algorithm. Intelligence agencies and adversaries know this, so they are executing a strategy called **"Harvest Now, Decrypt Later" (HNDL)** — recording encrypted internet traffic today with the intention of decrypting it years from now when quantum computers become available.

This project exists to demonstrate and implement a **post-quantum resistant** secure messaging system that protects conversations not just today, but against future quantum threats.

---

## 2. The Problem It Solves

### 2.1 The Quantum Threat

- Classical encryption (ECC, RSA) will be broken by sufficiently large quantum computers.
- Adversaries are already recording encrypted traffic for future decryption.
- Messages sent today using only classical encryption may be readable in 10–15 years.

### 2.2 The Trust Problem

- Most messaging apps require you to trust the server operator.
- Server operators can potentially read messages, comply with government requests, or be hacked.
- Users need a system where the server is mathematically incapable of reading messages.

### 2.3 The Forward Secrecy Problem

- If a long-term key is compromised, all past and future messages encrypted with it are exposed.
- A proper system should ensure that compromising one key only exposes a minimal window of messages.

---

## 3. How It Is Useful

| Use Case | How This Project Addresses It |
|----------|-------------------------------|
| **Journalists & whistleblowers** | Messages cannot be decrypted even if intercepted by state actors today or in the future |
| **Enterprise communications** | Zero-knowledge server means even the hosting company cannot read messages |
| **Long-term sensitive data** | Medical, legal, financial discussions remain private for decades |
| **Research & education** | Demonstrates practical hybrid PQC implementation for developers and cryptographers |
| **Compliance** | Meets emerging NIST post-quantum standards (FIPS 203 for ML-KEM) |

---

## 4. High-Level Architecture

The system has three main components:

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT (Trust Zone)                        │
│                                                                   │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────┐ │
│  │   React  │  │   Crypto     │  │   Session    │  │  Key    │ │
│  │    UI    │  │   Module     │  │   Manager    │  │  Store  │ │
│  └──────────┘  └──────────────┘  └──────────────┘  └─────────┘ │
│                                                                   │
│  All encryption/decryption happens HERE. Private keys never leave.│
└───────────────────────────────┬───────────────────────────────────┘
                                │ Encrypted blobs only
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    SERVER (Untrusted Zone)                        │
│                                                                   │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │ Fastify  │  │  WebSocket   │  │   SQLite     │              │
│  │   API    │  │   Relay      │  │   Storage    │              │
│  └──────────┘  └──────────────┘  └──────────────┘              │
│                                                                   │
│  Cannot decrypt anything. Routes opaque binary blobs.             │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ELECTRON (Desktop Shell)                       │
│                                                                   │
│  Security-hardened wrapper: sandbox, context isolation, CSP       │
└─────────────────────────────────────────────────────────────────┘
```

**Key principle:** The server is assumed to be hostile. It is designed as a "dumb pipe" that routes encrypted data between users without any ability to inspect, modify, or decrypt it.

---

## 5. The Cryptographic Design

### 5.1 The Hybrid Approach

This project uses a **hybrid** cryptographic design, combining:

1. **Classical ECC (Elliptic Curve Cryptography)** — proven, fast, well-audited, secure against classical computers.
2. **Post-Quantum ML-KEM-768 (Kyber)** — resistant to quantum attacks, standardized by NIST as FIPS 203.

The security guarantee: **an attacker must break BOTH** the classical and post-quantum layers to compromise a session. If either one holds, the communication remains secure.

### 5.2 Cryptographic Primitives Used

| Layer | Algorithm | Purpose | Standard |
|-------|-----------|---------|----------|
| Key Agreement (Classical) | ECDH P-384 | Derive shared secrets between two parties | NIST FIPS 186-4 |
| Key Agreement (Post-Quantum) | ML-KEM-768 | Quantum-resistant key encapsulation | NIST FIPS 203 |
| Digital Signatures | ECDSA P-384 + SHA-384 | Sign prekeys to prove authenticity | NIST FIPS 186-4 |
| Key Derivation | HKDF-SHA-384 | Derive session keys from shared secrets | RFC 5869 |
| Symmetric Encryption | AES-GCM-256 | Encrypt/decrypt message content | NIST SP 800-38D |
| Randomness | `crypto.getRandomValues()` | Cryptographically secure random bytes | Web Crypto API |
| Hashing | SHA-256, SHA-384 | Fingerprints, HMAC, integrity | NIST FIPS 180-4 |

### 5.3 Key Hierarchy

```
Identity Keys (long-lived)
├── ECC Identity Key Pair (P-384) — proves who you are
├── PQC Identity Key Pair (ML-KEM-768) — quantum-resistant identity
└── Signing Key Pair (ECDSA P-384) — signs prekeys

Signed Prekeys (medium-lived, rotated periodically)
├── Signed Prekey ECC — for X3DH key agreement
└── Signed Prekey PQC — for quantum-resistant encapsulation

One-Time Prekeys (single-use, consumed on first message)
└── One-Time Prekey ECC — additional forward secrecy

Session Keys (ephemeral, per-conversation)
├── Encryption Key (32 bytes) — AES-GCM-256 message encryption
├── MAC Key (32 bytes) — message authentication
└── Root Key (32 bytes) — derives new chain keys via ratchet
```

---

## 6. Key Exchange Protocol — Step by Step

The protocol is a **Hybrid X3DH** (Extended Triple Diffie-Hellman), combining Signal's X3DH with post-quantum KEM.

### 6.1 Setup Phase (Registration)

When a user registers:

1. Generate ECC Identity Key Pair (P-384 ECDH)
2. Generate PQC Identity Key Pair (ML-KEM-768)
3. Generate Signing Key Pair (ECDSA P-384)
4. Generate Signed Prekey ECC + sign it with signing key
5. Generate Signed Prekey PQC + sign it with signing key
6. Generate batch of One-Time Prekeys (ECC)
7. Upload all public keys + signatures to the server

### 6.2 Initiator Handshake (Alice wants to message Bob)

```
Step 1: Alice fetches Bob's prekey bundle from the server
        Bundle = {IK_ecc_pub, IK_pqc_pub, SPK_ecc_pub, SPK_pqc_pub, 
                  OPK_ecc_pub, signatures, signing_key_pub}

Step 2: Alice verifies Bob's prekey signatures using his signing key
        → Ensures the prekeys genuinely belong to Bob

Step 3: Alice generates an ephemeral ECC key pair (EK)

Step 4: Alice computes 3-4 ECDH shared secrets:
        DH1 = ECDH(Alice_IK_private, Bob_SPK_public)    — identity ↔ signed prekey
        DH2 = ECDH(Alice_EK_private, Bob_IK_public)     — ephemeral ↔ identity
        DH3 = ECDH(Alice_EK_private, Bob_SPK_public)    — ephemeral ↔ signed prekey
        DH4 = ECDH(Alice_EK_private, Bob_OPK_public)    — ephemeral ↔ one-time (optional)

Step 5: Alice performs ML-KEM encapsulation against Bob's PQC prekey:
        (ciphertext, pqc_shared_secret) = ML-KEM.Encaps(Bob_SPK_pqc_pub)

Step 6: Alice derives session keys using HKDF:
        IKM = DH1 || DH2 || DH3 || [DH4] || pqc_shared_secret
        context = "SecureMsg-Handshake-v1" || Alice_IK_pub || Bob_IK_pub
        session_keys = HKDF-SHA-384(salt, IKM, context, 96 bytes)
        
        Output: encryption_key (32B) + mac_key (32B) + root_key (32B)

Step 7: Alice sends handshake message to Bob:
        {version, Alice_IK_ecc_pub, Alice_EK_ecc_pub, pqc_ciphertext, OPK_id}
```

### 6.3 Responder Handshake (Bob receives Alice's first message)

```
Step 1: Bob receives the handshake message attached to the encrypted message

Step 2: Bob computes the same ECDH shared secrets (reversed roles):
        DH1 = ECDH(Bob_SPK_private, Alice_IK_public)
        DH2 = ECDH(Bob_IK_private, Alice_EK_public)
        DH3 = ECDH(Bob_SPK_private, Alice_EK_public)
        DH4 = ECDH(Bob_OPK_private, Alice_EK_public)    — if OPK was used

Step 3: Bob decapsulates the PQC shared secret:
        pqc_shared_secret = ML-KEM.Decaps(ciphertext, Bob_SPK_pqc_private)

Step 4: Bob derives the same session keys using identical HKDF parameters

Step 5: Bob deletes the consumed one-time prekey (single-use guarantee)

Step 6: Both parties now share identical session keys
```

### 6.4 Why This Works

- **DH1** binds Alice's identity to Bob's signed prekey → proves Alice initiated
- **DH2** binds Alice's ephemeral key to Bob's identity → forward secrecy
- **DH3** binds Alice's ephemeral key to Bob's signed prekey → additional binding
- **DH4** uses a one-time prekey → prevents replay of old handshakes
- **PQC shared secret** → even if all ECC is broken by quantum computers, this secret remains safe

---

## 7. Message Encryption Flow

Once a session is established, every message is encrypted as follows:

### 7.1 Sending a Message

```
1. Advance the send chain key using HMAC-SHA-384 ratchet:
   next_chain_key = HMAC(current_chain_key, "SecureMsg-ChainStep-v1")
   message_key = HMAC(current_chain_key, "SecureMsg-MessageKey-v1")[0:32]

2. Generate a random 12-byte nonce (for AES-GCM)

3. Build Additional Authenticated Data (AAD):
   AAD = "v1|messageId|senderId|recipientId|groupId|eventType|commitment"

4. Encrypt: ciphertext = AES-GCM-256(message_key, nonce, plaintext, AAD)

5. Combine: blob = nonce (12 bytes) || ciphertext (includes 16-byte auth tag)

6. Base64-encode the blob and send via WebSocket
```

### 7.2 Receiving a Message

```
1. Advance the receive chain key (or look up skipped key for out-of-order messages)

2. Extract nonce (first 12 bytes) and ciphertext from the blob

3. Reconstruct the same AAD from message metadata

4. Decrypt: plaintext = AES-GCM-256.Decrypt(message_key, nonce, ciphertext, AAD)
   → If AAD doesn't match (tampered metadata), decryption fails

5. Display the plaintext message
```

### 7.3 AAD (Additional Authenticated Data)

The AAD binds the encrypted content to its metadata. This means:
- You cannot take an encrypted message and re-attribute it to a different sender
- You cannot move a message from one conversation to another
- You cannot replay a group message into a different group
- Any tampering with metadata causes decryption to fail

---

## 8. Double Ratchet & Forward Secrecy

### 8.1 Symmetric Ratchet (Chain Key Ratchet)

Every message advances the chain key forward:

```
chain_key[0] → chain_key[1] → chain_key[2] → ...
     ↓              ↓              ↓
message_key[0]  message_key[1]  message_key[2]
```

Each message key is derived from the current chain key, then the chain key advances. Old chain keys are deleted. This means:
- Compromising `chain_key[5]` reveals messages 5, 6, 7... but NOT messages 0–4
- Each message has a unique one-time key

### 8.2 Asymmetric Ratchet (DH Ratchet)

Periodically, users exchange new ephemeral ECDH public keys (ratchet keys). When a new ratchet key arrives:

```
1. Perform ECDH with the new remote ratchet key and local private key
2. Derive new root key and chain key from the DH output
3. Generate a new local ratchet key pair
4. Announce the new public key in the next outgoing message
```

This provides **post-compromise security**: even if an attacker compromises the current session state, once a new DH ratchet step occurs, they lose access again.

### 8.3 Out-of-Order Message Handling

Messages may arrive out of order over the network. The system handles this by:
- Tracking expected message numbers per ratchet epoch
- Caching "skipped" message keys for messages that haven't arrived yet
- Limiting the gap (max 64 skipped messages) to prevent resource exhaustion
- Limiting total cached keys (max 128) with LRU eviction

---

## 9. Trust & Identity Verification

### 9.1 Trust-On-First-Use (TOFU)

When you first communicate with someone:
1. Their identity key fingerprints are recorded locally
2. The contact is marked as "unverified" — you trust them provisionally
3. Users are encouraged to verify fingerprints out-of-band (in person, phone call)

### 9.2 Key Change Detection

If a contact's identity keys change (they re-registered, or an attacker is impersonating them):
1. The system detects the fingerprint mismatch
2. The contact is marked as "changed" — messaging is **blocked**
3. The user must explicitly re-verify and re-trust the contact
4. This prevents silent man-in-the-middle attacks

### 9.3 Fingerprint Computation

```
fingerprint = SHA-256(raw_public_key_bytes) → hex string
```

Each contact has three fingerprints:
- ECC identity key fingerprint
- PQC identity key fingerprint
- Signing key fingerprint

---

## 10. Server Design — Zero-Knowledge Relay

### 10.1 What the Server CAN Do

- Store public key bundles (prekeys) for offline users
- Route encrypted blobs between connected WebSocket clients
- Queue messages for offline recipients (with TTL and size limits)
- Authenticate users via JWT tokens
- Track online/offline presence
- Manage group membership records

### 10.2 What the Server CANNOT Do

- Decrypt any message content
- Access any private keys
- Determine what users are saying
- Modify messages without detection (AAD prevents this)
- Impersonate users (signed prekeys prevent this)

### 10.3 Server Security Controls

- **Rate limiting**: 120 requests/minute globally, per-user WebSocket flood protection
- **JWT authentication**: Required for all API and WebSocket connections
- **Production fail-fast**: Refuses to start without proper JWT secret and CORS config
- **Pending message limits**: Max 500 queued messages per user, 7-day TTL
- **Delivery tracking**: Lease-based delivery with retry limits (max 20 attempts)
- **Input validation**: User existence checks, group membership verification
- **Log redaction**: Authorization headers and passwords are redacted from logs

---

## 11. Client Application

### 11.1 Technology

- **React** with TypeScript for the UI
- **Vite** as the build tool (fast HMR, no SSR secret leakage)
- **WebCrypto API** for all classical cryptographic operations
- **`mlkem` package** for post-quantum ML-KEM-768 (pure TypeScript FIPS 203 implementation)
- **IndexedDB** for persistent local storage (keys, messages, contacts)

### 11.2 Application Flow

```
1. User registers → generates all key material → uploads public keys to server
2. User logs in → unlocks local keystore with password-derived key (PBKDF2)
3. User adds contact → fetches their prekey bundle → verifies signatures
4. User sends first message → performs X3DH handshake → encrypts message
5. Recipient receives → processes handshake → derives same keys → decrypts
6. Subsequent messages → use ratcheted chain keys → no new handshake needed
7. User goes offline → messages queued on server → delivered on reconnect
```

### 11.3 State Management

- **AuthContext**: Handles login/registration state, JWT token management
- **MessengerContext**: Manages contacts, messages, WebSocket connection, encryption/decryption orchestration

---

## 12. Electron Desktop Shell

The Electron wrapper provides a native desktop experience with hardened security:

### 12.1 Security Configuration

| Setting | Value | Purpose |
|---------|-------|---------|
| `nodeIntegration` | `false` | Renderer cannot access Node.js APIs |
| `contextIsolation` | `true` | Preload script runs in isolated context |
| `sandbox` | `true` | Additional OS-level process isolation |
| `webSecurity` | `true` | Enforces same-origin policy |
| `allowRunningInsecureContent` | `false` | Blocks mixed HTTP/HTTPS content |

### 12.2 Content Security Policy (CSP)

```
default-src 'self';
script-src 'self' 'wasm-unsafe-eval';     ← allows WASM for PQC crypto
style-src 'self' 'unsafe-inline';          ← allows Tailwind inline styles
connect-src 'self' wss://relay.example.com; ← only configured relay endpoint
img-src 'self' data: blob:;
object-src 'none';                          ← no plugins/Flash
frame-ancestors 'none';                     ← no framing (clickjacking protection)
```

### 12.3 Additional Protections

- Single instance lock (prevents multiple app instances)
- Navigation restricted to app content only
- External links open in system browser
- WebView attachment blocked
- Certificate validation enforced (no silent bypass in production)

---

## 13. Data Storage & Persistence

### 13.1 Client-Side (IndexedDB)

| Store | Contents | Encryption |
|-------|----------|------------|
| `identity` | ECC/PQC identity keys, signing keys | Private keys encrypted with PBKDF2-derived key |
| `prekeys` | Signed prekeys, one-time prekeys | Private key material encrypted at rest |
| `sessions` | Active session state (chain keys, counters) | Entire payload encrypted with at-rest key |
| `messages` | Chat history | Message content encrypted at rest |
| `contacts` | Contact list, trust state, fingerprints | Stored with trust metadata |

### 13.2 At-Rest Encryption

When a user logs in, their password is used to derive an encryption key:

```
salt = stored per-user random 16 bytes
at_rest_key = PBKDF2(password, salt, 250000 iterations, SHA-256) → AES-GCM-256 key
```

All sensitive data in IndexedDB is encrypted with this key before storage and decrypted on read.

### 13.3 Server-Side (SQLite)

| Table | Contents |
|-------|----------|
| `users` | User records, public keys, password hashes |
| `one_time_prekeys` | Consumable one-time prekeys (deleted after use) |
| `groups` | Group metadata (name, owner, timestamps) |
| `group_members` | Group membership records |
| `pending_messages` | Queued encrypted blobs for offline users |

The server uses WAL (Write-Ahead Logging) mode for concurrent read performance.

---

## 14. Group Messaging

### 14.1 Architecture (Fan-Out Model)

Group messages use a **sender-side fan-out** approach:
- The sender encrypts the message separately for each group member
- Each encrypted copy uses the pairwise session with that specific member
- The server routes each copy to the respective recipient

This means:
- No shared group key that could be compromised
- Each pairwise session maintains its own ratchet state
- Adding/removing members doesn't require re-keying all sessions

### 14.2 Group Membership Commitment

To prevent stale-state attacks (sending to a group after being removed):

```
commitment = SHA-256(groupId | ownerId | updatedAt | sorted_member_ids)
```

This commitment is verified on both client and server before accepting group messages.

### 14.3 Group Operations

- **Create**: Owner specifies name + initial members (minimum 2)
- **Add member**: Owner adds a user → server updates membership → commitment changes
- **Remove member**: Owner removes a user → commitment changes → stale messages rejected
- **Leave**: Owner can transfer ownership to next-oldest member before leaving

---

## 15. Real-Time Communication (WebSocket)

### 15.1 Connection Authentication

WebSocket connections authenticate via the `Sec-WebSocket-Protocol` header:
```
Sec-WebSocket-Protocol: auth.<jwt_token>
```

The server verifies the JWT and maps the socket to the authenticated user ID.

### 15.2 Message Types

| Type | Direction | Purpose |
|------|-----------|---------|
| `send` | Client → Server → Client | Relay encrypted message |
| `ack` | Server → Client | Confirm message received by server |
| `delivered` | Client → Server → Client | Confirm recipient decrypted successfully |
| `read` | Client → Server → Client | Confirm recipient read the message |
| `typing` | Client → Server → Client | Typing indicator |
| `presence` | Server → Client | Online/offline status broadcast |
| `error` | Bidirectional | Error notifications (e.g., decrypt failure) |

### 15.3 Offline Message Delivery

When a recipient is offline:
1. Server stores the encrypted blob in `pending_messages` table
2. When recipient reconnects, server delivers all pending messages
3. Messages use a lease-based delivery system (mark as "in_flight", retry if not ACKed)
4. Messages expire after 7 days (configurable TTL)
5. Maximum 500 pending messages per user (oldest evicted on overflow)

### 15.4 Error Recovery

If a recipient cannot decrypt a message:
1. Recipient sends an `error` message with type `"decrypt-failed"` back to sender
2. Sender receives the error and automatically retries with a fresh session (one retry)
3. If retry also fails, the message is marked as "error" in the UI

---

## 16. Security Measures Summary

| Threat | Mitigation |
|--------|-----------|
| Quantum computer breaks ECC | ML-KEM-768 shared secret included in key derivation |
| Server compromise | Zero-knowledge design — server never has plaintext or private keys |
| Man-in-the-middle | Signed prekeys + identity fingerprint verification |
| Message replay | Per-message unique keys via chain ratchet + message counters |
| Message reordering/tampering | AAD binds ciphertext to metadata; counter validation |
| Key compromise (past messages) | Forward secrecy via ephemeral keys and chain ratchet |
| Key compromise (future messages) | Post-compromise security via DH ratchet |
| Endpoint compromise (device stolen) | At-rest encryption with password-derived key |
| XSS in Electron | Context isolation, sandbox, strict CSP, no node integration |
| Traffic analysis | Server only sees encrypted blob sizes and timing (content opaque) |
| Brute-force login | Rate limiting, login throttling, account lockout |

---

## 17. Technology Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| Language | TypeScript (full-stack) | Type safety prevents common logic errors |
| Client Framework | React | Component-based UI, large ecosystem |
| Build Tool | Vite | Fast dev server, no SSR secret leakage |
| Server Framework | Fastify | High performance, plugin architecture, schema validation |
| Database | SQLite (better-sqlite3) | Zero-config, single-file, WAL mode for concurrency |
| Desktop Shell | Electron | Cross-platform native app with web technologies |
| Classical Crypto | WebCrypto API | Browser-native, audited, hardware-accelerated |
| Post-Quantum Crypto | `mlkem` package | Pure TypeScript FIPS 203 implementation, passes KAT vectors |
| Real-Time Transport | WebSocket (ws) | Bidirectional, low-latency, persistent connection |
| Authentication | JWT (JSON Web Tokens) | Stateless, compact, standard |
| Client Storage | IndexedDB | Large capacity, async, structured data |
| Testing | Vitest | Fast, Vite-native, TypeScript-first |

---

## 18. Project Structure

```
secure-messaging-app/
│
├── client/                          # React frontend application
│   └── src/
│       ├── components/              # UI components (Auth, Chat, Sidebar, etc.)
│       ├── contexts/                # React contexts (Auth, Messenger state)
│       ├── crypto/                  # ALL cryptographic operations
│       │   ├── ecc/                 # ECDH key agreement + ECDSA signatures
│       │   ├── pqc/                 # ML-KEM-768 post-quantum KEM
│       │   ├── kdf/                 # HKDF-SHA-384 key derivation
│       │   ├── symmetric/           # AES-GCM-256 encryption + nonce management
│       │   ├── hybrid/              # X3DH handshake protocol implementation
│       │   ├── storage/             # IndexedDB keystore with at-rest encryption
│       │   ├── interfaces/          # TypeScript interfaces for crypto types
│       │   └── utils/               # Encoding, random, buffer utilities
│       ├── services/                # Business logic services
│       │   ├── HandshakeManager.ts  # Orchestrates X3DH handshake flow
│       │   ├── SessionManager.ts    # Manages session state + double ratchet
│       │   └── TrustManager.ts      # Identity verification + TOFU
│       ├── hooks/                   # React hooks (WebSocket connection)
│       ├── utils/                   # Message encryption/decryption utilities
│       └── types/                   # TypeScript type definitions
│
├── server/                          # Fastify relay server
│   └── src/
│       ├── routes/                  # REST API (users, prekeys, groups)
│       ├── websocket/               # WebSocket message relay handler
│       ├── store/                   # SQLite database layer
│       └── types/                   # Server type definitions
│
├── electron/                        # Electron desktop wrapper
│   └── src/
│       ├── main.ts                  # Security-hardened main process
│       └── preload.ts               # Minimal IPC bridge
│
├── ARCHITECTURE.md                  # System architecture documentation
├── PRODUCTION_AUDIT_REPORT.md       # Security audit and gap analysis
└── README.md                        # Setup and usage guide
```

---

## Summary

This project is a complete, working implementation of a **post-quantum secure messaging system**. It combines battle-tested classical cryptography with cutting-edge post-quantum algorithms to create a messaging platform that is secure against both today's threats and tomorrow's quantum computers.

The design philosophy is defense-in-depth: multiple layers of security (hybrid crypto, zero-knowledge server, forward secrecy, at-rest encryption, hardened desktop shell) ensure that no single point of failure can compromise user privacy.

It serves as both a functional messaging application and a reference implementation for developers building quantum-resistant communication systems.
