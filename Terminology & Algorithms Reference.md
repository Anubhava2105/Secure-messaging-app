
This document explains every technical term, algorithm, protocol, and concept referenced in `PROJECT_EXPLANATION.md`. Organized alphabetically within categories for easy lookup.

---

## Table of Contents

1. [Cryptographic Algorithms](Terminology%20&%20Algorithms%20Reference.md#1-cryptographic-algorithms)
2. [Protocols & Schemes](Terminology%20&%20Algorithms%20Reference.md#2-protocols--schemes)
3. [Key Types & Key Management](Terminology%20&%20Algorithms%20Reference.md#3-key-types--key-management)
4. [Security Properties & Concepts](Terminology%20&%20Algorithms%20Reference.md#4-security-properties--concepts)
5. [Data Structures & Encoding](Terminology%20&%20Algorithms%20Reference.md#5-data-structures--encoding)
6. [Networking & Transport](Terminology%20&%20Algorithms%20Reference.md#6-networking--transport)
7. [Application & Platform Terms](Terminology%20&%20Algorithms%20Reference.md#7-application--platform-terms)
8. [Standards & Specifications](Terminology%20&%20Algorithms%20Reference.md#8-standards--specifications)

---

## 1. Cryptographic Algorithms

### AES (Advanced Encryption Standard)

A symmetric block cipher adopted by NIST in 2001. It encrypts data in fixed 128-bit blocks using a secret key. AES is the most widely used symmetric encryption algorithm in the world — used by governments, banks, and messaging apps.

- **Key sizes**: 128, 192, or 256 bits
- **Block size**: 128 bits
- **Type**: Symmetric (same key encrypts and decrypts)

### AES-GCM (AES in Galois/Counter Mode)

A mode of operation for AES that provides both **confidentiality** (encryption) and **authenticity** (tamper detection) in a single operation. This is called "authenticated encryption."

How it works:
1. A counter generates a unique keystream for each block
2. Plaintext is XORed with the keystream → ciphertext
3. A Galois field multiplication computes an authentication tag over the ciphertext + any additional data (AAD)
4. The tag is appended to the ciphertext

If anyone modifies even one bit of the ciphertext or AAD, the tag verification fails and decryption is rejected.

**In this project**: AES-GCM-256 (256-bit key, 96-bit nonce, 128-bit auth tag) encrypts all message content.

### AES-GCM-256

AES-GCM with a 256-bit key. Provides approximately 128 bits of security against brute-force attacks (due to birthday bound considerations on the tag). This is the strongest commonly-used symmetric cipher configuration.

Parameters used in this project:
- Key: 32 bytes (256 bits)
- Nonce/IV: 12 bytes (96 bits) — NIST recommended size
- Auth tag: 16 bytes (128 bits)

### ECDH (Elliptic Curve Diffie-Hellman)

A key agreement protocol that allows two parties to establish a shared secret over an insecure channel, using elliptic curve mathematics.

How it works:
1. Alice has private key `a` and public key `A = a × G` (where G is the curve generator point)
2. Bob has private key `b` and public key `B = b × G`
3. Alice computes: `shared = a × B = a × b × G`
4. Bob computes: `shared = b × A = b × a × G`
5. Both arrive at the same point → same shared secret

**Security basis**: The Elliptic Curve Discrete Logarithm Problem (ECDLP) — given `A = a × G`, it's computationally infeasible to find `a`.

**In this project**: ECDH over P-384 curve, producing 48-byte (384-bit) shared secrets.

### ECDSA (Elliptic Curve Digital Signature Algorithm)

A digital signature algorithm using elliptic curves. It allows someone to sign data with their private key, and anyone with the corresponding public key can verify the signature is authentic.

How it works:
1. Signer computes a hash of the message
2. Uses their private key + a random nonce to produce a signature (r, s)
3. Verifier uses the public key + message hash to check if (r, s) is valid

**In this project**: ECDSA P-384 with SHA-384 signs prekeys to prove they genuinely belong to the claimed user.

### HKDF (HMAC-based Key Derivation Function)

A key derivation function defined in RFC 5869. It takes "input keying material" (which may not be uniformly random) and produces cryptographically strong output keys.

Two phases:
1. **Extract**: `PRK = HMAC(salt, IKM)` — concentrates entropy into a fixed-size pseudo-random key
2. **Expand**: Produces as many output bytes as needed by iteratively computing HMAC with a counter

**In this project**: HKDF-SHA-384 derives 96 bytes of session keys (encryption + MAC + root) from the concatenated ECDH and ML-KEM shared secrets.

### HMAC (Hash-based Message Authentication Code)

A construction that uses a cryptographic hash function (like SHA-384) with a secret key to produce a message authentication code. It proves both integrity (message wasn't modified) and authenticity (message came from someone with the key).

Formula: `HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))`

**In this project**: HMAC-SHA-384 is used in HKDF and in the symmetric ratchet to derive chain keys and message keys.

### ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism)

Formerly known as "Kyber." A post-quantum key encapsulation mechanism standardized by NIST as FIPS 203 in 2024. It is resistant to attacks by both classical and quantum computers.

How it works (simplified):
1. **Key Generation**: Generate a public/private key pair based on lattice problems
2. **Encapsulation**: Given a public key, produce a ciphertext and a shared secret
3. **Decapsulation**: Given the ciphertext and private key, recover the same shared secret

**Security basis**: The Module Learning With Errors (MLWE) problem — adding small random "errors" to lattice equations makes them computationally hard to solve, even for quantum computers.

**ML-KEM-768 parameters** (used in this project):
- Public key: 1184 bytes
- Private key: 2400 bytes
- Ciphertext: 1088 bytes
- Shared secret: 32 bytes
- Security level: NIST Level 3 (equivalent to AES-192)

### ML-KEM-768

The "768" refers to the lattice dimension parameter. ML-KEM comes in three sizes:
- ML-KEM-512: NIST Level 1 (equivalent to AES-128)
- ML-KEM-768: NIST Level 3 (equivalent to AES-192) ← **used in this project**
- ML-KEM-1024: NIST Level 5 (equivalent to AES-256)

ML-KEM-768 is the recommended balance between security and performance for most applications.

### P-384 (secp384r1)

An elliptic curve defined by NIST. The "384" means the prime field is 384 bits wide. It provides approximately 192 bits of classical security.

Curve parameters:
- Field size: 384 bits
- Key size: 48 bytes (private), 97 bytes (public, uncompressed)
- Shared secret size: 48 bytes
- Security level: ~192 bits (classical)

**Why P-384 over P-256**: P-384 provides a higher security margin. Since this project already handles the performance cost of ML-KEM, the marginal cost of P-384 over P-256 is acceptable for the extra security.

### PBKDF2 (Password-Based Key Derivation Function 2)

A function that derives a cryptographic key from a password. It applies a pseudorandom function (HMAC) many times iteratively to make brute-force attacks expensive.

Parameters in this project:
- Hash: SHA-256
- Iterations: 250,000
- Salt: 16 random bytes (per user)
- Output: 256-bit AES-GCM key

**Purpose**: Converts a human-memorable password into a strong encryption key for at-rest data protection.

### SHA-256 / SHA-384 (Secure Hash Algorithm)

Cryptographic hash functions from the SHA-2 family. They take arbitrary-length input and produce a fixed-length output (digest) that is:
- **One-way**: Cannot reverse the hash to find the input
- **Collision-resistant**: Infeasible to find two inputs with the same hash
- **Avalanche effect**: Changing one input bit changes ~50% of output bits

| Variant | Output size | Used for in this project |
|---------|-------------|--------------------------|
| SHA-256 | 32 bytes | Identity fingerprints, group membership commitments, PBKDF2 |
| SHA-384 | 48 bytes | HKDF, HMAC for key derivation, ECDSA signatures |

---

## 2. Protocols & Schemes

### Double Ratchet

A key management algorithm (invented by Signal) that combines two "ratchets":

1. **Symmetric ratchet** (KDF chain): Advances a chain key forward with each message, deriving a unique message key each time. Old keys are deleted → forward secrecy.

2. **Asymmetric ratchet** (DH ratchet): Periodically exchanges new Diffie-Hellman public keys between parties. Each new DH exchange resets the chain keys → post-compromise security.

The name "ratchet" comes from the mechanical device that only turns in one direction — you can advance the key state forward but never backward.

**In this project**: The SessionManager implements both ratchets. The symmetric ratchet advances per-message, and the DH ratchet advances when peers exchange new `ratchetKeyEcc` values.

### KEM (Key Encapsulation Mechanism)

A cryptographic primitive with three operations:
1. **KeyGen()** → (public_key, private_key)
2. **Encaps(public_key)** → (ciphertext, shared_secret)
3. **Decaps(ciphertext, private_key)** → shared_secret

Unlike Diffie-Hellman (which is interactive), KEM is non-interactive — the sender can produce a shared secret using only the recipient's public key, without any back-and-forth.

**In this project**: ML-KEM-768 is the KEM used for the post-quantum layer.

### X3DH (Extended Triple Diffie-Hellman)

A key agreement protocol designed by Signal for asynchronous messaging. It allows Alice to establish a shared secret with Bob even when Bob is offline, using pre-uploaded keys.

The "3" refers to the minimum three DH computations:
- DH between Alice's identity key and Bob's signed prekey
- DH between Alice's ephemeral key and Bob's identity key
- DH between Alice's ephemeral key and Bob's signed prekey
- (Optional 4th) DH between Alice's ephemeral key and Bob's one-time prekey

**In this project**: A hybrid variant of X3DH that adds ML-KEM encapsulation on top of the classical DH computations.

### Hybrid Key Exchange

Combining two different key agreement mechanisms (classical + post-quantum) so that the resulting shared secret is secure as long as **at least one** of the two mechanisms remains unbroken.

Implementation: Both shared secrets are concatenated and fed into a KDF:
```
session_key = HKDF(ECDH_secret || ML-KEM_secret)
```

This is a "belt and suspenders" approach — if quantum computers break ECC, ML-KEM still protects. If ML-KEM has an undiscovered flaw, ECC still protects.

### TOFU (Trust-On-First-Use)

A trust model where the first time you communicate with someone, you accept their identity key without prior verification. The key is then "pinned" — if it ever changes, you get a warning.

Similar to how SSH works: the first time you connect to a server, you accept its host key. If it changes later, SSH warns you of a potential man-in-the-middle attack.

**In this project**: Contacts start as "unverified" (TOFU). Users can verify fingerprints out-of-band to upgrade to "trusted." If keys change, the contact is marked "changed" and messaging is blocked.

---

## 3. Key Types & Key Management

### Identity Key

A long-lived key pair that represents a user's cryptographic identity. It persists across sessions and is used to authenticate the user in key exchanges.

In this project, each user has:
- **ECC Identity Key** (P-384 ECDH) — used in X3DH DH computations
- **PQC Identity Key** (ML-KEM-768) — quantum-resistant identity
- **Signing Key** (ECDSA P-384) — signs prekeys to prove ownership

### Signed Prekey

A medium-lived key pair that is signed by the user's signing key. The signature proves the prekey genuinely belongs to the claimed user (prevents an attacker from substituting their own key).

Signed prekeys are uploaded to the server and used by initiators during X3DH. They should be rotated periodically (e.g., weekly or monthly).

### One-Time Prekey

A single-use key pair uploaded to the server in batches. When someone initiates a handshake, the server provides one of these keys and then deletes it. This provides additional forward secrecy for the initial handshake — even if the signed prekey is later compromised, past handshakes that used a one-time prekey remain secure.

### Ephemeral Key

A key pair generated fresh for each handshake and immediately discarded after use. It exists only in memory for the duration of the key exchange computation.

**Purpose**: Ensures that even if long-term keys are compromised, the specific session key derived using the ephemeral key cannot be reconstructed.

### Chain Key

A symmetric key that advances forward with each message in the Double Ratchet. Each chain key produces one message key and one next chain key:
```
chain_key[n] → message_key[n] (used to encrypt one message)
chain_key[n] → chain_key[n+1] (used for the next message)
```

Old chain keys are deleted after advancing, providing forward secrecy.

### Message Key

A one-time symmetric key derived from the chain key, used to encrypt exactly one message. After encryption/decryption, it is discarded. This ensures each message has a unique key.

### Root Key

A key that sits above the chain keys in the hierarchy. When a DH ratchet step occurs, the root key is combined with the new DH shared secret to derive new chain keys:
```
(new_root_key, new_chain_key) = KDF(root_key, DH_shared_secret)
```

### Ratchet Key

An ephemeral ECDH key pair used in the asymmetric (DH) ratchet. Users periodically generate new ratchet keys and announce them in outgoing messages. When the peer receives a new ratchet key, they perform a DH computation to advance the root key.

### Prekey Bundle

The complete set of public keys that a user uploads to the server for others to initiate handshakes:
- Identity key (ECC public)
- Identity key (PQC public)
- Signing key (public)
- Signed prekey ECC (public + signature + ID + timestamp)
- Signed prekey PQC (public + signature + ID + timestamp)
- One-time prekey ECC (public + ID) — optional, consumed on use

### Key Fingerprint

A short, human-readable representation of a public key, computed as:
```
fingerprint = hex(SHA-256(raw_public_key_bytes))
```

Used for out-of-band verification — two users can compare fingerprints (in person or over phone) to confirm they have each other's genuine keys.

---

## 4. Security Properties & Concepts

### Authenticated Encryption

Encryption that provides both confidentiality (secrecy) and integrity/authenticity (tamper detection). AES-GCM is an authenticated encryption algorithm — if anyone modifies the ciphertext, decryption fails.

### Additional Authenticated Data (AAD)

Data that is authenticated (tamper-protected) but NOT encrypted. In this project, message metadata (sender ID, recipient ID, message ID, group ID) is included as AAD. This means:
- The metadata is transmitted in the clear (the server needs it for routing)
- But if anyone modifies the metadata, the authentication tag fails and decryption is rejected
- This prevents message re-attribution attacks

### Confidentiality

The property that message content is hidden from unauthorized parties. Only the intended recipient (who holds the decryption key) can read the message.

### Integrity

The property that a message has not been modified in transit. If even one bit changes, the recipient can detect the tampering.

### Authenticity

The property that a message genuinely came from the claimed sender. Digital signatures and authenticated encryption provide this.

### Forward Secrecy (Perfect Forward Secrecy / PFS)

The property that compromising a long-term key does NOT compromise past session keys. Even if an attacker steals your identity key today, they cannot decrypt messages you sent last week.

Achieved by: Using ephemeral keys that are deleted after use. Since the ephemeral key no longer exists, the session key cannot be reconstructed.

### Post-Compromise Security

The property that after a key compromise, security is eventually restored. Even if an attacker learns your current session state, once a new DH ratchet step occurs (exchanging fresh ephemeral keys), the attacker loses access.

### Harvest Now, Decrypt Later (HNDL)

An attack strategy where an adversary records encrypted communications today, stores them, and waits for future technology (quantum computers) to decrypt them. This is a real, documented threat — intelligence agencies are known to store encrypted traffic.

**Mitigation**: Using post-quantum algorithms (ML-KEM) ensures that even with a future quantum computer, the recorded traffic cannot be decrypted.

### Zero-Knowledge (Server)

In this context, it means the server has zero knowledge of message content or private keys. The server is designed so that even a fully compromised server (or a malicious server operator) cannot read messages. It only ever handles opaque encrypted blobs.

### Man-in-the-Middle (MITM) Attack

An attack where an adversary positions themselves between two communicating parties, intercepting and potentially modifying messages. The attacker presents their own keys to each party, pretending to be the other.

**Mitigation**: Signed prekeys (the server cannot substitute fake keys without detection) + fingerprint verification (users can confirm they have genuine keys).

### Replay Attack

An attack where a previously valid message is re-sent. For example, if Alice sends "Transfer $100 to Bob," an attacker could replay that message to trigger multiple transfers.

**Mitigation**: Per-message unique keys (chain ratchet), message counters, and nonce uniqueness ensure each message can only be processed once.

### Nonce

"Number used once." A value that must never be repeated with the same key. In AES-GCM, reusing a nonce with the same key catastrophically breaks security (reveals the XOR of two plaintexts and allows authentication tag forgery).

In this project: 12-byte random nonces generated via `crypto.getRandomValues()`.

### Context Isolation

An Electron security feature that runs the preload script in a separate JavaScript context from the web page. This prevents the web page from accessing Node.js APIs or modifying the preload script's behavior.

### Sandbox

An OS-level security mechanism that restricts what a process can do. In Electron, sandboxing limits the renderer process's access to the file system, network, and other OS resources — even if an attacker achieves code execution via XSS.

### Content Security Policy (CSP)

An HTTP header that tells the browser which sources of content are allowed. It prevents XSS attacks by blocking inline scripts, unauthorized external scripts, and other potentially dangerous content.

---

## 5. Data Structures & Encoding

### Base64

A binary-to-text encoding that represents binary data using 64 ASCII characters (A-Z, a-z, 0-9, +, /). Used to transmit binary data (keys, ciphertexts) over text-based protocols (JSON, HTTP).

Every 3 bytes of binary → 4 characters of Base64 (33% size increase).

### Uint8Array

A JavaScript typed array representing a sequence of unsigned 8-bit integers (bytes). This is the standard way to handle binary data (keys, ciphertexts, nonces) in browser JavaScript.

### ArrayBuffer

The underlying memory buffer behind typed arrays like Uint8Array. WebCrypto APIs often accept or return ArrayBuffers.

### IndexedDB

A browser-based NoSQL database for storing large amounts of structured data. Unlike localStorage (which only stores strings and has a ~5MB limit), IndexedDB supports binary data, indexes, and transactions with much larger storage limits.

**In this project**: Stores identity keys, prekeys, sessions, messages, and contacts — all encrypted at rest.

### WAL (Write-Ahead Logging)

A SQLite journaling mode where changes are written to a separate log file before being applied to the main database. This allows concurrent readers while a writer is active, improving performance for read-heavy workloads.

### JWT (JSON Web Token)

A compact, URL-safe token format for transmitting claims between parties. Structure: `header.payload.signature` (Base64-encoded JSON).

In this project: The server issues JWTs after login containing the user ID. These tokens authenticate API requests and WebSocket connections.

---

## 6. Networking & Transport

### WebSocket

A protocol providing full-duplex (bidirectional) communication over a single TCP connection. Unlike HTTP (request-response), WebSocket allows the server to push messages to the client at any time.

**In this project**: Used for real-time message relay, typing indicators, presence updates, and delivery receipts.

### TLS (Transport Layer Security)

A protocol that encrypts data in transit between client and server. HTTPS = HTTP + TLS. WSS = WebSocket + TLS.

**In this project**: All production connections must use TLS (https://, wss://) to prevent network-level eavesdropping.

### CORS (Cross-Origin Resource Sharing)

A browser security mechanism that restricts which origins (domains) can make requests to a server. The server specifies allowed origins via HTTP headers.

**In this project**: The server configures CORS to only accept requests from the legitimate client application domain.

### Rate Limiting

Restricting the number of requests a client can make within a time window. Prevents abuse, brute-force attacks, and denial-of-service.

**In this project**: 120 API requests per minute globally, plus per-user WebSocket message throttling (120 messages per 10 seconds).

---

## 7. Application & Platform Terms

### Electron

A framework for building cross-platform desktop applications using web technologies (HTML, CSS, JavaScript). It bundles Chromium (browser engine) and Node.js into a native application.

Architecture:
- **Main process**: Node.js process with full OS access (file system, native APIs)
- **Renderer process**: Chromium browser window (sandboxed, restricted)
- **Preload script**: Bridge between main and renderer (controlled API surface)

### Vite

A modern JavaScript build tool and development server. It provides:
- Instant hot module replacement (HMR) during development
- Optimized production builds with tree-shaking
- Native ES module support

### Fastify

A high-performance Node.js web framework. Chosen for its:
- Plugin architecture (JWT, CORS, rate limiting, WebSocket as plugins)
- Schema-based request validation
- Low overhead and high throughput

### React

A JavaScript library for building user interfaces using a component-based architecture. Components manage their own state and compose together to form complex UIs.

### TypeScript

A superset of JavaScript that adds static type checking. Catches type errors at compile time rather than runtime, preventing common bugs in cryptographic code (e.g., passing a string where bytes are expected).

### WebCrypto API

A browser-native JavaScript API for cryptographic operations. Benefits:
- Implemented in C/C++ (fast, constant-time)
- Audited by browser vendors
- Supports non-extractable keys (private key never leaves the crypto module)
- Hardware-accelerated on many platforms

### IPC (Inter-Process Communication)

Communication between the Electron main process and renderer process. The preload script exposes a minimal, validated API surface via `contextBridge.exposeInMainWorld()`.

### SQLite

A self-contained, serverless, zero-configuration SQL database engine. The entire database is a single file on disk. Used for the server's persistent storage.

### Vitest

A Vite-native testing framework. Fast, supports TypeScript natively, and provides a Jest-compatible API.

---

## 8. Standards & Specifications

### NIST (National Institute of Standards and Technology)

A U.S. government agency that publishes cryptographic standards. Their standards are widely adopted globally.

Relevant NIST publications for this project:
- **FIPS 186-4**: Digital Signature Standard (ECDSA, P-384)
- **FIPS 197**: AES
- **FIPS 203**: ML-KEM (Kyber) — post-quantum KEM standard (2024)
- **SP 800-38D**: AES-GCM mode
- **SP 800-56A**: Key agreement schemes (ECDH)
- **SP 800-180-4**: SHA-2 hash functions

### FIPS 203

The NIST standard for ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism), published in 2024. It defines three parameter sets (ML-KEM-512, ML-KEM-768, ML-KEM-1024) and specifies the exact algorithms for key generation, encapsulation, and decapsulation.

### RFC 5869

The IETF specification for HKDF (HMAC-based Extract-and-Expand Key Derivation Function). Defines the two-step Extract-then-Expand paradigm for deriving keys from shared secrets.

### KAT Vectors (Known Answer Tests)

Pre-computed test vectors published alongside cryptographic standards. They provide specific inputs and expected outputs that implementations must match exactly. Passing KAT vectors proves an implementation is correct.

**In this project**: The `mlkem` package passes all official NIST KAT vectors for ML-KEM-768.

### NIST Security Levels

NIST defines five security levels for post-quantum algorithms:
- **Level 1**: At least as hard to break as AES-128
- **Level 2**: At least as hard to break as SHA-256 collision
- **Level 3**: At least as hard to break as AES-192 ← **ML-KEM-768**
- **Level 4**: At least as hard to break as SHA-384 collision
- **Level 5**: At least as hard to break as AES-256

### Shor's Algorithm

A quantum algorithm (1994) that can factor large integers and compute discrete logarithms in polynomial time. This breaks RSA, DSA, ECDH, and ECDSA — all of which rely on these mathematical problems being hard.

**Timeline**: Current quantum computers are too small (~1000 qubits). Breaking P-384 ECDH would require millions of error-corrected qubits. Estimates range from 10–30 years, but the HNDL threat means we must protect data NOW.

### Grover's Algorithm

A quantum algorithm that provides a quadratic speedup for brute-force search. Against AES-256, it effectively reduces security to 128 bits. This is why AES-256 (not AES-128) is used — it remains secure even against Grover's algorithm.

---

## Quick Reference Table

| Term | One-Line Definition |
|------|-------------------|
| AES-GCM-256 | Symmetric authenticated encryption with 256-bit key |
| ECDH P-384 | Elliptic curve key agreement over a 384-bit prime field |
| ECDSA P-384 | Elliptic curve digital signatures over P-384 |
| ML-KEM-768 | Post-quantum key encapsulation based on lattice problems |
| HKDF-SHA-384 | Key derivation function using HMAC with SHA-384 |
| X3DH | Asynchronous key agreement protocol (Signal's design) |
| Double Ratchet | Per-message key advancement with periodic DH refresh |
| Forward Secrecy | Past messages stay safe even if current keys leak |
| Post-Compromise Security | Security recovers after a key compromise |
| HNDL | Record encrypted traffic now, decrypt with quantum later |
| Zero-Knowledge Server | Server cannot access plaintext or private keys |
| TOFU | Accept identity on first contact, alert if it changes |
| AAD | Metadata authenticated but not encrypted |
| Nonce | Unique value per encryption operation (never reuse) |
| KEM | Asymmetric primitive: encapsulate/decapsulate a shared secret |
| PBKDF2 | Derive encryption key from password (slow, anti-brute-force) |
| CSP | Browser policy restricting allowed content sources |
| JWT | Compact authentication token (header.payload.signature) |
| WAL | SQLite mode allowing concurrent reads during writes |
| WebSocket | Persistent bidirectional network connection |
| IndexedDB | Browser database for structured/binary data |
| Fingerprint | SHA-256 hash of a public key for human verification |
