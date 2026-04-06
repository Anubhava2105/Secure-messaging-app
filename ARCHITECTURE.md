# Secure Messaging App Architecture

## 1. Overview
This system is a real-time secure messaging application designed to be resistant to **Harvest Now, Decrypt Later (HNDL)** attacks by employing a **Hybrid Key Exchange (ECC + PQC)** mechanism.

The architecture strictly enforces a "Zero-Knowledge" principle for the relay server. The server is assumed to be hostile; it routes encrypted binary blobs without having the capability to inspect, modify, or decrypt them.

## 2. System Components

### 2.1. Client Application (The "Trust Zone")
The client is the only entity trusted with plaintext data and private keys.

*   **Platform**: Desktop (Electron) & Web
*   **Frameworks**: React, TypeScript, Vite, TailwindCSS
*   **Security Context**:
    *   **Electron**: `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`.
    *   **CSP**: Strict Content Security Policy allowing only local scripts and specific WebSocket endpoints.
*   **Storage**: IndexedDB (encrypted at rest) for keys and message history.

### 2.2. Cryptographic Module (Client-Side Only)
All cryptographic operations occur in the renderer process (or a dedicated Web Worker) to ensure isolation.

*   **Classical Layer**: NIST P-384 (secp384r1) via **WebCrypto API**.
*   **Post-Quantum Layer**: ML-KEM-768 (Kyber) via **liboqs-wasm** (or vetted WASM equivalent).
*   **Key Derivation**: Hybrid shared secrets (ECC + PQC) concatenated and passed through **HKDF-SHA-384**.
*   **Randomness**: `crypto.getRandomValues()` only.
*   **Prohibited**: `Math.random()`, Node.js `crypto` module in renderer, proprietary crypto implementations.

### 2.3. Relay Server (The "Untrusted Zone")
The server acts as a dumb pipe for encrypted traffic.

*   **Runtime**: Node.js
*   **Framework**: Fastify + WebSocket (ws)
*   **Responsibility**:
    *   Route encrypted packets between connected sockets.
    *   Store encrypted public key bundles (PreKeys) for offline users.
*   **Constraint**: The server **never** sees plaintext messages or private keys.

## 3. Data Flow & Protocol

### 3.1. Initialization & Identity
1.  **Key Gen**: Client generates Identity Keys for both ECC (P-384) and PQC (ML-KEM-768).
2.  **Publication**: Public keys are signed and uploaded to the Relay Server.

### 3.2. Hybrid Key Exchange (X3DH variant)
When User A wants to message User B:
1.  **Fetch**: User A fetches User B's signed pre-keys (ECC + PQC) from the server.
2.  **Encapsulate**:
    *   User A performs ECDH with User B's ECC key.
    *   User A encapsulates a shared secret against User B's PQC key (KEM).
3.  **Derive**: $K_{session} = HKDF(ECDH_{shared} || KEM_{shared})$
4.  **Encrypt**: Message is encrypted with $K_{session}$ using AES-GCM or ChaCha20-Poly1305.

### 3.3. Transport
1.  Encrypted binary blob is sent to Relay Server via WebSocket.
2.  Relay Server routes blob to User B's active socket.
3.  User B decapsulates (PQC) and performs ECDH to reconstruct $K_{session}$ and decrypt.

## 4. Threat Model Mitigation

| Threat | Mitigation |
| :--- | :--- |
| **Harvest Now, Decrypt Later (HNDL)** | **ML-KEM-768** layer ensures that recorded traffic cannot be decrypted even if quantum computers break ECC. |
| **Server Compromise** | Server holds no private keys; End-to-End Encryption (E2EE) protects all content. |
| **Rogue Renderer / XSS** | Strict CSP, no Node integration, keys isolated in non-exportable WebCrypto handles where possible. |
| **Man-in-the-Middle (MITM)** | Public keys are signed; users must verify fingerprints (out-of-band verification recommended). |

## 5. Technology Stack Summary

| Component | Technology | Rationale |
| :--- | :--- | :--- |
| **Language** | TypeScript | Type safety prevents common memory/logic errors. |
| **Bundler** | Vite | Faster dev loop, no SSR leakage of secrets. |
| **Crypto (Classic)** | WebCrypto API | Browser-native, audited, non-extractable key support. |
| **Crypto (PQC)** | liboqs-wasm | Industry standard for NIST PQC algorithms. |
| **Transport** | WebSockets (WSS) | Real-time bi-directional communication. |