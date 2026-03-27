# Secure Messaging App

A post-quantum resistant secure messaging application designed to defend against **Harvest Now, Decrypt Later (HNDL)** attacks.

## 🔐 Security Features

- **Hybrid Key Exchange**: Combines classical ECC (NIST P-384) with post-quantum ML-KEM-768 (Kyber)
- **Zero-Knowledge Server**: Relay server cannot decrypt messages or access keys
- **End-to-End Encryption**: AES-GCM-256 authenticated encryption
- **Forward Secrecy**: Ephemeral keys ensure past sessions remain secure
- **Secure Electron**: Context isolation, sandbox, strict CSP

## 📁 Project Structure

```
secure-messaging-app/
├── client/                 # React + Vite frontend
│   └── src/
│       └── crypto/         # Cryptographic modules
│           ├── ecc/        # P-384 ECDH/ECDSA via WebCrypto
│           ├── pqc/        # ML-KEM-768 via liboqs-wasm
│           ├── kdf/        # HKDF-SHA-384
│           ├── symmetric/  # AES-GCM-256
│           ├── hybrid/     # Hybrid X3DH handshake
│           └── storage/    # IndexedDB key storage
├── server/                 # Fastify relay server
│   └── src/
│       ├── routes/         # REST API endpoints
│       ├── websocket/      # Real-time message relay
│       └── store/          # In-memory data store
└── electron/               # Electron desktop wrapper
    └── src/
        ├── main.ts         # Security-hardened main process
        └── preload.ts      # Minimal IPC bridge
```

## 🛡️ Cryptographic Design

### Key Exchange Protocol (Hybrid X3DH)

```
Alice (Initiator)                           Bob (Recipient)
        |                                          |
        |    1. Fetch prekey bundle                |
        |<-----------------------------------------|
        |    {IK_ecc, IK_pqc, SPK_ecc, SPK_pqc}    |
        |                                          |
        |    2. Compute shared secrets             |
        |    DH1 = ECDH(IKA, SPKB)                 |
        |    DH2 = ECDH(EKA, IKB)                  |
        |    DH3 = ECDH(EKA, SPKB)                 |
        |    DH4 = ECDH(EKA, OPKB) [optional]      |
        |    (ct, ss) = ML-KEM.Encaps(SPKB_pqc)    |
        |                                          |
        |    3. Derive session keys                |
        |    K = HKDF(DH1||DH2||DH3||DH4||ss)      |
        |                                          |
        |    4. Send handshake + encrypted msg     |
        |----------------------------------------->|
        |    {IKA_ecc, EKA_ecc, ct_pqc, enc_msg}   |
        |                                          |
        |                   5. Bob decapsulates    |
        |                   and derives same K     |
```

### Security Guarantees

| Property                | Mechanism                                |
| ----------------------- | ---------------------------------------- |
| Post-Quantum Resistance | ML-KEM-768 shared secret included in KDF |
| Forward Secrecy         | Ephemeral ECDH keys + one-time prekeys   |
| Authenticity            | Signed prekeys + AEAD encryption         |
| Zero-Knowledge Server   | Server only routes encrypted blobs       |

## 🚀 Getting Started

### Prerequisites

- Node.js 20+
- npm 9+

### Installation

```bash
# Clone and install
git clone <repository-url>
cd secure-messaging-app

# Install all dependencies
npm run install:all
```

### Development

```bash
# Start client (Vite dev server)
npm run dev:client

# Start server (Fastify)
npm run dev:server

# Start both concurrently
npm run dev
```

### Electron Desktop App

```bash
# Build client first
npm run build:client

# Start Electron
npm run electron
```

## ⚠️ Security Notes

1. **ML-KEM-768 WASM**: The PQC module requires `liboqs-wasm` or equivalent. Install separately:

   ```bash
   cd client && npm install @aspect/mlkem-wasm
   ```

2. **No Production Keys**: The current implementation uses placeholder tokens. Implement proper JWT authentication for production.

3. **TLS Required**: Always use WSS (WebSocket Secure) in production.

4. **Prekey Replenishment**: Monitor one-time prekey counts and replenish when low.

## 📋 Roadmap

- [x] Hybrid key exchange (ECC + PQC)
- [x] Zero-knowledge relay server
- [x] Secure Electron configuration
- [ ] Double Ratchet for per-message forward secrecy
- [ ] Group messaging
- [ ] Voice/video calls

## 📄 License

MIT
