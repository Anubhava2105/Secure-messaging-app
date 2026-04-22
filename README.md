# Secure Messaging App

A post-quantum resistant secure messaging application designed to defend against
**Harvest Now, Decrypt Later (HNDL)** attacks.

## 🔐 Security Features

- **Hybrid Key Exchange**: Combines classical ECC (NIST P-384) with post-quantum
  ML-KEM-768 (Kyber)
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
│           ├── pqc/        # ML-KEM-768 via mlkem package
│           ├── kdf/        # HKDF-SHA-384
│           ├── symmetric/  # AES-GCM-256
│           ├── hybrid/     # Hybrid X3DH handshake
│           └── storage/    # IndexedDB key storage
├── server/                 # Fastify relay server
│   └── src/
│       ├── routes/         # REST API endpoints
│       ├── websocket/      # Real-time message relay
│       └── store/          # SQLite-backed persistence and queue controls
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

1. **ML-KEM-768**: PQC uses the `mlkem` package (pure TypeScript FIPS 203
   implementation).

2. **JWT Authentication**: API and WebSocket auth use signed JWTs.

3. **TLS Required**: For production, set secure relay origins
   (`VITE_RELAY_ORIGIN`, `RELAY_ORIGIN`) or explicit secure endpoint overrides
   (`VITE_WS_URL`, `VITE_API_BASE_URL`).

4. **Prekey Replenishment**: Monitor one-time prekey counts and replenish when
   low.

## 🧩 Production Configuration

Use environment variables to enforce production-safe defaults.

Client (Vite):

- `VITE_RELAY_ORIGIN=https://relay.example.com`
- Optional overrides: `VITE_API_BASE_URL`, `VITE_WS_URL`

Server:

- `NODE_ENV=production`
- `JWT_SECRET=<strong-random-secret>`
- `CORS_ORIGINS=https://app.example.com,https://desktop.example.com`
- `JWT_EXPIRES_IN=12h`
- `LOGIN_MAX_ATTEMPTS=5`
- `LOGIN_WINDOW_MS=60000`
- `LOGIN_LOCK_MS=300000`
- `PREKEY_FETCH_WINDOW_MS=60000`
- `PREKEY_FETCH_MAX_PER_WINDOW=30`
- `MAX_PENDING_MESSAGES_PER_USER=500`
- `PENDING_MESSAGE_TTL_MS=604800000`
- `MAX_PENDING_DELIVERY_BATCH=100`
- `PENDING_DELIVERY_LEASE_MS=30000`
- `MAX_PENDING_DELIVERY_ATTEMPTS=20`

Electron:

- `RELAY_ORIGIN=https://relay.example.com`
- Optional for local development only: `ALLOW_INSECURE_DEV_CERTS=true`

## 📋 Roadmap

- [x] Hybrid key exchange (ECC + PQC)
- [x] Zero-knowledge relay server
- [x] Secure Electron configuration
- [x] Double Ratchet for per-message forward secrecy
- [x] Group messaging (initial fan-out implementation)

## 📄 License

MIT
