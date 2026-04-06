# Secure Messaging App — Production Readiness & Deep Technical Audit

Date: 2026-03-29 Scope: Full repository review (client, server, electron, docs,
scripts) Standard: Production readiness for secure messaging with hybrid ECC+PQC
design

---

## 1) Executive Summary

1. Core architecture is implemented and coherent: React client, Fastify relay
   backend, Electron desktop shell, and crypto modules for ECC + ML-KEM + HKDF +
   AES-GCM.
2. Key exchange and encrypted messaging paths exist end-to-end, but production
   cryptographic assurances are not fully enforced in runtime behavior due
   development fallbacks.
3. Server and client authentication are currently dev-grade (username-derived
   hash, static JWT secret fallback, token in query string), and must be
   hardened before production.
4. Transport security is not production-safe by default (`ws://` and `http://`
   defaults), although code comments and docs acknowledge this.
5. WebSocket relay feature set is good (send/ack/read/typing/presence + offline
   queue), but message metadata and encrypted blobs are logged in plaintext
   server logs.
6. Persistent storage exists on server (SQLite) and client (IndexedDB), but
   key/session/message-at-rest controls and retention policies are incomplete.
7. Electron hardening baseline is strong (context isolation, sandbox, node off,
   CSP), but CSP allowances and dev certificate behavior still need production
   controls.
8. No automated test suite exists; no CI workflows; this is the largest blocker
   for production confidence.
9. The roadmap in docs is directionally accurate (Double Ratchet not yet
   implemented), but several security-critical non-roadmap items must be
   completed first.
10. Overall readiness: **MVP demo ready**, **not production ready**.

---

## 2) What Has Been Accomplished (Implemented)

### 2.1 Frontend (React + TypeScript)

- App shell and auth-to-messaging workflow are implemented:
  [client/src/App.tsx](client/src/App.tsx).
- State architecture is organized via `AuthContext` and `MessengerContext`:
  - [client/src/contexts/AuthContext.tsx](client/src/contexts/AuthContext.tsx)
  - [client/src/contexts/MessengerContext.tsx](client/src/contexts/MessengerContext.tsx)
- Messaging UX includes contact list, chat timeline, send flow, delivery state,
  typing indicators, and read receipts:
  - [client/src/components/Sidebar.tsx](client/src/components/Sidebar.tsx)
  - [client/src/components/ChatArea.tsx](client/src/components/ChatArea.tsx)
- Contacts and message history persist locally via IndexedDB `KeyStore`:
  - [client/src/crypto/storage/keystore.ts](client/src/crypto/storage/keystore.ts#L265)
  - [client/src/crypto/storage/keystore.ts](client/src/crypto/storage/keystore.ts#L298)

### 2.2 Cryptography Layer

- ECC ECDH P-384 key generation and shared secret derivation implemented:
  - [client/src/crypto/ecc/ecdh.ts](client/src/crypto/ecc/ecdh.ts)
- ECDSA P-384 signing/verification for prekeys implemented:
  - [client/src/crypto/ecc/ecdsa.ts](client/src/crypto/ecc/ecdsa.ts)
- ML-KEM-768 support via `mlkem` package implemented with key size checks:
  - [client/src/crypto/pqc/mlkem.ts](client/src/crypto/pqc/mlkem.ts)
- HKDF-SHA-384 key schedule implemented:
  - [client/src/crypto/kdf/hkdf.ts](client/src/crypto/kdf/hkdf.ts)
- AES-GCM-256 encrypt/decrypt wrappers with validations implemented:
  - [client/src/crypto/symmetric/aesgcm.ts](client/src/crypto/symmetric/aesgcm.ts)
- Hybrid handshake protocol implementation exists (`initiateHandshake`,
  `respondToHandshake`):
  - [client/src/crypto/hybrid/handshake.ts](client/src/crypto/hybrid/handshake.ts)

### 2.3 Session / Handshake Integration

- Session orchestration and caching layer exists:
  - [client/src/services/SessionManager.ts](client/src/services/SessionManager.ts)
- Handshake manager integrates prekey fetch + session save + responder
  processing:
  - [client/src/services/HandshakeManager.ts](client/src/services/HandshakeManager.ts#L129)
  - [client/src/services/HandshakeManager.ts](client/src/services/HandshakeManager.ts#L213)

### 2.4 Backend (Fastify + SQLite + WebSocket)

- Fastify server bootstrapped with JWT, CORS, health endpoint, API routes, and
  WS route:
  - [server/src/index.ts](server/src/index.ts)
- Registration/login/user lookup routes implemented:
  - [server/src/routes/users.ts](server/src/routes/users.ts)
- Prekey fetch/upload/count with atomic one-time prekey consumption implemented:
  - [server/src/routes/prekeys.ts](server/src/routes/prekeys.ts)
- WebSocket relay handler supports send/ack/read/typing/presence + pending
  delivery:
  - [server/src/websocket/handler.ts](server/src/websocket/handler.ts)
- Persistent storage moved from memory to SQLite with schema and indices:
  - [server/src/store/sqlite.ts](server/src/store/sqlite.ts)

### 2.5 Electron Desktop Shell

- Security-hardening baseline implemented (`nodeIntegration: false`,
  `contextIsolation: true`, `sandbox: true`):
  - [electron/src/main.ts](electron/src/main.ts#L64-L73)
- CSP enforcement and navigation/webview restrictions are in place:
  - [electron/src/main.ts](electron/src/main.ts#L150-L205)
- Minimal preload bridge with validation and bounded IPC API is implemented:
  - [electron/src/preload.ts](electron/src/preload.ts)

### 2.6 Documentation / Architecture Clarity

- High-level architecture and threat framing are documented:
  - [ARCHITECTURE.md](ARCHITECTURE.md)
- Main README explains hybrid design, setup, and roadmap:
  - [README.md](README.md)

---

## 3) What Is Yet To Be Accomplished (Production Gap Analysis)

Priority labels: **High** (release blocker), **Medium** (pre-launch), **Low**
(post-launch hardening/scale).

### 3.1 Security & Crypto Integrity

1. **[High] Remove development fallback sessions (`createDevSession`) in
   production path.**

   - Evidence:
     - [client/src/services/HandshakeManager.ts](client/src/services/HandshakeManager.ts#L226-L228)
     - [client/src/utils/devSession.ts](client/src/utils/devSession.ts#L3-L5)
   - Risk: deterministic shared key path can bypass true handshake assurances.

2. **[High] Replace username-derived pseudo-password hashing with real password
   handling.**

   - Evidence:
     - [client/src/components/Auth.tsx](client/src/components/Auth.tsx#L72)
     - [client/src/utils/passwordHash.ts](client/src/utils/passwordHash.ts#L18)
   - Required: real password input, Argon2id/PBKDF2 (server-side verified),
     per-user salt, optional pepper, lockout/rate limiting.

3. **[High] Enforce server secret management and key rotation policies.**

   - Evidence: [server/src/index.ts](server/src/index.ts#L20)
   - Required: fail-fast if JWT secret missing in production, key rotation
     (`kid`), token revocation strategy.

4. **[High] Eliminate token-in-query WebSocket auth.**

   - Evidence:
     - [client/src/hooks/useWebSocket.ts](client/src/hooks/useWebSocket.ts#L84)
     - [server/src/websocket/handler.ts](server/src/websocket/handler.ts#L293-L299)
   - Required: auth via secure header/cookie/session ticket + CSRF/Origin checks
     for browser context.

5. **[High] Remove encrypted blob previews from server logs.**

   - Evidence:
     [server/src/websocket/handler.ts](server/src/websocket/handler.ts#L149-L157)
   - Risk: metadata leakage, traffic analysis amplification, privacy policy
     breach.

6. **[Medium] Implement nonce/replay strategy tied to session state.**

   - Evidence: current message path uses random nonce only
     [client/src/utils/messageEncryption.ts](client/src/utils/messageEncryption.ts#L30)
   - Existing nonce utilities are not integrated into send/receive flow:
     [client/src/crypto/symmetric/nonce.ts](client/src/crypto/symmetric/nonce.ts)

7. **[Medium] Add cryptographic identity verification UX and trust-on-first-use
   policy.**
   - Current security modal is static information display:
     - [client/src/components/SecurityDetails.tsx](client/src/components/SecurityDetails.tsx)

### 3.2 Protocol / Messaging Correctness

1. **[High] Complete first-message handshake transport wiring.**

   - Client types support `handshakeData`:
     [client/src/types/wsTypes.ts](client/src/types/wsTypes.ts#L21)
   - Incoming handler checks it:
     [client/src/contexts/MessengerContext.tsx](client/src/contexts/MessengerContext.tsx#L173-L174)
   - Outgoing `send` currently does not attach `handshakeData`:
     [client/src/contexts/MessengerContext.tsx](client/src/contexts/MessengerContext.tsx#L299-L307)
   - Server WS message shape does not include `handshakeData`:
     [server/src/types/index.ts](server/src/types/index.ts#L88-L95)

2. **[High] Implement Double Ratchet for per-message forward secrecy and
   post-compromise security.**

   - Documented as pending roadmap item: [README.md](README.md#L135)

3. **[Medium] Persist and restore sessions securely (encrypted-at-rest) instead
   of memory-only map.**

   - Evidence:
     [client/src/services/SessionManager.ts](client/src/services/SessionManager.ts#L14)

4. **[Medium] Define explicit key/prekey rotation and expiry policy for ECC and
   PQC prekeys.**
   - Current implementation uses basic replenishment threshold only.

### 3.3 Transport / Platform Hardening

1. **[High] Move all transport defaults to TLS-secured endpoints (`https://`,
   `wss://`).**

   - Evidence:
     - [client/src/constants.ts](client/src/constants.ts#L6)
     - [client/src/constants.ts](client/src/constants.ts#L12)

2. **[High] Restrict CORS origin and enforce strict origin policy for API and
   WebSocket handshake.**

   - Evidence: [server/src/index.ts](server/src/index.ts#L32)

3. **[Medium] Tighten Electron CSP and external navigation policy for production
   host set.**

   - Current `connect-src` includes localhost/dev endpoint:
     [electron/src/main.ts](electron/src/main.ts#L176)

4. **[Medium] Add hard fail policy for invalid certs in all environments except
   explicit dev flags.**
   - Current code conditionally trusts certs in development:
     [electron/src/main.ts](electron/src/main.ts#L369-L374)

### 3.4 Data Protection & Privacy

1. **[High] Encrypt message history at rest in IndexedDB, or store ciphertext
   only and decrypt on render.**

   - Stored message includes plaintext `content`:
     [client/src/crypto/storage/keystore.ts](client/src/crypto/storage/keystore.ts#L436)

2. **[Medium] Add retention controls and secure deletion strategy for
   local/server data.**

   - Current data lifecycle is basic `clearAll` / pending delete after delivery.

3. **[Medium] Add structured audit logging policy with PII minimization and
   retention limits.**

### 3.5 Backend Security Controls

1. **[High] Replace direct hash comparison with constant-time verification and
   proper password strategy.**

   - Evidence:
     [server/src/routes/users.ts](server/src/routes/users.ts#L102-L103)

2. **[High] Add brute-force protections: rate limiting, login throttling,
   account lock strategy.**

3. **[Medium] Add request validation schemas (Fastify schema/Zod) for all route
   payloads.**

4. **[Medium] Add abuse controls for WebSocket channels (flood limits, per-user
   quotas, anti-spam).**

### 3.6 Quality Engineering / Release Engineering

1. **[High] Build automated test suites (unit + integration + crypto vector
   tests + WS e2e).**

   - No tests detected.
   - Placeholder server test script:
     [server/package.json](server/package.json#L12)

2. **[High] Add CI pipeline for lint/typecheck/test/build/security scanning.**

   - No workflow files found under `.github/workflows`.

3. **[Medium] Add environment templates and production configuration docs
   (`.env.example`, secrets guide).**

4. \*\*[Low] Add performance/load testing and chaos testing for relay
   resilience.

---

## 4) Explicit Security Checklist (Production Gate)

Status values:

- ✅ Implemented
- ⚠️ Partial / conditional
- ❌ Not implemented / inadequate for production

### 4.1 Cryptography

- ✅ WebCrypto for ECC + AES-GCM:
  [client/src/crypto/ecc/ecdh.ts](client/src/crypto/ecc/ecdh.ts),
  [client/src/crypto/symmetric/aesgcm.ts](client/src/crypto/symmetric/aesgcm.ts)
- ✅ ML-KEM-768 integrated via library:
  [client/src/crypto/pqc/mlkem.ts](client/src/crypto/pqc/mlkem.ts)
- ✅ HKDF-SHA-384 implemented:
  [client/src/crypto/kdf/hkdf.ts](client/src/crypto/kdf/hkdf.ts)
- ⚠️ Hybrid handshake exists but production trust model incomplete due fallback:
  [client/src/services/HandshakeManager.ts](client/src/services/HandshakeManager.ts#L226-L228)
- ❌ Double Ratchet not implemented: [README.md](README.md#L135)
- ❌ Replay/ordering hardening not fully integrated in active message path.

### 4.2 Authentication & Authorization

- ⚠️ JWT auth exists: [server/src/index.ts](server/src/index.ts#L42-L45)
- ❌ Static fallback JWT secret present:
  [server/src/index.ts](server/src/index.ts#L20)
- ❌ Password flow is dev-only (username-derived):
  [client/src/utils/passwordHash.ts](client/src/utils/passwordHash.ts#L18)
- ❌ Constant-time password verification missing:
  [server/src/routes/users.ts](server/src/routes/users.ts#L102-L103)
- ❌ Login abuse/rate limiting controls absent.

### 4.3 Transport Security

- ⚠️ Supports WS/WSS conceptually, but defaults are insecure in app constants:
  - [client/src/constants.ts](client/src/constants.ts#L6)
  - [client/src/constants.ts](client/src/constants.ts#L12)
- ❌ Token in URL query for WebSocket handshake:
  - [client/src/hooks/useWebSocket.ts](client/src/hooks/useWebSocket.ts#L84)
  - [server/src/websocket/handler.ts](server/src/websocket/handler.ts#L295)
- ❌ CORS policy too permissive for production:
  [server/src/index.ts](server/src/index.ts#L32)

### 4.4 Data Security & Privacy

- ✅ Server stores encrypted blobs only (no plaintext decode path):
  [server/src/websocket/handler.ts](server/src/websocket/handler.ts#L121)
- ⚠️ Client stores local messages but includes plaintext `content`:
  [client/src/crypto/storage/keystore.ts](client/src/crypto/storage/keystore.ts#L436)
- ❌ Sensitive encrypted payload excerpts are logged:
  [server/src/websocket/handler.ts](server/src/websocket/handler.ts#L157)
- ❌ Formal retention/deletion policy not defined.

### 4.5 Electron Desktop Security

- ✅ Hardened core flags present:
  [electron/src/main.ts](electron/src/main.ts#L64-L73)
- ✅ Preload bridge input checks present:
  [electron/src/preload.ts](electron/src/preload.ts)
- ⚠️ CSP present but includes environment-specific broad connect endpoints:
  [electron/src/main.ts](electron/src/main.ts#L176)
- ⚠️ Dev certificate bypass exists in development mode:
  [electron/src/main.ts](electron/src/main.ts#L369-L374)

### 4.6 Secure SDLC

- ❌ No test coverage baseline (unit/integration/e2e)
- ❌ No CI pipeline with security checks
- ❌ No SBOM / dependency vulnerability gating documented

---

## 5) Deep Technical Findings by Subsystem

### 5.1 Handshake and Session Lifecycle

- The protocol implementation supports hybrid key derivation from ECC DH set +
  PQC shared secret and context binding.
- However, runtime `ensureSession()` can drop to deterministic dev key mode,
  reducing effective security to predictable key derivation if handshake path
  fails.
- `SessionManager` stores all session material in-memory only; restarts
  invalidate sessions and recovery behavior depends on fallback logic.
- `handshakeData` appears designed in client message types but not fully carried
  through outgoing payload and server type definitions, indicating partial
  protocol wiring.

### 5.2 Message Protection

- Message encryption uses AES-GCM with random nonces and key from session keys.
- Dedicated nonce/replay tooling exists but is not the active path in
  `encryptMessage`/`decryptMessage` flow.
- This leaves room for replay/ordering edge cases at protocol level despite
  authenticated encryption.

### 5.3 Server Relay Behavior

- Server correctly treats payload as opaque encrypted blob and does not decrypt
  content.
- Offline queue and delivery behavior are implemented.
- Logging currently includes sender/recipient IDs and encrypted payload
  snippets; this is operationally useful but privacy/security costly in
  production.

### 5.4 Identity, Credentials, and Auth

- Registration and login are functionally present.
- Credential model is development placeholder and must be replaced for
  production.
- JWT auth baseline exists for HTTP and WS, but secret management and token
  transport methods are not production-grade.

### 5.5 Storage Model

- Server SQLite schema and persistence are stable for baseline operation.
- Client IndexedDB stores contacts, sessions/messages, but with plaintext
  message content and limited key-protection policy.
- No migration/retention policy docs or cryptographic key backup/recovery policy
  currently visible.

### 5.6 Electron Runtime

- Security-focused Electron configuration is above average for early-stage apps.
- Remaining work is operational hardening: production CSP, trust store behavior,
  endpoint pinning strategy, packaging/signing pipeline.

---

## 6) Production Risks & Technical Debt Register

1. **Critical**: Dev auth and session fallback paths can materially weaken
   security claims.
2. **Critical**: No automated tests/CI means regressions can silently break
   crypto/protocol behavior.
3. **High**: Token in URL query + permissive CORS + insecure default endpoints
   increases interception/exposure risks.
4. **High**: Logging encrypted payload previews may violate privacy commitments
   and leak metadata.
5. **High**: Plaintext local message storage increases endpoint compromise blast
   radius.
6. **Medium**: Protocol feature mismatch (`handshakeData`) can create
   inconsistent session establishment across peers.
7. **Medium**: No formal key rotation/revocation model.
8. **Medium**: No explicit abuse controls (rate limits/quotas) for public
   endpoints.

---

## 7) Production Implementation Sequencing (Recommended)

### Phase 0 — Security Stabilization (Immediate, Release Blockers)

- Remove/feature-flag dev session fallback from production build.
- Replace dev password flow with real password handling + server-side
  verification.
- Enforce required env secrets and fail startup without secure JWT config.
- Shift all defaults to TLS (`https`, `wss`), remove token query auth.
- Disable encrypted payload logging in server relay path.

### Phase 1 — Protocol Correctness & Storage Hardening

- Complete `handshakeData` transport model across client/server message
  contracts.
- Introduce replay protection and nonce/counter validation on receive path.
- Encrypt local message/session storage or store ciphertext-only with secure key
  handling.
- Add signed identity verification UX and TOFU/safety number workflows.

### Phase 2 — Security Controls & Abuse Resistance

- Implement route schemas, rate limiting, login throttles, IP/user quotas.
- Tighten CORS/origin policy and WebSocket origin checks.
- Finalize Electron CSP for production domains and cert handling policy.

### Phase 3 — Quality & Release Engineering

- Add unit tests for crypto wrappers + protocol serialization.
- Add integration/e2e tests for register/login/prekey/ws relay/offline delivery.
- Add CI for lint/typecheck/test/build + dependency scanning.
- Add release checklists, env templates, runbooks, and incident playbooks.

---

## 8) Definition of “Production Ready” for This Repository

Before go-live, all of the following should be true:

1. No development security fallback code is reachable in production builds.
2. Password and token flows are standards-compliant and independently
   test-verified.
3. All network transports and auth channels are TLS-only and non-leaky.
4. Protocol implementation is feature-complete for handshake lifecycle without
   silent fallback.
5. Local and server storage meet explicit confidentiality/integrity
   requirements.
6. Test/CI gates are mandatory for merge and release.
7. Security checklist above has no `❌` in High-priority rows.

---

## 9) Current Readiness Verdict

- Architecture maturity: **Good**
- Implementation completeness for secure production messaging: **Partial**
- Security posture for internet-facing production: **Insufficient today**
- Recommended release decision: **Do not release to production yet**
