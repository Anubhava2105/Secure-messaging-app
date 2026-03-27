/**
 * Secure Messaging Crypto Module
 *
 * This module provides all cryptographic functionality for the secure messaging app.
 * All operations are client-side only - the server never has access to keys or plaintext.
 *
 * SECURITY PRINCIPLES:
 * 1. Hybrid key exchange (ECC + PQC) for post-quantum resistance
 * 2. WebCrypto API for classical cryptography (no custom implementations)
 * 3. ML-KEM-768 via audited WASM for post-quantum cryptography
 * 4. HKDF-SHA-384 for key derivation with proper domain separation
 * 5. AES-GCM-256 for authenticated encryption
 * 6. WebCrypto CSPRNG only (no Math.random())
 */

// Core interfaces
export * from "./interfaces";

// Utility functions
export * from "./utils";

// Classical cryptography (ECC)
export * from "./ecc";

// Post-quantum cryptography
export * from "./pqc";

// Key derivation
export * from "./kdf";

// Symmetric encryption
export * from "./symmetric";

// Hybrid key exchange
export * from "./hybrid";

// Re-export commonly used items at top level
export {
  generateExportableECDHKeyPair,
  deriveECDHSharedSecret,
} from "./ecc/ecdh";

export { generateSigningKeyPair, sign, verify } from "./ecc/ecdsa";

export { getMlKem768 } from "./pqc/mlkem";

export { deriveSessionKeys } from "./kdf/hkdf";

export { aesGcmEncrypt, aesGcmDecrypt } from "./symmetric/aesgcm";

export { initiateHandshake, respondToHandshake } from "./hybrid/handshake";

export { getRandomBytes, generateRandomId } from "./utils/random";
