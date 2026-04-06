/**
 * Key pair interfaces for identity and session keys.
 */

/** ECC key pair using WebCrypto CryptoKey handles */
export interface EccKeyPair {
  /** Public key as CryptoKey (can be exported) */
  publicKey: CryptoKey;
  /** Private key as CryptoKey (non-extractable when possible) */
  privateKey: CryptoKey;
}

/** ECC key pair with serialized public key for transmission */
export interface ExportableEccKeyPair {
  /** Public key as raw bytes for network transmission */
  publicKeyBytes: Uint8Array;
  /** Private key as CryptoKey (kept in WebCrypto) */
  privateKey: CryptoKey;
}

/** PQC key pair (raw bytes, managed by WASM module) */
export interface PqcKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** Identity key bundle containing both ECC and PQC keys */
export interface IdentityKeyBundle {
  /** User identifier */
  userId: string;

  /** ECC identity key for ECDH */
  eccIdentity: ExportableEccKeyPair;

  /** PQC identity key for KEM */
  pqcIdentity: PqcKeyPair;

  /** ECC signing key for prekey signatures */
  signingKey: ExportableEccKeyPair;

  /** Creation timestamp */
  createdAt: number;
}

/** Signed prekey for key exchange */
export interface SignedPreKey {
  /** Unique identifier for this prekey */
  id: number;

  /** Public key bytes */
  publicKey: Uint8Array;

  /** ECDSA signature over the public key */
  signature: Uint8Array;

  /** Creation timestamp */
  createdAt: number;
}

/** One-time prekey (consumed after single use) */
export interface OneTimePreKey {
  /** Unique identifier */
  id: number;

  /** Public key bytes */
  publicKey: Uint8Array;
}

/** Complete prekey bundle for key exchange */
export interface PreKeyBundle {
  /** ECC identity public key */
  identityKeyEcc: Uint8Array;

  /** PQC identity public key */
  identityKeyPqc: Uint8Array;

  /** ECDSA signing public key */
  signingKeyPub: Uint8Array;

  /** Signed ECC prekey */
  signedPreKeyEcc: SignedPreKey;

  /** Signed PQC prekey */
  signedPreKeyPqc: SignedPreKey;

  /** Optional one-time ECC prekey */
  oneTimePreKeyEcc?: OneTimePreKey;
}

/** Derived session keys from hybrid key exchange */
export interface SessionKeys {
  /** 256-bit key for AES-GCM encryption */
  encryptionKey: Uint8Array;

  /** 256-bit key for HMAC authentication */
  macKey: Uint8Array;

  /** 256-bit root key for ratcheting */
  rootKey: Uint8Array;
}
