/**
 * ECDH key generation and shared secret derivation using WebCrypto.
 * Uses NIST P-384 (secp384r1) as specified in security requirements.
 *
 * SECURITY: All operations use native WebCrypto API.
 * No third-party ECC libraries or manual elliptic curve math.
 */

import type { EccKeyPair, ExportableEccKeyPair } from "../interfaces";
import { toArrayBuffer } from "../utils/buffer";

/** P-384 curve configuration */
const ECDH_ALGORITHM: EcKeyGenParams = {
  name: "ECDH",
  namedCurve: "P-384",
};

/** P-384 raw public key size: 1 byte prefix + 48 bytes X + 48 bytes Y */
export const ECC_PUBLIC_KEY_SIZE = 97;

/** P-384 shared secret size */
export const ECC_SHARED_SECRET_SIZE = 48; // 384 bits

/**
 * Generate a non-extractable ECDH key pair.
 * Use for identity keys where private key should never leave WebCrypto.
 *
 * @returns Promise resolving to CryptoKey pair
 */
export async function generateECDHKeyPair(): Promise<EccKeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    ECDH_ALGORITHM,
    false, // Non-extractable for security
    ["deriveBits"]
  );

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  };
}

/**
 * Generate an ECDH key pair with exportable public key.
 * Use for prekeys that need to be transmitted to server.
 *
 * @returns Promise resolving to public key bytes and private CryptoKey
 */
export async function generateExportableECDHKeyPair(): Promise<ExportableEccKeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    ECDH_ALGORITHM,
    true, // Extractable for export
    ["deriveBits"]
  );

  const publicKeyBytes = new Uint8Array(
    await crypto.subtle.exportKey("raw", keyPair.publicKey)
  );

  return {
    publicKeyBytes,
    privateKey: keyPair.privateKey,
  };
}

/**
 * Import a raw public key for ECDH.
 * Use when receiving public keys from network.
 *
 * @param publicKeyBytes - Raw public key bytes (97 bytes for P-384)
 * @returns Promise resolving to CryptoKey
 */
export async function importECDHPublicKey(
  publicKeyBytes: Uint8Array
): Promise<CryptoKey> {
  if (publicKeyBytes.length !== ECC_PUBLIC_KEY_SIZE) {
    throw new Error(
      `Invalid public key size: expected ${ECC_PUBLIC_KEY_SIZE}, got ${publicKeyBytes.length}`
    );
  }

  return crypto.subtle.importKey(
    "raw",
    toArrayBuffer(publicKeyBytes),
    ECDH_ALGORITHM,
    true, // Can be used for derivation
    []
  );
}

/**
 * Derive shared secret using ECDH.
 * Combines own private key with peer's public key.
 *
 * @param privateKey - Own ECDH private key
 * @param publicKey - Peer's ECDH public key
 * @returns Promise resolving to shared secret bytes (48 bytes for P-384)
 */
export async function deriveECDHSharedSecret(
  privateKey: CryptoKey,
  publicKey: CryptoKey
): Promise<Uint8Array> {
  const sharedSecretBits = await crypto.subtle.deriveBits(
    {
      name: "ECDH",
      public: publicKey,
    },
    privateKey,
    384 // P-384 produces 384-bit shared secret
  );

  return new Uint8Array(sharedSecretBits);
}

/**
 * Derive shared secret from raw public key bytes.
 * Convenience function that handles key import.
 *
 * @param privateKey - Own ECDH private key
 * @param publicKeyBytes - Peer's raw public key bytes
 * @returns Promise resolving to shared secret bytes
 */
export async function deriveECDHSharedSecretFromBytes(
  privateKey: CryptoKey,
  publicKeyBytes: Uint8Array
): Promise<Uint8Array> {
  const publicKey = await importECDHPublicKey(publicKeyBytes);
  return deriveECDHSharedSecret(privateKey, publicKey);
}

/**
 * Export a public key to raw bytes.
 *
 * @param publicKey - CryptoKey to export
 * @returns Promise resolving to raw public key bytes
 */
export async function exportECDHPublicKey(
  publicKey: CryptoKey
): Promise<Uint8Array> {
  const exported = await crypto.subtle.exportKey("raw", publicKey);
  return new Uint8Array(exported);
}
