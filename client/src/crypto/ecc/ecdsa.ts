/**
 * ECDSA signing and verification using WebCrypto.
 * Uses NIST P-384 with SHA-384 for prekey signatures.
 *
 * SECURITY: All operations use native WebCrypto API.
 */

import type { ExportableEccKeyPair } from "../interfaces";
import { toArrayBuffer } from "../utils/buffer";

/** P-384 ECDSA configuration */
const ECDSA_ALGORITHM: EcKeyGenParams = {
  name: "ECDSA",
  namedCurve: "P-384",
};

/** Signature parameters */
const SIGN_PARAMS: EcdsaParams = {
  name: "ECDSA",
  hash: "SHA-384",
};

/** P-384 ECDSA signature size (DER encoded, max ~104 bytes, but we use raw format) */
export const ECDSA_SIGNATURE_SIZE = 96; // 48 bytes r + 48 bytes s

/**
 * Generate an ECDSA signing key pair.
 * Public key is exportable for distribution, private key for signing.
 *
 * @returns Promise resolving to exportable key pair
 */
export async function generateSigningKeyPair(): Promise<ExportableEccKeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    ECDSA_ALGORITHM,
    true, // Extractable for public key export
    ["sign", "verify"]
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
 * Sign data using ECDSA-P384-SHA384.
 *
 * @param privateKey - ECDSA private key
 * @param data - Data to sign
 * @returns Promise resolving to signature bytes (96 bytes: r || s)
 */
export async function sign(
  privateKey: CryptoKey,
  data: Uint8Array
): Promise<Uint8Array> {
  const signature = await crypto.subtle.sign(
    SIGN_PARAMS,
    privateKey,
    toArrayBuffer(data)
  );

  return new Uint8Array(signature);
}

/**
 * Verify an ECDSA signature.
 *
 * @param publicKey - ECDSA public key (CryptoKey)
 * @param signature - Signature to verify
 * @param data - Original signed data
 * @returns Promise resolving to true if valid, false otherwise
 */
export async function verify(
  publicKey: CryptoKey,
  signature: Uint8Array,
  data: Uint8Array
): Promise<boolean> {
  try {
    return await crypto.subtle.verify(
      SIGN_PARAMS,
      publicKey,
      toArrayBuffer(signature),
      toArrayBuffer(data)
    );
  } catch {
    // Invalid signature format or verification failure
    return false;
  }
}

/**
 * Import a raw public key for ECDSA verification.
 *
 * @param publicKeyBytes - Raw public key bytes (97 bytes for P-384)
 * @returns Promise resolving to CryptoKey
 */
export async function importSigningPublicKey(
  publicKeyBytes: Uint8Array
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    toArrayBuffer(publicKeyBytes),
    ECDSA_ALGORITHM,
    true,
    ["verify"]
  );
}

/**
 * Verify signature using raw public key bytes.
 * Convenience function that handles key import.
 *
 * @param publicKeyBytes - Raw public key bytes
 * @param signature - Signature to verify
 * @param data - Original signed data
 * @returns Promise resolving to true if valid, false otherwise
 */
export async function verifyWithBytes(
  publicKeyBytes: Uint8Array,
  signature: Uint8Array,
  data: Uint8Array
): Promise<boolean> {
  try {
    const publicKey = await importSigningPublicKey(publicKeyBytes);
    return verify(publicKey, signature, data);
  } catch {
    return false;
  }
}

/**
 * Create a signed prekey structure.
 * Signs the public key concatenated with timestamp and ID.
 *
 * @param signingKey - ECDSA private key
 * @param prekeyPublicKey - Prekey public key bytes to sign
 * @param prekeyId - Unique identifier for this prekey
 * @param timestamp - Creation timestamp
 * @returns Promise resolving to signature bytes
 */
export async function signPrekey(
  signingKey: CryptoKey,
  prekeyPublicKey: Uint8Array,
  prekeyId: number,
  timestamp: number
): Promise<Uint8Array> {
  // Create signed data: id (4 bytes) || timestamp (8 bytes) || publicKey
  const signedData = new Uint8Array(4 + 8 + prekeyPublicKey.length);
  const view = new DataView(signedData.buffer);

  view.setUint32(0, prekeyId, false); // big-endian
  // JavaScript numbers are 64-bit floats, Date.now() fits in 53 bits
  view.setBigUint64(4, BigInt(timestamp), false);
  signedData.set(prekeyPublicKey, 12);

  return sign(signingKey, signedData);
}

/**
 * Verify a prekey signature.
 *
 * @param signingPublicKey - Public key of signer
 * @param signature - Signature to verify
 * @param prekeyPublicKey - Prekey public key bytes
 * @param prekeyId - Prekey identifier
 * @param timestamp - Creation timestamp
 * @returns Promise resolving to true if valid
 */
export async function verifyPrekeySignature(
  signingPublicKey: Uint8Array,
  signature: Uint8Array,
  prekeyPublicKey: Uint8Array,
  prekeyId: number,
  timestamp: number
): Promise<boolean> {
  // Reconstruct signed data
  const signedData = new Uint8Array(4 + 8 + prekeyPublicKey.length);
  const view = new DataView(signedData.buffer);

  view.setUint32(0, prekeyId, false);
  view.setBigUint64(4, BigInt(timestamp), false);
  signedData.set(prekeyPublicKey, 12);

  return verifyWithBytes(signingPublicKey, signature, signedData);
}
