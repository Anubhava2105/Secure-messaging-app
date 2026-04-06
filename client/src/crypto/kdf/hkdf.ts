/**
 * HKDF (HMAC-based Key Derivation Function) using SHA-384.
 * Implements RFC 5869 using WebCrypto.
 *
 * Used for deriving session keys from hybrid shared secrets.
 */

import { toArrayBuffer } from "../utils/buffer";

/**
 * HKDF Extract step: derive PRK from salt and IKM.
 *
 * @param salt - Optional salt (if null, uses zero-filled hash-length salt)
 * @param ikm - Input keying material
 * @returns Promise resolving to pseudo-random key (PRK)
 */
export async function hkdfExtract(
  salt: Uint8Array | null,
  ikm: Uint8Array
): Promise<Uint8Array> {
  // If salt is null, use hash-length zeros (48 bytes for SHA-384)
  const effectiveSalt = salt ?? new Uint8Array(48);

  // Import salt as HMAC key
  const saltKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(effectiveSalt),
    { name: "HMAC", hash: "SHA-384" },
    false,
    ["sign"]
  );

  // PRK = HMAC-SHA-384(salt, IKM)
  const prk = await crypto.subtle.sign("HMAC", saltKey, toArrayBuffer(ikm));
  return new Uint8Array(prk);
}

/**
 * HKDF Expand step: derive output keying material from PRK.
 *
 * @param prk - Pseudo-random key from Extract
 * @param info - Context/application-specific info
 * @param length - Desired output length in bytes (max 48 * 255 for SHA-384)
 * @returns Promise resolving to output keying material
 */
export async function hkdfExpand(
  prk: Uint8Array,
  info: Uint8Array,
  length: number
): Promise<Uint8Array> {
  const hashLen = 48; // SHA-384 output size
  const maxLength = hashLen * 255;

  if (length > maxLength) {
    throw new Error(`HKDF length exceeds maximum: ${length} > ${maxLength}`);
  }

  if (length <= 0) {
    throw new Error("HKDF length must be positive");
  }

  // Import PRK as HMAC key
  const prkKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(prk),
    { name: "HMAC", hash: "SHA-384" },
    false,
    ["sign"]
  );

  const n = Math.ceil(length / hashLen);
  const okm = new Uint8Array(n * hashLen);
  let t = new Uint8Array(0);

  for (let i = 1; i <= n; i++) {
    // T(i) = HMAC-SHA-384(PRK, T(i-1) || info || i)
    const input = new Uint8Array(t.length + info.length + 1);
    input.set(t, 0);
    input.set(info, t.length);
    input[input.length - 1] = i;

    const ti = await crypto.subtle.sign("HMAC", prkKey, toArrayBuffer(input));
    t = new Uint8Array(ti);
    okm.set(t, (i - 1) * hashLen);
  }

  return okm.slice(0, length);
}

/**
 * Complete HKDF: Extract-then-Expand in one call.
 *
 * @param salt - Optional salt value
 * @param ikm - Input keying material
 * @param info - Context/application-specific info
 * @param length - Desired output length in bytes
 * @returns Promise resolving to derived key bytes
 */
export async function hkdf(
  salt: Uint8Array | null,
  ikm: Uint8Array,
  info: Uint8Array,
  length: number
): Promise<Uint8Array> {
  const prk = await hkdfExtract(salt, ikm);
  return hkdfExpand(prk, info, length);
}

/** Domain separator for hybrid key derivation */
const HYBRID_KDF_SALT = new TextEncoder().encode("SecureMsg-Hybrid-KDF-v1");

/**
 * Derive session keys from hybrid shared secrets.
 * Combines ECC and PQC shared secrets using HKDF.
 *
 * @param eccSecrets - Array of ECDH shared secrets (DH1, DH2, DH3, [DH4])
 * @param pqcSecret - ML-KEM shared secret
 * @param context - Additional context info (e.g., user IDs)
 * @returns Promise resolving to session keys (96 bytes total)
 */
export async function deriveSessionKeys(
  eccSecrets: Uint8Array[],
  pqcSecret: Uint8Array,
  context: Uint8Array
): Promise<{
  encryptionKey: Uint8Array;
  macKey: Uint8Array;
  rootKey: Uint8Array;
}> {
  // Concatenate all shared secrets: DH1 || DH2 || DH3 || [DH4] || PQC_SS
  const totalLength =
    eccSecrets.reduce((sum, s) => sum + s.length, 0) + pqcSecret.length;
  const ikm = new Uint8Array(totalLength);

  let offset = 0;
  for (const secret of eccSecrets) {
    ikm.set(secret, offset);
    offset += secret.length;
  }
  ikm.set(pqcSecret, offset);

  // Derive 96 bytes: 32 encryption + 32 MAC + 32 root
  const okm = await hkdf(HYBRID_KDF_SALT, ikm, context, 96);

  return {
    encryptionKey: okm.slice(0, 32),
    macKey: okm.slice(32, 64),
    rootKey: okm.slice(64, 96),
  };
}
