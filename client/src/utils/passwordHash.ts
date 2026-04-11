/**
 * Password hashing utility for authentication.
 *
 * SECURITY: Uses PBKDF2-SHA-384 with 600,000 iterations.
 * The username is folded into the salt to prevent cross-user rainbow tables.
 * The actual user-supplied password is the key material.
 */

import { bytesToBase64 } from "../crypto/utils/encoding";

/** PBKDF2 iteration count — OWASP 2024 minimum for SHA-384 */
const PBKDF2_ITERATIONS = 600_000;

/**
 * Derive a password hash for server authentication.
 *
 * @param username - The user's username (used as salt component)
 * @param password - The user's password
 * @returns Base64-encoded 384-bit derived key
 */
export async function createPasswordHash(
  username: string,
  password: string,
): Promise<string> {
  const encoder = new TextEncoder();
  const salt = encoder.encode(`SecureMsg-v1:${username.toLowerCase()}`);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );

  const derived = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-384",
    },
    keyMaterial,
    384,
  );

  return bytesToBase64(new Uint8Array(derived));
}
