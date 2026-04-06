/**
 * Password hashing utility for authentication.
 * DEV MODE: Uses simple SHA-256 hash with username.
 * PRODUCTION: Should use proper password-based key derivation (PBKDF2, Argon2).
 */

import { bytesToBase64 } from "../crypto/utils/encoding";

/**
 * Create a deterministic password hash for authentication.
 * @param username - The user's username
 * @returns Base64-encoded SHA-256 hash
 */
export async function createPasswordHash(username: string): Promise<string> {
  const passwordHash = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(username + "-dev-password"),
    ),
  );
  return bytesToBase64(passwordHash);
}
