/**
 * Secure random number generation utilities.
 *
 * SECURITY: Only uses WebCrypto CSPRNG. No fallbacks allowed.
 * Math.random() is explicitly prohibited in this codebase.
 */

/**
 * Generate cryptographically secure random bytes.
 * @param length - Number of random bytes to generate
 * @returns Uint8Array of random bytes
 * @throws Error if CSPRNG is unavailable
 */
export function getRandomBytes(length: number): Uint8Array {
  if (typeof crypto === "undefined" || !crypto.getRandomValues) {
    throw new Error(
      "CSPRNG not available - cannot proceed securely. " +
        "Ensure running in a secure context (HTTPS or localhost)."
    );
  }

  if (length <= 0 || !Number.isInteger(length)) {
    throw new Error("Length must be a positive integer");
  }

  // WebCrypto has a limit of 65536 bytes per call
  if (length > 65536) {
    const result = new Uint8Array(length);
    for (let i = 0; i < length; i += 65536) {
      const chunk = new Uint8Array(Math.min(65536, length - i));
      crypto.getRandomValues(chunk);
      result.set(chunk, i);
    }
    return result;
  }

  const buffer = new Uint8Array(length);
  crypto.getRandomValues(buffer);
  return buffer;
}

/**
 * Generate a random nonce for AES-GCM using counter + random hybrid.
 *
 * Format: [4 bytes random][8 bytes counter]
 * This prevents nonce reuse even if counter wraps or is reset.
 *
 * @param counter - Message counter (should be incremented per message)
 * @returns 12-byte nonce suitable for AES-GCM
 */
export function generateNonce(counter: bigint): Uint8Array {
  const nonce = new Uint8Array(12);

  // First 4 bytes: random prefix
  const randomPrefix = getRandomBytes(4);
  nonce.set(randomPrefix, 0);

  // Last 8 bytes: counter (big-endian)
  const counterBytes = new Uint8Array(8);
  const view = new DataView(counterBytes.buffer);
  view.setBigUint64(0, counter, false); // false = big-endian
  nonce.set(counterBytes, 4);

  return nonce;
}

/**
 * Generate a random identifier.
 * @param length - Number of bytes (default 16 = 128 bits)
 * @returns Hex-encoded random identifier
 */
export function generateRandomId(length: number = 16): string {
  const bytes = getRandomBytes(length);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Constant-time comparison of two byte arrays.
 * Prevents timing attacks when comparing secrets.
 *
 * @param a - First byte array
 * @param b - Second byte array
 * @returns true if arrays are equal, false otherwise
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  // XOR lengths into result — avoids early-return timing leak on length mismatch.
  let result = a.length ^ b.length;
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

/**
 * Securely zero out a byte array.
 * Note: This may be optimized away by the JS engine in some cases.
 * For truly sensitive data, consider using non-exportable WebCrypto keys.
 *
 * @param buffer - Buffer to zero out
 */
export function secureZero(buffer: Uint8Array): void {
  buffer.fill(0);
}
