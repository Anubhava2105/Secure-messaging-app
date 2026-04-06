/**
 * Encoding utilities for cryptographic data.
 * Handles conversion between binary and string formats.
 */

/**
 * Encode bytes to Base64 string.
 * @param bytes - Byte array to encode
 * @returns Base64-encoded string
 */
export function bytesToBase64(bytes: Uint8Array): string {
  // Use btoa with manual byte-to-char conversion for browser compatibility
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Decode Base64 string to bytes.
 * @param base64 - Base64-encoded string
 * @returns Decoded byte array
 * @throws Error if input is invalid Base64
 */
export function base64ToBytes(base64: string): Uint8Array {
  try {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    throw new Error("Invalid Base64 encoding");
  }
}

/**
 * Encode bytes to URL-safe Base64 string (no padding).
 * @param bytes - Byte array to encode
 * @returns URL-safe Base64 string
 */
export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Decode URL-safe Base64 string to bytes.
 * @param base64url - URL-safe Base64 string
 * @returns Decoded byte array
 */
export function base64UrlToBytes(base64url: string): Uint8Array {
  // Restore standard Base64 format
  let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");

  // Add padding if needed
  const padding = (4 - (base64.length % 4)) % 4;
  base64 += "=".repeat(padding);

  return base64ToBytes(base64);
}

/**
 * Encode bytes to hexadecimal string.
 * @param bytes - Byte array to encode
 * @returns Hex-encoded string (lowercase)
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Decode hexadecimal string to bytes.
 * @param hex - Hex-encoded string
 * @returns Decoded byte array
 * @throws Error if input has invalid length or characters
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Hex string must have even length");
  }

  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (isNaN(byte)) {
      throw new Error("Invalid hex character");
    }
    bytes[i] = byte;
  }
  return bytes;
}

/**
 * Encode string to UTF-8 bytes.
 * @param str - String to encode
 * @returns UTF-8 encoded bytes
 */
export function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Decode UTF-8 bytes to string.
 * @param bytes - UTF-8 encoded bytes
 * @returns Decoded string
 */
export function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/**
 * Concatenate multiple byte arrays.
 * @param arrays - Arrays to concatenate
 * @returns Combined byte array
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);

  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
}

/**
 * Split a byte array at specified indices.
 * @param bytes - Array to split
 * @param sizes - Sizes of each resulting chunk
 * @returns Array of byte chunks
 * @throws Error if total sizes don't match input length
 */
export function splitBytes(bytes: Uint8Array, sizes: number[]): Uint8Array[] {
  const totalSize = sizes.reduce((sum, s) => sum + s, 0);
  if (totalSize !== bytes.length) {
    throw new Error(
      `Size mismatch: expected ${totalSize} bytes, got ${bytes.length}`
    );
  }

  const result: Uint8Array[] = [];
  let offset = 0;

  for (const size of sizes) {
    result.push(bytes.slice(offset, offset + size));
    offset += size;
  }

  return result;
}
