/**
 * Type compatibility utilities for WebCrypto.
 * Handles TypeScript strict mode compatibility between Uint8Array and BufferSource.
 */

/**
 * Convert Uint8Array to ArrayBuffer for WebCrypto compatibility.
 * TypeScript's strict mode doesn't allow Uint8Array<ArrayBufferLike> as BufferSource directly.
 *
 * @param data - Uint8Array to convert
 * @returns ArrayBuffer suitable for WebCrypto APIs
 */
export function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  // If the Uint8Array is a view of the entire buffer, return the buffer directly
  if (data.byteOffset === 0 && data.byteLength === data.buffer.byteLength) {
    return data.buffer as ArrayBuffer;
  }
  // Otherwise, create a copy to get a proper ArrayBuffer
  return data.slice().buffer as ArrayBuffer;
}

/**
 * Convert ArrayBuffer to Uint8Array.
 *
 * @param buffer - ArrayBuffer to convert
 * @returns Uint8Array view of the buffer
 */
export function fromArrayBuffer(buffer: ArrayBuffer): Uint8Array {
  return new Uint8Array(buffer);
}
