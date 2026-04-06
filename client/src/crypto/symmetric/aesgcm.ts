/**
 * AES-GCM-256 authenticated encryption using WebCrypto.
 * Provides confidentiality and authenticity for message content.
 *
 * SECURITY: Uses 12-byte nonces and 128-bit auth tags as recommended by NIST.
 */

import type { ICipherAlgorithm } from "../interfaces";
import { toArrayBuffer } from "../utils/buffer";

/** AES-GCM-256 configuration */
export const AES_GCM_KEY_SIZE = 32; // 256 bits
export const AES_GCM_NONCE_SIZE = 12; // 96 bits (recommended by NIST)
export const AES_GCM_TAG_SIZE = 16; // 128 bits

/**
 * AES-GCM-256 cipher implementation.
 */
export class AesGcmCipher implements ICipherAlgorithm {
  readonly name = "AES-GCM-256";
  readonly keySize = AES_GCM_KEY_SIZE;
  readonly nonceSize = AES_GCM_NONCE_SIZE;
  readonly tagSize = AES_GCM_TAG_SIZE;

  /**
   * Encrypt plaintext with AES-GCM.
   *
   * @param key - 256-bit encryption key
   * @param nonce - 96-bit nonce (MUST be unique per key)
   * @param plaintext - Data to encrypt
   * @param aad - Optional additional authenticated data
   * @returns Ciphertext with appended 128-bit auth tag
   */
  async encrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array> {
    this.validateKey(key);
    this.validateNonce(nonce);

    const cryptoKey = await this.importKey(key);

    // Ensure AAD is an ArrayBuffer (BufferSource)
    let aadBuffer: ArrayBuffer | undefined = undefined;
    const anyAad = aad as any;
    if (anyAad) {
      if (typeof anyAad === "string") {
        const encoder = new TextEncoder();
        aadBuffer = encoder.encode(anyAad).buffer;
      } else if (anyAad instanceof Uint8Array) {
        aadBuffer = toArrayBuffer(anyAad);
      } else if (anyAad instanceof ArrayBuffer) {
        aadBuffer = anyAad;
      }
    }

    const algorithm: AesGcmParams = {
      name: "AES-GCM",
      iv: toArrayBuffer(nonce),
      tagLength: 128, // 128-bit auth tag
    };

    if (aadBuffer) {
      algorithm.additionalData = aadBuffer;
    }

    const ciphertext = await crypto.subtle.encrypt(
      algorithm,
      cryptoKey,
      toArrayBuffer(plaintext),
    );

    return new Uint8Array(ciphertext);
  }

  /**
   * Decrypt ciphertext with AES-GCM.
   *
   * @param key - 256-bit decryption key
   * @param nonce - Same 96-bit nonce used for encryption
   * @param ciphertext - Encrypted data with auth tag
   * @param aad - Optional additional authenticated data (must match encryption)
   * @returns Decrypted plaintext
   * @throws Error if authentication fails
   */
  async decrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    aad?: Uint8Array,
  ): Promise<Uint8Array> {
    this.validateKey(key);
    this.validateNonce(nonce);

    if (ciphertext.length < this.tagSize) {
      throw new Error("Ciphertext too short to contain auth tag");
    }

    const cryptoKey = await this.importKey(key);

    // Ensure AAD is an ArrayBuffer (BufferSource) for SubtleCrypto compatibility.
    let aadBuffer: ArrayBuffer | undefined = undefined;
    const anyAad = aad as any;
    if (anyAad) {
      if (typeof anyAad === "string") {
        aadBuffer = new TextEncoder().encode(anyAad).buffer;
      } else if (anyAad instanceof Uint8Array) {
        aadBuffer = toArrayBuffer(anyAad);
      } else if (anyAad instanceof ArrayBuffer) {
        aadBuffer = anyAad;
      }
    }

    try {
      const algorithm: AesGcmParams = {
        name: "AES-GCM",
        iv: toArrayBuffer(nonce),
        tagLength: 128,
      };

      if (aadBuffer) {
        algorithm.additionalData = aadBuffer;
      }

      const plaintext = await crypto.subtle.decrypt(
        algorithm,
        cryptoKey,
        toArrayBuffer(ciphertext),
      );

      return new Uint8Array(plaintext);
    } catch {
      // WebCrypto throws generic error on auth failure
      throw new Error("Decryption failed: authentication tag mismatch");
    }
  }

  private validateKey(key: Uint8Array): void {
    if (key.length !== this.keySize) {
      throw new Error(
        `Invalid key size: expected ${this.keySize}, got ${key.length}`,
      );
    }
  }

  private validateNonce(nonce: Uint8Array): void {
    if (nonce.length !== this.nonceSize) {
      throw new Error(
        `Invalid nonce size: expected ${this.nonceSize}, got ${nonce.length}`,
      );
    }
  }

  private async importKey(keyBytes: Uint8Array): Promise<CryptoKey> {
    return crypto.subtle.importKey(
      "raw",
      toArrayBuffer(keyBytes),
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"],
    );
  }
}

// Default instance
export const aesGcm = new AesGcmCipher();

/**
 * Convenience function: encrypt with AES-GCM-256.
 */
export async function aesGcmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  return aesGcm.encrypt(key, nonce, plaintext, aad);
}

/**
 * Convenience function: decrypt with AES-GCM-256.
 */
export async function aesGcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  return aesGcm.decrypt(key, nonce, ciphertext, aad);
}
