/**
 * Symmetric cipher interface for cryptographic agility.
 * Supports AEAD ciphers like AES-GCM and ChaCha20-Poly1305.
 */
export interface ICipherAlgorithm {
  /** Algorithm identifier (e.g., "AES-GCM-256") */
  readonly name: string;

  /** Key size in bytes */
  readonly keySize: number;

  /** Nonce/IV size in bytes */
  readonly nonceSize: number;

  /** Authentication tag size in bytes */
  readonly tagSize: number;

  /**
   * Encrypt plaintext with authenticated encryption.
   * @param key - Encryption key
   * @param nonce - Unique nonce (never reuse with same key)
   * @param plaintext - Data to encrypt
   * @param aad - Optional additional authenticated data
   * @returns Promise resolving to ciphertext with auth tag
   */
  encrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad?: Uint8Array
  ): Promise<Uint8Array>;

  /**
   * Decrypt ciphertext with authenticated encryption.
   * @param key - Decryption key
   * @param nonce - Same nonce used for encryption
   * @param ciphertext - Data to decrypt (includes auth tag)
   * @param aad - Optional additional authenticated data (must match encryption)
   * @returns Promise resolving to plaintext, or throws on auth failure
   */
  decrypt(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    aad?: Uint8Array
  ): Promise<Uint8Array>;
}
