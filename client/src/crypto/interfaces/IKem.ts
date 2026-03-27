/**
 * Key Exchange Method (KEM) interface for cryptographic agility.
 * Allows swapping PQC algorithms without changing application code.
 */
export interface IKemAlgorithm {
  /** Algorithm identifier (e.g., "ML-KEM-768") */
  readonly name: string;

  /** Public key size in bytes */
  readonly publicKeySize: number;

  /** Private key size in bytes */
  readonly privateKeySize: number;

  /** Ciphertext size in bytes */
  readonly ciphertextSize: number;

  /** Shared secret size in bytes */
  readonly sharedSecretSize: number;

  /**
   * Generate a new KEM keypair.
   * @returns Promise resolving to public and private key bytes
   */
  keypair(): Promise<KemKeyPair>;

  /**
   * Encapsulate a shared secret for a recipient's public key.
   * @param publicKey - Recipient's public key bytes
   * @returns Promise resolving to ciphertext and shared secret
   */
  encapsulate(publicKey: Uint8Array): Promise<KemEncapsulation>;

  /**
   * Decapsulate a shared secret from ciphertext using private key.
   * @param ciphertext - Ciphertext from encapsulate()
   * @param privateKey - Recipient's private key bytes
   * @returns Promise resolving to shared secret bytes
   */
  decapsulate(
    ciphertext: Uint8Array,
    privateKey: Uint8Array
  ): Promise<Uint8Array>;
}

export interface KemKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface KemEncapsulation {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}
