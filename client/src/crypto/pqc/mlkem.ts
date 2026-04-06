/**
 * ML-KEM-768 (Kyber) Post-Quantum Key Encapsulation Mechanism.
 *
 * Uses the `mlkem` npm package — a pure TypeScript implementation
 * of NIST FIPS 203, passing all official KAT vectors.
 *
 * SECURITY: No custom PQC implementations. Only uses audited libraries.
 *
 * ML-KEM-768 parameters (FIPS 203):
 * - Public key: 1184 bytes
 * - Private key: 2400 bytes
 * - Ciphertext: 1088 bytes
 * - Shared secret: 32 bytes
 * - Security level: NIST Level 3 (equivalent to AES-192)
 */

import { createMlKem768 } from "mlkem";
import type {
  IKemAlgorithm,
  KemKeyPair,
  KemEncapsulation,
} from "../interfaces";

/** ML-KEM-768 sizes as defined in FIPS 203 */
export const MLKEM768_PUBLIC_KEY_SIZE = 1184;
export const MLKEM768_PRIVATE_KEY_SIZE = 2400;
export const MLKEM768_CIPHERTEXT_SIZE = 1088;
export const MLKEM768_SHARED_SECRET_SIZE = 32;

/**
 * ML-KEM-768 KEM implementation backed by the `mlkem` package.
 */
export class MlKem768 implements IKemAlgorithm {
  readonly name = "ML-KEM-768";
  readonly publicKeySize = MLKEM768_PUBLIC_KEY_SIZE;
  readonly privateKeySize = MLKEM768_PRIVATE_KEY_SIZE;
  readonly ciphertextSize = MLKEM768_CIPHERTEXT_SIZE;
  readonly sharedSecretSize = MLKEM768_SHARED_SECRET_SIZE;

  private instance: Awaited<ReturnType<typeof createMlKem768>> | null = null;
  private initialized = false;

  /**
   * Initialize the ML-KEM-768 instance.
   * Must be called before any cryptographic operations.
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    this.instance = await createMlKem768();
    this.initialized = true;
    console.log("[PQC] ML-KEM-768 initialized (FIPS 203)");
  }

  /**
   * Check if the module is initialized.
   */
  isInitialized(): boolean {
    return this.initialized;
  }

  /**
   * Generate a new ML-KEM-768 keypair.
   *
   * @returns Promise resolving to public and private key bytes
   */
  async keypair(): Promise<KemKeyPair> {
    this.ensureInitialized();

    const [publicKey, privateKey] = this.instance!.generateKeyPair();

    return {
      publicKey: new Uint8Array(publicKey),
      privateKey: new Uint8Array(privateKey),
    };
  }

  /**
   * Encapsulate a shared secret for a recipient's public key.
   *
   * @param publicKey - Recipient's ML-KEM-768 public key (1184 bytes)
   * @returns Promise resolving to ciphertext (1088 bytes) and shared secret (32 bytes)
   */
  async encapsulate(publicKey: Uint8Array): Promise<KemEncapsulation> {
    this.ensureInitialized();

    if (publicKey.length !== this.publicKeySize) {
      throw new Error(
        `Invalid public key size: expected ${this.publicKeySize}, got ${publicKey.length}`
      );
    }

    const [ciphertext, sharedSecret] = this.instance!.encap(publicKey);

    return {
      ciphertext: new Uint8Array(ciphertext),
      sharedSecret: new Uint8Array(sharedSecret),
    };
  }

  /**
   * Decapsulate a shared secret using private key.
   *
   * @param ciphertext - Ciphertext from encapsulate (1088 bytes)
   * @param privateKey - Recipient's private key (2400 bytes)
   * @returns Promise resolving to shared secret (32 bytes)
   */
  async decapsulate(
    ciphertext: Uint8Array,
    privateKey: Uint8Array
  ): Promise<Uint8Array> {
    this.ensureInitialized();

    if (ciphertext.length !== this.ciphertextSize) {
      throw new Error(
        `Invalid ciphertext size: expected ${this.ciphertextSize}, got ${ciphertext.length}`
      );
    }

    if (privateKey.length !== this.privateKeySize) {
      throw new Error(
        `Invalid private key size: expected ${this.privateKeySize}, got ${privateKey.length}`
      );
    }

    const sharedSecret = this.instance!.decap(ciphertext, privateKey);

    return new Uint8Array(sharedSecret);
  }

  private ensureInitialized(): void {
    if (!this.initialized || !this.instance) {
      throw new Error(
        "ML-KEM-768 module not initialized. Call initialize() first."
      );
    }
  }
}

// Singleton instance for application-wide use
let mlkemInstance: MlKem768 | null = null;

/**
 * Get the ML-KEM-768 singleton instance.
 * Initializes the module on first call.
 */
export async function getMlKem768(): Promise<MlKem768> {
  if (!mlkemInstance) {
    mlkemInstance = new MlKem768();
    await mlkemInstance.initialize();
  }
  return mlkemInstance;
}

/**
 * Check if ML-KEM-768 is available.
 * Use to gracefully degrade if not supported.
 */
export function isMlKem768Available(): boolean {
  return mlkemInstance?.isInitialized() ?? false;
}

