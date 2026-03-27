/**
 * Nonce management for AES-GCM.
 *
 * SECURITY: Nonce reuse with the same key catastrophically breaks AES-GCM.
 * This module ensures unique nonces using counter + random hybrid.
 */

import { getRandomBytes } from "../utils/random";

/** Nonce format: [4 bytes random][8 bytes counter] = 12 bytes */
export const NONCE_SIZE = 12;

/**
 * Nonce generator that combines random prefix with counter.
 * Thread-safe for single-threaded JavaScript runtime.
 */
export class NonceGenerator {
  private counter: bigint = 0n;
  private randomPrefix: Uint8Array;

  constructor() {
    // Generate random prefix on initialization
    this.randomPrefix = getRandomBytes(4);
  }

  /**
   * Generate the next unique nonce.
   * Format: [4 bytes random][8 bytes counter]
   *
   * @returns 12-byte unique nonce
   */
  next(): Uint8Array {
    const nonce = new Uint8Array(NONCE_SIZE);

    // Set random prefix
    nonce.set(this.randomPrefix, 0);

    // Set counter (big-endian)
    const view = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
    view.setBigUint64(4, this.counter, false);

    // Increment counter
    this.counter++;

    // Check for counter overflow (extremely unlikely with 64-bit counter)
    if (this.counter >= 2n ** 64n) {
      // Rotate random prefix and reset counter
      this.randomPrefix = getRandomBytes(4);
      this.counter = 0n;
    }

    return nonce;
  }

  /**
   * Reset the generator with a new random prefix.
   * Call when starting a new session.
   */
  reset(): void {
    this.randomPrefix = getRandomBytes(4);
    this.counter = 0n;
  }

  /**
   * Get current counter value for debugging/testing.
   */
  getCounter(): bigint {
    return this.counter;
  }
}

/**
 * Session-specific nonce state.
 * Each session should have its own nonce generator.
 */
export interface NonceState {
  /** Send nonce counter */
  sendCounter: bigint;
  /** Receive nonce counter (for replay detection) */
  receiveCounter: bigint;
  /** Random prefix for send nonces */
  sendPrefix: Uint8Array;
}

/**
 * Create a new nonce state for a session.
 */
export function createNonceState(): NonceState {
  return {
    sendCounter: 0n,
    receiveCounter: 0n,
    sendPrefix: getRandomBytes(4),
  };
}

/**
 * Generate send nonce and advance counter.
 */
export function nextSendNonce(state: NonceState): Uint8Array {
  const nonce = new Uint8Array(NONCE_SIZE);
  nonce.set(state.sendPrefix, 0);

  const view = new DataView(nonce.buffer);
  view.setBigUint64(4, state.sendCounter, false);

  state.sendCounter++;
  return nonce;
}

/**
 * Validate received nonce for replay protection.
 * Nonce counter must be greater than last seen.
 *
 * @param nonce - Received nonce
 * @param state - Session nonce state
 * @returns true if nonce is valid and not replayed
 */
export function validateReceivedNonce(
  nonce: Uint8Array,
  state: NonceState
): boolean {
  if (nonce.length !== NONCE_SIZE) {
    return false;
  }

  // Extract counter from nonce (last 8 bytes)
  const view = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  const receivedCounter = view.getBigUint64(4, false);

  // Counter must be strictly greater than last seen
  if (receivedCounter <= state.receiveCounter) {
    return false;
  }

  // Update receive counter
  state.receiveCounter = receivedCounter;
  return true;
}
