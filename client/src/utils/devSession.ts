/**
 * DEV-mode session creation utilities.
 * Creates deterministic shared keys for development/testing.
 *
 * SECURITY: In production, this should be replaced with proper X3DH handshake.
 */

import { generateRandomId } from "../crypto/utils/random";
import type { Session } from "../crypto/hybrid/handshake";

/**
 * Derive a deterministic shared key from two user IDs.
 * Both parties will derive the same key regardless of order.
 *
 * @param userId1 - First user ID
 * @param userId2 - Second user ID
 * @returns 32-byte shared key
 */
export async function deriveSharedDevKey(
  userId1: string,
  userId2: string,
): Promise<Uint8Array> {
  // Sort IDs to ensure both parties derive the same key
  const sortedIds = [userId1, userId2].sort();
  const combined = sortedIds.join(":");
  const encoder = new TextEncoder();
  const hash = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(combined + ":dev-key"),
  );
  return new Uint8Array(hash);
}

/**
 * Create a DEV-mode session with a deterministic shared key.
 *
 * @param myUserId - Current user's ID
 * @param peerId - Peer's user ID
 * @returns Session object with shared keys
 */
export async function createDevSession(
  myUserId: string,
  peerId: string,
): Promise<Session> {
  const sharedKey = await deriveSharedDevKey(myUserId, peerId);

  return {
    sessionId: generateRandomId(),
    peerId,
    keys: {
      rootKey: sharedKey,
      encryptionKey: sharedKey,
      macKey: sharedKey,
    },
    sendChainKey: sharedKey,
    recvChainKey: sharedKey,
    messageCounter: 0n,
    createdAt: Date.now(),
  };
}
