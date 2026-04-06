/**
 * Deprecated development-session helpers.
 *
 * SECURITY: deterministic shared-key fallbacks are disabled.
 * This module is kept temporarily only to avoid accidental import breakage.
 */

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
  _userId1: string,
  _userId2: string
): Promise<Uint8Array> {
  throw new Error("dev session fallback is disabled");
}

/**
 * Create a DEV-mode session with a deterministic shared key.
 *
 * @param myUserId - Current user's ID
 * @param peerId - Peer's user ID
 * @returns Session object with shared keys
 */
export async function createDevSession(
  _myUserId: string,
  _peerId: string
): Promise<Session> {
  throw new Error("dev session fallback is disabled");
}
