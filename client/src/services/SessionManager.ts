/**
 * Session Manager Service.
 *
 * Manages active encryption sessions with contacts.
 * Sessions are stored in memory and persist for the lifetime of the app.
 *
 * SECURITY: Sessions contain derived keys. In a production app,
 * these would be encrypted and stored in IndexedDB.
 */

import type { Session } from "../crypto/hybrid/handshake";

/** Map of contactId -> Session */
const activeSessions = new Map<string, Session>();

/**
 * Get an existing session for a contact.
 * Returns null if no session exists.
 */
export function getSession(contactId: string): Session | null {
  return activeSessions.get(contactId) ?? null;
}

/**
 * Save a session for a contact.
 * Overwrites any existing session.
 */
export function saveSession(contactId: string, session: Session): void {
  activeSessions.set(contactId, session);
  console.log(`[SessionManager] Session saved for contact: ${contactId}`);
}

/**
 * Check if a session exists for a contact.
 */
export function hasSession(contactId: string): boolean {
  return activeSessions.has(contactId);
}

/**
 * Delete a session for a contact.
 * Used when a session is compromised or expired.
 */
export function deleteSession(contactId: string): void {
  activeSessions.delete(contactId);
  console.log(`[SessionManager] Session deleted for contact: ${contactId}`);
}

/**
 * Get all active session contact IDs.
 */
export function getActiveSessionIds(): string[] {
  return Array.from(activeSessions.keys());
}

/**
 * Clear all sessions.
 * Used on logout.
 */
export function clearAllSessions(): void {
  activeSessions.clear();
  console.log("[SessionManager] All sessions cleared");
}

/**
 * Update the message counter for a session.
 * This is used for nonce generation to prevent replay attacks.
 */
export function incrementMessageCounter(contactId: string): bigint {
  const session = activeSessions.get(contactId);
  if (!session) {
    throw new Error(`No session found for contact: ${contactId}`);
  }
  session.messageCounter += 1n;
  return session.messageCounter;
}
