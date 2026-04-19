/**
 * Session Manager Service.
 *
 * Manages active encryption sessions with contacts.
 * Sessions are cached in memory and persisted in IndexedDB.
 */

import type { Session } from "../crypto/hybrid/handshake";
import { getKeyStore } from "../crypto/storage/keystore";
import type { StoredSession } from "../crypto/storage/keystore";
import {
  deriveECDHSharedSecretFromBytes,
  generateExportableECDHKeyPair,
} from "../crypto/ecc/ecdh";

/** Map of contactId -> Session */
const activeSessions = new Map<string, Session>();
const sendCounters = new Map<string, number>();
const recvCounters = new Map<string, number>();
const recvCountersByRatchet = new Map<string, Map<string, number>>();
const skippedRecvMessageKeys = new Map<string, Map<string, Uint8Array>>();
const localRatchetPrivateKeys = new Map<string, CryptoKey>();
const localRatchetPublicKeys = new Map<string, Uint8Array>();
const remoteRatchetPublicKeys = new Map<string, Uint8Array>();
const ratchetNeedsAnnouncement = new Map<string, boolean>();
const ratchetAdvertised = new Map<string, boolean>();
const pendingSendRatchetStep = new Map<string, boolean>();

const MAX_SKIPPED_KEYS = 128;
const MAX_RECEIVE_GAP = 64;
const MAX_RATCHET_EPOCHS = 8;

const ECDH_ALGORITHM: EcKeyImportParams = {
  name: "ECDH",
  namedCurve: "P-384",
};

const LEGACY_RATCHET_ID = "base";

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function getRatchetId(ratchetPublicKey?: Uint8Array): string {
  if (!ratchetPublicKey || ratchetPublicKey.length === 0) {
    return LEGACY_RATCHET_ID;
  }
  return toHex(ratchetPublicKey);
}

function makeSkippedMapKey(ratchetId: string, messageNumber: number): string {
  return `${ratchetId}:${messageNumber}`;
}

function getOrCreateReceiveEpochCounters(
  contactId: string,
): Map<string, number> {
  const existing = recvCountersByRatchet.get(contactId);
  if (existing) return existing;

  const created = new Map<string, number>();
  const fallback = recvCounters.get(contactId) ?? 0;
  created.set(LEGACY_RATCHET_ID, fallback);
  recvCountersByRatchet.set(contactId, created);
  return created;
}

function getReceiveExpectedForRatchet(
  contactId: string,
  ratchetId: string,
): number {
  const perEpoch = getOrCreateReceiveEpochCounters(contactId);
  if (perEpoch.has(ratchetId)) {
    return perEpoch.get(ratchetId) ?? 0;
  }

  const fallback = recvCounters.get(contactId) ?? 0;
  perEpoch.set(ratchetId, fallback);
  return fallback;
}

function setReceiveExpectedForRatchet(
  contactId: string,
  ratchetId: string,
  value: number,
): void {
  const perEpoch = getOrCreateReceiveEpochCounters(contactId);
  perEpoch.set(ratchetId, value);
  recvCounters.set(contactId, value);
}

function pruneReceiveEpochState(
  contactId: string,
  keepRatchetId?: string,
): void {
  const perEpoch = recvCountersByRatchet.get(contactId);
  if (!perEpoch || perEpoch.size <= MAX_RATCHET_EPOCHS) return;

  const keep = new Set<string>([LEGACY_RATCHET_ID]);
  if (keepRatchetId) keep.add(keepRatchetId);

  for (const ratchetId of perEpoch.keys()) {
    if (perEpoch.size <= MAX_RATCHET_EPOCHS) break;
    if (keep.has(ratchetId)) continue;
    perEpoch.delete(ratchetId);
  }

  // Trim skipped keys for removed epochs.
  const skipped = skippedRecvMessageKeys.get(contactId);
  if (!skipped || skipped.size === 0) return;

  for (const compositeKey of Array.from(skipped.keys())) {
    const parsed = parseSkippedMapKey(compositeKey);
    if (!parsed) {
      skipped.delete(compositeKey);
      continue;
    }
    if (!perEpoch.has(parsed.ratchetId)) {
      skipped.delete(compositeKey);
    }
  }
}

function parseSkippedMapKey(
  composite: string,
): { ratchetId: string; messageNumber: number } | null {
  const idx = composite.lastIndexOf(":");
  if (idx <= 0) return null;

  const ratchetId = composite.slice(0, idx);
  const messageNumber = Number.parseInt(composite.slice(idx + 1), 10);
  if (!Number.isInteger(messageNumber) || messageNumber < 0) return null;

  return { ratchetId, messageNumber };
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
}

async function exportRatchetPrivateKey(
  privateKey: CryptoKey | undefined,
): Promise<JsonWebKey | undefined> {
  if (!privateKey) return undefined;
  try {
    return (await crypto.subtle.exportKey("jwk", privateKey)) as JsonWebKey;
  } catch {
    return undefined;
  }
}

async function importRatchetPrivateKey(
  jwk: JsonWebKey | undefined,
): Promise<CryptoKey | null> {
  if (!jwk) return null;
  try {
    return await crypto.subtle.importKey("jwk", jwk, ECDH_ALGORITHM, true, [
      "deriveBits",
    ]);
  } catch {
    return null;
  }
}

async function toStoredSession(
  contactId: string,
  session: Session,
): Promise<StoredSession> {
  const skipped = skippedRecvMessageKeys.get(contactId);
  const serializedSkipped = skipped
    ? Array.from(skipped.entries())
        .map(([compositeKey, key]) => {
          const parsed = parseSkippedMapKey(compositeKey);
          if (!parsed) return null;
          return {
            ratchetId: parsed.ratchetId,
            messageNumber: parsed.messageNumber,
            key,
          };
        })
        .filter(
          (
            entry,
          ): entry is {
            ratchetId: string;
            messageNumber: number;
            key: Uint8Array;
          } => entry !== null,
        )
        .sort((a, b) => a.messageNumber - b.messageNumber)
        .slice(-MAX_SKIPPED_KEYS)
        .map(({ ratchetId, messageNumber, key }) => ({
          ratchetId,
          messageNumber,
          key: toArrayBuffer(key),
        }))
    : [];

  const localRatchetPrivateJwk = await exportRatchetPrivateKey(
    localRatchetPrivateKeys.get(contactId),
  );
  const localRatchetPublicKey = localRatchetPublicKeys.get(contactId);
  const remoteRatchetPublicKey = remoteRatchetPublicKeys.get(contactId);
  const recvPerRatchet = recvCountersByRatchet.get(contactId);
  const serializedRecvPerRatchet = recvPerRatchet
    ? Array.from(recvPerRatchet.entries())
        .filter(
          ([ratchetId, nextMessageNumber]) =>
            typeof ratchetId === "string" &&
            ratchetId.length > 0 &&
            Number.isInteger(nextMessageNumber) &&
            nextMessageNumber >= 0,
        )
        .map(([ratchetId, nextMessageNumber]) => ({
          ratchetId,
          nextMessageNumber,
        }))
    : undefined;

  return {
    peerId: contactId,
    sessionId: session.sessionId,
    encryptionKey: toArrayBuffer(session.keys.encryptionKey),
    macKey: toArrayBuffer(session.keys.macKey),
    rootKey: toArrayBuffer(session.keys.rootKey),
    sendChainKey: toArrayBuffer(session.sendChainKey),
    recvChainKey: toArrayBuffer(session.recvChainKey),
    messageCounter: Number(session.messageCounter),
    sendMessageCounter:
      sendCounters.get(contactId) ?? Number(session.messageCounter),
    recvMessageCounter: recvCounters.get(contactId) ?? 0,
    recvCountersByRatchet: serializedRecvPerRatchet,
    localRatchetPrivateJwk,
    localRatchetPublicKey: localRatchetPublicKey
      ? toArrayBuffer(localRatchetPublicKey)
      : undefined,
    remoteRatchetPublicKey: remoteRatchetPublicKey
      ? toArrayBuffer(remoteRatchetPublicKey)
      : undefined,
    ratchetNeedsAnnouncement: ratchetNeedsAnnouncement.get(contactId) ?? false,
    ratchetAdvertised: ratchetAdvertised.get(contactId) ?? false,
    pendingSendRatchetStep: pendingSendRatchetStep.get(contactId) ?? false,
    skippedMessageKeys: serializedSkipped,
    createdAt: session.createdAt,
    lastUsed: Date.now(),
  };
}

async function hydrateSessionState(
  contactId: string,
  stored: StoredSession,
): Promise<void> {
  const fallbackSendCounter = Number(stored.messageCounter);
  sendCounters.set(
    contactId,
    stored.sendMessageCounter ??
      (Number.isFinite(fallbackSendCounter) ? fallbackSendCounter : 0),
  );
  recvCounters.set(contactId, stored.recvMessageCounter ?? 0);

  const recvPerRatchet = new Map<string, number>();
  for (const entry of stored.recvCountersByRatchet ?? []) {
    if (
      typeof entry.ratchetId === "string" &&
      entry.ratchetId.length > 0 &&
      Number.isInteger(entry.nextMessageNumber) &&
      entry.nextMessageNumber >= 0
    ) {
      recvPerRatchet.set(entry.ratchetId, entry.nextMessageNumber);
    }
  }
  if (!recvPerRatchet.has(LEGACY_RATCHET_ID)) {
    recvPerRatchet.set(LEGACY_RATCHET_ID, stored.recvMessageCounter ?? 0);
  }
  recvCountersByRatchet.set(contactId, recvPerRatchet);
  pruneReceiveEpochState(contactId);

  if (stored.localRatchetPublicKey) {
    localRatchetPublicKeys.set(
      contactId,
      new Uint8Array(stored.localRatchetPublicKey),
    );
  }

  if (stored.remoteRatchetPublicKey) {
    remoteRatchetPublicKeys.set(
      contactId,
      new Uint8Array(stored.remoteRatchetPublicKey),
    );
  }

  const restoredLocalPrivate = await importRatchetPrivateKey(
    stored.localRatchetPrivateJwk,
  );
  if (restoredLocalPrivate) {
    localRatchetPrivateKeys.set(contactId, restoredLocalPrivate);
  }

  if (stored.localRatchetPublicKey && !restoredLocalPrivate) {
    // Public key without matching local private key cannot be used for DH.
    // Drop it and force a fresh local ratchet key announcement.
    localRatchetPublicKeys.delete(contactId);
    ratchetNeedsAnnouncement.set(contactId, true);
    ratchetAdvertised.set(contactId, false);
  } else {
    ratchetNeedsAnnouncement.set(
      contactId,
      stored.ratchetNeedsAnnouncement ?? false,
    );
    ratchetAdvertised.set(contactId, stored.ratchetAdvertised ?? false);
  }

  pendingSendRatchetStep.set(contactId, stored.pendingSendRatchetStep ?? false);

  const skippedMap = new Map<string, Uint8Array>();
  for (const entry of stored.skippedMessageKeys ?? []) {
    if (
      typeof entry.messageNumber === "number" &&
      Number.isFinite(entry.messageNumber) &&
      entry.messageNumber >= 0
    ) {
      const ratchetId =
        typeof entry.ratchetId === "string" && entry.ratchetId.length > 0
          ? entry.ratchetId
          : LEGACY_RATCHET_ID;
      skippedMap.set(
        makeSkippedMapKey(ratchetId, entry.messageNumber),
        new Uint8Array(entry.key),
      );
    }
  }

  if (skippedMap.size > MAX_SKIPPED_KEYS) {
    const sorted = Array.from(skippedMap.entries());
    const trimmed = sorted.slice(sorted.length - MAX_SKIPPED_KEYS);
    skippedRecvMessageKeys.set(contactId, new Map(trimmed));
  } else {
    skippedRecvMessageKeys.set(contactId, skippedMap);
  }
}

function fromStoredSession(stored: StoredSession): Session {
  return {
    sessionId: stored.sessionId,
    peerId: stored.peerId,
    keys: {
      encryptionKey: new Uint8Array(stored.encryptionKey),
      macKey: new Uint8Array(stored.macKey),
      rootKey: new Uint8Array(stored.rootKey),
    },
    sendChainKey: new Uint8Array(stored.sendChainKey),
    recvChainKey: new Uint8Array(stored.recvChainKey),
    messageCounter: BigInt(stored.messageCounter),
    createdAt: stored.createdAt,
  };
}

async function hmacSha384(
  key: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key as BufferSource,
    { name: "HMAC", hash: "SHA-384" },
    false,
    ["sign"],
  );
  const result = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    data as BufferSource,
  );
  return new Uint8Array(result);
}

async function ratchetStep(chainKey: Uint8Array): Promise<{
  nextChainKey: Uint8Array;
  messageKey: Uint8Array;
}> {
  const nextChainKey = await hmacSha384(
    chainKey,
    new TextEncoder().encode("SecureMsg-ChainStep-v1"),
  );
  const messageKeyFull = await hmacSha384(
    chainKey,
    new TextEncoder().encode("SecureMsg-MessageKey-v1"),
  );

  return {
    nextChainKey,
    messageKey: messageKeyFull.slice(0, 32), // AES-GCM-256 key
  };
}

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

async function ensureLocalRatchetKey(contactId: string): Promise<void> {
  if (
    localRatchetPrivateKeys.has(contactId) &&
    localRatchetPublicKeys.has(contactId)
  ) {
    return;
  }

  const keyPair = await generateExportableECDHKeyPair();
  localRatchetPrivateKeys.set(contactId, keyPair.privateKey);
  localRatchetPublicKeys.set(contactId, keyPair.publicKeyBytes);
  ratchetNeedsAnnouncement.set(contactId, true);
  if (!ratchetAdvertised.has(contactId)) {
    ratchetAdvertised.set(contactId, false);
  }
  if (!pendingSendRatchetStep.has(contactId)) {
    pendingSendRatchetStep.set(contactId, false);
  }
}

async function deriveRootAndChain(
  rootKey: Uint8Array,
  dhSecret: Uint8Array,
  direction: "send" | "recv",
): Promise<{ nextRootKey: Uint8Array; chainKey: Uint8Array }> {
  const nextRootKeyFull = await hmacSha384(
    rootKey,
    new Uint8Array([
      ...new TextEncoder().encode("SecureMsg-DR-Root-v1"),
      ...dhSecret,
    ]),
  );
  const nextRootKey = nextRootKeyFull.slice(0, 32);
  const chainKeyFull = await hmacSha384(
    nextRootKey,
    new TextEncoder().encode(
      direction === "send" ? "SecureMsg-DR-Send-v1" : "SecureMsg-DR-Recv-v1",
    ),
  );

  return {
    nextRootKey,
    chainKey: chainKeyFull.slice(0, 32),
  };
}

async function applyReceiveRatchet(
  contactId: string,
  session: Session,
  incomingRatchetPublicKey: Uint8Array,
): Promise<void> {
  await ensureLocalRatchetKey(contactId);
  const localPrivate = localRatchetPrivateKeys.get(contactId);
  if (!localPrivate) {
    throw new Error("Missing local ratchet private key");
  }

  const dhSecret = await deriveECDHSharedSecretFromBytes(
    localPrivate,
    incomingRatchetPublicKey,
  );
  const { nextRootKey, chainKey } = await deriveRootAndChain(
    session.keys.rootKey,
    dhSecret,
    "recv",
  );

  session.keys.rootKey = nextRootKey;
  session.recvChainKey = chainKey;
}

async function applySendRatchet(
  contactId: string,
  session: Session,
): Promise<void> {
  const remoteRatchet = remoteRatchetPublicKeys.get(contactId);
  if (!remoteRatchet) return;

  const newLocalRatchet = await generateExportableECDHKeyPair();
  const dhSecret = await deriveECDHSharedSecretFromBytes(
    newLocalRatchet.privateKey,
    remoteRatchet,
  );
  const { nextRootKey, chainKey } = await deriveRootAndChain(
    session.keys.rootKey,
    dhSecret,
    "send",
  );

  session.keys.rootKey = nextRootKey;
  session.sendChainKey = chainKey;
  localRatchetPrivateKeys.set(contactId, newLocalRatchet.privateKey);
  localRatchetPublicKeys.set(contactId, newLocalRatchet.publicKeyBytes);
  ratchetNeedsAnnouncement.set(contactId, true);
  pendingSendRatchetStep.set(contactId, false);
}

/**
 * Get an existing session for a contact.
 * Returns null if no session exists.
 */
export function getSession(contactId: string): Session | null {
  return activeSessions.get(contactId) ?? null;
}

/**
 * Get an existing session for a contact.
 * Checks memory cache first, then IndexedDB.
 */
export async function getSessionAsync(
  contactId: string,
): Promise<Session | null> {
  const cached = activeSessions.get(contactId);
  if (cached) {
    if (!sendCounters.has(contactId)) {
      sendCounters.set(contactId, Number(cached.messageCounter));
    }
    if (!recvCounters.has(contactId)) {
      recvCounters.set(contactId, 0);
    }
    if (!skippedRecvMessageKeys.has(contactId)) {
      skippedRecvMessageKeys.set(contactId, new Map());
    }
    await ensureLocalRatchetKey(contactId);
    return cached;
  }

  const stored = await getKeyStore().getSession(contactId);
  if (!stored) return null;

  const session = fromStoredSession(stored);
  activeSessions.set(contactId, session);
  await hydrateSessionState(contactId, stored);
  await ensureLocalRatchetKey(contactId);
  return session;
}

/**
 * Save a session for a contact.
 * Overwrites any existing session.
 */
export async function saveSession(
  contactId: string,
  session: Session,
): Promise<void> {
  if (!sendCounters.has(contactId)) {
    sendCounters.set(contactId, Number(session.messageCounter));
  }
  if (!recvCounters.has(contactId)) {
    recvCounters.set(contactId, 0);
  }
  if (!skippedRecvMessageKeys.has(contactId)) {
    skippedRecvMessageKeys.set(contactId, new Map());
  }
  await ensureLocalRatchetKey(contactId);

  activeSessions.set(contactId, session);
  await getKeyStore().storeSession(await toStoredSession(contactId, session));
  console.log(`[SessionManager] Session saved for contact: ${contactId}`);
}

/**
 * Check if a session exists for a contact.
 */
export async function hasSession(contactId: string): Promise<boolean> {
  if (activeSessions.has(contactId)) return true;
  const stored = await getKeyStore().getSession(contactId);
  return stored !== null;
}

/**
 * Delete a session for a contact.
 * Used when a session is compromised or expired.
 */
export async function deleteSession(contactId: string): Promise<void> {
  activeSessions.delete(contactId);
  sendCounters.delete(contactId);
  recvCounters.delete(contactId);
  recvCountersByRatchet.delete(contactId);
  skippedRecvMessageKeys.delete(contactId);
  localRatchetPrivateKeys.delete(contactId);
  localRatchetPublicKeys.delete(contactId);
  remoteRatchetPublicKeys.delete(contactId);
  ratchetNeedsAnnouncement.delete(contactId);
  ratchetAdvertised.delete(contactId);
  pendingSendRatchetStep.delete(contactId);
  await getKeyStore().deleteSession(contactId);
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
export async function clearAllSessions(): Promise<void> {
  activeSessions.clear();
  sendCounters.clear();
  recvCounters.clear();
  recvCountersByRatchet.clear();
  skippedRecvMessageKeys.clear();
  localRatchetPrivateKeys.clear();
  localRatchetPublicKeys.clear();
  remoteRatchetPublicKeys.clear();
  ratchetNeedsAnnouncement.clear();
  ratchetAdvertised.clear();
  pendingSendRatchetStep.clear();
  const keyStore = getKeyStore();
  const allSessions = await keyStore.getAllSessions();
  await Promise.all(allSessions.map((s) => keyStore.deleteSession(s.peerId)));
  console.log("[SessionManager] All sessions cleared");
}

/**
 * Update the message counter for a session.
 * This is used for nonce generation to prevent replay attacks.
 */
export async function incrementMessageCounter(
  contactId: string,
): Promise<bigint> {
  const session = await getSessionAsync(contactId);
  if (!session) {
    throw new Error(`No session found for contact: ${contactId}`);
  }
  session.messageCounter += 1n;
  sendCounters.set(contactId, Number(session.messageCounter));
  await saveSession(contactId, session);
  return session.messageCounter;
}

/**
 * Advance sender chain and derive one-time message key.
 */
export async function nextSendMessageKey(
  contactId: string,
): Promise<Uint8Array> {
  const derived = await nextSendMessageKeyWithNumber(contactId);
  return derived.messageKey;
}

/**
 * Advance sender chain and derive one-time message key + message number.
 */
export async function nextSendMessageKeyWithNumber(contactId: string): Promise<{
  messageKey: Uint8Array;
  messageNumber: number;
  ratchetPublicKey?: Uint8Array;
}> {
  const session = await getSessionAsync(contactId);
  if (!session) {
    throw new Error(`No session found for contact: ${contactId}`);
  }

  await ensureLocalRatchetKey(contactId);
  if (pendingSendRatchetStep.get(contactId)) {
    await applySendRatchet(contactId, session);
  }

  const messageNumber =
    sendCounters.get(contactId) ?? Number(session.messageCounter);

  const { nextChainKey, messageKey } = await ratchetStep(session.sendChainKey);
  session.sendChainKey = nextChainKey;
  session.messageCounter += 1n;
  sendCounters.set(contactId, messageNumber + 1);

  let ratchetPublicKey: Uint8Array | undefined;
  if (ratchetNeedsAnnouncement.get(contactId)) {
    ratchetPublicKey = localRatchetPublicKeys.get(contactId);
    ratchetNeedsAnnouncement.set(contactId, false);
    ratchetAdvertised.set(contactId, true);
  }

  await saveSession(contactId, session);
  return { messageKey, messageNumber, ratchetPublicKey };
}

/**
 * Advance receiver chain and derive one-time message key.
 */
export async function nextReceiveMessageKey(
  contactId: string,
): Promise<Uint8Array> {
  return nextReceiveMessageKeyAt(contactId);
}

function trimSkippedMap(skipped: Map<string, Uint8Array>): void {
  if (skipped.size <= MAX_SKIPPED_KEYS) return;
  const removeCount = skipped.size - MAX_SKIPPED_KEYS;
  const keys = skipped.keys();
  for (let i = 0; i < removeCount; i += 1) {
    const next = keys.next();
    if (next.done) break;
    skipped.delete(next.value);
  }
}

/**
 * Derive a receive-side message key for a specific message number.
 * Handles out-of-order delivery by caching skipped keys.
 */
export async function nextReceiveMessageKeyAt(
  contactId: string,
  targetMessageNumber?: number,
  incomingRatchetPublicKey?: Uint8Array,
): Promise<Uint8Array> {
  const session = await getSessionAsync(contactId);
  if (!session) {
    throw new Error(`No session found for contact: ${contactId}`);
  }

  await ensureLocalRatchetKey(contactId);

  const currentRemoteRatchetBeforeUpdate =
    remoteRatchetPublicKeys.get(contactId);
  const ratchetIdForMessage = getRatchetId(
    incomingRatchetPublicKey && incomingRatchetPublicKey.length > 0
      ? incomingRatchetPublicKey
      : currentRemoteRatchetBeforeUpdate,
  );

  let remoteChanged = false;

  if (incomingRatchetPublicKey && incomingRatchetPublicKey.length > 0) {
    const currentRemoteRatchet = remoteRatchetPublicKeys.get(contactId);
    remoteChanged =
      !currentRemoteRatchet ||
      !arraysEqual(currentRemoteRatchet, incomingRatchetPublicKey);

    if (remoteChanged) {
      const hasAdvertisedLocal = ratchetAdvertised.get(contactId) ?? false;
      remoteRatchetPublicKeys.set(contactId, incomingRatchetPublicKey);
      getOrCreateReceiveEpochCounters(contactId).set(
        ratchetIdForMessage,
        getReceiveExpectedForRatchet(contactId, ratchetIdForMessage),
      );
      pruneReceiveEpochState(contactId, ratchetIdForMessage);

      if (hasAdvertisedLocal || currentRemoteRatchet) {
        await applyReceiveRatchet(contactId, session, incomingRatchetPublicKey);
      }

      pendingSendRatchetStep.set(contactId, true);
    }
  }

  let expected = recvCounters.get(contactId);
  if (expected === undefined) {
    expected = 0;
    recvCounters.set(contactId, expected);
  }

  expected = getReceiveExpectedForRatchet(contactId, ratchetIdForMessage);

  const skipped =
    skippedRecvMessageKeys.get(contactId) ?? new Map<string, Uint8Array>();
  skippedRecvMessageKeys.set(contactId, skipped);

  if (typeof targetMessageNumber === "number") {
    if (!Number.isInteger(targetMessageNumber) || targetMessageNumber < 0) {
      throw new Error("Invalid inbound message number");
    }

    const compositeKey = makeSkippedMapKey(
      ratchetIdForMessage,
      targetMessageNumber,
    );
    const cached = skipped.get(compositeKey);
    if (cached) {
      skipped.delete(compositeKey);
      await saveSession(contactId, session);
      return cached;
    }

    // Backward compatibility: allow reading old sessions persisted before ratchetId.
    const legacyKey = makeSkippedMapKey(LEGACY_RATCHET_ID, targetMessageNumber);
    if (ratchetIdForMessage !== LEGACY_RATCHET_ID) {
      const legacyCached = skipped.get(legacyKey);
      if (legacyCached) {
        skipped.delete(legacyKey);
        await saveSession(contactId, session);
        return legacyCached;
      }
    }

    if (targetMessageNumber < expected) {
      // Some peers may reset sender-chain counters after a DH ratchet step.
      // If this message is explicitly tied to a newly observed ratchet key,
      // allow receive counter reset for this epoch.
      if (
        remoteChanged &&
        incomingRatchetPublicKey &&
        incomingRatchetPublicKey.length > 0
      ) {
        expected = 0;
        setReceiveExpectedForRatchet(contactId, ratchetIdForMessage, expected);
      } else {
        throw new Error("Replay or stale message detected");
      }
    }

    if (targetMessageNumber - expected > MAX_RECEIVE_GAP) {
      throw new Error("Inbound message gap too large");
    }

    while (expected <= targetMessageNumber) {
      const { nextChainKey, messageKey } = await ratchetStep(
        session.recvChainKey,
      );
      session.recvChainKey = nextChainKey;

      if (expected === targetMessageNumber) {
        setReceiveExpectedForRatchet(
          contactId,
          ratchetIdForMessage,
          expected + 1,
        );
        trimSkippedMap(skipped);
        await saveSession(contactId, session);
        return messageKey;
      }

      skipped.set(makeSkippedMapKey(ratchetIdForMessage, expected), messageKey);
      expected += 1;
      setReceiveExpectedForRatchet(contactId, ratchetIdForMessage, expected);
    }
  }

  const { nextChainKey, messageKey } = await ratchetStep(session.recvChainKey);
  session.recvChainKey = nextChainKey;
  setReceiveExpectedForRatchet(contactId, ratchetIdForMessage, expected + 1);
  trimSkippedMap(skipped);
  await saveSession(contactId, session);
  return messageKey;
}
