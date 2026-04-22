/**
 * Secure key storage using IndexedDB.
 *
 * SECURITY:
 * - Keys are stored encrypted where possible
 * - WebCrypto CryptoKey objects are stored as non-exportable handles
 * - PQC keys are stored as encrypted byte arrays
 * - No plaintext private keys in storage
 */

const DB_NAME = "SecureMsgKeyStore";
const DB_VERSION = 2;
const AT_REST_SALT_PREFIX = "securemsg.atrest.salt.";
const ARRAY_BUFFER_TAG = "securemsg.arraybuffer.v1";

let activeAtRestKey: CryptoKey | null = null;
let activeStorageUserId: string | null = null;

function requireActiveStorageUserId(): string {
  if (!activeStorageUserId) {
    throw new Error(
      "At-rest key unavailable. Login required to unlock storage.",
    );
  }
  return activeStorageUserId;
}

function toScopedStorageId(ownerUserId: string, rawId: string): string {
  return `${ownerUserId}:${rawId}`;
}

function fromScopedStorageId(ownerUserId: string, value: string): string {
  const prefix = `${ownerUserId}:`;
  return value.startsWith(prefix) ? value.slice(prefix.length) : value;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function getSaltStorageKey(userId: string): string {
  return `${AT_REST_SALT_PREFIX}${userId}`;
}

function requireAtRestKey(): CryptoKey {
  if (!activeAtRestKey) {
    throw new Error(
      "At-rest key unavailable. Login required to unlock storage.",
    );
  }
  return activeAtRestKey;
}

async function encryptBytes(plain: Uint8Array): Promise<string> {
  const key = requireAtRestKey();
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce as BufferSource },
      key,
      plain as BufferSource,
    ),
  );
  return bytesToBase64(concatBytes(nonce, ciphertext));
}

async function decryptBytes(encoded: string): Promise<Uint8Array> {
  const key = requireAtRestKey();
  const payload = base64ToBytes(encoded);
  const nonce = payload.slice(0, 12);
  const ciphertext = payload.slice(12);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce as BufferSource },
    key,
    ciphertext as BufferSource,
  );
  return new Uint8Array(plain);
}

async function encryptString(plain: string): Promise<string> {
  return encryptBytes(new TextEncoder().encode(plain));
}

async function decryptString(encoded: string): Promise<string> {
  return new TextDecoder().decode(await decryptBytes(encoded));
}

function serializeEncryptedPayload(value: unknown): unknown {
  if (value instanceof ArrayBuffer) {
    return {
      __type: ARRAY_BUFFER_TAG,
      data: bytesToBase64(new Uint8Array(value)),
    };
  }

  if (Array.isArray(value)) {
    return value.map((entry) => serializeEncryptedPayload(entry));
  }

  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      out[key] = serializeEncryptedPayload(entry);
    }
    return out;
  }

  return value;
}

function deserializeEncryptedPayload(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => deserializeEncryptedPayload(entry));
  }

  if (value && typeof value === "object") {
    const candidate = value as Record<string, unknown>;
    if (
      candidate.__type === ARRAY_BUFFER_TAG &&
      typeof candidate.data === "string"
    ) {
      return base64ToBytes(candidate.data).buffer;
    }

    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(candidate)) {
      out[key] = deserializeEncryptedPayload(entry);
    }
    return out;
  }

  return value;
}

async function encryptStructuredPayload(value: unknown): Promise<string> {
  return encryptString(JSON.stringify(serializeEncryptedPayload(value)));
}

async function decryptStructuredPayload<T>(encoded: string): Promise<T> {
  const parsed = JSON.parse(await decryptString(encoded)) as unknown;
  return deserializeEncryptedPayload(parsed) as T;
}

export async function setAtRestPassphrase(
  userId: string,
  password: string,
): Promise<void> {
  let saltB64 = localStorage.getItem(getSaltStorageKey(userId));
  if (!saltB64) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    saltB64 = bytesToBase64(salt);
    localStorage.setItem(getSaltStorageKey(userId), saltB64);
  }

  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  activeAtRestKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: base64ToBytes(saltB64) as BufferSource,
      iterations: 250000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  activeStorageUserId = userId;
}

export function clearAtRestPassphrase(): void {
  activeAtRestKey = null;
  activeStorageUserId = null;
}

// Store names
const IDENTITY_STORE = "identity";
const PREKEY_STORE = "prekeys";
const SESSION_STORE = "sessions";
const MESSAGE_STORE = "messages";
const CONTACT_STORE = "contacts";

/**
 * Secure key storage manager.
 */
export class KeyStore {
  private db: IDBDatabase | null = null;
  private dbReady: Promise<void>;

  constructor() {
    this.dbReady = this.open();
  }

  /**
   * Open the IndexedDB database.
   */
  private async open(): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      let settled = false;
      const finalize = (fn: () => void) => {
        if (settled) return;
        settled = true;
        fn();
      };

      request.onerror = () => {
        finalize(() =>
          reject(
            new Error(`Failed to open database: ${request.error?.message}`),
          ),
        );
      };

      request.onblocked = () => {
        finalize(() =>
          reject(
            new Error(
              "IndexedDB upgrade is blocked by another open tab/window. Close other app tabs and retry.",
            ),
          ),
        );
      };

      request.onsuccess = () => {
        this.db = request.result;

        // If a newer version is requested elsewhere, close this connection
        // so the upgrade can proceed and avoid deadlocks.
        this.db.onversionchange = () => {
          this.db?.close();
          this.db = null;
        };

        finalize(() => resolve());
      };

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;

        // Identity keys store
        if (!db.objectStoreNames.contains(IDENTITY_STORE)) {
          db.createObjectStore(IDENTITY_STORE, { keyPath: "id" });
        }

        // Prekeys store
        if (!db.objectStoreNames.contains(PREKEY_STORE)) {
          const prekeyStore = db.createObjectStore(PREKEY_STORE, {
            keyPath: "id",
          });
          prekeyStore.createIndex("type", "type", { unique: false });
        }

        // Sessions store
        if (!db.objectStoreNames.contains(SESSION_STORE)) {
          db.createObjectStore(SESSION_STORE, { keyPath: "peerId" });
        }

        // Messages store (v2)
        if (!db.objectStoreNames.contains(MESSAGE_STORE)) {
          const msgStore = db.createObjectStore(MESSAGE_STORE, {
            keyPath: "id",
          });
          msgStore.createIndex("peerId", "peerId", { unique: false });
          msgStore.createIndex("timestamp", "timestamp", { unique: false });
        }

        // Contacts store (v2)
        if (!db.objectStoreNames.contains(CONTACT_STORE)) {
          db.createObjectStore(CONTACT_STORE, { keyPath: "id" });
        }
      };
    });
  }

  /**
   * Ensure database is ready before operations.
   */
  private async ensureReady(): Promise<IDBDatabase> {
    await this.dbReady;
    if (!this.db) {
      throw new Error("Database not initialized");
    }
    return this.db;
  }

  /**
   * Store identity key bundle.
   */
  async storeIdentity(identity: StoredIdentity): Promise<void> {
    const db = await this.ensureReady();
    const persisted: Record<string, unknown> = {
      ...identity,
    };

    if (identity.eccIdentityPrivate) {
      persisted.eccIdentityPrivateEnc = await encryptString(
        JSON.stringify(identity.eccIdentityPrivate),
      );
      delete persisted.eccIdentityPrivate;
    }
    if (identity.signingPrivate) {
      persisted.signingPrivateEnc = await encryptString(
        JSON.stringify(identity.signingPrivate),
      );
      delete persisted.signingPrivate;
    }
    persisted.pqcIdentityPrivateEnc = await encryptBytes(
      new Uint8Array(identity.pqcIdentityPrivate),
    );
    delete persisted.pqcIdentityPrivate;

    return new Promise((resolve, reject) => {
      const tx = db.transaction(IDENTITY_STORE, "readwrite");
      const store = tx.objectStore(IDENTITY_STORE);

      const request = store.put(persisted);

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get identity key bundle.
   */
  async getIdentity(userId: string): Promise<StoredIdentity | null> {
    const db = await this.ensureReady();

    return new Promise((resolve, reject) => {
      const tx = db.transaction(IDENTITY_STORE, "readonly");
      const store = tx.objectStore(IDENTITY_STORE);

      const request = store.get(userId);

      request.onsuccess = async () => {
        try {
          const result = request.result as Record<string, unknown> | undefined;
          if (!result) {
            resolve(null);
            return;
          }

          if (typeof result.pqcIdentityPrivateEnc !== "string") {
            resolve(result as unknown as StoredIdentity);
            return;
          }

          const identity: StoredIdentity = {
            ...(result as unknown as StoredIdentity),
            eccIdentityPrivate:
              typeof result.eccIdentityPrivateEnc === "string"
                ? (JSON.parse(
                    await decryptString(result.eccIdentityPrivateEnc),
                  ) as JsonWebKey)
                : undefined,
            signingPrivate:
              typeof result.signingPrivateEnc === "string"
                ? (JSON.parse(
                    await decryptString(result.signingPrivateEnc),
                  ) as JsonWebKey)
                : undefined,
            pqcIdentityPrivate: (
              await decryptBytes(result.pqcIdentityPrivateEnc)
            ).buffer as ArrayBuffer,
          };

          resolve(identity);
        } catch (error) {
          reject(error);
        }
      };
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Store a signed prekey.
   */
  async storeSignedPrekey(
    prekey: StoredPrekey,
    ownerUserId = "local-user",
  ): Promise<void> {
    const db = await this.ensureReady();
    const persisted: Record<string, unknown> = {
      ...prekey,
      id: `${ownerUserId}:${prekey.id}`,
      ownerUserId,
    };

    if (prekey.privateKey instanceof ArrayBuffer) {
      persisted.privateKeyKind = "ab";
      persisted.privateKeyEnc = await encryptBytes(
        new Uint8Array(prekey.privateKey),
      );
    } else {
      persisted.privateKeyKind = "jwk";
      persisted.privateKeyEnc = await encryptString(
        JSON.stringify(prekey.privateKey),
      );
    }
    delete persisted.privateKey;

    return new Promise((resolve, reject) => {
      const tx = db.transaction(PREKEY_STORE, "readwrite");
      const store = tx.objectStore(PREKEY_STORE);

      const request = store.put(persisted);

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get current signed prekey.
   */
  async getSignedPrekey(
    id: number,
    type: "ecc" | "pqc",
    ownerUserId = "local-user",
  ): Promise<StoredPrekey | null> {
    const db = await this.ensureReady();

    return new Promise((resolve, reject) => {
      const tx = db.transaction(PREKEY_STORE, "readonly");
      const store = tx.objectStore(PREKEY_STORE);

      const namespacedRequest = store.get(`${ownerUserId}:${type}-${id}`);

      namespacedRequest.onsuccess = () => {
        if (namespacedRequest.result) {
          const result = namespacedRequest.result as Record<string, unknown>;
          if (
            typeof result.privateKeyEnc === "string" &&
            typeof result.privateKeyKind === "string"
          ) {
            const restore = async () => {
              const privateKeyEnc = result.privateKeyEnc as string;
              const privateKey =
                result.privateKeyKind === "ab"
                  ? ((await decryptBytes(privateKeyEnc)).buffer as ArrayBuffer)
                  : (JSON.parse(
                      await decryptString(privateKeyEnc),
                    ) as JsonWebKey);
              resolve({
                ...(result as unknown as StoredPrekey),
                privateKey,
              });
            };
            void restore().catch(reject);
            return;
          }
          resolve(result as unknown as StoredPrekey);
          return;
        }

        // Backward compatibility for legacy non-namespaced keys.
        const legacyRequest = store.get(`${type}-${id}`);
        legacyRequest.onsuccess = () => resolve(legacyRequest.result ?? null);
        legacyRequest.onerror = () => reject(legacyRequest.error);
      };
      namespacedRequest.onerror = () => reject(namespacedRequest.error);
    });
  }

  /**
   * Delete a prekey by numeric id and type.
   */
  async deletePrekey(
    id: number,
    type: "ecc" | "pqc",
    ownerUserId = "local-user",
  ): Promise<void> {
    const db = await this.ensureReady();

    return new Promise((resolve, reject) => {
      const tx = db.transaction(PREKEY_STORE, "readwrite");
      const store = tx.objectStore(PREKEY_STORE);

      const namespacedRequest = store.delete(`${ownerUserId}:${type}-${id}`);

      namespacedRequest.onsuccess = () => {
        // Also clear legacy non-namespaced key if present.
        const legacyRequest = store.delete(`${type}-${id}`);
        legacyRequest.onsuccess = () => resolve();
        legacyRequest.onerror = () => reject(legacyRequest.error);
      };
      namespacedRequest.onerror = () => reject(namespacedRequest.error);
    });
  }

  /**
   * Store session keys for a peer.
   */
  async storeSession(session: StoredSession): Promise<void> {
    const db = await this.ensureReady();
    const ownerUserId = requireActiveStorageUserId();
    const scopedPeerId = toScopedStorageId(ownerUserId, session.peerId);
    const payloadEnc = await encryptStructuredPayload(session);

    return new Promise((resolve, reject) => {
      const tx = db.transaction(SESSION_STORE, "readwrite");
      const store = tx.objectStore(SESSION_STORE);

      const request = store.put({
        peerId: scopedPeerId,
        peerIdRaw: session.peerId,
        ownerUserId,
        payloadEnc,
      });

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get session for a peer.
   */
  async getSession(peerId: string): Promise<StoredSession | null> {
    const db = await this.ensureReady();
    const ownerUserId = requireActiveStorageUserId();
    const scopedPeerId = toScopedStorageId(ownerUserId, peerId);

    return new Promise((resolve, reject) => {
      const tx = db.transaction(SESSION_STORE, "readonly");
      const store = tx.objectStore(SESSION_STORE);

      const request = store.get(scopedPeerId);

      request.onsuccess = async () => {
        try {
          const result = request.result as Record<string, unknown> | undefined;
          if (!result) {
            resolve(null);
            return;
          }
          if (typeof result.payloadEnc !== "string") {
            resolve(result as unknown as StoredSession);
            return;
          }
          resolve(
            await decryptStructuredPayload<StoredSession>(result.payloadEnc),
          );
        } catch (error) {
          reject(error);
        }
      };
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Delete session for a peer.
   */
  async deleteSession(peerId: string): Promise<void> {
    const db = await this.ensureReady();
    const ownerUserId = requireActiveStorageUserId();
    const scopedPeerId = toScopedStorageId(ownerUserId, peerId);

    return new Promise((resolve, reject) => {
      const tx = db.transaction(SESSION_STORE, "readwrite");
      const store = tx.objectStore(SESSION_STORE);

      const request = store.delete(scopedPeerId);

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get all sessions.
   */
  async getAllSessions(): Promise<StoredSession[]> {
    const db = await this.ensureReady();
    const ownerUserId = requireActiveStorageUserId();
    const scopedPrefix = `${ownerUserId}:`;

    return new Promise((resolve, reject) => {
      const tx = db.transaction(SESSION_STORE, "readonly");
      const store = tx.objectStore(SESSION_STORE);

      const request = store.getAll();

      request.onsuccess = async () => {
        try {
          const rows = (request.result ?? []) as Array<Record<string, unknown>>;
          const restored: StoredSession[] = [];
          for (const row of rows) {
            const storedOwner =
              typeof row.ownerUserId === "string" ? row.ownerUserId : undefined;
            const storedPeerId =
              typeof row.peerId === "string" ? row.peerId : undefined;
            const rowBelongsToActiveUser =
              storedOwner === ownerUserId ||
              (storedOwner === undefined &&
                typeof storedPeerId === "string" &&
                storedPeerId.startsWith(scopedPrefix));

            if (!rowBelongsToActiveUser) {
              continue;
            }

            if (typeof row.payloadEnc === "string") {
              const session = await decryptStructuredPayload<StoredSession>(
                row.payloadEnc,
              );
              restored.push({
                ...session,
                peerId:
                  typeof row.peerIdRaw === "string"
                    ? row.peerIdRaw
                    : fromScopedStorageId(ownerUserId, session.peerId),
              });
            } else {
              const raw = row as unknown as StoredSession;
              restored.push({
                ...raw,
                peerId:
                  typeof row.peerIdRaw === "string"
                    ? row.peerIdRaw
                    : fromScopedStorageId(ownerUserId, raw.peerId),
              });
            }
          }
          resolve(restored);
        } catch (error) {
          reject(error);
        }
      };
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Clear all data (for logout/account deletion).
   */
  async clearAll(): Promise<void> {
    const db = await this.ensureReady();

    const storeNames = [
      IDENTITY_STORE,
      PREKEY_STORE,
      SESSION_STORE,
      MESSAGE_STORE,
      CONTACT_STORE,
    ];
    const tx = db.transaction(storeNames, "readwrite");

    return new Promise((resolve, reject) => {
      for (const name of storeNames) {
        tx.objectStore(name).clear();
      }
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  /**
   * Clear runtime chat state while preserving long-lived identity/prekey material.
   * Used on logout so users can sign back into existing aliases on this profile.
   */
  async clearRuntimeData(): Promise<void> {
    const db = await this.ensureReady();
    const ownerUserId = requireActiveStorageUserId();
    const scopedPrefix = `${ownerUserId}:`;

    const storeNames = [SESSION_STORE, MESSAGE_STORE];
    const tx = db.transaction(storeNames, "readwrite");

    return new Promise((resolve, reject) => {
      tx.objectStore(SESSION_STORE).delete(
        IDBKeyRange.bound(scopedPrefix, `${scopedPrefix}\uffff`),
      );
      tx.objectStore(MESSAGE_STORE).delete(
        IDBKeyRange.bound(scopedPrefix, `${scopedPrefix}\uffff`),
      );
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  // ===== Message Store =====

  /**
   * Store a message.
   */
  async storeMessage(message: StoredMessage): Promise<void> {
    const db = await this.ensureReady();
    const ownerUserId = requireActiveStorageUserId();
    const scopedMessageId = toScopedStorageId(ownerUserId, message.id);
    const scopedPeerId = toScopedStorageId(ownerUserId, message.peerId);
    const persisted: Record<string, unknown> = {
      ...message,
      id: scopedMessageId,
      messageId: message.id,
      ownerUserId,
      peerId: scopedPeerId,
      peerIdRaw: message.peerId,
      contentEnc: await encryptString(message.content),
    };
    delete persisted.content;

    return new Promise((resolve, reject) => {
      const tx = db.transaction(MESSAGE_STORE, "readwrite");
      const store = tx.objectStore(MESSAGE_STORE);
      const request = store.put(persisted);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get all messages for a peer, sorted by timestamp.
   */
  async getMessagesByPeer(peerId: string): Promise<StoredMessage[]> {
    const db = await this.ensureReady();
    const ownerUserId = requireActiveStorageUserId();
    const scopedPeerId = toScopedStorageId(ownerUserId, peerId);
    return new Promise((resolve, reject) => {
      const tx = db.transaction(MESSAGE_STORE, "readonly");
      const store = tx.objectStore(MESSAGE_STORE);
      const index = store.index("peerId");
      const request = index.getAll(scopedPeerId);
      request.onsuccess = async () => {
        try {
          const rows = (request.result ?? []) as Array<Record<string, unknown>>;
          if (rows.some((row) => typeof row.contentEnc === "string")) {
            requireAtRestKey();
          }
          const results: StoredMessage[] = [];
          for (const row of rows) {
            try {
              const normalizedId =
                typeof row.messageId === "string"
                  ? row.messageId
                  : typeof row.id === "string"
                    ? fromScopedStorageId(ownerUserId, row.id)
                    : "";
              const normalizedPeerId =
                typeof row.peerIdRaw === "string"
                  ? row.peerIdRaw
                  : typeof row.peerId === "string"
                    ? fromScopedStorageId(ownerUserId, row.peerId)
                    : peerId;

              if (typeof row.contentEnc === "string") {
                results.push({
                  ...(row as unknown as StoredMessage),
                  id: normalizedId,
                  peerId: normalizedPeerId,
                  content: await decryptString(row.contentEnc),
                });
              } else {
                results.push({
                  ...(row as unknown as StoredMessage),
                  id: normalizedId,
                  peerId: normalizedPeerId,
                });
              }
            } catch (error) {
              console.warn(
                "[KeyStore] Skipping undecryptable message row for peer",
                peerId,
                error,
              );
            }
          }
          results.sort((a, b) => a.timestamp - b.timestamp);
          resolve(results);
        } catch (error) {
          reject(error);
        }
      };
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get all stored messages.
   */
  async getAllMessages(): Promise<StoredMessage[]> {
    const db = await this.ensureReady();
    const ownerUserId = requireActiveStorageUserId();
    const scopedPrefix = `${ownerUserId}:`;
    return new Promise((resolve, reject) => {
      const tx = db.transaction(MESSAGE_STORE, "readonly");
      const store = tx.objectStore(MESSAGE_STORE);
      const request = store.getAll();
      request.onsuccess = async () => {
        try {
          const allRows = (request.result ?? []) as Array<
            Record<string, unknown>
          >;
          const rows = allRows.filter((row) => {
            const storedOwner =
              typeof row.ownerUserId === "string" ? row.ownerUserId : undefined;
            if (storedOwner === ownerUserId) return true;
            if (storedOwner !== undefined) return false;

            return (
              typeof row.id === "string" && row.id.startsWith(scopedPrefix)
            );
          });
          if (rows.some((row) => typeof row.contentEnc === "string")) {
            requireAtRestKey();
          }
          const results: StoredMessage[] = [];
          for (const row of rows) {
            try {
              const normalizedId =
                typeof row.messageId === "string"
                  ? row.messageId
                  : typeof row.id === "string"
                    ? fromScopedStorageId(ownerUserId, row.id)
                    : "";
              const normalizedPeerId =
                typeof row.peerIdRaw === "string"
                  ? row.peerIdRaw
                  : typeof row.peerId === "string"
                    ? fromScopedStorageId(ownerUserId, row.peerId)
                    : "";

              if (typeof row.contentEnc === "string") {
                results.push({
                  ...(row as unknown as StoredMessage),
                  id: normalizedId,
                  peerId: normalizedPeerId,
                  content: await decryptString(row.contentEnc),
                });
              } else {
                results.push({
                  ...(row as unknown as StoredMessage),
                  id: normalizedId,
                  peerId: normalizedPeerId,
                });
              }
            } catch (error) {
              console.warn(
                "[KeyStore] Skipping undecryptable stored message row",
                error,
              );
            }
          }
          resolve(results);
        } catch (error) {
          reject(error);
        }
      };
      request.onerror = () => reject(request.error);
    });
  }

  // ===== Contact Store =====

  /**
   * Store a contact.
   */
  async storeContact(contact: StoredContact): Promise<void> {
    const db = await this.ensureReady();
    const ownerUserId = requireActiveStorageUserId();
    const scopedContactId = toScopedStorageId(ownerUserId, contact.id);

    const persisted: Record<string, unknown> = {
      ...contact,
      id: scopedContactId,
      contactId: contact.id,
      ownerUserId,
    };

    return new Promise((resolve, reject) => {
      const tx = db.transaction(CONTACT_STORE, "readwrite");
      const store = tx.objectStore(CONTACT_STORE);
      const request = store.put(persisted);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get a contact by ID.
   */
  async getContact(contactId: string): Promise<StoredContact | null> {
    const db = await this.ensureReady();
    const ownerUserId = requireActiveStorageUserId();
    const scopedContactId = toScopedStorageId(ownerUserId, contactId);
    return new Promise((resolve, reject) => {
      const tx = db.transaction(CONTACT_STORE, "readonly");
      const store = tx.objectStore(CONTACT_STORE);
      const request = store.get(scopedContactId);
      request.onsuccess = () => {
        const row = request.result as Record<string, unknown> | undefined;
        if (!row) {
          resolve(null);
          return;
        }

        resolve({
          ...(row as unknown as StoredContact),
          id:
            typeof row.contactId === "string"
              ? row.contactId
              : typeof row.id === "string"
                ? fromScopedStorageId(ownerUserId, row.id)
                : contactId,
        });
      };
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get all contacts.
   */
  async getAllContacts(): Promise<StoredContact[]> {
    const db = await this.ensureReady();
    const ownerUserId = requireActiveStorageUserId();
    const scopedPrefix = `${ownerUserId}:`;
    return new Promise((resolve, reject) => {
      const tx = db.transaction(CONTACT_STORE, "readonly");
      const store = tx.objectStore(CONTACT_STORE);
      const request = store.getAll();
      request.onsuccess = () => {
        const rows = (request.result ?? []) as Array<Record<string, unknown>>;
        const filtered = rows
          .filter((row) => {
            const storedOwner =
              typeof row.ownerUserId === "string" ? row.ownerUserId : undefined;
            if (storedOwner === ownerUserId) return true;
            if (storedOwner !== undefined) return false;

            return (
              typeof row.id === "string" && row.id.startsWith(scopedPrefix)
            );
          })
          .map((row) => ({
            ...(row as unknown as StoredContact),
            id:
              typeof row.contactId === "string"
                ? row.contactId
                : typeof row.id === "string"
                  ? fromScopedStorageId(ownerUserId, row.id)
                  : "",
          }));

        resolve(filtered);
      };
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Delete a contact.
   */
  async deleteContact(contactId: string): Promise<void> {
    const db = await this.ensureReady();
    const ownerUserId = requireActiveStorageUserId();
    const scopedContactId = toScopedStorageId(ownerUserId, contactId);
    return new Promise((resolve, reject) => {
      const tx = db.transaction(CONTACT_STORE, "readwrite");
      const store = tx.objectStore(CONTACT_STORE);
      const request = store.delete(scopedContactId);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }
}

/**
 * Stored identity format (serializable for IndexedDB).
 *
 * Note: CryptoKey objects with extractable: false cannot be stored.
 * For those, we store JWK format of public keys only.
 */
export interface StoredIdentity {
  id: string;
  userId: string;
  username?: string; // Display name for session recovery

  // ECC identity (JWK format for public, CryptoKey handle for private if extractable)
  eccIdentityPublic: JsonWebKey;
  eccIdentityPrivate?: JsonWebKey; // Only if extractable

  // PQC identity (raw bytes)
  pqcIdentityPublic: ArrayBuffer;
  pqcIdentityPrivate: ArrayBuffer;

  // Signing key
  signingPublic: JsonWebKey;
  signingPrivate?: JsonWebKey;

  createdAt: number;
}

/**
 * Stored prekey format.
 */
export interface StoredPrekey {
  id: string; // Format: "ecc-{id}" or "pqc-{id}"
  ownerUserId?: string;
  type: "ecc" | "pqc";
  prekeyId: number;

  // Key material
  publicKey: ArrayBuffer;
  privateKey: ArrayBuffer | JsonWebKey;

  // Signature
  signature: ArrayBuffer;

  createdAt: number;
}

/**
 * Stored session format.
 */
export interface StoredSession {
  peerId: string;
  sessionId: string;
  encryptionKey: ArrayBuffer;
  macKey: ArrayBuffer;
  rootKey: ArrayBuffer;
  sendChainKey: ArrayBuffer;
  recvChainKey: ArrayBuffer;
  messageCounter: number;
  /** Sender-chain message index for next outbound message key derivation */
  sendMessageCounter?: number;
  /** Receiver-chain expected message index for next inbound message key derivation */
  recvMessageCounter?: number;
  /** Epoch-aware receive counters keyed by remote ratchet identifier */
  recvCountersByRatchet?: Array<{
    ratchetId: string;
    nextMessageNumber: number;
  }>;
  /** Local DH-ratchet private key (JWK export) for post-reload continuity */
  localRatchetPrivateJwk?: JsonWebKey;
  /** Local DH-ratchet public key (raw P-384) */
  localRatchetPublicKey?: ArrayBuffer;
  /** Last seen remote DH-ratchet public key (raw P-384) */
  remoteRatchetPublicKey?: ArrayBuffer;
  /** Whether local ratchet public key still needs to be announced to peer */
  ratchetNeedsAnnouncement?: boolean;
  /** Whether local ratchet key has been advertised at least once */
  ratchetAdvertised?: boolean;
  /** Whether next outbound message must perform a send-side DH ratchet */
  pendingSendRatchetStep?: boolean;
  /** Cached receive-side message keys for out-of-order delivery */
  skippedMessageKeys?: Array<{
    /** Ratchet epoch identifier (derived from remote ratchet public key) */
    ratchetId?: string;
    messageNumber: number;
    key: ArrayBuffer;
  }>;
  createdAt: number;
  lastUsed: number;
}

/**
 * Stored message format (for persistence).
 */
export interface StoredMessage {
  id: string;
  senderId: string;
  recipientId: string;
  peerId: string; // indexed: the other party's ID
  conversationId?: string;
  groupId?: string;
  groupName?: string;
  groupMemberIds?: string[];
  groupEventType?: "group_message" | "group_membership";
  groupMembershipCommitment?: string;
  deliveredByUserIds?: string[];
  readByUserIds?: string[];
  content: string;
  timestamp: number;
  isPqcProtected: boolean;
  status: "sending" | "sent" | "delivered" | "read" | "error";
}

/**
 * Stored contact format.
 */
export interface StoredContact {
  id: string;
  username: string;
  kind?: "direct" | "group";
  ownerId?: string;
  membershipCommitment?: string;
  memberIds?: string[];
  status: "online" | "offline";
  lastSeen?: number;
  identityKeyEccFingerprint?: string;
  identityKeyPqcFingerprint?: string;
  signingKeyFingerprint?: string;
  trustState?: "trusted" | "unverified" | "changed";
  trustWarning?: string;
  trustUpdatedAt?: number;
}

// Singleton instance
let keyStoreInstance: KeyStore | null = null;

/**
 * Get the key store singleton.
 */
export function getKeyStore(): KeyStore {
  if (!keyStoreInstance) {
    keyStoreInstance = new KeyStore();
  }
  return keyStoreInstance;
}
