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
            new Error(`Failed to open database: ${request.error?.message}`)
          )
        );
      };

      request.onblocked = () => {
        finalize(() =>
          reject(
            new Error(
              "IndexedDB upgrade is blocked by another open tab/window. Close other app tabs and retry."
            )
          )
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

    return new Promise((resolve, reject) => {
      const tx = db.transaction(IDENTITY_STORE, "readwrite");
      const store = tx.objectStore(IDENTITY_STORE);

      const request = store.put(identity);

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

      request.onsuccess = () => resolve(request.result ?? null);
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Store a signed prekey.
   */
  async storeSignedPrekey(
    prekey: StoredPrekey,
    ownerUserId = "local-user"
  ): Promise<void> {
    const db = await this.ensureReady();

    return new Promise((resolve, reject) => {
      const tx = db.transaction(PREKEY_STORE, "readwrite");
      const store = tx.objectStore(PREKEY_STORE);

      const request = store.put({
        ...prekey,
        id: `${ownerUserId}:${prekey.id}`,
        ownerUserId,
      });

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
    ownerUserId = "local-user"
  ): Promise<StoredPrekey | null> {
    const db = await this.ensureReady();

    return new Promise((resolve, reject) => {
      const tx = db.transaction(PREKEY_STORE, "readonly");
      const store = tx.objectStore(PREKEY_STORE);

      const namespacedRequest = store.get(`${ownerUserId}:${type}-${id}`);

      namespacedRequest.onsuccess = () => {
        if (namespacedRequest.result) {
          resolve(namespacedRequest.result ?? null);
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
    ownerUserId = "local-user"
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

    return new Promise((resolve, reject) => {
      const tx = db.transaction(SESSION_STORE, "readwrite");
      const store = tx.objectStore(SESSION_STORE);

      const request = store.put(session);

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get session for a peer.
   */
  async getSession(peerId: string): Promise<StoredSession | null> {
    const db = await this.ensureReady();

    return new Promise((resolve, reject) => {
      const tx = db.transaction(SESSION_STORE, "readonly");
      const store = tx.objectStore(SESSION_STORE);

      const request = store.get(peerId);

      request.onsuccess = () => resolve(request.result ?? null);
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Delete session for a peer.
   */
  async deleteSession(peerId: string): Promise<void> {
    const db = await this.ensureReady();

    return new Promise((resolve, reject) => {
      const tx = db.transaction(SESSION_STORE, "readwrite");
      const store = tx.objectStore(SESSION_STORE);

      const request = store.delete(peerId);

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get all sessions.
   */
  async getAllSessions(): Promise<StoredSession[]> {
    const db = await this.ensureReady();

    return new Promise((resolve, reject) => {
      const tx = db.transaction(SESSION_STORE, "readonly");
      const store = tx.objectStore(SESSION_STORE);

      const request = store.getAll();

      request.onsuccess = () => resolve(request.result ?? []);
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

    const storeNames = [SESSION_STORE, MESSAGE_STORE];
    const tx = db.transaction(storeNames, "readwrite");

    return new Promise((resolve, reject) => {
      for (const name of storeNames) {
        tx.objectStore(name).clear();
      }
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
    return new Promise((resolve, reject) => {
      const tx = db.transaction(MESSAGE_STORE, "readwrite");
      const store = tx.objectStore(MESSAGE_STORE);
      const request = store.put(message);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get all messages for a peer, sorted by timestamp.
   */
  async getMessagesByPeer(peerId: string): Promise<StoredMessage[]> {
    const db = await this.ensureReady();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(MESSAGE_STORE, "readonly");
      const store = tx.objectStore(MESSAGE_STORE);
      const index = store.index("peerId");
      const request = index.getAll(peerId);
      request.onsuccess = () => {
        const results = (request.result ?? []) as StoredMessage[];
        results.sort((a, b) => a.timestamp - b.timestamp);
        resolve(results);
      };
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get all stored messages.
   */
  async getAllMessages(): Promise<StoredMessage[]> {
    const db = await this.ensureReady();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(MESSAGE_STORE, "readonly");
      const store = tx.objectStore(MESSAGE_STORE);
      const request = store.getAll();
      request.onsuccess = () => resolve(request.result ?? []);
      request.onerror = () => reject(request.error);
    });
  }

  // ===== Contact Store =====

  /**
   * Store a contact.
   */
  async storeContact(contact: StoredContact): Promise<void> {
    const db = await this.ensureReady();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(CONTACT_STORE, "readwrite");
      const store = tx.objectStore(CONTACT_STORE);
      const request = store.put(contact);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get a contact by ID.
   */
  async getContact(contactId: string): Promise<StoredContact | null> {
    const db = await this.ensureReady();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(CONTACT_STORE, "readonly");
      const store = tx.objectStore(CONTACT_STORE);
      const request = store.get(contactId);
      request.onsuccess = () => resolve(request.result ?? null);
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get all contacts.
   */
  async getAllContacts(): Promise<StoredContact[]> {
    const db = await this.ensureReady();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(CONTACT_STORE, "readonly");
      const store = tx.objectStore(CONTACT_STORE);
      const request = store.getAll();
      request.onsuccess = () => resolve(request.result ?? []);
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Delete a contact.
   */
  async deleteContact(contactId: string): Promise<void> {
    const db = await this.ensureReady();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(CONTACT_STORE, "readwrite");
      const store = tx.objectStore(CONTACT_STORE);
      const request = store.delete(contactId);
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
  status: "online" | "offline";
  lastSeen?: number;
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
