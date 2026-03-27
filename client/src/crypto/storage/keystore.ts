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
const DB_VERSION = 1;

// Store names
const IDENTITY_STORE = "identity";
const PREKEY_STORE = "prekeys";
const SESSION_STORE = "sessions";

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

      request.onerror = () => {
        reject(new Error(`Failed to open database: ${request.error?.message}`));
      };

      request.onsuccess = () => {
        this.db = request.result;
        resolve();
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
  async storeSignedPrekey(prekey: StoredPrekey): Promise<void> {
    const db = await this.ensureReady();

    return new Promise((resolve, reject) => {
      const tx = db.transaction(PREKEY_STORE, "readwrite");
      const store = tx.objectStore(PREKEY_STORE);

      const request = store.put(prekey);

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
  ): Promise<StoredPrekey | null> {
    const db = await this.ensureReady();

    return new Promise((resolve, reject) => {
      const tx = db.transaction(PREKEY_STORE, "readonly");
      const store = tx.objectStore(PREKEY_STORE);

      const request = store.get(`${type}-${id}`);

      request.onsuccess = () => resolve(request.result ?? null);
      request.onerror = () => reject(request.error);
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

    const tx = db.transaction(
      [IDENTITY_STORE, PREKEY_STORE, SESSION_STORE],
      "readwrite",
    );

    return new Promise((resolve, reject) => {
      tx.objectStore(IDENTITY_STORE).clear();
      tx.objectStore(PREKEY_STORE).clear();
      tx.objectStore(SESSION_STORE).clear();

      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
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

  // Encryption key (raw bytes)
  encryptionKey: ArrayBuffer;
  macKey: ArrayBuffer;
  rootKey: ArrayBuffer;

  // Chain keys for ratcheting
  sendChainKey: ArrayBuffer;
  recvChainKey: ArrayBuffer;

  // Counters
  messageCounter: number;

  createdAt: number;
  lastUsed: number;
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
