import Database from "better-sqlite3";
import path from "path";
import fs from "fs";
import type { UserRecord, OneTimePreKeyDto } from "../types/index.js";

const configuredDbPath = process.env.SQLITE_DB_PATH;
const DB_PATH = configuredDbPath
  ? path.isAbsolute(configuredDbPath)
    ? configuredDbPath
    : path.join(process.cwd(), configuredDbPath)
  : path.join(process.cwd(), "data", "secure_msg.db");

export class SqliteStore {
  private db: Database.Database;

  constructor() {
    // Ensure data directory exists
    const dir = path.dirname(DB_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    this.db = new Database(DB_PATH);
    this.initSchema();
  }

  private initSchema() {
    this.db.pragma("journal_mode = WAL");

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE COLLATE NOCASE,
        data TEXT,
        lastSeen INTEGER
      );

      CREATE TABLE IF NOT EXISTS one_time_prekeys (
        userId TEXT,
        id INTEGER,
        publicKey TEXT,
        PRIMARY KEY (userId, id),
        FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS pending_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipientId TEXT,
        senderId TEXT,
        blob TEXT,
        handshakeData TEXT,
        ratchetKeyEcc TEXT,
        messageNumber INTEGER,
        timestamp INTEGER,
        FOREIGN KEY(recipientId) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
      CREATE INDEX IF NOT EXISTS idx_pending_messages_recipient ON pending_messages(recipientId);
    `);

    // Lightweight migration for existing DBs created before handshakeData existed.
    const columns = this.db
      .prepare("PRAGMA table_info(pending_messages)")
      .all() as Array<{ name: string }>;
    const hasHandshakeData = columns.some((c) => c.name === "handshakeData");
    if (!hasHandshakeData) {
      this.db.exec(
        "ALTER TABLE pending_messages ADD COLUMN handshakeData TEXT",
      );
    }
    const hasMessageNumber = columns.some((c) => c.name === "messageNumber");
    if (!hasMessageNumber) {
      this.db.exec(
        "ALTER TABLE pending_messages ADD COLUMN messageNumber INTEGER",
      );
    }
    const hasRatchetKeyEcc = columns.some((c) => c.name === "ratchetKeyEcc");
    if (!hasRatchetKeyEcc) {
      this.db.exec(
        "ALTER TABLE pending_messages ADD COLUMN ratchetKeyEcc TEXT",
      );
    }
  }

  async createUser(user: UserRecord): Promise<void> {
    const { id, username, lastSeen, oneTimePrekeyEcc, ...rest } = user;
    const data = JSON.stringify({ ...rest, originalUsername: username });

    const insertUser = this.db.prepare(
      "INSERT INTO users (id, username, data, lastSeen) VALUES (?, ?, ?, ?)",
    );
    const insertPrekey = this.db.prepare(
      "INSERT INTO one_time_prekeys (userId, id, publicKey) VALUES (?, ?, ?)",
    );

    const tx = this.db.transaction(() => {
      insertUser.run(id, username, data, lastSeen);
      for (const pk of oneTimePrekeyEcc) {
        insertPrekey.run(id, pk.id, pk.publicKey);
      }
    });

    try {
      tx();
    } catch (error: any) {
      if (error.code === "SQLITE_CONSTRAINT_PRIMARYKEY") {
        throw new Error("User ID already exists");
      }
      if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
        throw new Error("Username already taken");
      }
      throw error;
    }
  }

  private rowToUser(row: any, prekeys: any[]): UserRecord {
    const data = JSON.parse(row.data);
    return {
      id: row.id,
      username: data.originalUsername || row.username,
      passwordHash: data.passwordHash,
      identityKeyEccPub: data.identityKeyEccPub,
      identityKeyPqcPub: data.identityKeyPqcPub,
      signingKeyPub: data.signingKeyPub,
      signedPrekeyEcc: data.signedPrekeyEcc,
      signedPrekeyPqc: data.signedPrekeyPqc,
      createdAt: data.createdAt,
      lastSeen: row.lastSeen,
      oneTimePrekeyEcc: prekeys.map((pk) => ({
        id: pk.id,
        publicKey: pk.publicKey,
      })),
    };
  }

  async getUserById(userId: string): Promise<UserRecord | null> {
    const row = this.db
      .prepare("SELECT * FROM users WHERE id = ?")
      .get(userId) as any;
    if (!row) return null;
    const prekeys = this.db
      .prepare(
        "SELECT id, publicKey FROM one_time_prekeys WHERE userId = ? ORDER BY id ASC",
      )
      .all(userId) as any[];
    return this.rowToUser(row, prekeys);
  }

  async getUserByUsername(username: string): Promise<UserRecord | null> {
    const row = this.db
      .prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE")
      .get(username) as any;
    if (!row) return null;
    const prekeys = this.db
      .prepare(
        "SELECT id, publicKey FROM one_time_prekeys WHERE userId = ? ORDER BY id ASC",
      )
      .all(row.id) as any[];
    return this.rowToUser(row, prekeys);
  }

  async updateLastSeen(userId: string): Promise<void> {
    this.db
      .prepare("UPDATE users SET lastSeen = ? WHERE id = ?")
      .run(Date.now(), userId);
  }

  async consumeOneTimePrekey(userId: string): Promise<OneTimePreKeyDto | null> {
    const stmtSelect = this.db.prepare(
      "SELECT id, publicKey FROM one_time_prekeys WHERE userId = ? ORDER BY id ASC LIMIT 1",
    );
    const stmtDelete = this.db.prepare(
      "DELETE FROM one_time_prekeys WHERE userId = ? AND id = ?",
    );

    const tx = this.db.transaction(() => {
      const prekey = stmtSelect.get(userId) as any;
      if (prekey) {
        stmtDelete.run(userId, prekey.id);
        return { id: prekey.id, publicKey: prekey.publicKey };
      }
      return null;
    });

    return tx();
  }

  async addOneTimePrekeys(
    userId: string,
    prekeys: OneTimePreKeyDto[],
  ): Promise<void> {
    const insertPrekey = this.db.prepare(
      "INSERT OR IGNORE INTO one_time_prekeys (userId, id, publicKey) VALUES (?, ?, ?)",
    );
    const tx = this.db.transaction(() => {
      for (const pk of prekeys) {
        insertPrekey.run(userId, pk.id, pk.publicKey);
      }
    });
    tx();
  }

  async getOneTimePrekeyCount(userId: string): Promise<number> {
    const row = this.db
      .prepare(
        "SELECT COUNT(*) as count FROM one_time_prekeys WHERE userId = ?",
      )
      .get(userId) as any;
    return row.count;
  }

  async storePendingMessage(
    recipientId: string,
    senderId: string,
    blob: string,
    handshakeData?: string,
    ratchetKeyEcc?: string,
    messageNumber?: number,
  ): Promise<void> {
    this.db
      .prepare(
        "INSERT INTO pending_messages (recipientId, senderId, blob, handshakeData, ratchetKeyEcc, messageNumber, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        recipientId,
        senderId,
        blob,
        handshakeData ?? null,
        ratchetKeyEcc ?? null,
        Number.isInteger(messageNumber) ? messageNumber : null,
        Date.now(),
      );
  }

  async getPendingMessages(userId: string): Promise<
    Array<{
      senderId: string;
      blob: string;
      handshakeData?: string;
      ratchetKeyEcc?: string;
      messageNumber?: number;
      timestamp: number;
    }>
  > {
    const stmtSelect = this.db.prepare(
      "SELECT senderId, blob, handshakeData, ratchetKeyEcc, messageNumber, timestamp FROM pending_messages WHERE recipientId = ? ORDER BY timestamp ASC",
    );
    const stmtDelete = this.db.prepare(
      "DELETE FROM pending_messages WHERE recipientId = ?",
    );

    const tx = this.db.transaction(() => {
      const messages = stmtSelect.all(userId) as any[];
      stmtDelete.run(userId);
      return messages;
    });

    return tx();
  }

  async userExists(userId: string): Promise<boolean> {
    const row = this.db.prepare("SELECT 1 FROM users WHERE id = ?").get(userId);
    return !!row;
  }
}

export const store = new SqliteStore();
