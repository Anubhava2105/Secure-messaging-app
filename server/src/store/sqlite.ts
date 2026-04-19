import Database from "better-sqlite3";
import path from "path";
import fs from "fs";
import { createHash, randomUUID } from "crypto";
import type {
  GroupRecord,
  UserRecord,
  OneTimePreKeyDto,
} from "../types/index.js";

const configuredDbPath = process.env.SQLITE_DB_PATH;
const DB_PATH = configuredDbPath
  ? path.isAbsolute(configuredDbPath)
    ? configuredDbPath
    : path.join(process.cwd(), configuredDbPath)
  : path.join(process.cwd(), "data", "secure_msg.db");

const MAX_PENDING_MESSAGES_PER_USER = Math.max(
  1,
  Number.parseInt(process.env.MAX_PENDING_MESSAGES_PER_USER ?? "500", 10) ||
    500,
);
const PENDING_MESSAGE_TTL_MS = Math.max(
  60_000,
  Number.parseInt(process.env.PENDING_MESSAGE_TTL_MS ?? "604800000", 10) ||
    604_800_000,
);
const MAX_PENDING_DELIVERY_BATCH = Math.max(
  1,
  Number.parseInt(process.env.MAX_PENDING_DELIVERY_BATCH ?? "100", 10) || 100,
);
const PENDING_DELIVERY_LEASE_MS = Math.max(
  1_000,
  Number.parseInt(process.env.PENDING_DELIVERY_LEASE_MS ?? "30000", 10) ||
    30_000,
);
const MAX_PENDING_DELIVERY_ATTEMPTS = Math.max(
  1,
  Number.parseInt(process.env.MAX_PENDING_DELIVERY_ATTEMPTS ?? "20", 10) || 20,
);

function parseJsonStringArray(value?: string | null): string[] | undefined {
  if (!value) return undefined;
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!Array.isArray(parsed)) return undefined;
    return parsed.filter((item): item is string => typeof item === "string");
  } catch {
    return undefined;
  }
}

function computeMembershipCommitment(
  groupId: string,
  ownerId: string,
  memberUserIds: string[],
  updatedAt: number,
): string {
  const sortedMembers = [...memberUserIds].sort();
  const payload = `${groupId}|${ownerId}|${updatedAt}|${sortedMembers.join(",")}`;
  return createHash("sha256").update(payload).digest("hex");
}

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

      CREATE TABLE IF NOT EXISTS groups (
        id TEXT PRIMARY KEY,
        name TEXT,
        ownerId TEXT,
        createdAt INTEGER,
        updatedAt INTEGER,
        FOREIGN KEY(ownerId) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS group_members (
        groupId TEXT,
        userId TEXT,
        addedAt INTEGER,
        PRIMARY KEY (groupId, userId),
        FOREIGN KEY(groupId) REFERENCES groups(id) ON DELETE CASCADE,
        FOREIGN KEY(userId) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS pending_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipientId TEXT,
        senderId TEXT,
        messageId TEXT,
        groupId TEXT,
        groupName TEXT,
        groupMemberIds TEXT,
        groupEventType TEXT,
        groupMembershipCommitment TEXT,
        blob TEXT,
        handshakeData TEXT,
        ratchetKeyEcc TEXT,
        messageNumber INTEGER,
        deliveryState TEXT DEFAULT 'queued',
        deliveryAttemptCount INTEGER DEFAULT 0,
        lastDeliveryAttemptAt INTEGER,
        timestamp INTEGER,
        FOREIGN KEY(recipientId) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
      CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(userId);
      CREATE INDEX IF NOT EXISTS idx_pending_messages_recipient ON pending_messages(recipientId);
      CREATE INDEX IF NOT EXISTS idx_pending_messages_recipient_ts ON pending_messages(recipientId, timestamp);
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
    const hasMessageId = columns.some((c) => c.name === "messageId");
    if (!hasMessageId) {
      this.db.exec("ALTER TABLE pending_messages ADD COLUMN messageId TEXT");
    }
    const hasGroupId = columns.some((c) => c.name === "groupId");
    if (!hasGroupId) {
      this.db.exec("ALTER TABLE pending_messages ADD COLUMN groupId TEXT");
    }
    const hasGroupName = columns.some((c) => c.name === "groupName");
    if (!hasGroupName) {
      this.db.exec("ALTER TABLE pending_messages ADD COLUMN groupName TEXT");
    }
    const hasGroupMemberIds = columns.some((c) => c.name === "groupMemberIds");
    if (!hasGroupMemberIds) {
      this.db.exec(
        "ALTER TABLE pending_messages ADD COLUMN groupMemberIds TEXT",
      );
    }
    const hasGroupEventType = columns.some((c) => c.name === "groupEventType");
    if (!hasGroupEventType) {
      this.db.exec(
        "ALTER TABLE pending_messages ADD COLUMN groupEventType TEXT",
      );
    }
    const hasGroupMembershipCommitment = columns.some(
      (c) => c.name === "groupMembershipCommitment",
    );
    if (!hasGroupMembershipCommitment) {
      this.db.exec(
        "ALTER TABLE pending_messages ADD COLUMN groupMembershipCommitment TEXT",
      );
    }
    const hasDeliveryState = columns.some((c) => c.name === "deliveryState");
    if (!hasDeliveryState) {
      this.db.exec(
        "ALTER TABLE pending_messages ADD COLUMN deliveryState TEXT DEFAULT 'queued'",
      );
    }
    const hasDeliveryAttemptCount = columns.some(
      (c) => c.name === "deliveryAttemptCount",
    );
    if (!hasDeliveryAttemptCount) {
      this.db.exec(
        "ALTER TABLE pending_messages ADD COLUMN deliveryAttemptCount INTEGER DEFAULT 0",
      );
    }
    const hasLastDeliveryAttemptAt = columns.some(
      (c) => c.name === "lastDeliveryAttemptAt",
    );
    if (!hasLastDeliveryAttemptAt) {
      this.db.exec(
        "ALTER TABLE pending_messages ADD COLUMN lastDeliveryAttemptAt INTEGER",
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
      passwordSalt: data.passwordSalt,
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
    messageId: string,
    blob: string,
    handshakeData?: string,
    ratchetKeyEcc?: string,
    messageNumber?: number,
    groupId?: string,
    groupName?: string,
    groupMemberIds?: string[],
    groupEventType?: string,
    groupMembershipCommitment?: string,
  ): Promise<void> {
    const now = Date.now();
    const cutoff = now - PENDING_MESSAGE_TTL_MS;

    const tx = this.db.transaction(() => {
      this.db
        .prepare("DELETE FROM pending_messages WHERE timestamp < ?")
        .run(cutoff);

      if (messageId) {
        this.db
          .prepare(
            "DELETE FROM pending_messages WHERE recipientId = ? AND messageId = ?",
          )
          .run(recipientId, messageId);
      }

      const countRow = this.db
        .prepare(
          "SELECT COUNT(*) as count FROM pending_messages WHERE recipientId = ?",
        )
        .get(recipientId) as { count: number };

      const overflow = Math.max(
        0,
        countRow.count - MAX_PENDING_MESSAGES_PER_USER + 1,
      );

      if (overflow > 0) {
        this.db
          .prepare(
            "DELETE FROM pending_messages WHERE id IN (SELECT id FROM pending_messages WHERE recipientId = ? ORDER BY timestamp ASC LIMIT ?)",
          )
          .run(recipientId, overflow);
      }

      this.db
        .prepare(
          "INSERT INTO pending_messages (recipientId, senderId, messageId, groupId, groupName, groupMemberIds, groupEventType, groupMembershipCommitment, blob, handshakeData, ratchetKeyEcc, messageNumber, deliveryState, deliveryAttemptCount, lastDeliveryAttemptAt, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', 0, NULL, ?)",
        )
        .run(
          recipientId,
          senderId,
          messageId,
          groupId ?? null,
          groupName ?? null,
          groupMemberIds && groupMemberIds.length > 0
            ? JSON.stringify(groupMemberIds)
            : null,
          groupEventType ?? null,
          groupMembershipCommitment ?? null,
          blob,
          handshakeData ?? null,
          ratchetKeyEcc ?? null,
          Number.isInteger(messageNumber) ? messageNumber : null,
          now,
        );
    });

    tx();
  }

  async getPendingMessages(userId: string): Promise<
    Array<{
      messageId: string;
      senderId: string;
      groupId?: string;
      groupName?: string;
      groupMemberIds?: string[];
      groupEventType?: string;
      groupMembershipCommitment?: string;
      blob: string;
      handshakeData?: string;
      ratchetKeyEcc?: string;
      messageNumber?: number;
      timestamp: number;
    }>
  > {
    const now = Date.now();
    const cutoff = now - PENDING_MESSAGE_TTL_MS;
    const leaseCutoff = now - PENDING_DELIVERY_LEASE_MS;

    const tx = this.db.transaction(() => {
      this.db
        .prepare("DELETE FROM pending_messages WHERE timestamp < ?")
        .run(cutoff);

      this.db
        .prepare(
          "DELETE FROM pending_messages WHERE recipientId = ? AND deliveryAttemptCount >= ?",
        )
        .run(userId, MAX_PENDING_DELIVERY_ATTEMPTS);

      const messages = this.db
        .prepare(
          "SELECT id, messageId, senderId, groupId, groupName, groupMemberIds, groupEventType, groupMembershipCommitment, blob, handshakeData, ratchetKeyEcc, messageNumber, timestamp FROM pending_messages WHERE recipientId = ? AND (deliveryState = 'queued' OR (deliveryState = 'in_flight' AND (lastDeliveryAttemptAt IS NULL OR lastDeliveryAttemptAt <= ?))) ORDER BY timestamp ASC LIMIT ?",
        )
        .all(userId, leaseCutoff, MAX_PENDING_DELIVERY_BATCH) as Array<{
        id: number;
        messageId?: string | null;
        senderId: string;
        groupId?: string | null;
        groupName?: string | null;
        groupMemberIds?: string | null;
        groupEventType?: string | null;
        groupMembershipCommitment?: string | null;
        blob: string;
        handshakeData?: string;
        ratchetKeyEcc?: string;
        messageNumber?: number;
        timestamp: number;
      }>;

      if (messages.length > 0) {
        const ids = messages.map((msg) => msg.id);
        const placeholders = ids.map(() => "?").join(",");
        this.db
          .prepare(
            `UPDATE pending_messages SET deliveryState = 'in_flight', deliveryAttemptCount = deliveryAttemptCount + 1, lastDeliveryAttemptAt = ? WHERE id IN (${placeholders})`,
          )
          .run(now, ...ids);
      }

      return messages.map((msg) => ({
        messageId:
          typeof msg.messageId === "string" && msg.messageId.length > 0
            ? msg.messageId
            : `pending-${msg.id}`,
        senderId: msg.senderId,
        groupId:
          typeof msg.groupId === "string" && msg.groupId.length > 0
            ? msg.groupId
            : undefined,
        groupName:
          typeof msg.groupName === "string" && msg.groupName.length > 0
            ? msg.groupName
            : undefined,
        groupMemberIds:
          typeof msg.groupMemberIds === "string" &&
          msg.groupMemberIds.length > 0
            ? parseJsonStringArray(msg.groupMemberIds)
            : undefined,
        groupEventType:
          typeof msg.groupEventType === "string" &&
          msg.groupEventType.length > 0
            ? msg.groupEventType
            : undefined,
        groupMembershipCommitment:
          typeof msg.groupMembershipCommitment === "string" &&
          msg.groupMembershipCommitment.length > 0
            ? msg.groupMembershipCommitment
            : undefined,
        blob: msg.blob,
        handshakeData: msg.handshakeData,
        ratchetKeyEcc: msg.ratchetKeyEcc,
        messageNumber: msg.messageNumber,
        timestamp: msg.timestamp,
      }));
    });

    return tx();
  }

  async ackPendingMessage(
    recipientId: string,
    messageId: string,
  ): Promise<void> {
    this.db
      .prepare(
        "DELETE FROM pending_messages WHERE recipientId = ? AND messageId = ?",
      )
      .run(recipientId, messageId);
  }

  async userExists(userId: string): Promise<boolean> {
    const row = this.db.prepare("SELECT 1 FROM users WHERE id = ?").get(userId);
    return !!row;
  }

  private mapGroupRow(row: {
    id: string;
    name: string;
    ownerId: string;
    createdAt: number;
    updatedAt: number;
  }): GroupRecord {
    const members = this.db
      .prepare(
        "SELECT userId FROM group_members WHERE groupId = ? ORDER BY addedAt ASC",
      )
      .all(row.id) as Array<{ userId: string }>;

    return {
      id: row.id,
      name: row.name,
      ownerId: row.ownerId,
      memberUserIds: members.map((entry) => entry.userId),
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      membershipCommitment: computeMembershipCommitment(
        row.id,
        row.ownerId,
        members.map((entry) => entry.userId),
        row.updatedAt,
      ),
    };
  }

  async createGroup(
    ownerId: string,
    name: string,
    memberUserIds: string[],
  ): Promise<GroupRecord> {
    const uniqueMembers = Array.from(
      new Set([ownerId, ...memberUserIds.filter((id) => id !== ownerId)]),
    );

    if (uniqueMembers.length < 2) {
      throw new Error("Group must include at least 2 members");
    }

    for (const memberId of uniqueMembers) {
      const exists = await this.userExists(memberId);
      if (!exists) {
        throw new Error("One or more members do not exist");
      }
    }

    const now = Date.now();
    const groupId = randomUUID();
    const insertGroup = this.db.prepare(
      "INSERT INTO groups (id, name, ownerId, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?)",
    );
    const insertMember = this.db.prepare(
      "INSERT INTO group_members (groupId, userId, addedAt) VALUES (?, ?, ?)",
    );

    const tx = this.db.transaction(() => {
      insertGroup.run(groupId, name, ownerId, now, now);
      for (const memberId of uniqueMembers) {
        insertMember.run(groupId, memberId, now);
      }
    });

    tx();

    const created = await this.getGroupById(groupId);
    if (!created) {
      throw new Error("Failed to create group");
    }

    return created;
  }

  async getGroupById(groupId: string): Promise<GroupRecord | null> {
    const row = this.db
      .prepare(
        "SELECT id, name, ownerId, createdAt, updatedAt FROM groups WHERE id = ?",
      )
      .get(groupId) as
      | {
          id: string;
          name: string;
          ownerId: string;
          createdAt: number;
          updatedAt: number;
        }
      | undefined;

    if (!row) return null;
    return this.mapGroupRow(row);
  }

  async getGroupsForUser(userId: string): Promise<GroupRecord[]> {
    const rows = this.db
      .prepare(
        "SELECT g.id, g.name, g.ownerId, g.createdAt, g.updatedAt FROM groups g INNER JOIN group_members gm ON gm.groupId = g.id WHERE gm.userId = ? ORDER BY g.updatedAt DESC",
      )
      .all(userId) as Array<{
      id: string;
      name: string;
      ownerId: string;
      createdAt: number;
      updatedAt: number;
    }>;

    return rows.map((row) => this.mapGroupRow(row));
  }

  async isGroupMember(groupId: string, userId: string): Promise<boolean> {
    const row = this.db
      .prepare("SELECT 1 FROM group_members WHERE groupId = ? AND userId = ?")
      .get(groupId, userId);
    return Boolean(row);
  }

  async addGroupMember(groupId: string, userId: string): Promise<GroupRecord> {
    const exists = await this.userExists(userId);
    if (!exists) {
      throw new Error("User not found");
    }

    const now = Date.now();
    this.db
      .prepare(
        "INSERT OR IGNORE INTO group_members (groupId, userId, addedAt) VALUES (?, ?, ?)",
      )
      .run(groupId, userId, now);

    this.touchGroup(groupId, now);
    return this.getRequiredGroup(groupId);
  }

  async removeGroupMember(
    groupId: string,
    userId: string,
  ): Promise<GroupRecord> {
    const now = Date.now();
    this.db
      .prepare("DELETE FROM group_members WHERE groupId = ? AND userId = ?")
      .run(groupId, userId);

    this.touchGroup(groupId, now);
    return this.getRequiredGroup(groupId);
  }

  async transferGroupOwnershipAndRemoveMember(
    groupId: string,
    ownerUserId: string,
  ): Promise<GroupRecord> {
    const remainingMembers = this.db
      .prepare(
        "SELECT userId, addedAt FROM group_members WHERE groupId = ? AND userId <> ? ORDER BY addedAt ASC, userId ASC",
      )
      .all(groupId, ownerUserId) as Array<{ userId: string; addedAt: number }>;

    if (remainingMembers.length < 2) {
      throw new Error(
        "Owner cannot leave while the group would drop below two members",
      );
    }

    const nextOwnerId = remainingMembers[0].userId;
    const now = Date.now();

    const tx = this.db.transaction(() => {
      this.db
        .prepare("UPDATE groups SET ownerId = ?, updatedAt = ? WHERE id = ?")
        .run(nextOwnerId, now, groupId);

      this.db
        .prepare("DELETE FROM group_members WHERE groupId = ? AND userId = ?")
        .run(groupId, ownerUserId);
    });

    tx();

    return this.getRequiredGroup(groupId);
  }

  private touchGroup(groupId: string, updatedAt: number): void {
    this.db
      .prepare("UPDATE groups SET updatedAt = ? WHERE id = ?")
      .run(updatedAt, groupId);
  }

  private async getRequiredGroup(groupId: string): Promise<GroupRecord> {
    const group = await this.getGroupById(groupId);
    if (!group) {
      throw new Error("Group not found");
    }
    return group;
  }
}

export const store = new SqliteStore();
