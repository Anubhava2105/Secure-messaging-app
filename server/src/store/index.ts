/**
 * In-memory data store for development.
 * Replace with persistent storage (PostgreSQL, Redis) for production.
 *
 * SECURITY: Only stores public keys and encrypted blobs.
 * No private keys or plaintext messages are ever stored.
 */

import type { UserRecord, OneTimePreKeyDto } from "../types/index.js";

class InMemoryStore {
  private users: Map<string, UserRecord> = new Map();
  private usersByUsername: Map<string, string> = new Map();
  private pendingMessages: Map<
    string,
    Array<{ senderId: string; blob: string; timestamp: number }>
  > = new Map();

  /**
   * Create a new user.
   */
  async createUser(user: UserRecord): Promise<void> {
    if (this.users.has(user.id)) {
      throw new Error("User ID already exists");
    }
    if (this.usersByUsername.has(user.username.toLowerCase())) {
      throw new Error("Username already taken");
    }

    this.users.set(user.id, user);
    this.usersByUsername.set(user.username.toLowerCase(), user.id);
  }

  /**
   * Get user by ID.
   */
  async getUserById(userId: string): Promise<UserRecord | null> {
    return this.users.get(userId) ?? null;
  }

  /**
   * Get user by username.
   */
  async getUserByUsername(username: string): Promise<UserRecord | null> {
    const userId = this.usersByUsername.get(username.toLowerCase());
    return userId ? this.users.get(userId) ?? null : null;
  }

  /**
   * Update user's last seen timestamp.
   */
  async updateLastSeen(userId: string): Promise<void> {
    const user = this.users.get(userId);
    if (user) {
      user.lastSeen = Date.now();
    }
  }

  /**
   * Consume one one-time prekey (atomic operation).
   * Returns the consumed prekey or null if none available.
   */
  async consumeOneTimePrekey(userId: string): Promise<OneTimePreKeyDto | null> {
    const user = this.users.get(userId);
    if (!user || user.oneTimePrekeyEcc.length === 0) {
      return null;
    }

    // Pop first prekey (FIFO)
    const prekey = user.oneTimePrekeyEcc.shift()!;
    return prekey;
  }

  /**
   * Add more one-time prekeys.
   */
  async addOneTimePrekeys(
    userId: string,
    prekeys: OneTimePreKeyDto[]
  ): Promise<void> {
    const user = this.users.get(userId);
    if (!user) {
      throw new Error("User not found");
    }

    user.oneTimePrekeyEcc.push(...prekeys);
  }

  /**
   * Get count of remaining one-time prekeys.
   */
  async getOneTimePrekeyCount(userId: string): Promise<number> {
    const user = this.users.get(userId);
    return user?.oneTimePrekeyEcc.length ?? 0;
  }

  /**
   * Store a message for offline delivery.
   */
  async storePendingMessage(
    recipientId: string,
    senderId: string,
    blob: string
  ): Promise<void> {
    if (!this.pendingMessages.has(recipientId)) {
      this.pendingMessages.set(recipientId, []);
    }

    this.pendingMessages.get(recipientId)!.push({
      senderId,
      blob,
      timestamp: Date.now(),
    });
  }

  /**
   * Get and clear pending messages for a user.
   */
  async getPendingMessages(
    userId: string
  ): Promise<Array<{ senderId: string; blob: string; timestamp: number }>> {
    const messages = this.pendingMessages.get(userId) ?? [];
    this.pendingMessages.delete(userId);
    return messages;
  }

  /**
   * Check if user exists.
   */
  async userExists(userId: string): Promise<boolean> {
    return this.users.has(userId);
  }
}

// Singleton instance
export const store = new InMemoryStore();
