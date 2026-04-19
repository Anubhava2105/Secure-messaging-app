import { beforeEach, describe, expect, it } from "vitest";
import {
  clearAtRestPassphrase,
  getKeyStore,
  setAtRestPassphrase,
  type StoredIdentity,
  type StoredMessage,
} from "../crypto/storage/keystore";

describe("keystore at-rest encryption", () => {
  beforeEach(async () => {
    clearAtRestPassphrase();
    localStorage.clear();
  });

  it("locks and unlocks encrypted identity data", async () => {
    const userId = "user-at-rest";
    await setAtRestPassphrase(userId, "super-secret-password");

    const store = getKeyStore();
    const identity: StoredIdentity = {
      id: userId,
      userId,
      username: "alice",
      eccIdentityPublic: { kty: "EC", crv: "P-384", x: "x", y: "y" },
      eccIdentityPrivate: { kty: "EC", crv: "P-384", d: "d", x: "x", y: "y" },
      pqcIdentityPublic: new Uint8Array([1, 2, 3]).buffer,
      pqcIdentityPrivate: new Uint8Array([4, 5, 6]).buffer,
      signingPublic: { kty: "EC", crv: "P-384", x: "sx", y: "sy" },
      signingPrivate: { kty: "EC", crv: "P-384", d: "sd", x: "sx", y: "sy" },
      createdAt: Date.now(),
    };

    await store.storeIdentity(identity);

    const unlocked = await store.getIdentity(userId);
    expect(unlocked?.username).toBe("alice");
    expect(unlocked?.pqcIdentityPrivate).toBeInstanceOf(ArrayBuffer);

    clearAtRestPassphrase();
    await expect(store.getIdentity(userId)).rejects.toThrow(
      /At-rest key unavailable/,
    );

    await setAtRestPassphrase(userId, "super-secret-password");
    const reopened = await store.getIdentity(userId);
    expect(reopened?.username).toBe("alice");
  });

  it("encrypts message content at rest and requires unlocked key to read", async () => {
    const userId = "user-messages";
    await setAtRestPassphrase(userId, "another-strong-password");

    const store = getKeyStore();
    const message: StoredMessage = {
      id: "m1",
      senderId: "a",
      recipientId: "b",
      peerId: "b",
      content: "secret plaintext",
      timestamp: Date.now(),
      isPqcProtected: true,
      status: "sent",
    };

    await store.storeMessage(message);

    const unlocked = await store.getMessagesByPeer("b");
    expect(unlocked).toHaveLength(1);
    expect(unlocked[0].content).toBe("secret plaintext");

    clearAtRestPassphrase();
    await expect(store.getMessagesByPeer("b")).rejects.toThrow(
      /At-rest key unavailable/,
    );
  });
});
