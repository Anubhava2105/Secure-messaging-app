import { beforeEach, describe, expect, it } from "vitest";
import {
  clearAtRestPassphrase,
  getKeyStore,
  setAtRestPassphrase,
  type StoredIdentity,
  type StoredMessage,
  type StoredSession,
} from "../crypto/storage/keystore";

function equalBytes(a: ArrayBuffer, b: ArrayBuffer): boolean {
  const left = new Uint8Array(a);
  const right = new Uint8Array(b);
  if (left.length !== right.length) return false;
  for (let i = 0; i < left.length; i += 1) {
    if (left[i] !== right[i]) return false;
  }
  return true;
}

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

  it("round-trips encrypted sessions with ArrayBuffer fields intact", async () => {
    const userId = "user-session";
    await setAtRestPassphrase(userId, "session-storage-password");

    const store = getKeyStore();
    const session: StoredSession = {
      peerId: "peer-1",
      sessionId: "s-1",
      encryptionKey: new Uint8Array(32).fill(1).buffer,
      macKey: new Uint8Array(32).fill(2).buffer,
      rootKey: new Uint8Array(32).fill(3).buffer,
      sendChainKey: new Uint8Array(32).fill(4).buffer,
      recvChainKey: new Uint8Array(32).fill(5).buffer,
      messageCounter: 7,
      sendMessageCounter: 7,
      recvMessageCounter: 3,
      recvCountersByRatchet: [{ ratchetId: "base", nextMessageNumber: 3 }],
      localRatchetPublicKey: new Uint8Array(97).fill(9).buffer,
      remoteRatchetPublicKey: new Uint8Array(97).fill(10).buffer,
      skippedMessageKeys: [
        {
          ratchetId: "base",
          messageNumber: 1,
          key: new Uint8Array(32).fill(11).buffer,
        },
      ],
      createdAt: Date.now(),
      lastUsed: Date.now(),
    };

    await store.storeSession(session);
    const restored = await store.getSession(session.peerId);

    expect(restored).not.toBeNull();
    expect(restored?.sendChainKey).toBeInstanceOf(ArrayBuffer);
    expect(restored?.recvChainKey).toBeInstanceOf(ArrayBuffer);
    expect(restored?.localRatchetPublicKey).toBeInstanceOf(ArrayBuffer);
    expect(restored?.remoteRatchetPublicKey).toBeInstanceOf(ArrayBuffer);
    expect(restored?.sendChainKey.byteLength).toBe(32);
    expect(restored?.recvChainKey.byteLength).toBe(32);
    expect(restored?.localRatchetPublicKey?.byteLength).toBe(97);
    expect(restored?.remoteRatchetPublicKey?.byteLength).toBe(97);
    expect(equalBytes(restored!.sendChainKey, session.sendChainKey)).toBe(true);

    clearAtRestPassphrase();
    await expect(store.getSession(session.peerId)).rejects.toThrow(
      /At-rest key unavailable/,
    );
  });
});
