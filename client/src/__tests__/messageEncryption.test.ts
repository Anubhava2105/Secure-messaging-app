import { encryptMessage, decryptMessage } from "../utils/messageEncryption";

describe("messageEncryption", () => {
  it("encrypts and decrypts round-trip", async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const plaintext = "hello secure world";

    const encrypted = await encryptMessage(plaintext, key);
    const decrypted = await decryptMessage(encrypted, key);

    expect(decrypted).toBe(plaintext);
  });

  it("fails decryption when authenticated message context does not match", async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const plaintext = "group-authenticated-payload";

    const encrypted = await encryptMessage(plaintext, key, {
      messageId: "m-1",
      senderId: "alice",
      recipientId: "bob",
      groupId: "group-123",
      groupEventType: "group_message",
      groupMembershipCommitment: "commitment-a",
    });

    await expect(
      decryptMessage(encrypted, key, {
        messageId: "m-1",
        senderId: "alice",
        recipientId: "bob",
        groupId: "group-123",
        groupEventType: "group_message",
        groupMembershipCommitment: "commitment-b",
      }),
    ).rejects.toThrow(/authentication tag mismatch/i);
  });

  it("fails decryption when ciphertext is tampered", async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const plaintext = "tamper check payload";

    const encrypted = await encryptMessage(plaintext, key, {
      messageId: "m-2",
      senderId: "alice",
      recipientId: "bob",
    });

    const raw = atob(encrypted);
    const bytes = Uint8Array.from(raw, (char) => char.charCodeAt(0));
    bytes[bytes.length - 1] ^= 0x01;

    const tampered = btoa(String.fromCharCode(...bytes));
    await expect(
      decryptMessage(tampered, key, {
        messageId: "m-2",
        senderId: "alice",
        recipientId: "bob",
      }),
    ).rejects.toThrow(/authentication tag mismatch/i);
  });

  it("fails decryption when nonce bytes are tampered", async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const plaintext = "nonce tamper payload";

    const encrypted = await encryptMessage(plaintext, key, {
      messageId: "m-3",
      senderId: "alice",
      recipientId: "bob",
    });

    const raw = atob(encrypted);
    const bytes = Uint8Array.from(raw, (char) => char.charCodeAt(0));
    bytes[0] ^= 0x80;

    const tampered = btoa(String.fromCharCode(...bytes));
    await expect(
      decryptMessage(tampered, key, {
        messageId: "m-3",
        senderId: "alice",
        recipientId: "bob",
      }),
    ).rejects.toThrow(/authentication tag mismatch/i);
  });
});
