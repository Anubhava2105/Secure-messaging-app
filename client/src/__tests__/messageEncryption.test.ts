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
});
