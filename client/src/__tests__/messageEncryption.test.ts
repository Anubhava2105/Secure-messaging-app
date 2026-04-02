import { encryptMessage, decryptMessage } from "../utils/messageEncryption";

describe("messageEncryption", () => {
  it("encrypts and decrypts round-trip", async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const plaintext = "hello secure world";

    const encrypted = await encryptMessage(plaintext, key);
    const decrypted = await decryptMessage(encrypted, key);

    expect(decrypted).toBe(plaintext);
  });
});
