import {
  AES_GCM_KEY_SIZE,
  AES_GCM_NONCE_SIZE,
  aesGcmDecrypt,
  aesGcmEncrypt,
} from "../symmetric/aesgcm";

describe("aes-gcm", () => {
  it("encrypts and decrypts round-trip", async () => {
    const key = crypto.getRandomValues(new Uint8Array(AES_GCM_KEY_SIZE));
    const nonce = crypto.getRandomValues(new Uint8Array(AES_GCM_NONCE_SIZE));
    const plaintext = new TextEncoder().encode("secure payload");

    const ciphertext = await aesGcmEncrypt(key, nonce, plaintext);
    const decrypted = await aesGcmDecrypt(key, nonce, ciphertext);

    expect(new TextDecoder().decode(decrypted)).toBe("secure payload");
  });

  it("fails decryption with mismatched AAD", async () => {
    const key = crypto.getRandomValues(new Uint8Array(AES_GCM_KEY_SIZE));
    const nonce = crypto.getRandomValues(new Uint8Array(AES_GCM_NONCE_SIZE));
    const plaintext = new TextEncoder().encode("secure payload");

    const ciphertext = await aesGcmEncrypt(
      key,
      nonce,
      plaintext,
      new Uint8Array([1, 2, 3])
    );

    await expect(
      aesGcmDecrypt(key, nonce, ciphertext, new Uint8Array([9, 9, 9]))
    ).rejects.toThrow("authentication tag mismatch");
  });

  it("rejects invalid nonce length", async () => {
    const key = crypto.getRandomValues(new Uint8Array(AES_GCM_KEY_SIZE));
    const badNonce = new Uint8Array(8);
    const plaintext = new Uint8Array([1, 2, 3]);

    await expect(aesGcmEncrypt(key, badNonce, plaintext)).rejects.toThrow(
      "Invalid nonce size"
    );
  });
});
