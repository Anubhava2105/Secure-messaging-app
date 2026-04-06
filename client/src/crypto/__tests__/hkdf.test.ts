import { deriveSessionKeys } from "../kdf/hkdf";

describe("deriveSessionKeys", () => {
  it("derives deterministic 32-byte keys", async () => {
    const ecc1 = new Uint8Array(48).fill(1);
    const ecc2 = new Uint8Array(48).fill(2);
    const ecc3 = new Uint8Array(48).fill(3);
    const pqc = new Uint8Array(32).fill(9);
    const context = new TextEncoder().encode("ctx");

    const first = await deriveSessionKeys([ecc1, ecc2, ecc3], pqc, context);
    const second = await deriveSessionKeys([ecc1, ecc2, ecc3], pqc, context);

    expect(first.encryptionKey.length).toBe(32);
    expect(first.macKey.length).toBe(32);
    expect(first.rootKey.length).toBe(32);
    expect(Array.from(first.encryptionKey)).toEqual(
      Array.from(second.encryptionKey)
    );
    expect(Array.from(first.macKey)).toEqual(Array.from(second.macKey));
    expect(Array.from(first.rootKey)).toEqual(Array.from(second.rootKey));
  });
});
