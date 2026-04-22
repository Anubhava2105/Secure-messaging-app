import { deriveSessionKeys } from "../kdf/hkdf";

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function flipLowestBit(bytes: Uint8Array): Uint8Array {
  const out = bytes.slice();
  out[out.length - 1] ^= 0x01;
  return out;
}

describe("hybrid assurance", () => {
  it("changes derived keys when PQC shared secret changes", async () => {
    const eccSecrets = [
      new Uint8Array(48).fill(1),
      new Uint8Array(48).fill(2),
      new Uint8Array(48).fill(3),
    ];
    const pqcSecret = new Uint8Array(32).fill(9);
    const context = new TextEncoder().encode("SecureMsg-ctx");

    const base = await deriveSessionKeys(eccSecrets, pqcSecret, context);
    const changed = await deriveSessionKeys(
      eccSecrets,
      flipLowestBit(pqcSecret),
      context,
    );

    expect(toHex(changed.rootKey)).not.toBe(toHex(base.rootKey));
    expect(toHex(changed.encryptionKey)).not.toBe(toHex(base.encryptionKey));
  });

  it("changes derived keys when ECC shared secrets change", async () => {
    const eccSecrets = [
      new Uint8Array(48).fill(1),
      new Uint8Array(48).fill(2),
      new Uint8Array(48).fill(3),
    ];
    const pqcSecret = new Uint8Array(32).fill(9);
    const context = new TextEncoder().encode("SecureMsg-ctx");

    const base = await deriveSessionKeys(eccSecrets, pqcSecret, context);
    const changedEccSecrets = [
      flipLowestBit(eccSecrets[0]),
      eccSecrets[1],
      eccSecrets[2],
    ];

    const changed = await deriveSessionKeys(
      changedEccSecrets,
      pqcSecret,
      context,
    );

    expect(toHex(changed.rootKey)).not.toBe(toHex(base.rootKey));
    expect(toHex(changed.macKey)).not.toBe(toHex(base.macKey));
  });

  it("changes derived keys when handshake context changes", async () => {
    const eccSecrets = [
      new Uint8Array(48).fill(1),
      new Uint8Array(48).fill(2),
      new Uint8Array(48).fill(3),
    ];
    const pqcSecret = new Uint8Array(32).fill(9);
    const contextA = new TextEncoder().encode("SecureMsg-ctx-A");
    const contextB = new TextEncoder().encode("SecureMsg-ctx-B");

    const first = await deriveSessionKeys(eccSecrets, pqcSecret, contextA);
    const second = await deriveSessionKeys(eccSecrets, pqcSecret, contextB);

    expect(toHex(first.encryptionKey)).not.toBe(toHex(second.encryptionKey));
    expect(toHex(first.rootKey)).not.toBe(toHex(second.rootKey));
  });
});
