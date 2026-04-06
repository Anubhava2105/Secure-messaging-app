import {
  ECC_PUBLIC_KEY_SIZE,
  ECC_SHARED_SECRET_SIZE,
  deriveECDHSharedSecretFromBytes,
  exportECDHPublicKey,
  generateECDHKeyPair,
  generateExportableECDHKeyPair,
  importECDHPublicKey,
} from "../ecc/ecdh";

describe("ecdh", () => {
  it("derives the same shared secret on both sides", async () => {
    const alice = await generateExportableECDHKeyPair();
    const bob = await generateExportableECDHKeyPair();

    const aliceSecret = await deriveECDHSharedSecretFromBytes(
      alice.privateKey,
      bob.publicKeyBytes
    );
    const bobSecret = await deriveECDHSharedSecretFromBytes(
      bob.privateKey,
      alice.publicKeyBytes
    );

    expect(aliceSecret.length).toBe(ECC_SHARED_SECRET_SIZE);
    expect(bobSecret.length).toBe(ECC_SHARED_SECRET_SIZE);
    expect(Array.from(aliceSecret)).toEqual(Array.from(bobSecret));
  });

  it("exports/imports valid P-384 public keys", async () => {
    const pair = await generateECDHKeyPair();
    const exported = await exportECDHPublicKey(pair.publicKey);
    const imported = await importECDHPublicKey(exported);

    expect(exported.length).toBe(ECC_PUBLIC_KEY_SIZE);
    expect(imported.type).toBe("public");
  });

  it("rejects invalid raw public key length", async () => {
    await expect(importECDHPublicKey(new Uint8Array(5))).rejects.toThrow(
      "Invalid public key size"
    );
  });
});
