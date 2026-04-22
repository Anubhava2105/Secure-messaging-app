import {
  serializeHandshakeMessage,
  deserializeHandshakeMessage,
} from "../hybrid/handshake";

describe("handshake serialization", () => {
  it("round-trips handshake payload", () => {
    const original = {
      version: 1,
      identityKeyEcc: new Uint8Array([1, 2, 3]),
      ephemeralKeyEcc: new Uint8Array([4, 5, 6]),
      pqcCiphertext: new Uint8Array([7, 8, 9, 10]),
      oneTimePrekeyId: 42,
      encryptedPayload: new Uint8Array([11, 12]),
      payloadNonce: new Uint8Array([13]),
    };

    const serialized = serializeHandshakeMessage(original);
    const parsed = deserializeHandshakeMessage(serialized);

    expect(parsed.version).toBe(original.version);
    expect(parsed.oneTimePrekeyId).toBe(original.oneTimePrekeyId);
    expect(Array.from(parsed.identityKeyEcc)).toEqual(
      Array.from(original.identityKeyEcc),
    );
    expect(Array.from(parsed.ephemeralKeyEcc)).toEqual(
      Array.from(original.ephemeralKeyEcc),
    );
    expect(Array.from(parsed.pqcCiphertext)).toEqual(
      Array.from(original.pqcCiphertext),
    );
    expect(Array.from(parsed.encryptedPayload ?? new Uint8Array())).toEqual(
      Array.from(original.encryptedPayload ?? new Uint8Array()),
    );
    expect(Array.from(parsed.payloadNonce ?? new Uint8Array())).toEqual(
      Array.from(original.payloadNonce ?? new Uint8Array()),
    );
  });

  it("rejects malformed truncated payload", () => {
    const malformed = new Uint8Array([1, 0, 97]);
    expect(() => deserializeHandshakeMessage(malformed)).toThrow();
  });
});
