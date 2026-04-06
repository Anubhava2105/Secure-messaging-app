/**
 * Hybrid Key Exchange Protocol (X3DH variant with PQC).
 *
 * Combines classical ECC (ECDH P-384) with post-quantum ML-KEM-768
 * to provide resistance against Harvest Now, Decrypt Later attacks.
 *
 * SECURITY: Session keys are derived from BOTH ECC and PQC shared secrets.
 * An attacker must break both to compromise the session.
 */

import {
  generateExportableECDHKeyPair,
  importECDHPublicKey,
  deriveECDHSharedSecret,
} from "../ecc/ecdh";
import { verifyPrekeySignature } from "../ecc/ecdsa";
import { getMlKem768 } from "../pqc/mlkem";
import { deriveSessionKeys } from "../kdf/hkdf";
import { concatBytes, stringToBytes, bytesToHex } from "../utils/encoding";

import type {
  PreKeyBundle,
  SessionKeys,
  ExportableEccKeyPair,
  PqcKeyPair,
} from "../interfaces";

/** Handshake message from initiator to responder */
export interface HandshakeMessage {
  /** Protocol version */
  version: number;
  /** Initiator's ECC identity public key */
  identityKeyEcc: Uint8Array;
  /** Initiator's ephemeral ECC public key */
  ephemeralKeyEcc: Uint8Array;
  /** ML-KEM ciphertext (encapsulated shared secret) */
  pqcCiphertext: Uint8Array;
  /** ID of one-time prekey used (0 if none) */
  oneTimePrekeyId: number;
  /** Encrypted initial message (optional) */
  encryptedPayload?: Uint8Array;
  /** Nonce for encrypted payload */
  payloadNonce?: Uint8Array;
}

/** Session established after handshake */
export interface Session {
  /** Unique session identifier */
  sessionId: string;
  /** Peer's user ID */
  peerId: string;
  /** Derived session keys */
  keys: SessionKeys;
  /** Our sending chain key */
  sendChainKey: Uint8Array;
  /** Their receiving chain key */
  recvChainKey: Uint8Array;
  /** Message counter for nonce generation */
  messageCounter: bigint;
  /** Timestamp of session creation */
  createdAt: number;
}

/** Local identity for handshake operations */
export interface LocalIdentity {
  userId: string;
  eccIdentity: ExportableEccKeyPair;
  pqcIdentity: PqcKeyPair;
  signingKey: ExportableEccKeyPair;
  signedPrekeyEcc: {
    id: number;
    keyPair: ExportableEccKeyPair;
    createdAt: number;
  };
  signedPrekeyPqc: { id: number; keyPair: PqcKeyPair; createdAt: number };
  oneTimePrekeysEcc: Map<number, ExportableEccKeyPair>;
}

/**
 * Initiator side of the hybrid X3DH handshake.
 *
 * Creates a session with the recipient using their prekey bundle.
 * Returns the handshake message to send and the derived session.
 */
export async function initiateHandshake(
  localIdentity: LocalIdentity,
  recipientBundle: PreKeyBundle
): Promise<{ message: HandshakeMessage; session: Session }> {
  // 1. Verify prekey signatures
  const eccPrekeyValid = await verifyPrekeySignature(
    recipientBundle.signingKeyPub,
    recipientBundle.signedPreKeyEcc.signature,
    recipientBundle.signedPreKeyEcc.publicKey,
    recipientBundle.signedPreKeyEcc.id,
    recipientBundle.signedPreKeyEcc.createdAt
  );

  if (!eccPrekeyValid) {
    throw new Error("Invalid ECC prekey signature");
  }

  const pqcPrekeyValid = await verifyPrekeySignature(
    recipientBundle.signingKeyPub,
    recipientBundle.signedPreKeyPqc.signature,
    recipientBundle.signedPreKeyPqc.publicKey,
    recipientBundle.signedPreKeyPqc.id,
    recipientBundle.signedPreKeyPqc.createdAt
  );

  if (!pqcPrekeyValid) {
    throw new Error("Invalid PQC prekey signature");
  }

  // 2. Generate ephemeral ECC key
  const ephemeralEcc = await generateExportableECDHKeyPair();

  // Import recipient keys
  const recipientSpkEcc = await importECDHPublicKey(
    recipientBundle.signedPreKeyEcc.publicKey
  );
  const recipientIkEcc = await importECDHPublicKey(
    recipientBundle.identityKeyEcc
  );

  // 3. Compute DH shared secrets
  // DH1 = ECDH(IKA, SPKB)
  const dh1 = await deriveECDHSharedSecret(
    localIdentity.eccIdentity.privateKey,
    recipientSpkEcc
  );

  // DH2 = ECDH(EKA, IKB)
  const dh2 = await deriveECDHSharedSecret(
    ephemeralEcc.privateKey,
    recipientIkEcc
  );

  // DH3 = ECDH(EKA, SPKB)
  const dh3 = await deriveECDHSharedSecret(
    ephemeralEcc.privateKey,
    recipientSpkEcc
  );

  // DH4 = ECDH(EKA, OPKB) if one-time prekey available
  let dh4: Uint8Array | null = null;
  let oneTimePrekeyId = 0;

  if (recipientBundle.oneTimePreKeyEcc) {
    const recipientOpkEcc = await importECDHPublicKey(
      recipientBundle.oneTimePreKeyEcc.publicKey
    );
    dh4 = await deriveECDHSharedSecret(
      ephemeralEcc.privateKey,
      recipientOpkEcc
    );
    oneTimePrekeyId = recipientBundle.oneTimePreKeyEcc.id;
  }

  // 4. PQC encapsulation
  const mlkem = await getMlKem768();
  const { ciphertext: pqcCiphertext, sharedSecret: pqcSharedSecret } =
    await mlkem.encapsulate(recipientBundle.signedPreKeyPqc.publicKey);

  // 5. Derive session keys using HKDF
  const eccSecrets = dh4 ? [dh1, dh2, dh3, dh4] : [dh1, dh2, dh3];

  // Context includes both identity public keys for binding
  const context = concatBytes(
    stringToBytes("SecureMsg-Handshake-v1"),
    localIdentity.eccIdentity.publicKeyBytes,
    recipientBundle.identityKeyEcc
  );

  const sessionKeys = await deriveSessionKeys(
    eccSecrets,
    pqcSharedSecret,
    context
  );

  // 6. Create session
  const session: Session = {
    sessionId: bytesToHex(sessionKeys.rootKey.slice(0, 8)),
    peerId: "recipient", // Would be actual user ID in practice
    keys: sessionKeys,
    sendChainKey: sessionKeys.rootKey.slice(),
    recvChainKey: sessionKeys.rootKey.slice(),
    messageCounter: 0n,
    createdAt: Date.now(),
  };

  // 7. Create handshake message
  const message: HandshakeMessage = {
    version: 1,
    identityKeyEcc: localIdentity.eccIdentity.publicKeyBytes,
    ephemeralKeyEcc: ephemeralEcc.publicKeyBytes,
    pqcCiphertext,
    oneTimePrekeyId,
  };

  return { message, session };
}

/**
 * Responder side of the hybrid X3DH handshake.
 *
 * Processes the initiator's handshake message to establish a session.
 */
export async function respondToHandshake(
  localIdentity: LocalIdentity,
  _initiatorIdentityKeyEcc: Uint8Array,
  message: HandshakeMessage
): Promise<Session> {
  // 1. Import initiator's keys
  const initiatorIdentity = await importECDHPublicKey(message.identityKeyEcc);
  const initiatorEphemeral = await importECDHPublicKey(message.ephemeralKeyEcc);

  // 2. Compute DH shared secrets (reverse of initiator)
  // DH1 = ECDH(SPKB, IKA)
  const dh1 = await deriveECDHSharedSecret(
    localIdentity.signedPrekeyEcc.keyPair.privateKey,
    initiatorIdentity
  );

  // DH2 = ECDH(IKB, EKA)
  const dh2 = await deriveECDHSharedSecret(
    localIdentity.eccIdentity.privateKey,
    initiatorEphemeral
  );

  // DH3 = ECDH(SPKB, EKA)
  const dh3 = await deriveECDHSharedSecret(
    localIdentity.signedPrekeyEcc.keyPair.privateKey,
    initiatorEphemeral
  );

  // DH4 = ECDH(OPKB, EKA) if one-time prekey was used
  let dh4: Uint8Array | null = null;

  if (message.oneTimePrekeyId !== 0) {
    const oneTimeKey = localIdentity.oneTimePrekeysEcc.get(
      message.oneTimePrekeyId
    );
    if (!oneTimeKey) {
      throw new Error("One-time prekey not found or already consumed");
    }

    dh4 = await deriveECDHSharedSecret(
      oneTimeKey.privateKey,
      initiatorEphemeral
    );

    // SECURITY: Delete one-time prekey after use
    localIdentity.oneTimePrekeysEcc.delete(message.oneTimePrekeyId);
  }

  // 3. PQC decapsulation
  const mlkem = await getMlKem768();
  const pqcSharedSecret = await mlkem.decapsulate(
    message.pqcCiphertext,
    localIdentity.signedPrekeyPqc.keyPair.privateKey
  );

  // 4. Derive session keys using HKDF
  const eccSecrets = dh4 ? [dh1, dh2, dh3, dh4] : [dh1, dh2, dh3];

  const context = concatBytes(
    stringToBytes("SecureMsg-Handshake-v1"),
    message.identityKeyEcc,
    localIdentity.eccIdentity.publicKeyBytes
  );

  const sessionKeys = await deriveSessionKeys(
    eccSecrets,
    pqcSharedSecret,
    context
  );

  // 5. Create session (keys match initiator)
  const session: Session = {
    sessionId: bytesToHex(sessionKeys.rootKey.slice(0, 8)),
    peerId: "initiator", // Would be actual user ID
    keys: sessionKeys,
    sendChainKey: sessionKeys.rootKey.slice(),
    recvChainKey: sessionKeys.rootKey.slice(),
    messageCounter: 0n,
    createdAt: Date.now(),
  };

  return session;
}

/**
 * Serialize handshake message for transmission.
 */
export function serializeHandshakeMessage(
  message: HandshakeMessage
): Uint8Array {
  // Simple serialization format:
  // [version:1][ikEccLen:2][ikEcc][ekEccLen:2][ekEcc][pqcCtLen:2][pqcCt][otkId:4][payloadLen:4][payload][nonceLen:1][nonce]

  const parts: Uint8Array[] = [];

  // Version
  parts.push(new Uint8Array([message.version]));

  // Identity key ECC
  const ikLen = new Uint8Array(2);
  new DataView(ikLen.buffer).setUint16(0, message.identityKeyEcc.length, false);
  parts.push(ikLen);
  parts.push(message.identityKeyEcc);

  // Ephemeral key ECC
  const ekLen = new Uint8Array(2);
  new DataView(ekLen.buffer).setUint16(
    0,
    message.ephemeralKeyEcc.length,
    false
  );
  parts.push(ekLen);
  parts.push(message.ephemeralKeyEcc);

  // PQC ciphertext
  const ctLen = new Uint8Array(2);
  new DataView(ctLen.buffer).setUint16(0, message.pqcCiphertext.length, false);
  parts.push(ctLen);
  parts.push(message.pqcCiphertext);

  // One-time prekey ID
  const otkId = new Uint8Array(4);
  new DataView(otkId.buffer).setUint32(0, message.oneTimePrekeyId, false);
  parts.push(otkId);

  // Optional encrypted payload
  const payloadLen = new Uint8Array(4);
  const payload = message.encryptedPayload ?? new Uint8Array(0);
  new DataView(payloadLen.buffer).setUint32(0, payload.length, false);
  parts.push(payloadLen);
  if (payload.length > 0) {
    parts.push(payload);
  }

  // Optional nonce
  const nonceLen = new Uint8Array(1);
  const nonce = message.payloadNonce ?? new Uint8Array(0);
  nonceLen[0] = nonce.length;
  parts.push(nonceLen);
  if (nonce.length > 0) {
    parts.push(nonce);
  }

  return concatBytes(...parts);
}

/**
 * Deserialize handshake message from bytes.
 */
export function deserializeHandshakeMessage(
  data: Uint8Array
): HandshakeMessage {
  let offset = 0;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

  // Version
  const version = data[offset++];

  // Identity key ECC
  const ikLen = view.getUint16(offset, false);
  offset += 2;
  const identityKeyEcc = data.slice(offset, offset + ikLen);
  offset += ikLen;

  // Ephemeral key ECC
  const ekLen = view.getUint16(offset, false);
  offset += 2;
  const ephemeralKeyEcc = data.slice(offset, offset + ekLen);
  offset += ekLen;

  // PQC ciphertext
  const ctLen = view.getUint16(offset, false);
  offset += 2;
  const pqcCiphertext = data.slice(offset, offset + ctLen);
  offset += ctLen;

  // One-time prekey ID
  const oneTimePrekeyId = view.getUint32(offset, false);
  offset += 4;

  // Optional payload
  const payloadLen = view.getUint32(offset, false);
  offset += 4;
  const encryptedPayload =
    payloadLen > 0 ? data.slice(offset, offset + payloadLen) : undefined;
  offset += payloadLen;

  // Optional nonce
  const nonceLen = data[offset++];
  const payloadNonce =
    nonceLen > 0 ? data.slice(offset, offset + nonceLen) : undefined;

  return {
    version,
    identityKeyEcc,
    ephemeralKeyEcc,
    pqcCiphertext,
    oneTimePrekeyId,
    encryptedPayload,
    payloadNonce,
  };
}
