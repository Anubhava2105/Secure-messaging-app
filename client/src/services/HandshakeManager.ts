/**
 * Handshake Manager Service.
 *
 * Orchestrates the X3DH handshake between two users:
 * 1. Fetches the recipient's prekey bundle from the server.
 * 2. Performs the initiator-side hybrid X3DH handshake.
 * 3. Stores the resulting session.
 *
 * For the responder side, incoming handshake messages are handled
 * by processing the handshake data attached to the first message.
 *
 * SECURITY: In production, if a real handshake cannot be established,
 * session creation fails (no insecure fallback).
 */

import {
  initiateHandshake,
  respondToHandshake,
  serializeHandshakeMessage,
  deserializeHandshakeMessage,
} from "../crypto/hybrid/handshake";
import type {
  LocalIdentity,
  Session,
  HandshakeMessage,
} from "../crypto/hybrid/handshake";
import type { PreKeyBundle } from "../crypto/interfaces";
import { base64ToBytes, bytesToBase64 } from "../crypto/utils/encoding";
import { getKeyStore } from "../crypto/storage/keystore";
import { deleteSession, saveSession, getSessionAsync } from "./SessionManager";
import { getPreKeyBundle } from "./api";
import type { PreKeyBundleDTO } from "./api";
import {
  ensureContactTrustFromBundle,
  verifyIncomingHandshakeIdentity,
} from "./TrustManager";

/** In-memory local identity (generated once per session) */
let localIdentity: LocalIdentity | null = null;

function toUint8(data: ArrayBuffer): Uint8Array {
  return new Uint8Array(data);
}

async function importEcdhPrivateKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-384" },
    true,
    ["deriveBits"],
  );
}

async function importEcdhPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-384" },
    true,
    [],
  );
}

async function importEcdsaPrivateKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-384" },
    true,
    ["sign"],
  );
}

async function importEcdsaPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-384" },
    true,
    ["verify"],
  );
}

async function ensureOneTimePrekeyLoaded(
  identity: LocalIdentity,
  oneTimePrekeyId: number,
): Promise<void> {
  if (identity.oneTimePrekeysEcc.has(oneTimePrekeyId)) return;

  const stored = await getKeyStore().getSignedPrekey(
    oneTimePrekeyId,
    "ecc",
    identity.userId,
  );
  if (!stored) return;

  if (stored.type !== "ecc" || !stored.privateKey) return;
  if (stored.privateKey instanceof ArrayBuffer) return;

  const privateKey = await importEcdhPrivateKey(stored.privateKey);
  identity.oneTimePrekeysEcc.set(oneTimePrekeyId, {
    publicKeyBytes: toUint8(stored.publicKey),
    privateKey,
  });
}

/**
 * Generate or retrieve the local identity for handshake operations.
 * This creates the full key material needed for X3DH.
 */
export async function getOrCreateLocalIdentity(
  userId: string,
): Promise<LocalIdentity> {
  if (localIdentity && localIdentity.userId === userId) {
    return localIdentity;
  }

  const store = getKeyStore();
  let persistedIdentity = await store.getIdentity(userId);
  if (!persistedIdentity) {
    const legacyIdentity = await store.getIdentity("local-user");
    if (legacyIdentity?.userId === userId) {
      await store.storeIdentity({
        ...legacyIdentity,
        id: userId,
      });
      persistedIdentity = legacyIdentity;
    }
  }
  if (!persistedIdentity || persistedIdentity.userId !== userId) {
    throw new Error("Local identity not found for current user");
  }

  if (
    !persistedIdentity.eccIdentityPrivate ||
    !persistedIdentity.signingPrivate
  ) {
    throw new Error("Local identity is incomplete (missing private keys)");
  }

  const signedPrekeyEcc = await store.getSignedPrekey(1, "ecc", userId);
  const signedPrekeyPqc = await store.getSignedPrekey(1, "pqc", userId);
  if (!signedPrekeyEcc || !signedPrekeyPqc) {
    throw new Error("Signed prekeys are missing from local keystore");
  }

  if (
    !(
      signedPrekeyEcc.privateKey &&
      !(signedPrekeyEcc.privateKey instanceof ArrayBuffer)
    )
  ) {
    throw new Error("Invalid ECC signed prekey private material");
  }

  const eccIdentityPrivate = await importEcdhPrivateKey(
    persistedIdentity.eccIdentityPrivate,
  );
  const eccIdentityPublic = await importEcdhPublicKey(
    persistedIdentity.eccIdentityPublic,
  );
  const signingPrivate = await importEcdsaPrivateKey(
    persistedIdentity.signingPrivate,
  );
  const signingPublic = await importEcdsaPublicKey(
    persistedIdentity.signingPublic,
  );

  const eccIdentityPublicRaw = new Uint8Array(
    await crypto.subtle.exportKey("raw", eccIdentityPublic),
  );
  const signingPublicRaw = new Uint8Array(
    await crypto.subtle.exportKey("raw", signingPublic),
  );

  const eccSignedPrekeyPrivate = await importEcdhPrivateKey(
    signedPrekeyEcc.privateKey,
  );

  localIdentity = {
    userId,
    eccIdentity: {
      publicKeyBytes: eccIdentityPublicRaw,
      privateKey: eccIdentityPrivate,
    },
    pqcIdentity: {
      publicKey: toUint8(persistedIdentity.pqcIdentityPublic),
      privateKey: toUint8(persistedIdentity.pqcIdentityPrivate),
    },
    signingKey: {
      publicKeyBytes: signingPublicRaw,
      privateKey: signingPrivate,
    },
    signedPrekeyEcc: {
      id: signedPrekeyEcc.prekeyId,
      keyPair: {
        publicKeyBytes: toUint8(signedPrekeyEcc.publicKey),
        privateKey: eccSignedPrekeyPrivate,
      },
      createdAt: signedPrekeyEcc.createdAt,
    },
    signedPrekeyPqc: {
      id: signedPrekeyPqc.prekeyId,
      keyPair: {
        publicKey: toUint8(signedPrekeyPqc.publicKey),
        privateKey:
          signedPrekeyPqc.privateKey instanceof ArrayBuffer
            ? toUint8(signedPrekeyPqc.privateKey)
            : new Uint8Array(0),
      },
      createdAt: signedPrekeyPqc.createdAt,
    },
    oneTimePrekeysEcc: new Map(),
  };

  if (localIdentity.signedPrekeyPqc.keyPair.privateKey.length === 0) {
    throw new Error("Invalid PQC signed prekey private material");
  }

  console.log("[Handshake] Local identity loaded from keystore");
  return localIdentity;
}

/**
 * Convert a server PreKeyBundleDTO to the crypto PreKeyBundle format.
 */
function dtoToPreKeyBundle(
  dto: PreKeyBundleDTO,
  includeOneTimePrekey = true,
): PreKeyBundle {
  const bundle: PreKeyBundle = {
    identityKeyEcc: base64ToBytes(dto.identityKeyEccPub),
    identityKeyPqc: base64ToBytes(dto.identityKeyPqcPub),
    signingKeyPub: base64ToBytes(dto.signingKeyPub),
    signedPreKeyEcc: {
      id: dto.signedPrekeyEcc.id,
      publicKey: base64ToBytes(dto.signedPrekeyEcc.publicKey),
      signature: base64ToBytes(dto.signedPrekeyEcc.signature),
      createdAt: dto.signedPrekeyEcc.createdAt,
    },
    signedPreKeyPqc: {
      id: dto.signedPrekeyPqc.id,
      publicKey: base64ToBytes(dto.signedPrekeyPqc.publicKey),
      signature: base64ToBytes(dto.signedPrekeyPqc.signature),
      createdAt: dto.signedPrekeyPqc.createdAt,
    },
  };

  if (includeOneTimePrekey && dto.oneTimePrekeyEcc) {
    bundle.oneTimePreKeyEcc = {
      id: dto.oneTimePrekeyEcc.id,
      publicKey: base64ToBytes(dto.oneTimePrekeyEcc.publicKey),
    };
  }

  return bundle;
}

/**
 * Initiate a handshake with a contact.
 * Fetches their prekey bundle and performs the X3DH initiator side.
 *
 * @returns The session and serialized handshake message to send
 */
export async function initiateHandshakeWithContact(
  myUserId: string,
  contactId: string,
  options?: {
    disableOneTimePrekey?: boolean;
  },
): Promise<{ session: Session; handshakeData: string } | null> {
  try {
    // 1. Get local identity
    const identity = await getOrCreateLocalIdentity(myUserId);

    // 2. Fetch contact's prekey bundle
    const bundleDTO = await getPreKeyBundle(contactId);
    if (!bundleDTO) {
      console.warn("[Handshake] Could not fetch prekey bundle for:", contactId);
      return null;
    }

    const trust = await ensureContactTrustFromBundle(contactId, bundleDTO);
    if (!trust.trusted) {
      throw new Error(trust.reason ?? "Contact trust verification failed");
    }

    // 3. Convert DTO to crypto format
    const bundle = dtoToPreKeyBundle(
      bundleDTO,
      !(options?.disableOneTimePrekey ?? false),
    );

    // 4. Perform X3DH initiator handshake
    const { message, session } = await initiateHandshake(identity, bundle);

    // 5. Update session with real peer ID
    session.peerId = contactId;

    // 6. Save session
    await saveSession(contactId, session);

    // 7. Serialize handshake message for transmission
    const serialized = serializeHandshakeMessage(message);
    const handshakeData = bytesToBase64(serialized);

    console.log("[Handshake] Initiated with:", contactId);
    return { session, handshakeData };
  } catch (err) {
    console.error("[Handshake] Failed to initiate:", err);
    return null;
  }
}

/**
 * Handle an incoming handshake message from a peer.
 * Performs the X3DH responder side.
 *
 * @returns The established session, or null on failure
 */
export async function handleIncomingHandshake(
  myUserId: string,
  senderId: string,
  handshakeData: string,
): Promise<Session | null> {
  try {
    // 1. Get local identity
    const identity = await getOrCreateLocalIdentity(myUserId);

    // 2. Deserialize the handshake message
    const serialized = base64ToBytes(handshakeData);
    const message: HandshakeMessage = deserializeHandshakeMessage(serialized);

    const incomingTrust = await verifyIncomingHandshakeIdentity(
      senderId,
      message.identityKeyEcc,
    );
    if (!incomingTrust.trusted) {
      throw new Error(
        incomingTrust.reason ?? "Incoming handshake trust verification failed",
      );
    }

    if (message.oneTimePrekeyId !== 0) {
      await ensureOneTimePrekeyLoaded(identity, message.oneTimePrekeyId);
    }

    // 3. Perform X3DH responder handshake
    const session = await respondToHandshake(
      identity,
      message.identityKeyEcc,
      message,
    );

    // 4. Update session with real peer ID
    session.peerId = senderId;

    // If this handshake replaces an existing session, clear all in-memory
    // ratchet/counter state first so message numbers restart consistently.
    await deleteSession(senderId);

    // 5. Save session
    await saveSession(senderId, session);

    if (message.oneTimePrekeyId !== 0) {
      identity.oneTimePrekeysEcc.delete(message.oneTimePrekeyId);
      await getKeyStore().deletePrekey(
        message.oneTimePrekeyId,
        "ecc",
        identity.userId,
      );
    }

    console.log("[Handshake] Responded to handshake from:", senderId);
    return session;
  } catch (err) {
    console.error("[Handshake] Failed to respond:", err);
    return null;
  }
}

/**
 * Get or create a session with a contact.
 * Tries existing session first, then attempts handshake.
 */
export async function ensureSession(
  myUserId: string,
  contactId: string,
  options?: {
    disableOneTimePrekey?: boolean;
  },
): Promise<Session | null> {
  // Check for existing session
  const existing = await getSessionAsync(contactId);
  if (existing) return existing;

  // Try real handshake
  const result = await initiateHandshakeWithContact(
    myUserId,
    contactId,
    options,
  );
  if (result) return result.session;

  return null;
}

/**
 * Ensure a session is available for an outgoing message.
 * If a new handshake is created, returns the serialized handshake payload
 * that must be attached to the first encrypted message.
 */
export async function ensureSessionForOutgoing(
  myUserId: string,
  contactId: string,
  options?: {
    disableOneTimePrekey?: boolean;
  },
): Promise<{ session: Session; handshakeData?: string } | null> {
  const existing = await getSessionAsync(contactId);
  if (existing) {
    return { session: existing };
  }

  const initiated = await initiateHandshakeWithContact(
    myUserId,
    contactId,
    options,
  );
  if (!initiated) return null;

  return {
    session: initiated.session,
    handshakeData: initiated.handshakeData,
  };
}
