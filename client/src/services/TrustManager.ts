import { getKeyStore } from "../crypto/storage/keystore";
import { base64ToBytes } from "../crypto/utils/encoding";
import type { PreKeyBundleDTO } from "./api";

export interface ContactTrustFingerprints {
  identityKeyEccFingerprint: string;
  identityKeyPqcFingerprint: string;
  signingKeyFingerprint: string;
}

export interface TrustCheckResult {
  trusted: boolean;
  state: "trusted" | "unverified" | "changed";
  reason?: string;
  fingerprints: ContactTrustFingerprints;
}

export interface IncomingIdentityTrustResult {
  trusted: boolean;
  state: "trusted" | "unverified" | "changed";
  reason?: string;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function defaultUsername(contactId: string): string {
  return `User-${contactId.slice(0, 8)}`;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return toHex(new Uint8Array(digest));
}

export async function fingerprintIdentityKeyEcc(
  identityKeyEcc: Uint8Array,
): Promise<string> {
  return sha256Hex(identityKeyEcc);
}

export async function fingerprintsFromBundle(
  bundle: PreKeyBundleDTO,
): Promise<ContactTrustFingerprints> {
  return {
    identityKeyEccFingerprint: await sha256Hex(
      base64ToBytes(bundle.identityKeyEccPub),
    ),
    identityKeyPqcFingerprint: await sha256Hex(
      base64ToBytes(bundle.identityKeyPqcPub),
    ),
    signingKeyFingerprint: await sha256Hex(base64ToBytes(bundle.signingKeyPub)),
  };
}

export async function markContactTrustChanged(
  contactId: string,
  warning: string,
  username?: string,
): Promise<void> {
  const store = getKeyStore();
  const existing = await store.getContact(contactId);

  await store.storeContact({
    id: contactId,
    username: username ?? existing?.username ?? defaultUsername(contactId),
    status: existing?.status ?? "offline",
    identityKeyEccFingerprint: existing?.identityKeyEccFingerprint,
    identityKeyPqcFingerprint: existing?.identityKeyPqcFingerprint,
    signingKeyFingerprint: existing?.signingKeyFingerprint,
    trustState: "changed",
    trustWarning: warning,
    trustUpdatedAt: Date.now(),
    lastSeen: existing?.lastSeen,
  });
}

export async function ensureContactTrustFromBundle(
  contactId: string,
  bundle: PreKeyBundleDTO,
  username?: string,
): Promise<TrustCheckResult> {
  const store = getKeyStore();
  const existing = await store.getContact(contactId);
  const fingerprints = await fingerprintsFromBundle(bundle);

  if (existing?.trustState === "changed") {
    return {
      trusted: false,
      state: "changed",
      reason:
        existing.trustWarning ??
        "Security warning: contact key set changed. Messaging is blocked until re-verified.",
      fingerprints,
    };
  }

  const hasAnyPin =
    typeof existing?.identityKeyEccFingerprint === "string" ||
    typeof existing?.identityKeyPqcFingerprint === "string" ||
    typeof existing?.signingKeyFingerprint === "string";

  const eccMismatch =
    typeof existing?.identityKeyEccFingerprint === "string" &&
    existing.identityKeyEccFingerprint !==
      fingerprints.identityKeyEccFingerprint;
  const pqcMismatch =
    typeof existing?.identityKeyPqcFingerprint === "string" &&
    existing.identityKeyPqcFingerprint !==
      fingerprints.identityKeyPqcFingerprint;
  const signingMismatch =
    typeof existing?.signingKeyFingerprint === "string" &&
    existing.signingKeyFingerprint !== fingerprints.signingKeyFingerprint;

  if (eccMismatch || pqcMismatch || signingMismatch) {
    const warning =
      "Security warning: contact key set changed. Messaging is blocked until re-verified.";
    await markContactTrustChanged(contactId, warning, username);
    return {
      trusted: false,
      state: "changed",
      reason: warning,
      fingerprints,
    };
  }

  const trustState: "trusted" | "unverified" = hasAnyPin
    ? existing?.trustState === "trusted"
      ? "trusted"
      : "unverified"
    : "unverified";

  const trustWarning =
    trustState === "unverified"
      ? "Trust-on-first-use: verify this contact identity out-of-band before sharing sensitive data."
      : undefined;

  await store.storeContact({
    id: contactId,
    username: username ?? existing?.username ?? defaultUsername(contactId),
    status: existing?.status ?? "offline",
    identityKeyEccFingerprint: fingerprints.identityKeyEccFingerprint,
    identityKeyPqcFingerprint: fingerprints.identityKeyPqcFingerprint,
    signingKeyFingerprint: fingerprints.signingKeyFingerprint,
    trustState,
    trustWarning,
    trustUpdatedAt: Date.now(),
    lastSeen: existing?.lastSeen,
  });

  return {
    trusted: true,
    state: trustState,
    reason: trustWarning,
    fingerprints,
  };
}

export async function markContactTrusted(
  contactId: string,
  username?: string,
): Promise<void> {
  const store = getKeyStore();
  const existing = await store.getContact(contactId);
  if (!existing) return;

  await store.storeContact({
    ...existing,
    username: username ?? existing.username,
    trustState: "trusted",
    trustWarning: undefined,
    trustUpdatedAt: Date.now(),
  });
}

export async function verifyIncomingHandshakeIdentity(
  contactId: string,
  identityKeyEcc: Uint8Array,
  username?: string,
): Promise<IncomingIdentityTrustResult> {
  const store = getKeyStore();
  const existing = await store.getContact(contactId);
  const incomingFingerprint = await fingerprintIdentityKeyEcc(identityKeyEcc);

  if (existing?.trustState === "changed") {
    return {
      trusted: false,
      state: "changed",
      reason:
        existing.trustWarning ??
        "Security warning: contact key set changed. Messaging is blocked until re-verified.",
    };
  }

  if (existing?.identityKeyEccFingerprint) {
    if (existing.identityKeyEccFingerprint !== incomingFingerprint) {
      const warning =
        "Security warning: incoming handshake identity key mismatch.";
      await markContactTrustChanged(contactId, warning, username);
      return {
        trusted: false,
        state: "changed",
        reason: warning,
      };
    }

    return {
      trusted: true,
      state: existing.trustState === "unverified" ? "unverified" : "trusted",
      reason: existing.trustWarning,
    };
  }

  const warning =
    "Trust-on-first-use: sender identity pinned from handshake only. Verify out-of-band before sharing sensitive data.";

  await store.storeContact({
    id: contactId,
    username: username ?? existing?.username ?? defaultUsername(contactId),
    status: existing?.status ?? "offline",
    identityKeyEccFingerprint: incomingFingerprint,
    identityKeyPqcFingerprint: existing?.identityKeyPqcFingerprint,
    signingKeyFingerprint: existing?.signingKeyFingerprint,
    trustState: "unverified",
    trustWarning: warning,
    trustUpdatedAt: Date.now(),
    lastSeen: existing?.lastSeen,
  });

  return {
    trusted: true,
    state: "unverified",
    reason: warning,
  };
}
