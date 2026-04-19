/**
 * Type definitions for the relay server.
 * All types represent encrypted/public data only.
 */

/** User registration request */
export interface RegisterUserRequest {
  username: string;
  /** User password (hashed server-side with per-user salt) */
  password: string;
  /** ECC identity public key (Base64, 97 bytes) */
  identityKeyEccPub: string;
  /** PQC identity public key (Base64, 1184 bytes) */
  identityKeyPqcPub: string;
  /** Signing public key (Base64, 97 bytes) */
  signingKeyPub: string;
  /** Signed ECC prekey */
  signedPrekeyEcc: SignedPreKeyDto;
  /** Signed PQC prekey */
  signedPrekeyPqc: SignedPreKeyDto;
  /** One-time ECC prekeys (initial batch) */
  oneTimePrekeyEcc: OneTimePreKeyDto[];
}

/** Signed prekey data transfer object */
export interface SignedPreKeyDto {
  id: number;
  /** Base64 public key */
  publicKey: string;
  /** Base64 signature */
  signature: string;
  /** Creation timestamp */
  createdAt: number;
}

/** One-time prekey data transfer object */
export interface OneTimePreKeyDto {
  id: number;
  /** Base64 public key */
  publicKey: string;
}

/** Prekey bundle response */
export interface PreKeyBundleResponse {
  /** User ID */
  userId: string;
  /** ECC identity public key (Base64) */
  identityKeyEccPub: string;
  /** PQC identity public key (Base64) */
  identityKeyPqcPub: string;
  /** Signing public key (Base64) */
  signingKeyPub: string;
  /** Current signed ECC prekey */
  signedPrekeyEcc: SignedPreKeyDto;
  /** Current signed PQC prekey */
  signedPrekeyPqc: SignedPreKeyDto;
  /** One-time ECC prekey (optional, consumed after fetch) */
  oneTimePrekeyEcc?: OneTimePreKeyDto;
}

/** User record in storage */
export interface UserRecord {
  id: string;
  username: string;
  passwordSalt: string;
  passwordHash: string;
  identityKeyEccPub: string;
  identityKeyPqcPub: string;
  signingKeyPub: string;
  signedPrekeyEcc: SignedPreKeyDto;
  signedPrekeyPqc: SignedPreKeyDto;
  oneTimePrekeyEcc: OneTimePreKeyDto[];
  createdAt: number;
  lastSeen: number;
}

/** Group record in storage */
export interface GroupRecord {
  id: string;
  name: string;
  ownerId: string;
  memberUserIds: string[];
  createdAt: number;
  updatedAt: number;
  membershipCommitment: string;
}

export type GroupEventType = "group_message" | "group_membership";

/** WebSocket message types */
export enum WsMessageType {
  SEND = "send",
  ACK = "ack",
  DELIVERED = "delivered",
  READ = "read",
  TYPING = "typing",
  PRESENCE = "presence",
  ERROR = "error",
}

/** Client to server WebSocket message */
export interface WsClientMessage {
  type: WsMessageType;
  messageId: string;
  recipientId?: string;
  /** Group conversation ID for fan-out group messages */
  groupId?: string;
  /** Optional display name for group conversation */
  groupName?: string;
  /** Optional participant user IDs for group membership hydration */
  groupMemberIds?: string[];
  /** Optional group event category for server-side canonicalization */
  groupEventType?: GroupEventType;
  /** Optional membership commitment pinned by sender at encryption time */
  groupMembershipCommitment?: string;
  /** Base64 encoded encrypted blob */
  encryptedBlob?: string;
  /** Optional serialized handshake payload for first-message session establishment */
  handshakeData?: string;
  /** Optional error payload for peer notifications */
  error?: string;
  /** Optional sender DH-ratchet public key (Base64 P-384 raw key) */
  ratchetKeyEcc?: string;
  /** Optional sender-chain message number */
  messageNumber?: number;
  /** Optional timestamp for read receipts */
  timestamp?: number;
}

/** Server to client WebSocket message */
export interface WsServerMessage {
  type: WsMessageType;
  messageId: string;
  senderId?: string;
  /** Group conversation ID for fan-out group messages */
  groupId?: string;
  /** Optional display name for group conversation */
  groupName?: string;
  /** Optional participant user IDs for group membership hydration */
  groupMemberIds?: string[];
  /** Canonical group event category assigned by relay */
  groupEventType?: GroupEventType;
  /** Canonical membership commitment assigned by relay */
  groupMembershipCommitment?: string;
  /** Base64 encoded encrypted blob */
  encryptedBlob?: string;
  /** Optional serialized handshake payload */
  handshakeData?: string;
  /** Optional sender DH-ratchet public key (Base64 P-384 raw key) */
  ratchetKeyEcc?: string;
  /** Optional sender-chain message number */
  messageNumber?: number;
  timestamp: number;
  error?: string;
}

/** Connected socket info */
export interface ConnectedUser {
  userId: string;
  /** WebSocket instance reference */
  socket: unknown;
  connectedAt: number;
}
