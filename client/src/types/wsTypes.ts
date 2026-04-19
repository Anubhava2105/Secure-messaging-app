/**
 * WebSocket protocol types for client-server communication.
 */

export type WsMessageType =
  | "send"
  | "ack"
  | "error"
  | "handshake"
  | "encrypted"
  | "typing"
  | "read"
  | "delivered"
  | "presence";

export interface WsOutgoingMessage {
  type: WsMessageType;
  messageId: string;
  recipientId: string;
  groupId?: string;
  groupName?: string;
  groupMemberIds?: string[];
  groupEventType?: "group_message" | "group_membership";
  groupMembershipCommitment?: string;
  encryptedBlob?: string; // Base64
  handshakeData?: string; // Base64 serialized handshake message
  error?: string;
  /** Optional sender DH-ratchet public key (Base64 P-384 raw key) */
  ratchetKeyEcc?: string;
  /** Sender-chain message number used for out-of-order key recovery */
  messageNumber?: number;
  timestamp?: number;
}

export interface WsIncomingMessage {
  type: WsMessageType;
  messageId: string;
  senderId?: string;
  groupId?: string;
  groupName?: string;
  groupMemberIds?: string[];
  groupEventType?: "group_message" | "group_membership";
  groupMembershipCommitment?: string;
  encryptedBlob?: string;
  handshakeData?: string;
  /** Optional sender DH-ratchet public key (Base64 P-384 raw key) */
  ratchetKeyEcc?: string;
  /** Sender-chain message number */
  messageNumber?: number;
  timestamp?: number;
  error?: string;
  /** For presence: online/offline */
  status?: "online" | "offline";
}
