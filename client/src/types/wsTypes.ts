/**
 * WebSocket protocol types for client-server communication.
 */

export type WsMessageType =
  | "send"
  | "ack"
  | "error"
  | "handshake"
  | "encrypted";

export interface WsOutgoingMessage {
  type: WsMessageType;
  messageId: string;
  recipientId: string;
  encryptedBlob?: string; // Base64
  handshakeData?: string; // Base64 serialized handshake message
  timestamp?: number;
}

export interface WsIncomingMessage {
  type: WsMessageType;
  messageId: string;
  senderId?: string;
  encryptedBlob?: string;
  handshakeData?: string;
  timestamp?: number;
  error?: string;
}
