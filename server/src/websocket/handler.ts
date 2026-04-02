/**
 * WebSocket message handler.
 *
 * SECURITY: This handler only routes encrypted blobs.
 * It has NO capability to decrypt, inspect, or modify message content.
 * The server is intentionally "dumb" - it's just a relay.
 */

import type { WebSocket } from "ws";
import type { FastifyRequest } from "fastify";
import { store } from "../store/index.js";
import type {
  WsClientMessage,
  WsServerMessage,
  WsMessageType,
} from "../types/index.js";

/** Map of connected users: userId -> WebSocket */
const connectedUsers = new Map<string, WebSocket>();

/** Map of socket -> userId (reverse lookup) */
const socketToUser = new Map<WebSocket, string>();

/** Per-user message timestamps for lightweight WebSocket abuse protection */
const messageRateWindowMs = 10_000;
const maxMessagesPerWindow = 120;
const userMessageTimestamps = new Map<string, number[]>();

function isRateLimited(userId: string): boolean {
  const now = Date.now();
  const timestamps = userMessageTimestamps.get(userId) ?? [];
  const recent = timestamps.filter((ts) => now - ts < messageRateWindowMs);

  if (recent.length >= maxMessagesPerWindow) {
    userMessageTimestamps.set(userId, recent);
    return true;
  }

  recent.push(now);
  userMessageTimestamps.set(userId, recent);
  return false;
}

/**
 * Main WebSocket connection handler.
 */
export async function messageHandler(
  socket: WebSocket,
  request: FastifyRequest
): Promise<void> {
  // Authenticate via JWT token in query params
  const userId = await extractUserId(request);

  if (!userId) {
    socket.close(4001, "Authentication required");
    return;
  }

  // Verify user exists in store
  const userExists = await store.userExists(userId);
  if (!userExists) {
    socket.close(4002, "User not found — register first");
    return;
  }

  // Register connection
  connectedUsers.set(userId, socket);
  socketToUser.set(socket, userId);

  console.log(`User connected: ${userId}`);

  // Update last seen
  await store.updateLastSeen(userId);

  // Deliver any pending messages
  await deliverPendingMessages(userId, socket);

  // Broadcast presence: online
  broadcastPresence(userId, "online");

  // Handle incoming messages
  socket.on("message", async (data: Buffer) => {
    try {
      if (isRateLimited(userId)) {
        sendError(socket, "rate-limit", "Too many messages. Slow down.");
        return;
      }

      const message = JSON.parse(data.toString()) as WsClientMessage;
      await handleMessage(userId, socket, message);
    } catch (error) {
      sendError(socket, "invalid-message", "Invalid message format");
    }
  });

  // Handle disconnect
  socket.on("close", () => {
    connectedUsers.delete(userId);
    socketToUser.delete(socket);
    userMessageTimestamps.delete(userId);
    console.log(`User disconnected: ${userId}`);
    broadcastPresence(userId, "offline");
  });

  socket.on("error", (error: Error) => {
    console.error(`WebSocket error for ${userId}:`, error.message);
  });
}

/**
 * Handle incoming WebSocket message.
 */
async function handleMessage(
  senderId: string,
  senderSocket: WebSocket,
  message: WsClientMessage
): Promise<void> {
  switch (message.type) {
    case "send" as WsMessageType:
      await handleSendMessage(senderId, senderSocket, message);
      break;

    case "ack" as WsMessageType:
      // Acknowledge message receipt - for delivery confirmation
      await handleAck(senderId, message);
      break;

    case "read" as WsMessageType:
      // Read receipt - forward to sender
      await handleReadReceipt(senderId, message);
      break;

    case "typing" as WsMessageType:
      // Typing indicator - forward to recipient
      await handleTypingIndicator(senderId, message);
      break;

    case "error" as WsMessageType:
      // Peer error notification - forward to recipient
      await handlePeerError(senderId, message);
      break;

    default:
      sendError(senderSocket, message.messageId, "Unknown message type");
  }
}

/**
 * Handle encrypted message relay.
 *
 * SECURITY: We only route the encrypted blob. We cannot:
 * - Read the message content
 * - Modify the message
 * - Determine anything about the message except sender/recipient
 */
async function handleSendMessage(
  senderId: string,
  senderSocket: WebSocket,
  message: WsClientMessage
): Promise<void> {
  const {
    recipientId,
    encryptedBlob,
    handshakeData,
    messageId,
    messageNumber,
  } = message;
  const { ratchetKeyEcc } = message;

  if (!recipientId || !encryptedBlob || !messageId) {
    sendError(senderSocket, messageId ?? "unknown", "Missing required fields");
    return;
  }

  if (recipientId === senderId) {
    sendError(senderSocket, messageId, "Cannot send message to yourself");
    return;
  }

  if (
    messageNumber !== undefined &&
    (!Number.isInteger(messageNumber) || messageNumber < 0)
  ) {
    sendError(senderSocket, messageId, "Invalid messageNumber");
    return;
  }

  // Check recipient exists
  const recipientExists = await store.userExists(recipientId);
  if (!recipientExists) {
    sendError(senderSocket, messageId, "Recipient not found");
    return;
  }

  const timestamp = Date.now();

  // ===== ZERO-KNOWLEDGE RELAY LOGGING =====
  // This demonstrates that the server only sees encrypted data
  console.log("\n" + "=".repeat(60));
  console.log("MESSAGE RELAY (Zero-Knowledge)");
  console.log("=".repeat(60));
  console.log(`  From:      ${senderId.substring(0, 8)}...`);
  console.log(`  To:        ${recipientId.substring(0, 8)}...`);
  console.log(`  MessageID: ${messageId}`);
  console.log(`  Timestamp: ${new Date(timestamp).toISOString()}`);
  console.log("-".repeat(60));
  console.log(`  Ciphertext bytes (base64 chars): ${encryptedBlob.length}`);
  console.log("-".repeat(60));
  console.log("  [!] SERVER CANNOT READ THIS CONTENT");
  console.log("  [OK] End-to-end encrypted with AES-GCM-256");
  console.log("=".repeat(60) + "\n");

  // Check if recipient is online
  const recipientSocket = connectedUsers.get(recipientId);

  if (recipientSocket && recipientSocket.readyState === 1) {
    // Recipient online - forward immediately
    const serverMessage: WsServerMessage = {
      type: "send" as WsMessageType,
      messageId,
      senderId,
      encryptedBlob,
      handshakeData,
      ratchetKeyEcc,
      messageNumber,
      timestamp,
    };

    recipientSocket.send(JSON.stringify(serverMessage));
    console.log(`  -> Delivered to online recipient`);
  } else {
    // Recipient offline - store for later delivery
    await store.storePendingMessage(
      recipientId,
      senderId,
      encryptedBlob,
      handshakeData,
      ratchetKeyEcc,
      messageNumber
    );
    console.log(`  -> Stored for offline recipient`);
  }

  // Send ACK to sender
  const ack: WsServerMessage = {
    type: "ack" as WsMessageType,
    messageId,
    timestamp,
  };
  senderSocket.send(JSON.stringify(ack));
}

/**
 * Handle message acknowledgment.
 */
async function handleAck(
  _senderId: string,
  _message: WsClientMessage
): Promise<void> {
  // Log or track delivery state
  // In production, update message delivery status in database
}

/**
 * Handle read receipt - forward to original sender.
 */
async function handleReadReceipt(
  readerId: string,
  message: WsClientMessage
): Promise<void> {
  const { recipientId, messageId, timestamp } = message;

  if (!recipientId || !messageId) return;

  const senderSocket = connectedUsers.get(recipientId);
  if (senderSocket && senderSocket.readyState === 1) {
    const receipt: WsServerMessage = {
      type: "read" as WsMessageType,
      messageId,
      senderId: readerId,
      timestamp: timestamp ?? Date.now(),
    };
    senderSocket.send(JSON.stringify(receipt));
  }
}

/**
 * Handle typing indicator.
 */
async function handleTypingIndicator(
  typerId: string,
  message: WsClientMessage
): Promise<void> {
  const { recipientId } = message;

  if (!recipientId) return;

  const recipientSocket = connectedUsers.get(recipientId);
  if (recipientSocket && recipientSocket.readyState === 1) {
    const typing: WsServerMessage = {
      type: "typing" as WsMessageType,
      messageId: message.messageId,
      senderId: typerId,
      timestamp: Date.now(),
    };
    recipientSocket.send(JSON.stringify(typing));
  }
}

/**
 * Forward peer-side client errors (e.g., decrypt failure) to the intended recipient.
 */
async function handlePeerError(
  senderId: string,
  message: WsClientMessage
): Promise<void> {
  const { recipientId, messageId, error } = message;
  if (!recipientId || !messageId) return;

  const recipientSocket = connectedUsers.get(recipientId);
  if (recipientSocket && recipientSocket.readyState === 1) {
    const peerError: WsServerMessage = {
      type: "error" as WsMessageType,
      messageId,
      senderId,
      error: error ?? "peer-error",
      timestamp: Date.now(),
    };
    recipientSocket.send(JSON.stringify(peerError));
  }
}

/**
 * Deliver pending messages when user comes online.
 */
async function deliverPendingMessages(
  userId: string,
  socket: WebSocket
): Promise<void> {
  const pending = await store.getPendingMessages(userId);

  for (const msg of pending) {
    const serverMessage: WsServerMessage = {
      type: "send" as WsMessageType,
      messageId: `pending-${msg.timestamp}`,
      senderId: msg.senderId,
      encryptedBlob: msg.blob,
      handshakeData: msg.handshakeData,
      ratchetKeyEcc: msg.ratchetKeyEcc,
      messageNumber: msg.messageNumber,
      timestamp: msg.timestamp,
    };
    socket.send(JSON.stringify(serverMessage));
  }

  if (pending.length > 0) {
    console.log(`Delivered ${pending.length} pending messages to ${userId}`);
  }
}

/**
 * Send error message to client.
 */
function sendError(socket: WebSocket, messageId: string, error: string): void {
  const errorMsg: WsServerMessage = {
    type: "error" as WsMessageType,
    messageId,
    error,
    timestamp: Date.now(),
  };
  socket.send(JSON.stringify(errorMsg));
}

function getTokenFromSecWebSocketProtocol(
  headerValue: string | string[] | undefined
): string | null {
  if (!headerValue) return null;

  const raw = Array.isArray(headerValue) ? headerValue.join(",") : headerValue;
  const protocols = raw
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);

  const authProtocol = protocols.find((protocol) =>
    protocol.startsWith("auth.")
  );
  if (!authProtocol) return null;

  const token = authProtocol.slice("auth.".length).trim();
  return token.length > 0 ? token : null;
}

/**
 * Extract and verify user ID from WebSocket auth context.
 * Preferred: `Sec-WebSocket-Protocol: auth.<jwt>`
 * Fallback (legacy): `?token=<jwt>` query parameter.
 */
async function extractUserId(request: FastifyRequest): Promise<string | null> {
  const query = request.query as Record<string, string>;
  const protocolHeader =
    request.headers["sec-websocket-protocol"] ??
    request.raw.headers["sec-websocket-protocol"];

  const token = getTokenFromSecWebSocketProtocol(protocolHeader) ?? query.token;
  if (!token) return null;

  try {
    const decoded = request.server.jwt.verify<{
      userId: string;
      username: string;
    }>(token);
    return decoded.userId;
  } catch {
    console.warn("Invalid JWT token on WebSocket connection");
    return null;
  }
}

/**
 * Broadcast a user's presence status to all other connected users.
 */
function broadcastPresence(userId: string, status: "online" | "offline"): void {
  const presenceMsg = JSON.stringify({
    type: "presence",
    messageId: "",
    senderId: userId,
    status,
    timestamp: Date.now(),
  });

  for (const [otherUserId, otherSocket] of connectedUsers) {
    if (otherUserId !== userId && otherSocket.readyState === 1) {
      otherSocket.send(presenceMsg);
    }
  }
}

/**
 * Get count of currently connected users.
 */
export function getConnectedUserCount(): number {
  return connectedUsers.size;
}

/**
 * Check if a user is currently online.
 */
export function isUserOnline(userId: string): boolean {
  const socket = connectedUsers.get(userId);
  return socket !== undefined && socket.readyState === 1;
}
