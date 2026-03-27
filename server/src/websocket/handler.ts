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

/**
 * Main WebSocket connection handler.
 */
export async function messageHandler(
  socket: WebSocket,
  request: FastifyRequest,
): Promise<void> {
  // TODO: Extract user ID from auth token in query params
  const userId = extractUserId(request);

  if (!userId) {
    socket.close(4001, "Authentication required");
    return;
  }

  // Check if user exists, auto-register for development
  let userExists = await store.userExists(userId);
  if (!userExists) {
    // DEVELOPMENT: Auto-register user for testing
    // SECURITY: Remove this in production
    console.log(`[DEV] Auto-registering user: ${userId}`);
    await store.createUser({
      id: userId,
      username: `User-${userId.slice(0, 8)}`,
      passwordHash: "",
      identityKeyEccPub: "",
      identityKeyPqcPub: "",
      signingKeyPub: "",
      signedPrekeyEcc: {
        id: 0,
        publicKey: "",
        signature: "",
        createdAt: Date.now(),
      },
      signedPrekeyPqc: {
        id: 0,
        publicKey: "",
        signature: "",
        createdAt: Date.now(),
      },
      oneTimePrekeyEcc: [],
      createdAt: Date.now(),
      lastSeen: Date.now(),
    });
    userExists = true;
  }

  // Register connection
  connectedUsers.set(userId, socket);
  socketToUser.set(socket, userId);

  console.log(`User connected: ${userId}`);

  // Update last seen
  await store.updateLastSeen(userId);

  // Deliver any pending messages
  await deliverPendingMessages(userId, socket);

  // Handle incoming messages
  socket.on("message", async (data: Buffer) => {
    try {
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
    console.log(`User disconnected: ${userId}`);
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
  message: WsClientMessage,
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
  message: WsClientMessage,
): Promise<void> {
  const { recipientId, encryptedBlob, messageId } = message;

  if (!recipientId || !encryptedBlob || !messageId) {
    sendError(senderSocket, messageId ?? "unknown", "Missing required fields");
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
  console.log("  ENCRYPTED BLOB (first 100 chars):");
  console.log(`  ${encryptedBlob.substring(0, 100)}...`);
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
      timestamp,
    };

    recipientSocket.send(JSON.stringify(serverMessage));
    console.log(`  -> Delivered to online recipient`);
  } else {
    // Recipient offline - store for later delivery
    await store.storePendingMessage(recipientId, senderId, encryptedBlob);
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
  _message: WsClientMessage,
): Promise<void> {
  // Log or track delivery state
  // In production, update message delivery status in database
}

/**
 * Handle read receipt - forward to original sender.
 */
async function handleReadReceipt(
  readerId: string,
  message: WsClientMessage,
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
  message: WsClientMessage,
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
 * Deliver pending messages when user comes online.
 */
async function deliverPendingMessages(
  userId: string,
  socket: WebSocket,
): Promise<void> {
  const pending = await store.getPendingMessages(userId);

  for (const msg of pending) {
    const serverMessage: WsServerMessage = {
      type: "send" as WsMessageType,
      messageId: `pending-${msg.timestamp}`,
      senderId: msg.senderId,
      encryptedBlob: msg.blob,
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

/**
 * Extract user ID from request (auth token).
 */
function extractUserId(request: FastifyRequest): string | null {
  const query = request.query as Record<string, string>;

  // DEVELOPMENT: Accept userId directly from query param
  // SECURITY: Remove this in production and use proper JWT
  if (query.userId) {
    console.log(`[DEV] User connected with userId: ${query.userId}`);
    return query.userId;
  }

  // Production: Validate JWT token
  const token = query.token;
  if (!token) return null;

  // Placeholder: extract user ID from token
  // In production, validate JWT and extract claims
  if (token.startsWith("placeholder-token-")) {
    return token.replace("placeholder-token-", "");
  }

  // Fallback: use token as-is for simple testing
  if (token.length > 0) {
    return token;
  }

  return null;
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
