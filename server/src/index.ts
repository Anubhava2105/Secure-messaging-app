/**
 * Secure Messaging Relay Server
 *
 * SECURITY: This is a ZERO-KNOWLEDGE relay server.
 * - Routes encrypted blobs without decryption capability
 * - Stores public keys only
 * - No access to private keys or session keys
 * - All stored data is encrypted end-to-end
 */

import Fastify from "fastify";
import fastifyWebSocket from "@fastify/websocket";
import fastifyCors from "@fastify/cors";
import { prekeyRoutes } from "./routes/prekeys.js";
import { userRoutes } from "./routes/users.js";
import { messageHandler } from "./websocket/handler.js";

const server = Fastify({
  logger: {
    level: "info",
    // SECURITY: Redact sensitive fields from logs
    redact: ["req.headers.authorization", "req.body.password"],
  },
});

// Register plugins
await server.register(fastifyCors, {
  origin: true, // Configure appropriately for production
  credentials: true,
});

await server.register(fastifyWebSocket, {
  options: {
    maxPayload: 1024 * 1024, // 1MB max message size
  },
});

// Health check endpoint
server.get("/health", async () => {
  return { status: "ok", timestamp: Date.now() };
});

// API routes
server.register(userRoutes, { prefix: "/api/v1" });
server.register(prekeyRoutes, { prefix: "/api/v1" });

// WebSocket handler for real-time messaging
server.register(async function (fastify) {
  fastify.get("/ws", { websocket: true }, messageHandler);
});

// Start server
const start = async (): Promise<void> => {
  try {
    const port = parseInt(process.env.PORT ?? "3000", 10);
    const host = process.env.HOST ?? "0.0.0.0";

    await server.listen({ port, host });
    console.log(`Relay server listening on ${host}:${port}`);
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
};

start();

export { server };
