/**
 * Secure Messaging Relay Server
 *
 * SECURITY: This is a ZERO-KNOWLEDGE relay server.
 * - Routes encrypted blobs without decryption capability
 * - Stores public keys only
 * - No access to private keys or session keys
 * - All stored data is encrypted end-to-end
 */

import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import fastifyWebSocket from "@fastify/websocket";
import fastifyCors from "@fastify/cors";
import fastifyJwt from "@fastify/jwt";
import fastifyRateLimit from "@fastify/rate-limit";
import { prekeyRoutes } from "./routes/prekeys.js";
import { userRoutes } from "./routes/users.js";
import { groupRoutes } from "./routes/groups.js";
import { messageHandler } from "./websocket/handler.js";

// JWT secret — use env var in production
const JWT_SECRET = process.env.JWT_SECRET ?? "dev-secret-change-in-production";
const isProduction = process.env.NODE_ENV === "production";
const corsOrigins = (process.env.CORS_ORIGINS ?? "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

if (isProduction && JWT_SECRET === "dev-secret-change-in-production") {
  throw new Error(
    "JWT_SECRET must be set in production; refusing to start with default secret",
  );
}

if (isProduction && corsOrigins.length === 0) {
  throw new Error("CORS_ORIGINS must be explicitly configured in production");
}

const server = Fastify({
  logger: {
    level: "info",
    // SECURITY: Redact sensitive fields from logs
    redact: ["req.headers.authorization", "req.body.password"],
  },
});

// Register plugins
await server.register(fastifyCors, {
  origin: corsOrigins.length > 0 ? corsOrigins : isProduction ? false : true,
  credentials: true,
});

await server.register(fastifyWebSocket, {
  options: {
    maxPayload: 1024 * 1024, // 1MB max message size
  },
});

// JWT plugin
await server.register(fastifyJwt, {
  secret: JWT_SECRET,
});

// Basic API rate limiting
await server.register(fastifyRateLimit, {
  global: true,
  max: 120,
  timeWindow: "1 minute",
});

// Reusable auth decorator
server.decorate(
  "authenticate",
  async function (request: FastifyRequest, reply: FastifyReply) {
  try {
    await request.jwtVerify();
  } catch (_err) {
    reply.code(401).send({ error: "Unauthorized" });
  }
  },
);

// Health check endpoint
server.get("/health", async () => {
  return { status: "ok", timestamp: Date.now() };
});

// API routes
server.register(userRoutes, { prefix: "/api/v1" });
server.register(prekeyRoutes, { prefix: "/api/v1" });
server.register(groupRoutes, { prefix: "/api/v1" });

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

export { server, JWT_SECRET };
