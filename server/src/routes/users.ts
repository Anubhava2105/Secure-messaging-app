/**
 * User registration and authentication routes.
 *
 * SECURITY: Only handles public key registration.
 * No private keys ever touch the server.
 */

import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { randomUUID } from "crypto";
import { store } from "../store/index.js";
import type { RegisterUserRequest, UserRecord } from "../types/index.js";

export async function userRoutes(fastify: FastifyInstance): Promise<void> {
  /**
   * Register a new user with their public keys.
   */
  fastify.post<{
    Body: RegisterUserRequest;
  }>(
    "/register",
    async (
      request: FastifyRequest<{ Body: RegisterUserRequest }>,
      reply: FastifyReply,
    ) => {
      const body = request.body;

      // Validate required fields
      if (!body.username || !body.passwordHash) {
        return reply
          .code(400)
          .send({ error: "Username and password hash required" });
      }

      if (
        !body.identityKeyEccPub ||
        !body.identityKeyPqcPub ||
        !body.signingKeyPub
      ) {
        return reply.code(400).send({ error: "Identity keys required" });
      }

      if (!body.signedPrekeyEcc || !body.signedPrekeyPqc) {
        return reply.code(400).send({ error: "Signed prekeys required" });
      }

      // Check username availability
      const existing = await store.getUserByUsername(body.username);
      if (existing) {
        return reply.code(409).send({ error: "Username already taken" });
      }

      // Create user record
      const userId = randomUUID();
      const now = Date.now();

      const user: UserRecord = {
        id: userId,
        username: body.username,
        passwordHash: body.passwordHash,
        identityKeyEccPub: body.identityKeyEccPub,
        identityKeyPqcPub: body.identityKeyPqcPub,
        signingKeyPub: body.signingKeyPub,
        signedPrekeyEcc: body.signedPrekeyEcc,
        signedPrekeyPqc: body.signedPrekeyPqc,
        oneTimePrekeyEcc: body.oneTimePrekeyEcc ?? [],
        createdAt: now,
        lastSeen: now,
      };

      await store.createUser(user);

      fastify.log.info({ userId, username: body.username }, "User registered");

      return reply.code(201).send({
        userId,
        username: body.username,
        createdAt: now,
      });
    },
  );

  /**
   * Login (verify credentials and return token).
   * Simple implementation - use proper auth (JWT, etc.) in production.
   */
  fastify.post<{
    Body: { username: string; passwordHash: string };
  }>("/login", async (request, reply) => {
    const { username, passwordHash } = request.body;

    const user = await store.getUserByUsername(username);
    if (!user) {
      return reply.code(401).send({ error: "Invalid credentials" });
    }

    // Constant-time comparison would be better here
    if (user.passwordHash !== passwordHash) {
      return reply.code(401).send({ error: "Invalid credentials" });
    }

    await store.updateLastSeen(user.id);

    // In production, generate a proper JWT here
    return {
      userId: user.id,
      username: user.username,
      token: `placeholder-token-${user.id}`, // Replace with JWT
    };
  });

  /**
   * Get user public info by username (for contact discovery).
   */
  fastify.get<{
    Params: { username: string };
  }>("/users/:username", async (request, reply) => {
    const user = await store.getUserByUsername(request.params.username);

    if (!user) {
      return reply.code(404).send({ error: "User not found" });
    }

    return {
      userId: user.id,
      username: user.username,
    };
  });

  /**
   * Get user public info by user ID.
   */
  fastify.get<{
    Params: { userId: string };
  }>("/users/id/:userId", async (request, reply) => {
    const user = await store.getUserById(request.params.userId);

    if (!user) {
      return reply.code(404).send({ error: "User not found" });
    }

    return {
      userId: user.id,
      username: user.username,
    };
  });
}
