/**
 * User registration and authentication routes.
 *
 * SECURITY: Only handles public key registration.
 * No private keys ever touch the server.
 */

import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { randomUUID, timingSafeEqual } from "crypto";
import { z } from "zod";
import { store } from "../store/index.js";
import type { RegisterUserRequest, UserRecord } from "../types/index.js";

const signedPrekeySchema = z.object({
  id: z.number().int().nonnegative(),
  publicKey: z.string().min(1),
  signature: z.string().min(1),
  createdAt: z.number().int().nonnegative(),
});

const oneTimePrekeySchema = z.object({
  id: z.number().int().nonnegative(),
  publicKey: z.string().min(1),
});

const registerSchema = z.object({
  username: z.string().min(3).max(64),
  passwordHash: z.string().min(16),
  identityKeyEccPub: z.string().min(1),
  identityKeyPqcPub: z.string().min(1),
  signingKeyPub: z.string().min(1),
  signedPrekeyEcc: signedPrekeySchema,
  signedPrekeyPqc: signedPrekeySchema,
  oneTimePrekeyEcc: z.array(oneTimePrekeySchema).max(100).optional(),
});

const loginSchema = z.object({
  username: z.string().min(3).max(64),
  passwordHash: z.string().min(16),
});

type LoginAttemptState = {
  fails: number;
  windowStart: number;
  lockedUntil: number;
};

const LOGIN_MAX_ATTEMPTS = Math.max(
  1,
  Number.parseInt(process.env.LOGIN_MAX_ATTEMPTS ?? "5", 10) || 5
);
const LOGIN_WINDOW_MS = Math.max(
  1_000,
  Number.parseInt(process.env.LOGIN_WINDOW_MS ?? "60000", 10) || 60_000
);
const LOGIN_LOCK_MS = Math.max(
  1_000,
  Number.parseInt(process.env.LOGIN_LOCK_MS ?? "300000", 10) || 300_000
);

/** Maximum tracked throttle keys to prevent memory exhaustion DoS */
const MAX_TRACKED_KEYS = 50_000;

const loginAttempts = new Map<string, LoginAttemptState>();

// Periodic cleanup of stale throttle entries (every 5 minutes)
setInterval(() => {
  const now = Date.now();
  for (const [key, state] of loginAttempts) {
    // Remove entries that are well past their window AND no longer locked
    if (now - state.windowStart > LOGIN_WINDOW_MS * 2 && state.lockedUntil < now) {
      loginAttempts.delete(key);
    }
  }
}, 5 * 60 * 1000).unref();

function attemptKey(username: string, ip: string): string {
  return `${username.toLowerCase()}|${ip}`;
}

function getAttemptState(key: string, now: number): LoginAttemptState {
  const existing = loginAttempts.get(key);
  if (!existing) {
    // Evict oldest entry if at capacity
    if (loginAttempts.size >= MAX_TRACKED_KEYS) {
      const firstKey = loginAttempts.keys().next().value;
      if (firstKey !== undefined) loginAttempts.delete(firstKey);
    }
    const initial: LoginAttemptState = {
      fails: 0,
      windowStart: now,
      lockedUntil: 0,
    };
    loginAttempts.set(key, initial);
    return initial;
  }

  if (now - existing.windowStart > LOGIN_WINDOW_MS) {
    existing.fails = 0;
    existing.windowStart = now;
  }

  return existing;
}

function secureStringEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  // Pad shorter buffer to avoid length leak from timingSafeEqual throw
  if (left.length !== right.length) {
    const padded = Buffer.alloc(left.length);
    right.copy(padded, 0, 0, Math.min(right.length, left.length));
    timingSafeEqual(left, padded);
    return false;
  }
  return timingSafeEqual(left, right);
}

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
      reply: FastifyReply
    ) => {
      const parsed = registerSchema.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({
          error: "Invalid registration payload",
          details: parsed.error.issues,
        });
      }
      const body = parsed.data;

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

      // Generate JWT token
      const token = fastify.jwt.sign(
        { userId, username: body.username },
        { expiresIn: "7d" }
      );

      fastify.log.info({ userId, username: body.username }, "User registered");

      return reply.code(201).send({
        userId,
        username: body.username,
        token,
        createdAt: now,
      });
    }
  );

  /**
   * Login (verify credentials and return JWT).
   */
  fastify.post<{
    Body: { username: string; passwordHash: string };
  }>("/login", async (request, reply) => {
    const parsed = loginSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({
        error: "Invalid login payload",
        details: parsed.error.issues,
      });
    }

    const { username, passwordHash } = parsed.data;
    const now = Date.now();
    const key = attemptKey(username, request.ip ?? "unknown");
    const state = getAttemptState(key, now);

    if (state.lockedUntil > now) {
      return reply.code(429).send({
        error: "Too many login attempts. Please try again later.",
      });
    }

    const user = await store.getUserByUsername(username);
    if (!user) {
      state.fails += 1;
      if (state.fails >= LOGIN_MAX_ATTEMPTS) {
        state.lockedUntil = now + LOGIN_LOCK_MS;
      }
      return reply.code(401).send({ error: "Invalid credentials" });
    }

    if (!secureStringEqual(user.passwordHash, passwordHash)) {
      state.fails += 1;
      if (state.fails >= LOGIN_MAX_ATTEMPTS) {
        state.lockedUntil = now + LOGIN_LOCK_MS;
      }
      return reply.code(401).send({ error: "Invalid credentials" });
    }

    // Successful login: clear throttling state for this identity/IP.
    loginAttempts.delete(key);

    await store.updateLastSeen(user.id);

    // Generate JWT token
    const token = fastify.jwt.sign(
      { userId: user.id, username: user.username },
      { expiresIn: "7d" }
    );

    return {
      userId: user.id,
      username: user.username,
      token,
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
