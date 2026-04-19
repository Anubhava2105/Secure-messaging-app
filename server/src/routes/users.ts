/**
 * User registration and authentication routes.
 *
 * SECURITY: Only handles public key registration.
 * No private keys ever touch the server.
 */

import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { randomUUID, randomBytes, scryptSync, timingSafeEqual } from "crypto";
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
  password: z.string().min(8).max(256),
  identityKeyEccPub: z.string().min(1),
  identityKeyPqcPub: z.string().min(1),
  signingKeyPub: z.string().min(1),
  signedPrekeyEcc: signedPrekeySchema,
  signedPrekeyPqc: signedPrekeySchema,
  oneTimePrekeyEcc: z.array(oneTimePrekeySchema).max(100).optional(),
});

const loginSchema = z.object({
  username: z.string().min(3).max(64),
  password: z.string().min(8).max(256),
});

type LoginAttemptState = {
  fails: number;
  windowStart: number;
  lockedUntil: number;
};

const LOGIN_MAX_ATTEMPTS = Math.max(
  1,
  Number.parseInt(process.env.LOGIN_MAX_ATTEMPTS ?? "5", 10) || 5,
);
const LOGIN_WINDOW_MS = Math.max(
  1_000,
  Number.parseInt(process.env.LOGIN_WINDOW_MS ?? "60000", 10) || 60_000,
);
const LOGIN_LOCK_MS = Math.max(
  1_000,
  Number.parseInt(process.env.LOGIN_LOCK_MS ?? "300000", 10) || 300_000,
);
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN ?? "12h";

const loginAttempts = new Map<string, LoginAttemptState>();

function attemptKey(username: string, ip: string): string {
  return `${username.toLowerCase()}|${ip}`;
}

function getAttemptState(key: string, now: number): LoginAttemptState {
  const existing = loginAttempts.get(key);
  if (!existing) {
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
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

function hashPassword(password: string): { salt: string; hash: string } {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 64);
  return {
    salt: salt.toString("base64"),
    hash: hash.toString("base64"),
  };
}

function verifyPassword(user: UserRecord, password: string): boolean {
  if (!user.passwordSalt) {
    // Legacy fallback: older records may only have passwordHash.
    return secureStringEqual(user.passwordHash, password);
  }

  try {
    const salt = Buffer.from(user.passwordSalt, "base64");
    const expected = Buffer.from(user.passwordHash, "base64");
    const actual = scryptSync(password, salt, 64);

    if (expected.length !== actual.length) return false;
    return timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
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
      reply: FastifyReply,
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
      const passwordRecord = hashPassword(body.password);

      const user: UserRecord = {
        id: userId,
        username: body.username,
        passwordSalt: passwordRecord.salt,
        passwordHash: passwordRecord.hash,
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
        { expiresIn: JWT_EXPIRES_IN },
      );

      fastify.log.info({ userId, username: body.username }, "User registered");

      return reply.code(201).send({
        userId,
        username: body.username,
        token,
        createdAt: now,
      });
    },
  );

  /**
   * Login (verify credentials and return JWT).
   */
  fastify.post<{
    Body: { username: string; password: string };
  }>("/login", async (request, reply) => {
    const parsed = loginSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({
        error: "Invalid login payload",
        details: parsed.error.issues,
      });
    }

    const { username, password } = parsed.data;
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

    if (!verifyPassword(user, password)) {
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
      { expiresIn: JWT_EXPIRES_IN },
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
