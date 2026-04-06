/**
 * Prekey bundle routes.
 *
 * SECURITY: Only handles public prekey distribution.
 * One-time prekeys are consumed atomically to prevent reuse.
 */

import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { z } from "zod";
import { store } from "../store/index.js";
import type { PreKeyBundleResponse, OneTimePreKeyDto } from "../types/index.js";

const userIdParamsSchema = z.object({
  userId: z.string().uuid(),
});

const prekeyUploadSchema = z.object({
  oneTimePrekeys: z
    .array(
      z.object({
        id: z.number().int().nonnegative(),
        publicKey: z.string().min(1),
      })
    )
    .min(1)
    .max(100),
});

export async function prekeyRoutes(fastify: FastifyInstance): Promise<void> {
  /**
   * Fetch a user's prekey bundle for initiating key exchange.
   *
   * SECURITY: Consumes one-time prekey atomically.
   * If no one-time prekeys available, bundle is returned without it.
   */
  fastify.get<{
    Params: { userId: string };
  }>(
    "/users/:userId/prekeys",
    async (
      request: FastifyRequest<{ Params: { userId: string } }>,
      reply: FastifyReply
    ) => {
      const parsedParams = userIdParamsSchema.safeParse(request.params);
      if (!parsedParams.success) {
        return reply.code(400).send({
          error: "Invalid userId",
          details: parsedParams.error.issues,
        });
      }
      const { userId } = parsedParams.data;

      const user = await store.getUserById(userId);
      if (!user) {
        return reply.code(404).send({ error: "User not found" });
      }

      // Atomically consume one-time prekey
      const oneTimePrekey = await store.consumeOneTimePrekey(userId);

      const bundle: PreKeyBundleResponse = {
        userId: user.id,
        identityKeyEccPub: user.identityKeyEccPub,
        identityKeyPqcPub: user.identityKeyPqcPub,
        signingKeyPub: user.signingKeyPub,
        signedPrekeyEcc: user.signedPrekeyEcc,
        signedPrekeyPqc: user.signedPrekeyPqc,
        oneTimePrekeyEcc: oneTimePrekey ?? undefined,
      };

      // Log prekey consumption (for monitoring prekey depletion)
      if (oneTimePrekey) {
        const remaining = await store.getOneTimePrekeyCount(userId);
        fastify.log.info(
          { userId, prekeyId: oneTimePrekey.id, remaining },
          "One-time prekey consumed"
        );

        // Warn if running low
        if (remaining < 10) {
          fastify.log.warn({ userId, remaining }, "Low one-time prekey count");
        }
      }

      return bundle;
    }
  );

  /**
   * Upload additional one-time prekeys.
   * Requires JWT authentication.
   */
  fastify.post<{
    Body: { oneTimePrekeys: OneTimePreKeyDto[] };
  }>(
    "/prekeys",
    { onRequest: [fastify.authenticate] },
    async (request, reply) => {
      const userId = request.user.userId;

      const parsed = prekeyUploadSchema.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({
          error: "Invalid prekey payload",
          details: parsed.error.issues,
        });
      }
      const { oneTimePrekeys } = parsed.data;

      await store.addOneTimePrekeys(userId, oneTimePrekeys);

      const count = await store.getOneTimePrekeyCount(userId);
      fastify.log.info(
        { userId, added: oneTimePrekeys.length, total: count },
        "Prekeys added"
      );

      return { added: oneTimePrekeys.length, total: count };
    }
  );

  /**
   * Get current prekey count.
   * Requires JWT authentication.
   */
  fastify.get(
    "/prekeys/count",
    { onRequest: [fastify.authenticate] },
    async (request, _reply) => {
      const userId = request.user.userId;

      const count = await store.getOneTimePrekeyCount(userId);
      return { count };
    }
  );
}
