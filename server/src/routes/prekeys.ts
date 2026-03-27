/**
 * Prekey bundle routes.
 *
 * SECURITY: Only handles public prekey distribution.
 * One-time prekeys are consumed atomically to prevent reuse.
 */

import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { store } from "../store/index.js";
import type { PreKeyBundleResponse, OneTimePreKeyDto } from "../types/index.js";

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
      const { userId } = request.params;

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
   * Client should call this when prekey count is low.
   */
  fastify.post<{
    Body: { oneTimePrekeys: OneTimePreKeyDto[] };
  }>("/prekeys", async (request, reply) => {
    // TODO: Add authentication to get user ID from token
    const userId = "placeholder-user-id"; // Get from auth token

    const { oneTimePrekeys } = request.body;

    if (!oneTimePrekeys || !Array.isArray(oneTimePrekeys)) {
      return reply.code(400).send({ error: "oneTimePrekeys array required" });
    }

    if (oneTimePrekeys.length === 0) {
      return reply.code(400).send({ error: "At least one prekey required" });
    }

    if (oneTimePrekeys.length > 100) {
      return reply.code(400).send({ error: "Maximum 100 prekeys per request" });
    }

    await store.addOneTimePrekeys(userId, oneTimePrekeys);

    const count = await store.getOneTimePrekeyCount(userId);
    fastify.log.info(
      { userId, added: oneTimePrekeys.length, total: count },
      "Prekeys added"
    );

    return { added: oneTimePrekeys.length, total: count };
  });

  /**
   * Get current prekey count.
   * Client uses this to determine when to upload more.
   */
  fastify.get("/prekeys/count", async (_request, _reply) => {
    // TODO: Add authentication to get user ID from token
    const userId = "placeholder-user-id"; // Get from auth token

    const count = await store.getOneTimePrekeyCount(userId);
    return { count };
  });
}
