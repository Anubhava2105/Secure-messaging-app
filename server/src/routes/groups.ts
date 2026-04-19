import { FastifyInstance } from "fastify";
import { z } from "zod";
import { store } from "../store/index.js";
import type { GroupRecord } from "../types/index.js";

const createGroupSchema = z.object({
  name: z.string().min(1).max(100),
  memberUserIds: z.array(z.string().min(1)).max(200),
});

const groupIdParamsSchema = z.object({
  groupId: z.string().min(1),
});

const addMemberSchema = z.object({
  userId: z.string().min(1),
});

const removeMemberParamsSchema = z.object({
  groupId: z.string().min(1),
  userId: z.string().min(1),
});

function toGroupResponse(group: {
  id: string;
  name: string;
  ownerId: string;
  memberUserIds: string[];
  createdAt: number;
  updatedAt: number;
  membershipCommitment: string;
}) {
  return {
    groupId: group.id,
    name: group.name,
    ownerId: group.ownerId,
    memberUserIds: group.memberUserIds,
    createdAt: group.createdAt,
    updatedAt: group.updatedAt,
    membershipCommitment: group.membershipCommitment,
  };
}

function sendValidationError(
  reply: {
    code: (statusCode: number) => {
      send: (payload: Record<string, unknown>) => unknown;
    };
  },
  error: string,
  details: unknown,
) {
  return reply.code(400).send({ error, details });
}

async function getAuthorizedGroup(
  groupId: string,
  actorId: string,
): Promise<{ group: GroupRecord } | { errorCode: 403 | 404; error: string }> {
  const group = await store.getGroupById(groupId);
  if (!group) {
    return { errorCode: 404, error: "Group not found" };
  }

  const actorIsMember = await store.isGroupMember(group.id, actorId);
  if (!actorIsMember) {
    return { errorCode: 403, error: "Forbidden" };
  }

  return { group };
}

export async function groupRoutes(fastify: FastifyInstance): Promise<void> {
  fastify.get(
    "/groups",
    { onRequest: [fastify.authenticate] },
    async (request, reply) => {
      const groups = await store.getGroupsForUser(request.user.userId);
      return reply.code(200).send({
        groups: groups.map(toGroupResponse),
      });
    },
  );

  fastify.get<{
    Params: { groupId: string };
  }>(
    "/groups/:groupId",
    { onRequest: [fastify.authenticate] },
    async (request, reply) => {
      const parsed = groupIdParamsSchema.safeParse(request.params);
      if (!parsed.success) {
        return sendValidationError(
          reply,
          "Invalid group ID",
          parsed.error.issues,
        );
      }

      const authorized = await getAuthorizedGroup(
        parsed.data.groupId,
        request.user.userId,
      );
      if ("errorCode" in authorized) {
        return reply
          .code(authorized.errorCode)
          .send({ error: authorized.error });
      }

      return reply.code(200).send(toGroupResponse(authorized.group));
    },
  );

  fastify.post<{
    Body: { name: string; memberUserIds: string[] };
  }>(
    "/groups",
    { onRequest: [fastify.authenticate] },
    async (request, reply) => {
      const parsed = createGroupSchema.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({
          error: "Invalid group payload",
          details: parsed.error.issues,
        });
      }

      const ownerId = request.user.userId;
      const normalizedMemberIds = Array.from(
        new Set(
          parsed.data.memberUserIds
            .map((id) => id.trim())
            .filter(Boolean)
            .filter((id) => id !== ownerId),
        ),
      );

      if (normalizedMemberIds.length < 1) {
        return reply.code(400).send({
          error: "Group must include at least one other member",
        });
      }

      try {
        const created = await store.createGroup(
          ownerId,
          parsed.data.name.trim(),
          normalizedMemberIds,
        );
        return reply.code(201).send(toGroupResponse(created));
      } catch (error) {
        const message = (error as Error).message;
        if (message.includes("do not exist")) {
          return reply.code(404).send({ error: message });
        }
        if (message.includes("at least 2 members")) {
          return reply.code(400).send({ error: message });
        }
        return reply.code(500).send({ error: "Failed to create group" });
      }
    },
  );

  fastify.post<{
    Params: { groupId: string };
    Body: { userId: string };
  }>(
    "/groups/:groupId/members",
    { onRequest: [fastify.authenticate] },
    async (request, reply) => {
      const parsedParams = groupIdParamsSchema.safeParse(request.params);
      if (!parsedParams.success) {
        return sendValidationError(
          reply,
          "Invalid group ID",
          parsedParams.error.issues,
        );
      }

      const parsedBody = addMemberSchema.safeParse(request.body);
      if (!parsedBody.success) {
        return sendValidationError(
          reply,
          "Invalid member payload",
          parsedBody.error.issues,
        );
      }

      const actorId = request.user.userId;
      const authorized = await getAuthorizedGroup(
        parsedParams.data.groupId,
        actorId,
      );
      if ("errorCode" in authorized) {
        return reply
          .code(authorized.errorCode)
          .send({ error: authorized.error });
      }
      const group = authorized.group;

      if (group.ownerId !== actorId) {
        return reply
          .code(403)
          .send({ error: "Only group owner can add members" });
      }

      const targetUserId = parsedBody.data.userId;
      if (group.memberUserIds.includes(targetUserId)) {
        return reply.code(200).send(toGroupResponse(group));
      }

      try {
        const updated = await store.addGroupMember(group.id, targetUserId);
        return reply.code(200).send(toGroupResponse(updated));
      } catch (error) {
        const message = (error as Error).message;
        if (message.includes("User not found")) {
          return reply.code(404).send({ error: message });
        }
        return reply.code(500).send({ error: "Failed to add group member" });
      }
    },
  );

  fastify.delete<{
    Params: { groupId: string; userId: string };
  }>(
    "/groups/:groupId/members/:userId",
    { onRequest: [fastify.authenticate] },
    async (request, reply) => {
      const parsed = removeMemberParamsSchema.safeParse(request.params);
      if (!parsed.success) {
        return sendValidationError(
          reply,
          "Invalid remove member params",
          parsed.error.issues,
        );
      }

      const { groupId, userId } = parsed.data;
      const actorId = request.user.userId;
      const authorized = await getAuthorizedGroup(groupId, actorId);
      if ("errorCode" in authorized) {
        return reply
          .code(authorized.errorCode)
          .send({ error: authorized.error });
      }
      const group = authorized.group;

      if (!group.memberUserIds.includes(userId)) {
        return reply.code(200).send(toGroupResponse(group));
      }

      if (group.ownerId === userId && actorId !== userId) {
        return reply.code(400).send({ error: "Cannot remove group owner" });
      }

      if (actorId !== group.ownerId && actorId !== userId) {
        return reply.code(403).send({ error: "Only owner can remove others" });
      }

      if (group.ownerId === userId && actorId === userId) {
        try {
          const updated = await store.transferGroupOwnershipAndRemoveMember(
            group.id,
            userId,
          );
          return reply.code(200).send(toGroupResponse(updated));
        } catch (error) {
          const message = (error as Error).message;
          if (message.includes("drop below two members")) {
            return reply.code(400).send({
              error:
                "Owner cannot leave a 2-member group. Add another member first.",
            });
          }

          return reply.code(500).send({
            error: "Failed to transfer ownership and leave group",
          });
        }
      }

      if (group.memberUserIds.length <= 2) {
        return reply.code(400).send({
          error: "Group must retain at least 2 members",
        });
      }

      try {
        const updated = await store.removeGroupMember(group.id, userId);
        return reply.code(200).send(toGroupResponse(updated));
      } catch {
        return reply.code(500).send({ error: "Failed to remove group member" });
      }
    },
  );
}
