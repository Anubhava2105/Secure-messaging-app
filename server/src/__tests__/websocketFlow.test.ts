import { spawn, ChildProcessWithoutNullStreams } from "child_process";
import path from "path";
import { WebSocket } from "ws";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { getAvailablePort } from "./helpers/port.js";

let TEST_PORT = 0;
let TEST_DB_PATH = "";

function baseUrl(): string {
  return `http://127.0.0.1:${TEST_PORT}`;
}

function wsUrl(): string {
  return `ws://127.0.0.1:${TEST_PORT}/ws`;
}

let serverProcess: ChildProcessWithoutNullStreams | null = null;

async function waitForHealth(timeoutMs = 15000): Promise<void> {
  const started = Date.now();

  while (Date.now() - started < timeoutMs) {
    try {
      const res = await fetch(`${baseUrl()}/health`);
      if (res.ok) return;
    } catch {
      // ignore until timeout
    }
    await new Promise((r) => setTimeout(r, 200));
  }

  throw new Error("Server health endpoint did not become ready in time");
}

async function waitForOpen(ws: WebSocket, timeoutMs = 5000): Promise<void> {
  if (ws.readyState === ws.OPEN) return;

  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error("WebSocket open timeout"));
    }, timeoutMs);

    const onOpen = () => {
      cleanup();
      resolve();
    };

    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };

    const cleanup = () => {
      clearTimeout(timeout);
      ws.off("open", onOpen);
      ws.off("error", onError);
    };

    ws.on("open", onOpen);
    ws.on("error", onError);
  });
}

async function waitForClose(ws: WebSocket, timeoutMs = 5000): Promise<void> {
  if (ws.readyState === ws.CLOSED) return;

  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error("WebSocket close timeout"));
    }, timeoutMs);

    const onClose = () => {
      cleanup();
      resolve();
    };

    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };

    const cleanup = () => {
      clearTimeout(timeout);
      ws.off("close", onClose);
      ws.off("error", onError);
    };

    ws.on("close", onClose);
    ws.on("error", onError);
  });
}

async function waitForMessage<T extends Record<string, unknown>>(
  ws: WebSocket,
  predicate: (msg: T) => boolean,
  timeoutMs = 5000,
  label = "unnamed",
): Promise<T> {
  return await new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error(`Timed out waiting for WebSocket message: ${label}`));
    }, timeoutMs);

    const onMessage = (raw: Buffer) => {
      try {
        const parsed = JSON.parse(raw.toString()) as T;
        if (!predicate(parsed)) return;
        cleanup();
        resolve(parsed);
      } catch {
        // ignore malformed/unexpected frames in test wait
      }
    };

    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };

    const cleanup = () => {
      clearTimeout(timeout);
      ws.off("message", onMessage);
      ws.off("error", onError);
    };

    ws.on("message", onMessage);
    ws.on("error", onError);
  });
}

async function waitForNoMatchingMessage<T extends Record<string, unknown>>(
  ws: WebSocket,
  predicate: (msg: T) => boolean,
  timeoutMs = 1000,
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      resolve();
    }, timeoutMs);

    const onMessage = (raw: Buffer) => {
      try {
        const parsed = JSON.parse(raw.toString()) as T;
        if (!predicate(parsed)) {
          return;
        }

        cleanup();
        reject(new Error("Received unexpected matching message"));
      } catch {
        // Ignore non-json frames for this assertion window.
      }
    };

    const cleanup = () => {
      clearTimeout(timeout);
      ws.off("message", onMessage);
    };

    ws.on("message", onMessage);
  });
}

async function registerAndLogin(username: string): Promise<{
  userId: string;
  token: string;
}> {
  const registerPayload = {
    username,
    password: "correct-horse-battery-staple",
    identityKeyEccPub: `ecc-${username}`,
    identityKeyPqcPub: `pqc-${username}`,
    signingKeyPub: `sign-${username}`,
    signedPrekeyEcc: {
      id: 1,
      publicKey: `ecc-spk-${username}`,
      signature: `ecc-sig-${username}`,
      createdAt: Date.now(),
    },
    signedPrekeyPqc: {
      id: 1,
      publicKey: `pqc-spk-${username}`,
      signature: `pqc-sig-${username}`,
      createdAt: Date.now(),
    },
    oneTimePrekeyEcc: [{ id: 100, publicKey: `otpk-${username}` }],
  };

  const registerRes = await fetch(`${baseUrl()}/api/v1/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(registerPayload),
  });

  expect(registerRes.status).toBe(201);

  const loginRes = await fetch(`${baseUrl()}/api/v1/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username,
      password: registerPayload.password,
    }),
  });

  expect(loginRes.status).toBe(200);

  const loginBody = (await loginRes.json()) as {
    userId: string;
    token: string;
  };

  return { userId: loginBody.userId, token: loginBody.token };
}

async function connectWs(token: string): Promise<WebSocket> {
  const ws = new WebSocket(wsUrl(), [`auth.${token}`]);
  await waitForOpen(ws);
  return ws;
}

async function createGroup(
  ownerToken: string,
  name: string,
  memberUserIds: string[],
): Promise<{
  groupId: string;
  ownerId: string;
  memberUserIds: string[];
  membershipCommitment: string;
}> {
  const response = await fetch(`${baseUrl()}/api/v1/groups`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${ownerToken}`,
    },
    body: JSON.stringify({ name, memberUserIds }),
  });

  expect(response.status).toBe(201);
  return (await response.json()) as {
    groupId: string;
    ownerId: string;
    memberUserIds: string[];
    membershipCommitment: string;
  };
}

async function addGroupMember(
  ownerToken: string,
  groupId: string,
  userId: string,
): Promise<{ membershipCommitment: string }> {
  const response = await fetch(
    `${baseUrl()}/api/v1/groups/${encodeURIComponent(groupId)}/members`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${ownerToken}`,
      },
      body: JSON.stringify({ userId }),
    },
  );

  expect(response.status).toBe(200);
  return (await response.json()) as { membershipCommitment: string };
}

async function removeGroupMember(
  actorToken: string,
  groupId: string,
  userId: string,
): Promise<void> {
  const response = await fetch(
    `${baseUrl()}/api/v1/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(userId)}`,
    {
      method: "DELETE",
      headers: { Authorization: `Bearer ${actorToken}` },
    },
  );

  expect(response.status).toBe(200);
}

describe("websocket relay integration", () => {
  beforeAll(async () => {
    TEST_PORT = await getAvailablePort();
    TEST_DB_PATH = `data/test-${TEST_PORT}-${process.pid}-${Date.now()}.db`;

    const serverRoot = path.resolve(process.cwd());
    const npxBin = process.platform === "win32" ? "npx.cmd" : "npx";

    serverProcess = spawn(npxBin, ["tsx", "src/index.ts"], {
      cwd: serverRoot,
      shell: process.platform === "win32",
      env: {
        ...process.env,
        PORT: String(TEST_PORT),
        HOST: "127.0.0.1",
        JWT_SECRET: "test-jwt-secret",
        SQLITE_DB_PATH: TEST_DB_PATH,
      },
      stdio: "pipe",
    });

    serverProcess.stderr.on("data", () => {
      // Keep stream drained to avoid backpressure.
    });
    serverProcess.stdout.on("data", () => {
      // Keep stream drained to avoid backpressure.
    });

    await waitForHealth();
  });

  afterAll(async () => {
    if (serverProcess) {
      serverProcess.kill();
      serverProcess = null;
    }
  });

  it("relays send/ack/read/typing and preserves handshake metadata", async () => {
    const alice = await registerAndLogin(`alice-ws-${Date.now()}`);
    const bob = await registerAndLogin(`bob-ws-${Date.now()}`);

    const bobWs = await connectWs(bob.token);
    const aliceWs = await connectWs(alice.token);

    const messageId = `msg-${Date.now()}`;
    const bobSendPromise = waitForMessage<{
      type: string;
      messageId: string;
      senderId: string;
      encryptedBlob: string;
      handshakeData?: string;
      ratchetKeyEcc?: string;
      messageNumber?: number;
    }>(
      bobWs,
      (m) => m.type === "send" && m.messageId === messageId,
      5000,
      "bob receive send",
    );
    const aliceAckPromise = waitForMessage<{ type: string; messageId: string }>(
      aliceWs,
      (m) => m.type === "ack" && m.messageId === messageId,
      5000,
      "alice ack",
    );

    aliceWs.send(
      JSON.stringify({
        type: "send",
        messageId,
        recipientId: bob.userId,
        encryptedBlob: "cipher-blob-1",
        handshakeData: "hs-blob-1",
        ratchetKeyEcc: "ratchet-key-1",
        messageNumber: 7,
      }),
    );

    const bobSend = await bobSendPromise;
    const aliceAck = await aliceAckPromise;

    expect(bobSend.senderId).toBe(alice.userId);
    expect(bobSend.encryptedBlob).toBe("cipher-blob-1");
    expect(bobSend.handshakeData).toBe("hs-blob-1");
    expect(bobSend.ratchetKeyEcc).toBe("ratchet-key-1");
    expect(bobSend.messageNumber).toBe(7);
    expect(aliceAck.type).toBe("ack");

    const aliceReadPromise = waitForMessage<{
      type: string;
      messageId: string;
      senderId: string;
    }>(
      aliceWs,
      (m) => m.type === "read" && m.messageId === messageId,
      5000,
      "alice read receipt",
    );

    bobWs.send(
      JSON.stringify({
        type: "read",
        messageId,
        recipientId: alice.userId,
        timestamp: Date.now(),
      }),
    );

    const readReceipt = await aliceReadPromise;
    expect(readReceipt.senderId).toBe(bob.userId);

    const aliceTypingPromise = waitForMessage<{
      type: string;
      senderId: string;
    }>(
      aliceWs,
      (m) => m.type === "typing" && m.senderId === bob.userId,
      5000,
      "alice typing",
    );

    bobWs.send(
      JSON.stringify({
        type: "typing",
        messageId: "typing-1",
        recipientId: alice.userId,
      }),
    );

    const typing = await aliceTypingPromise;
    expect(typing.type).toBe("typing");

    bobWs.close();
    await waitForClose(bobWs);

    const offlineMessageId = `msg-offline-${Date.now()}`;
    const aliceAckOfflinePromise = waitForMessage<{
      type: string;
      messageId: string;
    }>(
      aliceWs,
      (m) => m.type === "ack" && m.messageId === offlineMessageId,
      5000,
      "alice offline ack",
    );

    aliceWs.send(
      JSON.stringify({
        type: "send",
        messageId: offlineMessageId,
        recipientId: bob.userId,
        encryptedBlob: "cipher-blob-offline",
        handshakeData: "hs-offline",
        ratchetKeyEcc: "ratchet-key-offline",
        messageNumber: 9,
      }),
    );

    await aliceAckOfflinePromise;

    const bobWsReconnect = await connectWs(bob.token);

    const pending = await waitForMessage<{
      type: string;
      senderId: string;
      encryptedBlob: string;
      handshakeData?: string;
      ratchetKeyEcc?: string;
      messageNumber?: number;
    }>(
      bobWsReconnect,
      (m) => m.type === "send" && m.encryptedBlob === "cipher-blob-offline",
      5000,
      "bob pending delivery",
    );

    expect(pending.senderId).toBe(alice.userId);
    expect(pending.handshakeData).toBe("hs-offline");
    expect(pending.ratchetKeyEcc).toBe("ratchet-key-offline");
    expect(pending.messageNumber).toBe(9);

    const aliceDeliveredPromise = waitForMessage<{
      type: string;
      messageId: string;
      senderId: string;
    }>(
      aliceWs,
      (m) => m.type === "delivered" && m.messageId === offlineMessageId,
      5000,
      "alice delivered receipt",
    );

    bobWsReconnect.send(
      JSON.stringify({
        type: "delivered",
        messageId: offlineMessageId,
        recipientId: alice.userId,
        timestamp: Date.now(),
      }),
    );

    const delivered = await aliceDeliveredPromise;
    expect(delivered.senderId).toBe(bob.userId);

    bobWsReconnect.close();
    await waitForClose(bobWsReconnect);

    const bobWsAfterDeliveredAck = await connectWs(bob.token);
    await waitForNoMatchingMessage<{
      type: string;
      encryptedBlob?: string;
      messageId?: string;
    }>(
      bobWsAfterDeliveredAck,
      (m) =>
        m.type === "send" &&
        (m.encryptedBlob === "cipher-blob-offline" ||
          m.messageId === offlineMessageId),
      1200,
    );

    const badMessageId = `bad-${Date.now()}`;
    const errorPromise = waitForMessage<{
      type: string;
      messageId: string;
      error: string;
    }>(
      aliceWs,
      (m) => m.type === "error" && m.messageId === badMessageId,
      5000,
      "alice invalid messageNumber error",
    );

    aliceWs.send(
      JSON.stringify({
        type: "send",
        messageId: badMessageId,
        recipientId: bob.userId,
        encryptedBlob: "cipher-bad",
        messageNumber: -1,
      }),
    );

    const errorMsg = await errorPromise;
    expect(errorMsg.error).toContain("Invalid messageNumber");

    bobWsAfterDeliveredAck.close();
    aliceWs.close();
    await waitForClose(bobWsAfterDeliveredAck);
    await waitForClose(aliceWs);
  });

  it("rejects unauthorized group sends and stale membership context", async () => {
    const alice = await registerAndLogin(`alice-group-ws-${Date.now()}`);
    const bob = await registerAndLogin(`bob-group-ws-${Date.now()}`);
    const charlie = await registerAndLogin(`charlie-group-ws-${Date.now()}`);
    const dave = await registerAndLogin(`dave-group-ws-${Date.now()}`);

    const created = await createGroup(alice.token, "ops", [
      bob.userId,
      charlie.userId,
    ]);

    const aliceWs = await connectWs(alice.token);
    const bobWs = await connectWs(bob.token);
    const charlieWs = await connectWs(charlie.token);
    const daveWs = await connectWs(dave.token);

    const unauthorizedSenderId = `group-unauth-${Date.now()}`;
    const daveUnauthorizedPromise = waitForMessage<{
      type: string;
      messageId: string;
      error: string;
    }>(
      daveWs,
      (m) => m.type === "error" && m.messageId === unauthorizedSenderId,
      5000,
      "dave unauthorized sender",
    );

    daveWs.send(
      JSON.stringify({
        type: "send",
        messageId: unauthorizedSenderId,
        recipientId: bob.userId,
        groupId: created.groupId,
        groupEventType: "group_message",
        groupMembershipCommitment: created.membershipCommitment,
        encryptedBlob: "cipher-unauth-sender",
      }),
    );

    const unauthorizedSenderError = await daveUnauthorizedPromise;
    expect(unauthorizedSenderError.error).toContain(
      "Sender is not a group member",
    );

    const unauthorizedRecipientId = `group-bad-recipient-${Date.now()}`;
    const aliceBadRecipientPromise = waitForMessage<{
      type: string;
      messageId: string;
      error: string;
    }>(
      aliceWs,
      (m) => m.type === "error" && m.messageId === unauthorizedRecipientId,
      5000,
      "alice unauthorized recipient",
    );

    aliceWs.send(
      JSON.stringify({
        type: "send",
        messageId: unauthorizedRecipientId,
        recipientId: dave.userId,
        groupId: created.groupId,
        groupEventType: "group_message",
        groupMembershipCommitment: created.membershipCommitment,
        encryptedBlob: "cipher-unauth-recipient",
      }),
    );

    const unauthorizedRecipientError = await aliceBadRecipientPromise;
    expect(unauthorizedRecipientError.error).toContain(
      "Recipient is not a group member",
    );

    const validGroupMessageId = `group-valid-${Date.now()}`;
    const bobValidReceivePromise = waitForMessage<{
      type: string;
      messageId: string;
      groupId?: string;
      groupEventType?: string;
      groupMembershipCommitment?: string;
    }>(
      bobWs,
      (m) => m.type === "send" && m.messageId === validGroupMessageId,
      5000,
      "bob receives valid group message",
    );

    aliceWs.send(
      JSON.stringify({
        type: "send",
        messageId: validGroupMessageId,
        recipientId: bob.userId,
        groupId: created.groupId,
        groupEventType: "group_message",
        groupMembershipCommitment: created.membershipCommitment,
        encryptedBlob: "cipher-valid-group",
      }),
    );

    const validForward = await bobValidReceivePromise;
    expect(validForward.groupId).toBe(created.groupId);
    expect(validForward.groupEventType).toBe("group_message");
    expect(validForward.groupMembershipCommitment).toBe(
      created.membershipCommitment,
    );

    const afterAdd = await addGroupMember(
      alice.token,
      created.groupId,
      dave.userId,
    );

    const staleContextMessageId = `group-stale-${Date.now()}`;
    const staleContextPromise = waitForMessage<{
      type: string;
      messageId: string;
      error: string;
    }>(
      aliceWs,
      (m) => m.type === "error" && m.messageId === staleContextMessageId,
      5000,
      "alice stale context rejected",
    );

    aliceWs.send(
      JSON.stringify({
        type: "send",
        messageId: staleContextMessageId,
        recipientId: bob.userId,
        groupId: created.groupId,
        groupEventType: "group_message",
        groupMembershipCommitment: created.membershipCommitment,
        encryptedBlob: "cipher-stale",
      }),
    );

    const staleError = await staleContextPromise;
    expect(staleError.error).toContain("Stale group membership context");

    const postUpdateMessageId = `group-updated-${Date.now()}`;
    const bobUpdatedPromise = waitForMessage<{
      type: string;
      messageId: string;
      groupMembershipCommitment?: string;
    }>(
      bobWs,
      (m) => m.type === "send" && m.messageId === postUpdateMessageId,
      5000,
      "bob receives updated context",
    );

    aliceWs.send(
      JSON.stringify({
        type: "send",
        messageId: postUpdateMessageId,
        recipientId: bob.userId,
        groupId: created.groupId,
        groupEventType: "group_message",
        groupMembershipCommitment: afterAdd.membershipCommitment,
        encryptedBlob: "cipher-updated",
      }),
    );

    const updatedForward = await bobUpdatedPromise;
    expect(updatedForward.groupMembershipCommitment).toBe(
      afterAdd.membershipCommitment,
    );

    await removeGroupMember(alice.token, created.groupId, charlie.userId);

    const removedRecipientMessageId = `group-removed-recipient-${Date.now()}`;
    const removedRecipientPromise = waitForMessage<{
      type: string;
      messageId: string;
      error: string;
    }>(
      aliceWs,
      (m) => m.type === "error" && m.messageId === removedRecipientMessageId,
      5000,
      "alice removed recipient rejected",
    );

    aliceWs.send(
      JSON.stringify({
        type: "send",
        messageId: removedRecipientMessageId,
        recipientId: charlie.userId,
        groupId: created.groupId,
        groupEventType: "group_message",
        groupMembershipCommitment: afterAdd.membershipCommitment,
        encryptedBlob: "cipher-removed-recipient",
      }),
    );

    const removedRecipientError = await removedRecipientPromise;
    expect(removedRecipientError.error).toContain(
      "Recipient is not a group member",
    );

    aliceWs.close();
    bobWs.close();
    charlieWs.close();
    daveWs.close();

    await waitForClose(aliceWs);
    await waitForClose(bobWs);
    await waitForClose(charlieWs);
    await waitForClose(daveWs);
  });
});
