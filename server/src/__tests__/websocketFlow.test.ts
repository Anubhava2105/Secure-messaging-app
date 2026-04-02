import { spawn, ChildProcessWithoutNullStreams } from "child_process";
import path from "path";
import { WebSocket } from "ws";
import { describe, it, expect, beforeAll, afterAll } from "vitest";

const TEST_PORT = 3202 + Math.floor(Math.random() * 1000);
const BASE_URL = `http://127.0.0.1:${TEST_PORT}`;
const WS_URL = `ws://127.0.0.1:${TEST_PORT}/ws`;
const TEST_DB_PATH = `data/test-${TEST_PORT}-${process.pid}-${Date.now()}.db`;

let serverProcess: ChildProcessWithoutNullStreams | null = null;

async function waitForHealth(timeoutMs = 15000): Promise<void> {
  const started = Date.now();

  while (Date.now() - started < timeoutMs) {
    try {
      const res = await fetch(`${BASE_URL}/health`);
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
  label = "unnamed"
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

async function registerAndLogin(username: string): Promise<{
  userId: string;
  token: string;
}> {
  const registerPayload = {
    username,
    passwordHash: "f".repeat(96),
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

  const registerRes = await fetch(`${BASE_URL}/api/v1/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(registerPayload),
  });

  expect(registerRes.status).toBe(201);

  const loginRes = await fetch(`${BASE_URL}/api/v1/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username,
      passwordHash: registerPayload.passwordHash,
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
  const ws = new WebSocket(`${WS_URL}?token=${encodeURIComponent(token)}`);
  await waitForOpen(ws);
  return ws;
}

describe("websocket relay integration", () => {
  beforeAll(async () => {
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
      "bob receive send"
    );
    const aliceAckPromise = waitForMessage<{ type: string; messageId: string }>(
      aliceWs,
      (m) => m.type === "ack" && m.messageId === messageId,
      5000,
      "alice ack"
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
      })
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
      "alice read receipt"
    );

    bobWs.send(
      JSON.stringify({
        type: "read",
        messageId,
        recipientId: alice.userId,
        timestamp: Date.now(),
      })
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
      "alice typing"
    );

    bobWs.send(
      JSON.stringify({
        type: "typing",
        messageId: "typing-1",
        recipientId: alice.userId,
      })
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
      "alice offline ack"
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
      })
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
      "bob pending delivery"
    );

    expect(pending.senderId).toBe(alice.userId);
    expect(pending.handshakeData).toBe("hs-offline");
    expect(pending.ratchetKeyEcc).toBe("ratchet-key-offline");
    expect(pending.messageNumber).toBe(9);

    const badMessageId = `bad-${Date.now()}`;
    const errorPromise = waitForMessage<{
      type: string;
      messageId: string;
      error: string;
    }>(
      aliceWs,
      (m) => m.type === "error" && m.messageId === badMessageId,
      5000,
      "alice invalid messageNumber error"
    );

    aliceWs.send(
      JSON.stringify({
        type: "send",
        messageId: badMessageId,
        recipientId: bob.userId,
        encryptedBlob: "cipher-bad",
        messageNumber: -1,
      })
    );

    const errorMsg = await errorPromise;
    expect(errorMsg.error).toContain("Invalid messageNumber");

    bobWsReconnect.close();
    aliceWs.close();
    await waitForClose(bobWsReconnect);
    await waitForClose(aliceWs);
  });
});
