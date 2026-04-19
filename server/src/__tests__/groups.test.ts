import { spawn, ChildProcessWithoutNullStreams } from "child_process";
import path from "path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { getAvailablePort } from "./helpers/port.js";

let TEST_PORT = 0;
let TEST_DB_PATH = "";
let serverProcess: ChildProcessWithoutNullStreams | null = null;

function baseUrl(): string {
  return `http://127.0.0.1:${TEST_PORT}`;
}

async function waitForHealth(timeoutMs = 15000): Promise<void> {
  const started = Date.now();

  while (Date.now() - started < timeoutMs) {
    try {
      const res = await fetch(`${baseUrl()}/health`);
      if (res.ok) return;
    } catch {
      // Ignore until timeout.
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }

  throw new Error("Server health endpoint did not become ready in time");
}

async function registerAndLogin(username: string): Promise<{
  userId: string;
  token: string;
}> {
  const password = "correct-horse-battery-staple";
  const registerRes = await fetch(`${baseUrl()}/api/v1/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username,
      password,
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
      oneTimePrekeyEcc: [{ id: 101, publicKey: `otpk-${username}` }],
    }),
  });

  expect(registerRes.status).toBe(201);

  const loginRes = await fetch(`${baseUrl()}/api/v1/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });

  expect(loginRes.status).toBe(200);

  const loginBody = (await loginRes.json()) as {
    userId: string;
    token: string;
  };

  return loginBody;
}

describe("group registry routes", () => {
  beforeAll(async () => {
    TEST_PORT = await getAvailablePort();
    TEST_DB_PATH = `data/test-groups-${TEST_PORT}-${process.pid}-${Date.now()}.db`;

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
      // Drain stream to avoid backpressure.
    });
    serverProcess.stdout.on("data", () => {
      // Drain stream to avoid backpressure.
    });

    await waitForHealth();
  });

  afterAll(() => {
    if (serverProcess) {
      serverProcess.kill();
      serverProcess = null;
    }
  });

  it("creates groups and manages membership with owner/member permissions", async () => {
    const alice = await registerAndLogin(`alice-g-${Date.now()}`);
    const bob = await registerAndLogin(`bob-g-${Date.now()}`);
    const charlie = await registerAndLogin(`charlie-g-${Date.now()}`);
    const dave = await registerAndLogin(`dave-g-${Date.now()}`);

    const createRes = await fetch(`${baseUrl()}/api/v1/groups`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${alice.token}`,
      },
      body: JSON.stringify({
        name: "Core Team",
        memberUserIds: [bob.userId, charlie.userId],
      }),
    });

    expect(createRes.status).toBe(201);
    const created = (await createRes.json()) as {
      groupId: string;
      ownerId: string;
      memberUserIds: string[];
    };

    expect(created.ownerId).toBe(alice.userId);
    expect(created.memberUserIds).toContain(alice.userId);
    expect(created.memberUserIds).toContain(bob.userId);
    expect(created.memberUserIds).toContain(charlie.userId);

    const listBob = await fetch(`${baseUrl()}/api/v1/groups`, {
      headers: { Authorization: `Bearer ${bob.token}` },
    });
    expect(listBob.status).toBe(200);
    const bobGroups = (await listBob.json()) as {
      groups: Array<{ groupId: string }>;
    };
    expect(bobGroups.groups.some((g) => g.groupId === created.groupId)).toBe(
      true,
    );

    const bobAddMember = await fetch(
      `${baseUrl()}/api/v1/groups/${encodeURIComponent(created.groupId)}/members`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${bob.token}`,
        },
        body: JSON.stringify({ userId: dave.userId }),
      },
    );
    expect(bobAddMember.status).toBe(403);

    const aliceAddMember = await fetch(
      `${baseUrl()}/api/v1/groups/${encodeURIComponent(created.groupId)}/members`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${alice.token}`,
        },
        body: JSON.stringify({ userId: dave.userId }),
      },
    );
    expect(aliceAddMember.status).toBe(200);
    const afterAdd = (await aliceAddMember.json()) as {
      memberUserIds: string[];
    };
    expect(afterAdd.memberUserIds).toContain(dave.userId);

    const bobRemoveCharlie = await fetch(
      `${baseUrl()}/api/v1/groups/${encodeURIComponent(created.groupId)}/members/${encodeURIComponent(charlie.userId)}`,
      {
        method: "DELETE",
        headers: { Authorization: `Bearer ${bob.token}` },
      },
    );
    expect(bobRemoveCharlie.status).toBe(403);

    const bobLeave = await fetch(
      `${baseUrl()}/api/v1/groups/${encodeURIComponent(created.groupId)}/members/${encodeURIComponent(bob.userId)}`,
      {
        method: "DELETE",
        headers: { Authorization: `Bearer ${bob.token}` },
      },
    );
    expect(bobLeave.status).toBe(200);

    const ownerRemoveCharlie = await fetch(
      `${baseUrl()}/api/v1/groups/${encodeURIComponent(created.groupId)}/members/${encodeURIComponent(charlie.userId)}`,
      {
        method: "DELETE",
        headers: { Authorization: `Bearer ${alice.token}` },
      },
    );
    expect(ownerRemoveCharlie.status).toBe(200);

    const ownerRemoveDave = await fetch(
      `${baseUrl()}/api/v1/groups/${encodeURIComponent(created.groupId)}/members/${encodeURIComponent(dave.userId)}`,
      {
        method: "DELETE",
        headers: { Authorization: `Bearer ${alice.token}` },
      },
    );
    expect(ownerRemoveDave.status).toBe(400);

    const transferGroupRes = await fetch(`${baseUrl()}/api/v1/groups`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${alice.token}`,
      },
      body: JSON.stringify({
        name: "Ownership Transfer Group",
        memberUserIds: [bob.userId, charlie.userId],
      }),
    });
    expect(transferGroupRes.status).toBe(201);

    const transferGroup = (await transferGroupRes.json()) as {
      groupId: string;
      ownerId: string;
      memberUserIds: string[];
    };

    const ownerLeaves = await fetch(
      `${baseUrl()}/api/v1/groups/${encodeURIComponent(transferGroup.groupId)}/members/${encodeURIComponent(alice.userId)}`,
      {
        method: "DELETE",
        headers: { Authorization: `Bearer ${alice.token}` },
      },
    );
    expect(ownerLeaves.status).toBe(200);

    const afterOwnerLeave = (await ownerLeaves.json()) as {
      ownerId: string;
      memberUserIds: string[];
    };
    expect(afterOwnerLeave.ownerId).not.toBe(alice.userId);
    expect(
      afterOwnerLeave.memberUserIds.includes(afterOwnerLeave.ownerId),
    ).toBe(true);
    expect(afterOwnerLeave.memberUserIds.includes(alice.userId)).toBe(false);

    const oldOwnerFetch = await fetch(
      `${baseUrl()}/api/v1/groups/${encodeURIComponent(transferGroup.groupId)}`,
      {
        headers: { Authorization: `Bearer ${alice.token}` },
      },
    );
    expect(oldOwnerFetch.status).toBe(403);

    const transferredOwnerToken =
      afterOwnerLeave.ownerId === bob.userId ? bob.token : charlie.token;

    const newOwnerAddBack = await fetch(
      `${baseUrl()}/api/v1/groups/${encodeURIComponent(transferGroup.groupId)}/members`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${transferredOwnerToken}`,
        },
        body: JSON.stringify({ userId: alice.userId }),
      },
    );
    expect(newOwnerAddBack.status).toBe(200);
  });
});
