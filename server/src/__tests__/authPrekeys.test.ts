import { spawn, ChildProcessWithoutNullStreams } from "child_process";
import path from "path";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { getAvailablePort } from "./helpers/port.js";

let TEST_PORT = 0;
let TEST_DB_PATH = "";

function baseUrl(): string {
  return `http://127.0.0.1:${TEST_PORT}`;
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

function authHeaders(token: string): Record<string, string> {
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };
}

describe("auth + prekeys integration", () => {
  let token = "";

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

  it("registers, logs in, and manages prekeys", async () => {
    const registerPayload = {
      username: `alice-${Date.now()}`,
      password: "correct-horse-battery-staple",
      identityKeyEccPub: "ecc-pub",
      identityKeyPqcPub: "pqc-pub",
      signingKeyPub: "sign-pub",
      signedPrekeyEcc: {
        id: 1,
        publicKey: "ecc-spk",
        signature: "ecc-sig",
        createdAt: Date.now(),
      },
      signedPrekeyPqc: {
        id: 1,
        publicKey: "pqc-spk",
        signature: "pqc-sig",
        createdAt: Date.now(),
      },
      oneTimePrekeyEcc: [
        { id: 100, publicKey: "otpk-100" },
        { id: 101, publicKey: "otpk-101" },
      ],
    };

    const registerRes = await fetch(`${baseUrl()}/api/v1/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(registerPayload),
    });

    expect(registerRes.status).toBe(201);
    const registered = (await registerRes.json()) as {
      username: string;
      token: string;
    };
    expect(registered.username).toBe(registerPayload.username);
    expect(typeof registered.token).toBe("string");
    expect(registered.token.length).toBeGreaterThan(10);

    const loginRes = await fetch(`${baseUrl()}/api/v1/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: registerPayload.username,
        password: registerPayload.password,
      }),
    });

    expect(loginRes.status).toBe(200);
    const loginBody = (await loginRes.json()) as { token: string };
    token = loginBody.token;
    expect(typeof token).toBe("string");
    expect(token.length).toBeGreaterThan(10);

    const prekeyCountRes = await fetch(`${baseUrl()}/api/v1/prekeys/count`, {
      headers: authHeaders(token),
    });
    expect(prekeyCountRes.status).toBe(200);

    const prekeyCount = (await prekeyCountRes.json()) as { count: number };
    expect(prekeyCount.count).toBe(2);

    const addPrekeysRes = await fetch(`${baseUrl()}/api/v1/prekeys`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({
        oneTimePrekeys: [
          { id: 102, publicKey: "otpk-102" },
          { id: 103, publicKey: "otpk-103" },
        ],
      }),
    });

    expect(addPrekeysRes.status).toBe(200);

    const updatedCountRes = await fetch(`${baseUrl()}/api/v1/prekeys/count`, {
      headers: authHeaders(token),
    });
    expect(updatedCountRes.status).toBe(200);

    const updatedCount = (await updatedCountRes.json()) as { count: number };
    expect(updatedCount.count).toBe(4);
  });
});
