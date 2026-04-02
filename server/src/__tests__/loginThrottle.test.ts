import { spawn, ChildProcessWithoutNullStreams } from "child_process";
import path from "path";
import { describe, it, expect, beforeAll, afterAll } from "vitest";

const TEST_PORT = 3203 + Math.floor(Math.random() * 1000);
const BASE_URL = `http://127.0.0.1:${TEST_PORT}`;
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

describe("login throttling", () => {
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
        LOGIN_MAX_ATTEMPTS: "2",
        LOGIN_LOCK_MS: "10000",
        LOGIN_WINDOW_MS: "60000",
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

  it("locks login after repeated invalid attempts", async () => {
    const username = `throttle-${Date.now()}`;
    const passwordHash = "f".repeat(96);

    const registerRes = await fetch(`${BASE_URL}/api/v1/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        passwordHash,
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
        oneTimePrekeyEcc: [{ id: 100, publicKey: "otpk-100" }],
      }),
    });

    expect(registerRes.status).toBe(201);

    const bad1 = await fetch(`${BASE_URL}/api/v1/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        passwordHash: "0".repeat(96),
      }),
    });
    expect(bad1.status).toBe(401);

    const bad2 = await fetch(`${BASE_URL}/api/v1/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        passwordHash: "1".repeat(96),
      }),
    });
    expect(bad2.status).toBe(401);

    const locked = await fetch(`${BASE_URL}/api/v1/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        passwordHash,
      }),
    });

    expect(locked.status).toBe(429);
  });
});
