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

describe("server integration", () => {
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

  it("responds to health endpoint", async () => {
    const res = await fetch(`${baseUrl()}/health`);
    expect(res.status).toBe(200);

    const body = (await res.json()) as { status: string };
    expect(body.status).toBe("ok");
  });
});
