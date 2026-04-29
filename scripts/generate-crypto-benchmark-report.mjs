import { createMlKem768 } from "mlkem";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { promises as fs } from "node:fs";
import { webcrypto } from "node:crypto";

const subtle = webcrypto.subtle;
const encoder = new TextEncoder();

const P384 = {
  name: "ECDH",
  namedCurve: "P-384",
};

const HYBRID_SALT = encoder.encode("SecureMsg-Hybrid-KDF-v1");
const CLASSICAL_SALT = encoder.encode("SecureMsg-Classical-KDF-v1");
const HANDSHAKE_LABEL = encoder.encode("SecureMsg-Handshake-v1");

const DEFAULT_ITERATIONS = 40;
const DEFAULT_WARMUPS = 8;

function toArrayBuffer(bytes) {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  );
}

function concatBytes(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function arraysEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

async function generateExportableP384KeyPair() {
  const pair = await subtle.generateKey(P384, true, ["deriveBits"]);
  const publicKeyRaw = new Uint8Array(
    await subtle.exportKey("raw", pair.publicKey),
  );
  return {
    privateKey: pair.privateKey,
    publicKeyRaw,
  };
}

async function importPublicKey(raw) {
  return subtle.importKey("raw", toArrayBuffer(raw), P384, true, []);
}

async function deriveSharedSecret(privateKey, peerPublicRaw) {
  const peerPublic = await importPublicKey(peerPublicRaw);
  const bits = await subtle.deriveBits(
    {
      name: "ECDH",
      public: peerPublic,
    },
    privateKey,
    384,
  );
  return new Uint8Array(bits);
}

async function hkdfExtract(salt, ikm) {
  const key = await subtle.importKey(
    "raw",
    toArrayBuffer(salt),
    { name: "HMAC", hash: "SHA-384" },
    false,
    ["sign"],
  );
  const prk = await subtle.sign("HMAC", key, toArrayBuffer(ikm));
  return new Uint8Array(prk);
}

async function hkdfExpand(prk, info, length) {
  const hashLen = 48;
  const n = Math.ceil(length / hashLen);
  const okm = new Uint8Array(n * hashLen);

  const key = await subtle.importKey(
    "raw",
    toArrayBuffer(prk),
    { name: "HMAC", hash: "SHA-384" },
    false,
    ["sign"],
  );

  let t = new Uint8Array(0);
  for (let i = 1; i <= n; i += 1) {
    const input = concatBytes(t, info, new Uint8Array([i]));
    const block = new Uint8Array(
      await subtle.sign("HMAC", key, toArrayBuffer(input)),
    );
    okm.set(block, (i - 1) * hashLen);
    t = block;
  }

  return okm.slice(0, length);
}

async function hkdf(salt, ikm, info, length) {
  const prk = await hkdfExtract(salt, ikm);
  return hkdfExpand(prk, info, length);
}

async function deriveClassicalKeys(eccSecrets, context) {
  const ikm = concatBytes(...eccSecrets);
  return hkdf(CLASSICAL_SALT, ikm, context, 96);
}

async function deriveHybridKeys(eccSecrets, pqcSecret, context) {
  const ikm = concatBytes(...eccSecrets, pqcSecret);
  return hkdf(HYBRID_SALT, ikm, context, 96);
}

function percentile(values, p) {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(sorted.length - 1, idx))];
}

function computeStats(samples) {
  const count = samples.length;
  const sum = samples.reduce((acc, value) => acc + value, 0);
  const mean = sum / count;
  const variance =
    samples.reduce((acc, value) => acc + (value - mean) ** 2, 0) / count;

  return {
    count,
    mean,
    stdDev: Math.sqrt(variance),
    min: Math.min(...samples),
    p50: percentile(samples, 50),
    p95: percentile(samples, 95),
    max: Math.max(...samples),
  };
}

async function benchmark(name, warmups, iterations, fn) {
  for (let i = 0; i < warmups; i += 1) {
    await fn();
  }

  const samples = [];
  for (let i = 0; i < iterations; i += 1) {
    const started = performance.now();
    await fn();
    const ended = performance.now();
    samples.push(ended - started);
  }

  return {
    name,
    samples,
    stats: computeStats(samples),
  };
}

function formatMs(value) {
  return `${value.toFixed(3)} ms`;
}

async function createBenchmarkState() {
  const aliceIdentity = await generateExportableP384KeyPair();
  const bobIdentity = await generateExportableP384KeyPair();
  const bobSignedPrekey = await generateExportableP384KeyPair();

  const context = concatBytes(
    HANDSHAKE_LABEL,
    aliceIdentity.publicKeyRaw,
    bobIdentity.publicKeyRaw,
  );

  const mlkem = await createMlKem768();
  const [bobPqcPublicKey, bobPqcPrivateKey] = mlkem.generateKeyPair();

  return {
    aliceIdentity,
    bobIdentity,
    bobSignedPrekey,
    context,
    mlkem,
    bobPqcPublicKey: new Uint8Array(bobPqcPublicKey),
    bobPqcPrivateKey: new Uint8Array(bobPqcPrivateKey),
  };
}

async function runClassicalHandshake(state) {
  const aliceEphemeral = await generateExportableP384KeyPair();
  const dh1 = await deriveSharedSecret(
    state.aliceIdentity.privateKey,
    state.bobSignedPrekey.publicKeyRaw,
  );
  const dh2 = await deriveSharedSecret(
    aliceEphemeral.privateKey,
    state.bobIdentity.publicKeyRaw,
  );
  const dh3 = await deriveSharedSecret(
    aliceEphemeral.privateKey,
    state.bobSignedPrekey.publicKeyRaw,
  );
  const okm = await deriveClassicalKeys([dh1, dh2, dh3], state.context);
  return okm[0];
}

async function runHybridHandshake(state) {
  const aliceEphemeral = await generateExportableP384KeyPair();
  const dh1 = await deriveSharedSecret(
    state.aliceIdentity.privateKey,
    state.bobSignedPrekey.publicKeyRaw,
  );
  const dh2 = await deriveSharedSecret(
    aliceEphemeral.privateKey,
    state.bobIdentity.publicKeyRaw,
  );
  const dh3 = await deriveSharedSecret(
    aliceEphemeral.privateKey,
    state.bobSignedPrekey.publicKeyRaw,
  );

  const [pqcCiphertext, pqcSharedSecretInitiator] = state.mlkem.encap(
    state.bobPqcPublicKey,
  );
  const pqcSharedSecretResponder = state.mlkem.decap(
    pqcCiphertext,
    state.bobPqcPrivateKey,
  );

  if (!arraysEqual(pqcSharedSecretInitiator, pqcSharedSecretResponder)) {
    throw new Error(
      "PQC shared secret mismatch between encapsulate/decapsulate",
    );
  }

  const okm = await deriveHybridKeys(
    [dh1, dh2, dh3],
    new Uint8Array(pqcSharedSecretInitiator),
    state.context,
  );
  return okm[0];
}

function buildMarkdownReport({
  generatedAt,
  iterations,
  warmups,
  classical,
  hybrid,
  overheadPct,
}) {
  const cpu = os.cpus()[0]?.model ?? "unknown";
  const nodeVersion = process.version;
  const platform = `${process.platform} ${process.arch}`;

  return [
    "# Hybrid vs Classical Handshake Benchmark Report",
    "",
    `Generated at: ${generatedAt}`,
    `Node: ${nodeVersion}`,
    `Platform: ${platform}`,
    `CPU: ${cpu}`,
    "",
    "## Configuration",
    "",
    `- Warmup iterations: ${warmups}`,
    `- Measured iterations: ${iterations}`,
    "- Classical baseline: P-384 ECDH X3DH-style DH terms + HKDF-SHA-384",
    "- Hybrid: Same classical path + ML-KEM-768 encapsulation/decapsulation + HKDF-SHA-384",
    "",
    "## Latency Summary",
    "",
    "| Variant | Mean | P50 | P95 | Min | Max | StdDev |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    `| Classical | ${formatMs(classical.stats.mean)} | ${formatMs(classical.stats.p50)} | ${formatMs(classical.stats.p95)} | ${formatMs(classical.stats.min)} | ${formatMs(classical.stats.max)} | ${formatMs(classical.stats.stdDev)} |`,
    `| Hybrid | ${formatMs(hybrid.stats.mean)} | ${formatMs(hybrid.stats.p50)} | ${formatMs(hybrid.stats.p95)} | ${formatMs(hybrid.stats.min)} | ${formatMs(hybrid.stats.max)} | ${formatMs(hybrid.stats.stdDev)} |`,
    "",
    `Hybrid overhead vs classical (mean): ${overheadPct.toFixed(2)}%`,
    "",
    "## Interpretation",
    "",
    "- This benchmark quantifies runtime cost of adding PQC KEM operations to the existing classical handshake.",
    "- Security benefit of hybrid mode is long-horizon risk reduction (harvest-now-decrypt-later), while this report captures the latency tradeoff.",
    "",
  ].join("\n");
}

async function main() {
  const iterations = Number.parseInt(process.env.BENCH_ITERATIONS ?? "", 10);
  const warmups = Number.parseInt(process.env.BENCH_WARMUPS ?? "", 10);

  const measuredIterations =
    Number.isInteger(iterations) && iterations > 0
      ? iterations
      : DEFAULT_ITERATIONS;
  const measuredWarmups =
    Number.isInteger(warmups) && warmups >= 0 ? warmups : DEFAULT_WARMUPS;

  const state = await createBenchmarkState();

  const classical = await benchmark(
    "classical",
    measuredWarmups,
    measuredIterations,
    () => runClassicalHandshake(state),
  );

  const hybrid = await benchmark(
    "hybrid",
    measuredWarmups,
    measuredIterations,
    () => runHybridHandshake(state),
  );

  const overheadPct =
    ((hybrid.stats.mean - classical.stats.mean) / classical.stats.mean) * 100;

  const generatedAt = new Date().toISOString();
  const timestamp = generatedAt.replace(/[:.]/g, "-");

  const reportsDir = path.join(process.cwd(), "reports");
  await fs.mkdir(reportsDir, { recursive: true });

  const markdownReport = buildMarkdownReport({
    generatedAt,
    iterations: measuredIterations,
    warmups: measuredWarmups,
    classical,
    hybrid,
    overheadPct,
  });

  const markdownPath = path.join(
    reportsDir,
    `hybrid-handshake-benchmark-${timestamp}.md`,
  );
  const latestMarkdownPath = path.join(
    reportsDir,
    "hybrid-handshake-benchmark-latest.md",
  );

  const jsonReport = {
    generatedAt,
    node: process.version,
    platform: `${process.platform} ${process.arch}`,
    cpu: os.cpus()[0]?.model ?? "unknown",
    warmups: measuredWarmups,
    iterations: measuredIterations,
    classical,
    hybrid,
    overheadPct,
  };

  const jsonPath = path.join(
    reportsDir,
    `hybrid-handshake-benchmark-${timestamp}.json`,
  );
  const latestJsonPath = path.join(
    reportsDir,
    "hybrid-handshake-benchmark-latest.json",
  );

  await fs.writeFile(markdownPath, markdownReport, "utf8");
  await fs.writeFile(latestMarkdownPath, markdownReport, "utf8");
  await fs.writeFile(jsonPath, JSON.stringify(jsonReport, null, 2), "utf8");
  await fs.writeFile(
    latestJsonPath,
    JSON.stringify(jsonReport, null, 2),
    "utf8",
  );

  console.log("Benchmark reports generated:");
  console.log(`- ${markdownPath}`);
  console.log(`- ${jsonPath}`);
  console.log(`- ${latestMarkdownPath}`);
  console.log(`- ${latestJsonPath}`);
}

main().catch((error) => {
  console.error("Failed to generate benchmark report:", error);
  process.exitCode = 1;
});
