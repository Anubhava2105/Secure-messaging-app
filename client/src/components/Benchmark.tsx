import React, { useState, useCallback } from "react";
import { Shield, Zap, Database, BarChart3, Play, Activity } from "lucide-react";
import { getMlKem768 } from "../crypto/pqc/mlkem";
import { generateExportableECDHKeyPair, deriveECDHSharedSecretFromBytes } from "../crypto/ecc/ecdh";
import "../styles/Benchmark.css";

interface BenchmarkResult {
  name: string;
  type: "classical" | "modern" | "hybrid";
  keyGenTime: number; // ms
  handshakeTime: number; // ms
  payloadSize: number; // bytes
  securityLevel: string;
  pqcProtected: boolean;
}

const Benchmark: React.FC = () => {
  const [results, setResults] = useState<BenchmarkResult[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState(0);

  const runBenchmark = async () => {
    setIsRunning(true);
    setProgress(0);
    const newResults: BenchmarkResult[] = [];

    try {
      // 1. Classical Profile (P-256)
      setProgress(10);
      const classical = await benchmarkClassical();
      newResults.push(classical);

      // 2. Modern Profile (P-384)
      setProgress(40);
      const modern = await benchmarkModern();
      newResults.push(modern);

      // 3. Hybrid Profile (P-384 + Kyber-768)
      setProgress(70);
      const hybrid = await benchmarkHybrid();
      newResults.push(hybrid);

      setResults(newResults);
    } catch (err) {
      console.error("Benchmark failed:", err);
    } finally {
      setIsRunning(false);
      setProgress(100);
    }
  };

  const benchmarkClassical = async (): Promise<BenchmarkResult> => {
    const start = performance.now();
    // Use P-256 for standard classical
    const aliceKeys = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
    const keyGenTime = performance.now() - start;

    const bobKeys = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );

    const handshakeStart = performance.now();
    const bobPub = await crypto.subtle.exportKey("raw", bobKeys.publicKey);
    await crypto.subtle.deriveBits(
      { name: "ECDH", public: aliceKeys.publicKey },
      bobKeys.privateKey,
      256
    );
    const handshakeTime = performance.now() - handshakeStart;

    return {
      name: "Standard ECC",
      type: "classical",
      keyGenTime,
      handshakeTime,
      payloadSize: 65, // P-256 raw public key is 65 bytes (uncompressed)
      securityLevel: "128-bit (Classical)",
      pqcProtected: false,
    };
  };

  const benchmarkModern = async (): Promise<BenchmarkResult> => {
    const start = performance.now();
    const aliceKeys = await generateExportableECDHKeyPair(); // This uses P-384
    const keyGenTime = performance.now() - start;

    const bobKeys = await generateExportableECDHKeyPair();

    const handshakeStart = performance.now();
    await deriveECDHSharedSecretFromBytes(bobKeys.privateKey, aliceKeys.publicKeyBytes);
    const handshakeTime = performance.now() - handshakeStart;

    return {
      name: "Modern ECC",
      type: "modern",
      keyGenTime,
      handshakeTime,
      payloadSize: 97, // P-384 raw public key is 97 bytes
      securityLevel: "192-bit (Classical)",
      pqcProtected: false,
    };
  };

  const benchmarkHybrid = async (): Promise<BenchmarkResult> => {
    const mlkem = await getMlKem768();

    const start = performance.now();
    // Hybrid KeyGen (ECC P-384 + ML-KEM-768)
    await generateExportableECDHKeyPair();
    await mlkem.generateKeyPair();
    const keyGenTime = performance.now() - start;

    const bobEcc = await generateExportableECDHKeyPair();
    const bobPqc = await mlkem.generateKeyPair();

    const handshakeStart = performance.now();
    // Hybrid Handshake (ECDH + ML-KEM Encapsulation)
    await deriveECDHSharedSecretFromBytes(bobEcc.privateKey, bobEcc.publicKeyBytes);
    const { ciphertext } = await mlkem.encapsulate(bobPqc.publicKey);
    const handshakeTime = performance.now() - handshakeStart;

    return {
      name: "Cipher Hybrid",
      type: "hybrid",
      keyGenTime,
      handshakeTime,
      payloadSize: 97 + 1184 + 1088, // ECC Pub + Kyber Pub + Kyber CT
      securityLevel: "192-bit (Quantum Safe)",
      pqcProtected: true,
    };
  };

  const maxHandshake = Math.max(...results.map(r => r.handshakeTime), 1);
  const maxSize = Math.max(...results.map(r => r.payloadSize), 1);

  return (
    <div className="benchmark-container">
      <header className="benchmark-header">
        <h1>Cipher Crypto Testbench</h1>
        <p className="benchmark-intro">Comparing Hybrid Post-Quantum Measures vs. Traditional ECC</p>
      </header>

      <div className="benchmark-grid">
        {results.length > 0 ? (
          results.map((res) => (
            <div key={res.type} className={`benchmark-card profile-${res.type}`}>
              <h3>
                {res.pqcProtected ? <Shield size={20} className="text-success" /> : <Zap size={20} className="text-warning" />}
                {res.name}
                <span className={`profile-tag tag-${res.type}`}>{res.type}</span>
              </h3>
              
              <div className="metric-group">
                <div className="metric-item">
                  <span>Key Generation</span>
                  <span className="metric-value">
                    {res.keyGenTime.toFixed(2)}<span className="metric-unit">ms</span>
                  </span>
                </div>
                <div className="metric-item">
                  <span>Handshake Latency</span>
                  <span className="metric-value">
                    {res.handshakeTime.toFixed(2)}<span className="metric-unit">ms</span>
                  </span>
                </div>
                <div className="progress-bar-bg">
                  <div className="progress-bar-fill" style={{ width: `${(res.handshakeTime / maxHandshake) * 100}%` }}></div>
                </div>
                
                <div className="metric-item" style={{ marginTop: '1rem' }}>
                  <span>Payload Size</span>
                  <span className="metric-value">
                    {res.payloadSize}<span className="metric-unit">bytes</span>
                  </span>
                </div>
                <div className="progress-bar-bg">
                  <div className="progress-bar-fill" style={{ width: `${(res.payloadSize / maxSize) * 100}%`, background: 'var(--bench-success)' }}></div>
                </div>

                <div className="metric-item" style={{ marginTop: '1rem' }}>
                  <span>Security Target</span>
                  <span className="metric-value" style={{ color: res.pqcProtected ? 'var(--bench-success)' : 'var(--bench-warning)' }}>
                    {res.securityLevel}
                  </span>
                </div>
              </div>
            </div>
          ))
        ) : (
          <div className="benchmark-card" style={{ gridColumn: '1 / -1', textAlign: 'center', padding: '4rem' }}>
            <Activity size={48} style={{ opacity: 0.2, marginBottom: '1rem' }} />
            <p>Select profiles and run the benchmark to see performance metrics.</p>
          </div>
        )}
      </div>

      <div className="benchmark-actions">
        <button 
          className="btn-benchmark" 
          onClick={runBenchmark} 
          disabled={isRunning}
        >
          {isRunning ? `Running Benchmark (${progress}%)` : (
            <>
              <Play size={18} style={{ marginRight: '8px', verticalAlign: 'middle' }} />
              Run Performance Analysis
            </>
          )}
        </button>
      </div>

      {results.length > 0 && (
        <section className="chart-section">
          <div className="chart-title">
            <h2>Payload Overhead Comparison</h2>
            <Database size={24} />
          </div>
          <div className="size-comparison">
            {results.map(res => (
              <div key={res.name} className="size-bar-container">
                <div 
                  className="size-bar" 
                  style={{ height: `${Math.max(10, (res.payloadSize / maxSize) * 100)}%` }}
                ></div>
                <span className="size-label">{res.name} ({res.payloadSize}B)</span>
              </div>
            ))}
          </div>
          <p style={{ marginTop: '1rem', color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
            * Hybrid payloads are significantly larger due to ML-KEM-768 public keys and ciphertexts (~1KB each).
          </p>
        </section>
      )}
    </div>
  );
};

export default Benchmark;
