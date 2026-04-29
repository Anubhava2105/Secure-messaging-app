# Hybrid vs Classical Handshake Benchmark Report

Generated at: 2026-04-21T03:38:33.096Z
Node: v22.13.0
Platform: win32 x64
CPU: AMD Ryzen 5 5600H with Radeon Graphics         

## Configuration

- Warmup iterations: 8
- Measured iterations: 40
- Classical baseline: P-384 ECDH X3DH-style DH terms + HKDF-SHA-384
- Hybrid: Same classical path + ML-KEM-768 encapsulation/decapsulation + HKDF-SHA-384

## Latency Summary

| Variant | Mean | P50 | P95 | Min | Max | StdDev |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Classical | 8.767 ms | 8.719 ms | 9.242 ms | 8.308 ms | 9.507 ms | 0.270 ms |
| Hybrid | 10.003 ms | 9.805 ms | 10.842 ms | 9.284 ms | 11.345 ms | 0.499 ms |

Hybrid overhead vs classical (mean): 14.10%

## Interpretation

- This benchmark quantifies runtime cost of adding PQC KEM operations to the existing classical handshake.
- Security benefit of hybrid mode is long-horizon risk reduction (harvest-now-decrypt-later), while this report captures the latency tradeoff.
