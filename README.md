<img width="1024" height="1024" alt="mondoshawan_project_logo" src="https://github.com/user-attachments/assets/c64dc3b4-fdd7-4a74-89c2-a78ded951675" />
# MondoShawan — Core Concepts

This repository contains two standalone algorithmic modules extracted from the
[MondoShawan](https://github.com/dev-mondoshawan/mondoshawan) post-quantum Layer 1
blockchain. They are published here to give technical reviewers a concrete look at
the engineering depth of the project without exposing the full protocol implementation.

The full codebase (consensus, EVM, P2P networking, sharding) is available for review
under NDA or by arrangement. Contact: **DM [@DevMondoshawan](https://twitter.com/DevMondoshawan)**.

---

## What Is MondoShawan?

MondoShawan is a Layer 1 blockchain combining three proven technologies into a single
production-ready protocol:

| Pillar | Technology | Proven By |
|--------|-----------|-----------|
| **Consensus** | GhostDAG (BlockDAG) | Kaspa ($874M market cap) |
| **Security** | ML-KEM-768 + ML-DSA (NIST FIPS 203/204) | NIST post-quantum standards |
| **Programmability** | EVM (SputnikVM, Shanghai hard fork) | Ethereum ecosystem |

**No other Layer 1 combines all three.** Kaspa has GhostDAG but no PQC and no EVM.
Ethereum has EVM but no GhostDAG and no PQC. MondoShawan is the first to integrate all three.

A live multi-node testnet is running between two datacenters, producing blocks at a
~10-11s median interval with real cryptographic Proof-of-Work and a fully functional
EVM RPC surface (MetaMask compatible, 129+ JSON-RPC methods).

---

## Module 1: `pow_simd.rs` — B3MemHash with SIMD-Accelerated Memory Mixing

### What It Does

`B3MemHash` is a memory-hard hash function built on Blake3. It is used in **Stream B**
of MondoShawan's BraidCore Proof-of-Work architecture to provide ASIC resistance while. **BraidCore** — Mondoshawan's multi-stream mining architecture where three parallel mining streams (A, B, C) cross-reference each other at the parent level, braiding into a single GhostDAG consensus layer.
keeping mining accessible to consumer CPUs and GPUs.

The memory mixing step — the inner loop bottleneck — uses automatic SIMD dispatch:

```
AVX2  → 32 bytes per _mm256_xor_si256 instruction  (8× scalar)
SSE2  → 16 bytes per _mm_xor_si128 instruction      (4× scalar)
Scalar → 8 bytes per u64 XOR word operation          (always available)
```

Runtime detection via `is_x86_feature_detected!` selects the fastest available path
without requiring a specific compile target.

### Difficulty Adjustment Algorithm (DAA)

The DAA uses fixed-point arithmetic (×1000) to avoid floating-point in consensus-critical
code. The adjustment ratio is clamped to **[0.667×, 1.5×]** per epoch to prevent
oscillation. A moving-average variant averages the last N block times for production stability.

This DAA was tuned live on the testnet to eliminate oscillation at `INITIAL_DIFFICULTY_A = 20`,
producing stable ~10-11s block times between two datacenter nodes.

### BraidCore Architecture

```
Stream A (Blake3)     → ASIC-friendly, ~10s target
Stream B (B3MemHash)  → CPU/GPU, ~5s target, memory-hard
Stream C (ZK fees)    → Validator nodes, fee-based only
```

The three streams run in parallel, with each contributing to the GhostDAG block ordering.
This balances hardware accessibility, ASIC resistance, and ZK-proof integration.

---

## Module 2: `kyber_transport.rs` — ML-KEM-768 Post-Quantum P2P Key Exchange

### What It Does

Every peer connection in MondoShawan is secured with a forward-secret session key
derived via **ML-KEM-768** (CRYSTALS-Kyber), the NIST FIPS 203 standard for
post-quantum key encapsulation. The handshake runs over a dedicated QUIC stream
after TLS 1.3 connection establishment.

### Why This Matters

Classical ECDH key exchange is vulnerable to "harvest now, decrypt later" attacks.
An adversary can record encrypted peer traffic today and decrypt it once a sufficiently
powerful quantum computer is available. ML-KEM-768 provides **IND-CCA2 security**
against quantum adversaries, making MondoShawan's P2P layer quantum-safe from the
first packet.

### ML-KEM-768 Parameters (NIST FIPS 203)

| Parameter | Value | Notes |
|-----------|-------|-------|
| Public key | 1184 bytes | Encapsulation key |
| Ciphertext | 1088 bytes | Sent by initiator |
| Session key | 32 bytes | AES-256 compatible |
| Security | 128-bit post-quantum | 256-bit classical equivalent |

### Handshake Protocol

```
Initiator                          Responder
   |                                   |
   |--- public_key (1184 B) ---------->|
   |<-- public_key (1184 B) -----------|
   |                                   |
   |--- ciphertext (1088 B) ---------->|  [encapsulated shared secret]
   |<-- ACK (1 B) ---------------------|  [decapsulation confirmed]
   |                                   |
   Both sides hold the same 32-byte SessionKey
```

### Broader Security Model

The Kyber handshake is one layer of a defence-in-depth P2P security model:

- **TOFU identity** — Each node's Ed25519 public key is embedded in its self-signed
  TLS certificate SAN. Peers are identified by cryptographic key, not IP address.
- **Subnet diversity** — At most 3 peers accepted from the same `/16` subnet
  (eclipse attack prevention).
- **Jaccard Sybil detection** — Peers with >80% overlap in their advertised peer
  lists are flagged as potential Sybil clusters.
- **Outbound slot reservation** — 70% of peer slots reserved for outbound connections
  to prevent inbound flooding.

---

## Network Security Architecture

The `kyber_transport.rs` module is one layer of a five-layer defense-in-depth P2P security model:

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| Transport | QUIC + TLS 1.3 | Wire encryption |
| Identity | Ed25519 + TOFU | Peer authentication |
| Messages | Ed25519 signatures | Per-message auth + replay protection |
| Network | Subnet limits + reputation scoring | Sybil/eclipse prevention |
| Post-Quantum | ML-KEM-768 | Quantum-resistant forward secrecy |

The ML-KEM-768 implementation in Module 2 provides the post-quantum layer, protecting against "harvest now, decrypt later" attacks where adversaries record encrypted traffic today for future quantum decryption.

See [docs/NETWORK_SECURITY.md](docs/NETWORK_SECURITY.md) for the full specification, including the HKDF domain separation protocol, reputation scoring model, and ban system.

---

## Running the Tests

```bash
git clone https://github.com/dev-mondoshawan/mondoshawan-core-concepts
cd mondoshawan-core-concepts
cargo test
```

Expected output:
```
test pow_simd::tests::test_meets_difficulty_zero_hash ... ok
test pow_simd::tests::test_xor_bytes_scalar_correctness ... ok
test pow_simd::tests::test_xor_bytes_identity ... ok
test pow_simd::tests::test_daa_speeds_up_when_too_fast ... ok
test pow_simd::tests::test_daa_slows_down_when_too_slow ... ok
test pow_simd::tests::test_daa_max_cap ... ok
test pow_simd::tests::test_daa_moving_average_stability ... ok
test pow_simd::tests::test_b3memhash_deterministic ... ok
test pow_simd::tests::test_b3memhash_different_inputs ... ok
test kyber_transport::tests::test_session_key_roundtrip ... ok
test kyber_transport::tests::test_encapsulate_wrong_key_size ... ok
test kyber_transport::tests::test_decapsulate_wrong_ciphertext_size ... ok
test kyber_transport::tests::test_key_size_constants ... ok
```

---

## What Is Not Here

This repository intentionally omits:

- The GhostDAG consensus implementation (blue score calculation, DAG ordering)
- The full P2P networking stack (QUIC transport, gossip protocol, IBD sync)
- The EVM integration (SputnikVM, JSON-RPC surface, receipt system)
- The sharding layer and cross-shard transaction protocol
- The account abstraction implementation

These components are available for review under NDA. Contact via DM to arrange access.

---

## License

This code is published under the **Business Source License 1.1**.

- **Licensor:** Mondoshawan Project
- **Licensed Work:** MondoShawan Core Concepts v0.1.0
- **Change Date:** April 1, 2030
- **Change License:** Apache 2.0

Non-production use (research, study, personal projects) is permitted. Commercial use
or deployment requires a separate license until the Change Date, after which the
Apache 2.0 license applies automatically.

See [LICENSE](LICENSE) for full terms.

---

## Contact

- **Twitter/X:** [@DevMondoshawan](https://twitter.com/DevMondoshawan)
- **GitHub:** [dev-mondoshawan](https://github.com/dev-mondoshawan)
- **Testnet Explorer:** explorer.mondoshawan.io
