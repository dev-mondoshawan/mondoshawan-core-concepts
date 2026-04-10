//! # Post-Quantum P2P Key Exchange — ML-KEM-768 (Kyber) over QUIC
//!
//! This module demonstrates the post-quantum key exchange layer used in
//! MondoShawan's P2P networking stack. Every peer connection is secured with
//! a forward-secret session key derived via ML-KEM-768 (CRYSTALS-Kyber),
//! the NIST-standardized post-quantum KEM.
//!
//! ## Why Post-Quantum Key Exchange?
//!
//! Classical Diffie-Hellman and ECDH key exchange are vulnerable to "harvest now,
//! decrypt later" attacks: an adversary can record encrypted traffic today and
//! decrypt it once a sufficiently powerful quantum computer is available. For a
//! blockchain network, this means historical peer communications (including block
//! propagation and mempool gossip) could be retroactively exposed.
//!
//! ML-KEM-768 provides IND-CCA2 security against quantum adversaries. Combined
//! with QUIC's TLS 1.3 transport encryption, every MondoShawan peer connection
//! is quantum-safe from the first packet.
//!
//! ## ML-KEM-768 Parameters
//!
//! | Parameter         | Value  | Notes                              |
//! |-------------------|--------|------------------------------------|
//! | Public key size   | 1184 B | Encapsulation key                  |
//! | Ciphertext size   | 1088 B | Sent by initiator to responder     |
//! | Session key size  | 32 B   | Shared secret (AES-256 compatible) |
//! | Security level    | 128-bit post-quantum / 256-bit classical |
//!
//! ## Handshake Protocol
//!
//! The handshake runs over a dedicated QUIC stream (stream type `0x03`) after
//! the TLS 1.3 connection is established. The protocol is:
//!
//! ```text
//! Initiator                          Responder
//!    |                                   |
//!    |--- our_public_key (1184 B) ------>|
//!    |<-- their_public_key (1184 B) -----|
//!    |                                   |
//!    | [Initiator encapsulates using     |
//!    |  responder's public key]          |
//!    |                                   |
//!    |--- ciphertext (1088 B) ---------->|
//!    |                                   |
//!    |   [Responder decapsulates using   |
//!    |    its secret key]                |
//!    |                                   |
//!    |<-- ACK (1 B) ---------------------|
//!    |                                   |
//!    Both sides now hold the same        |
//!    32-byte session key.                |
//! ```
//!
//! After the handshake, the session key is used to derive an AES-256-GCM key
//! for encrypting application-layer messages (block gossip, mempool sync, etc.).
//!
//! ## Sybil and Eclipse Attack Mitigations
//!
//! The key exchange is one layer of a broader peer security model:
//!
//! - **TOFU identity** — Each node's Ed25519 public key is embedded in its
//!   self-signed TLS certificate SAN. Peers are identified by their Ed25519 key,
//!   not by IP address.
//! - **Subnet diversity** — At most 3 peers are accepted from the same `/16`
//!   subnet, preventing eclipse attacks from a single network prefix.
//! - **Jaccard Sybil detection** — Peers with >80% overlap in their advertised
//!   peer lists are flagged as potential Sybil clusters.
//! - **Outbound slot reservation** — 70% of peer slots are reserved for
//!   outbound connections to prevent inbound flooding.

use serde::{Deserialize, Serialize};

// ============================================================================
// ML-KEM-768 Key Sizes (NIST FIPS 203)
// ============================================================================

/// ML-KEM-768 encapsulation key (public key) size in bytes.
pub const KYBER_PUBLIC_KEY_SIZE: usize = 1184;

/// ML-KEM-768 ciphertext size in bytes.
pub const KYBER_CIPHERTEXT_SIZE: usize = 1088;

/// Derived session key size in bytes (AES-256 compatible).
pub const SESSION_KEY_SIZE: usize = 32;

// ============================================================================
// Session Key
// ============================================================================

/// A 32-byte session key derived from the Kyber key exchange.
///
/// This key is used to initialize an AES-256-GCM cipher for encrypting
/// all subsequent application-layer messages on the peer connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKey(pub [u8; SESSION_KEY_SIZE]);

impl SessionKey {
    /// Wrap raw bytes into a `SessionKey`.
    pub fn new(key: [u8; SESSION_KEY_SIZE]) -> Self {
        Self(key)
    }

    /// Access the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; SESSION_KEY_SIZE] {
        &self.0
    }
}

// ============================================================================
// KyberKeyExchange — ML-KEM-768 Wrapper
// ============================================================================

/// ML-KEM-768 keypair for post-quantum P2P key exchange.
///
/// Each node generates a fresh `KyberKeyExchange` on startup. The public key
/// is exchanged with every peer during the handshake; the secret key never
/// leaves the local process.
///
/// # Cross-Platform Support
///
/// - **Linux/macOS** — Uses the `ml-kem` crate (pure Rust, NIST reference implementation).
/// - **Windows** — Uses `pqcrypto-kyber` (C bindings to the NIST submission).
///
/// Both backends produce identical wire-format keys and ciphertexts.
#[derive(Clone)]
pub struct KyberKeyExchange {
    /// ML-KEM-768 encapsulation key (public, 1184 bytes)
    public_key: Vec<u8>,
    /// ML-KEM-768 decapsulation key (private, never transmitted)
    secret_key: Vec<u8>,
}

impl KyberKeyExchange {
    /// Generate a fresh ML-KEM-768 keypair using the OS CSPRNG.
    ///
    /// This is a CPU-bound operation (~0.5ms on modern hardware). In async
    /// contexts, call `generate_async()` to avoid blocking the executor.
    pub fn generate_stub() -> Self {
        // NOTE: This is a size-correct stub for illustration.
        // The production implementation uses ml_kem::MlKem768::generate_keypair_from_rng()
        // on Linux/macOS and pqcrypto_kyber::kyber768::keypair() on Windows.
        Self {
            public_key: vec![0u8; KYBER_PUBLIC_KEY_SIZE],
            secret_key: vec![0u8; 64], // ml-kem uses 64-byte seed-based secret keys
        }
    }

    /// Return the public key bytes (1184 bytes for ML-KEM-768).
    ///
    /// This is sent to the peer during the handshake.
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    /// Encapsulate a shared secret using the peer's public key (initiator side).
    ///
    /// Returns `(ciphertext, session_key)`. The ciphertext (1088 bytes) is sent
    /// to the responder; the session key (32 bytes) is held locally.
    ///
    /// # Errors
    /// Returns an error if `peer_public_key` is not exactly `KYBER_PUBLIC_KEY_SIZE` bytes
    /// or if the key cannot be deserialized.
    pub fn encapsulate(&self, peer_public_key: &[u8]) -> Result<(Vec<u8>, SessionKey), String> {
        if peer_public_key.len() != KYBER_PUBLIC_KEY_SIZE {
            return Err(format!(
                "Invalid public key size: expected {}, got {}",
                KYBER_PUBLIC_KEY_SIZE,
                peer_public_key.len()
            ));
        }
        // Production: ek.encapsulate_with_rng(&mut rng) → (ciphertext, shared_key)
        // Stub: return zeroed values for illustration
        let ciphertext = vec![0u8; KYBER_CIPHERTEXT_SIZE];
        let session_key = SessionKey::new([0u8; SESSION_KEY_SIZE]);
        Ok((ciphertext, session_key))
    }

    /// Decapsulate a ciphertext to recover the shared secret (responder side).
    ///
    /// Returns the `SessionKey` that matches the one produced by the initiator's
    /// `encapsulate()` call.
    ///
    /// # Errors
    /// Returns an error if `ciphertext` is not exactly `KYBER_CIPHERTEXT_SIZE` bytes.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<SessionKey, String> {
        if ciphertext.len() != KYBER_CIPHERTEXT_SIZE {
            return Err(format!(
                "Invalid ciphertext size: expected {}, got {}",
                KYBER_CIPHERTEXT_SIZE,
                ciphertext.len()
            ));
        }
        // Production: dk.decapsulate(&ct) → shared_key
        // Stub: return zeroed value for illustration
        Ok(SessionKey::new([0u8; SESSION_KEY_SIZE]))
    }
}

// ============================================================================
// Handshake Protocol
// ============================================================================

/// Role in the Kyber key exchange handshake.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KyberRole {
    /// Sends public key first, then encapsulates and sends ciphertext.
    Initiator,
    /// Receives public key first, then sends its own key and an ACK.
    Responder,
}

/// Perform a Kyber key exchange handshake over a bidirectional byte stream.
///
/// This function implements the full two-round protocol described in the module
/// documentation. In production, `send` and `recv` are QUIC stream handles
/// (`quinn::SendStream` / `quinn::RecvStream`). The function is generic over
/// any `AsyncWrite + AsyncRead` pair for testability.
///
/// # Protocol Summary
///
/// ```text
/// Initiator → Responder: public_key (1184 B)
/// Responder → Initiator: public_key (1184 B)
/// Initiator → Responder: ciphertext (1088 B)   [encapsulated shared secret]
/// Responder → Initiator: ACK (1 B)             [decapsulation confirmed]
/// ```
///
/// Both sides derive the same 32-byte `SessionKey` at the end.
///
/// # Arguments
/// * `send` — writable half of the QUIC stream
/// * `recv` — readable half of the QUIC stream
/// * `role` — whether this node is the connection initiator or responder
/// * `our_kyber` — this node's ML-KEM-768 keypair
///
/// # Returns
/// The shared `SessionKey` on success, or a descriptive error string on failure.
pub async fn perform_kyber_handshake<W, R>(
    send: &mut W,
    recv: &mut R,
    role: KyberRole,
    our_kyber: KyberKeyExchange,
) -> Result<SessionKey, String>
where
    W: tokio::io::AsyncWriteExt + Unpin,
    R: tokio::io::AsyncReadExt + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    match role {
        KyberRole::Initiator => {
            // Round 1: Send our public key
            send.write_all(our_kyber.public_key_bytes())
                .await
                .map_err(|e| format!("Failed to send public key: {}", e))?;

            // Round 1: Receive responder's public key
            let mut peer_pk = [0u8; KYBER_PUBLIC_KEY_SIZE];
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                recv.read_exact(&mut peer_pk),
            )
            .await
            .map_err(|_| "Timeout waiting for responder public key".to_string())?
            .map_err(|e| format!("Failed to receive responder public key: {}", e))?;

            // Encapsulate: derive ciphertext + session key
            let (ciphertext, session_key) = our_kyber.encapsulate(&peer_pk)?;

            // Round 2: Send ciphertext to responder
            send.write_all(&ciphertext)
                .await
                .map_err(|e| format!("Failed to send ciphertext: {}", e))?;

            // Round 2: Wait for ACK confirming successful decapsulation
            let mut ack = [0u8; 1];
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                recv.read_exact(&mut ack),
            )
            .await
            .map_err(|_| "Timeout waiting for ACK".to_string())?
            .map_err(|e| format!("Failed to receive ACK: {}", e))?;

            if ack[0] != 0x01 {
                return Err(format!("Unexpected ACK byte: 0x{:02x}", ack[0]));
            }

            Ok(session_key)
        }

        KyberRole::Responder => {
            // Round 1: Receive initiator's public key
            let mut peer_pk = [0u8; KYBER_PUBLIC_KEY_SIZE];
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                recv.read_exact(&mut peer_pk),
            )
            .await
            .map_err(|_| "Timeout waiting for initiator public key".to_string())?
            .map_err(|e| format!("Failed to receive initiator public key: {}", e))?;

            // Round 1: Send our public key
            send.write_all(our_kyber.public_key_bytes())
                .await
                .map_err(|e| format!("Failed to send public key: {}", e))?;

            // Round 2: Receive ciphertext from initiator
            let mut ct_buf = [0u8; KYBER_CIPHERTEXT_SIZE];
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                recv.read_exact(&mut ct_buf),
            )
            .await
            .map_err(|_| "Timeout waiting for ciphertext".to_string())?
            .map_err(|e| format!("Failed to receive ciphertext: {}", e))?;

            // Decapsulate: recover session key
            let session_key = our_kyber.decapsulate(&ct_buf)?;

            // Round 2: Send ACK to confirm successful decapsulation
            send.write_all(&[0x01u8])
                .await
                .map_err(|e| format!("Failed to send ACK: {}", e))?;

            Ok(session_key)
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_key_roundtrip() {
        let key_bytes = [42u8; SESSION_KEY_SIZE];
        let key = SessionKey::new(key_bytes);
        assert_eq!(key.as_bytes(), &key_bytes);
    }

    #[test]
    fn test_encapsulate_wrong_key_size() {
        let kyber = KyberKeyExchange::generate_stub();
        let bad_key = vec![0u8; 100]; // Wrong size
        let result = kyber.encapsulate(&bad_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid public key size"));
    }

    #[test]
    fn test_decapsulate_wrong_ciphertext_size() {
        let kyber = KyberKeyExchange::generate_stub();
        let bad_ct = vec![0u8; 100]; // Wrong size
        let result = kyber.decapsulate(&bad_ct);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid ciphertext size"));
    }

    #[test]
    fn test_key_size_constants() {
        // Verify NIST FIPS 203 ML-KEM-768 parameter sizes
        assert_eq!(KYBER_PUBLIC_KEY_SIZE, 1184);
        assert_eq!(KYBER_CIPHERTEXT_SIZE, 1088);
        assert_eq!(SESSION_KEY_SIZE, 32);
    }
}
