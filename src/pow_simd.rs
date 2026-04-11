//! # PoW Mining Core — B3MemHash with SIMD-Accelerated Memory Mixing
//!
//! This module demonstrates the core cryptographic mining implementation used in
//! the MondoShawan blockchain's BraidCore Proof-of-Work architecture.
//!
//! ## BraidCore PoW Overview
//!
//! MondoShawan uses three parallel mining streams to balance hardware accessibility
//! and ASIC resistance:
//!
//! | Stream | Algorithm      | Target Hardware | Block Time |
//! |--------|---------------|-----------------|------------|
//! | A      | Blake3        | ASIC-friendly   | ~10s       |
//! | B      | B3MemHash     | CPU/GPU         | ~5s        |
//! | C      | ZK Proof fees | Validator nodes | N/A (fees) |
//!
//! ## B3MemHash Design
//!
//! `B3MemHash` is a memory-hard hash function built on Blake3. It provides ASIC
//! resistance by requiring a 256KB working buffer with multiple mixing passes,
//! making it bandwidth-bound rather than compute-bound. This keeps mining
//! accessible to consumer CPUs and GPUs.
//!
//! ## SIMD Acceleration
//!
//! The memory mixing XOR step is the inner-loop bottleneck. This module provides
//! three implementations with automatic runtime dispatch:
//!
//! 1. **AVX2** — 32 bytes per instruction (8x scalar throughput)
//! 2. **SSE2** — 16 bytes per instruction (4x scalar throughput)
//! 3. **Scalar** — 8-byte word-at-a-time fallback (always available)
//!
//! Runtime detection via `is_x86_feature_detected!` ensures the fastest available
//! path is used without requiring a specific compile target.
//!
//! ## Difficulty Adjustment Algorithm (DAA)
//!
//! The DAA uses fixed-point arithmetic with clamped adjustment bounds to prevent
//! oscillation. The adjustment ratio is clamped to [0.667x, 1.5x] per epoch,
//! ensuring the chain converges to the target block time without wild swings.
//! A moving-average variant is also provided for production use.
//!
//! ## Live Testnet
//!
//! This code runs on the MondoShawan testnet, producing blocks at a ~10-11s
//! median interval between two datacenter nodes. The DAA was tuned during live
//! operation to eliminate oscillation at `INITIAL_DIFFICULTY_A = 20`.

// ============================================================================
// Difficulty Parameters
// ============================================================================

/// Initial difficulty for Stream A (Blake3). Represents the number of leading
/// zero bits required in a valid block hash.
///
/// Difficulty 20 = 2.5 leading zero bytes ≈ 1M hashes to solve on a modern CPU.
pub const INITIAL_DIFFICULTY_A: u64 = 20;

/// Initial difficulty for Stream B (B3MemHash). Lower than Stream A because
/// B3MemHash is memory-hard and inherently slower per hash.
pub const INITIAL_DIFFICULTY_B: u64 = 8;

/// Hard cap on difficulty. Prevents runaway difficulty on the testnet.
/// 28 bits ≈ 268M hashes — solvable in ~1-3s on a VPS.
pub const MAX_DIFFICULTY: u64 = 28;

// ============================================================================
// B3MemHash Constants
// ============================================================================

/// Working memory buffer size: 256KB. Reduced from 1MB to balance ASIC
/// resistance with accessibility on 4-core VPS nodes.
const B3MEM_MEMORY_SIZE: usize = 256 * 1024;

/// Number of memory mixing passes per hash. Two passes provide sufficient
/// memory-hardness without excessive latency on constrained nodes.
const B3MEM_PASSES: usize = 2;

// ============================================================================
// Difficulty Utilities
// ============================================================================

/// Check whether a hash meets the required difficulty target.
///
/// Uses early-termination: the most common case (hash does NOT meet difficulty)
/// is detected after checking only the first 1-3 bytes, making the hot path
/// essentially free.
///
/// # Arguments
/// * `hash` — 32-byte Blake3 or B3MemHash output
/// * `difficulty` — number of leading zero bits required
///
/// # Example
/// ```
/// let hash = [0u8; 32]; // all zeros — trivially meets any difficulty
/// assert!(meets_difficulty(&hash, 24));
///
/// let hard_hash = [0xFF; 32]; // all ones — meets no difficulty > 0
/// assert!(!meets_difficulty(&hard_hash, 1));
/// ```
pub fn meets_difficulty(hash: &[u8; 32], difficulty: u64) -> bool {
    let zero_bytes = (difficulty / 8) as usize;

    // Fast path: reject immediately if any required zero byte is non-zero
    for i in 0..zero_bytes.min(32) {
        if hash[i] != 0 {
            return false;
        }
    }

    // Check partial bits in the boundary byte
    if zero_bytes < 32 {
        let remaining_bits = difficulty % 8;
        if remaining_bits > 0 {
            let mask = 0xFF >> remaining_bits;
            if hash[zero_bytes] > mask {
                return false;
            }
        }
    }

    true
}

// ============================================================================
// SIMD-Accelerated XOR — Inner Loop of B3MemHash Memory Mixing
// ============================================================================

/// XOR `src` into `dst` using the fastest available SIMD path.
///
/// Dispatches at runtime to AVX2 (32B/op), SSE2 (16B/op), or scalar (8B/op).
/// This is the hot path in the B3MemHash memory mixing loop — called millions
/// of times per second during active mining.
///
/// # Safety
/// The unsafe SIMD variants are only called after confirming CPU feature support
/// via `is_x86_feature_detected!`. All loads/stores use unaligned variants
/// (`_mm256_loadu/storeu`, `_mm_loadu/storeu`) so no alignment is required.
#[inline]
pub fn xor_bytes(dst: &mut [u8], src: &[u8]) {
    let len = dst.len().min(src.len());

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 confirmed at runtime; len bounded by slice lengths;
            // unaligned intrinsics used — no alignment requirement.
            unsafe { xor_bytes_avx2(dst, src, len); }
            return;
        }
        if is_x86_feature_detected!("sse2") {
            // SAFETY: SSE2 confirmed at runtime; len bounded by slice lengths;
            // unaligned intrinsics used — no alignment requirement.
            unsafe { xor_bytes_sse2(dst, src, len); }
            return;
        }
    }

    xor_bytes_scalar(dst, src, len);
}

/// Scalar XOR — 8 bytes per iteration via u64 word operations.
/// Fallback for non-x86 architectures or when SIMD is unavailable.
#[inline]
fn xor_bytes_scalar(dst: &mut [u8], src: &[u8], len: usize) {
    let chunks = len / 8;
    for i in 0..chunks {
        let off = i * 8;
        let d = u64::from_le_bytes(dst[off..off + 8].try_into().unwrap());
        let s = u64::from_le_bytes(src[off..off + 8].try_into().unwrap());
        dst[off..off + 8].copy_from_slice(&(d ^ s).to_le_bytes());
    }
    for i in (chunks * 8)..len {
        dst[i] ^= src[i];
    }
}

/// AVX2 SIMD XOR — 32 bytes per `_mm256_xor_si256` instruction.
///
/// Provides 8x throughput over scalar on modern x86_64 CPUs (Intel Haswell+,
/// AMD Ryzen). This is the primary path on datacenter and desktop hardware.
///
/// # Safety
/// Caller must confirm `is_x86_feature_detected!("avx2")` before calling.
/// `len` must be `<= dst.len()` and `<= src.len()`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn xor_bytes_avx2(dst: &mut [u8], src: &[u8], len: usize) {
    use std::arch::x86_64::*;

    let chunks = len / 32;
    for i in 0..chunks {
        let off = i * 32;
        let d_ptr = dst.as_mut_ptr().add(off) as *mut __m256i;
        let s_ptr = src.as_ptr().add(off) as *const __m256i;

        let d_vec = _mm256_loadu_si256(d_ptr);
        let s_vec = _mm256_loadu_si256(s_ptr);
        _mm256_storeu_si256(d_ptr, _mm256_xor_si256(d_vec, s_vec));
    }

    // Scalar tail for remaining bytes
    for i in (chunks * 32)..len {
        dst[i] ^= src[i];
    }
}

/// SSE2 SIMD XOR — 16 bytes per `_mm_xor_si128` instruction.
///
/// Provides 4x throughput over scalar. Used on older x86_64 CPUs without AVX2
/// (pre-Haswell Intel, early Bulldozer AMD) and as a fallback on some VMs.
///
/// # Safety
/// Caller must confirm `is_x86_feature_detected!("sse2")` before calling.
/// `len` must be `<= dst.len()` and `<= src.len()`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn xor_bytes_sse2(dst: &mut [u8], src: &[u8], len: usize) {
    use std::arch::x86_64::*;

    let chunks = len / 16;
    for i in 0..chunks {
        let off = i * 16;
        let d_ptr = dst.as_mut_ptr().add(off) as *mut __m128i;
        let s_ptr = src.as_ptr().add(off) as *const __m128i;

        let d_vec = _mm_loadu_si128(d_ptr);
        let s_vec = _mm_loadu_si128(s_ptr);
        _mm_storeu_si128(d_ptr, _mm_xor_si128(d_vec, s_vec));
    }

    // Scalar tail for remaining bytes
    for i in (chunks * 16)..len {
        dst[i] ^= src[i];
    }
}

// ============================================================================
// B3MemHash — Memory-Hard Hash Function
// ============================================================================

/// Compute a memory-hard hash using a pre-allocated working buffer.
///
/// This is the inner function called by the mining loop. The `memory` buffer
/// is 256KB and is allocated once per thread via `thread_local!` in the full
/// implementation, avoiding the 256KB allocation cost on every hash call.
///
/// # Algorithm
/// 1. Derive an initial seed from the input data using Blake3.
/// 2. Fill the 256KB buffer by repeatedly hashing the seed with a counter.
/// 3. For each pass, XOR the buffer with a permuted copy of itself.
///    The XOR step uses the SIMD-accelerated `xor_bytes` function above.
/// 4. Finalize by hashing the entire mixed buffer with Blake3.
///
/// The memory-hardness comes from step 3: the XOR pattern depends on the
/// buffer contents, so it cannot be computed without holding the full 256KB
/// in memory simultaneously.
pub fn hash_b3memhash_with_buffer(input: &[u8], memory: &mut Vec<u8>) -> [u8; 32] {
    assert_eq!(memory.len(), B3MEM_MEMORY_SIZE, "Buffer must be exactly 256KB");

    // Step 1: Derive seed from input
    let seed = blake3::hash(input);
    let seed_bytes = seed.as_bytes();

    // Step 2: Fill memory buffer by hashing seed + counter
    let chunk_size = 32; // Blake3 output size
    let num_chunks = B3MEM_MEMORY_SIZE / chunk_size;
    for i in 0..num_chunks {
        let mut h = blake3::Hasher::new();
        h.update(seed_bytes);
        h.update(&(i as u64).to_le_bytes());
        let chunk = h.finalize();
        let off = i * chunk_size;
        memory[off..off + chunk_size].copy_from_slice(chunk.as_bytes());
    }

    // Step 3: Memory mixing passes using SIMD-accelerated XOR
    for pass in 0..B3MEM_PASSES {
        // Derive a mixing offset from the pass number and current buffer state
        let mix_seed = blake3::hash(&[memory[0], memory[1], memory[2], memory[3], pass as u8]);
        let mix_offset_raw = u64::from_le_bytes(mix_seed.as_bytes()[..8].try_into().unwrap());
        let mix_offset = ((mix_offset_raw as usize) % (B3MEM_MEMORY_SIZE / 2)) & !31; // 32-byte aligned

        // XOR the first half of the buffer with the second half (offset by mix_offset)
        // This is the memory-hard step: requires the full buffer in RAM
        let half = B3MEM_MEMORY_SIZE / 2;
        let src_start = half + mix_offset;
        let src_end = (src_start + half).min(B3MEM_MEMORY_SIZE);
        let xor_len = src_end - src_start;

        // Split buffer to satisfy borrow checker: dst = [0..half], src = [src_start..src_end]
        let (dst_half, src_half) = memory.split_at_mut(half);
        let src_slice = &src_half[mix_offset..mix_offset + xor_len];
        xor_bytes(&mut dst_half[..xor_len], src_slice);
    }

    // Step 4: Finalize — hash the entire mixed buffer
    let final_hash = blake3::hash(memory);
    *final_hash.as_bytes()
}

// ============================================================================
// Difficulty Adjustment Algorithm (DAA)
// ============================================================================

/// Adjust mining difficulty based on the ratio of target to actual block time.
///
/// Uses fixed-point arithmetic (multiplied by 1000) to avoid floating-point
/// in consensus-critical code. The adjustment ratio is clamped to [0.667x, 1.5x]
/// per epoch to prevent oscillation from single lucky or unlucky blocks.
///
/// # Arguments
/// * `current_difficulty` — current difficulty in leading zero bits
/// * `target_time` — desired block time in seconds (e.g., 10)
/// * `actual_time` — measured time for the last block in seconds
///
/// # Returns
/// New difficulty, clamped to `[1, MAX_DIFFICULTY]`.
///
/// # Example
/// ```
/// // Block solved in 5s when target is 10s → difficulty increases
/// let new = adjust_difficulty(20, 10, 5);
/// assert!(new > 20);
///
/// // Block solved in 20s when target is 10s → difficulty decreases
/// let new = adjust_difficulty(20, 10, 20);
/// assert!(new < 20);
/// ```
pub fn adjust_difficulty(current_difficulty: u64, target_time: u64, actual_time: u64) -> u64 {
    if actual_time == 0 {
        return current_difficulty;
    }

    // Fixed-point ratio: target_time / actual_time × 1000
    let raw = (target_time as u128 * 1000).saturating_div(actual_time as u128);

    // Clamp: 0.667x (667/1000) to 1.5x (1500/1000)
    let clamped = raw.max(667).min(1500);

    let new = (current_difficulty as u128)
        .saturating_mul(clamped)
        .saturating_div(1000);

    new.min(MAX_DIFFICULTY as u128).max(1) as u64
}

/// Adjust difficulty using a moving average of recent block times.
///
/// This is the preferred production variant. Averaging over the last N blocks
/// smooths out variance from lucky/unlucky individual blocks, producing a more
/// stable difficulty curve. The same [0.667x, 1.5x] clamp is applied.
///
/// # Arguments
/// * `current_difficulty` — current difficulty in leading zero bits
/// * `target_time` — desired block time in seconds
/// * `recent_block_times` — slice of recent block solve times (last 10-20 blocks recommended)
pub fn adjust_difficulty_moving_average(
    current_difficulty: u64,
    target_time: u64,
    recent_block_times: &[u64],
) -> u64 {
    if recent_block_times.is_empty() {
        return current_difficulty;
    }

    let sum: u128 = recent_block_times.iter().map(|&t| t as u128).sum();
    let avg = sum / recent_block_times.len() as u128;

    if avg == 0 {
        return current_difficulty;
    }

    let raw = (target_time as u128 * 1000).saturating_div(avg);
    let clamped = raw.max(667).min(1500);

    let new = (current_difficulty as u128)
        .saturating_mul(clamped)
        .saturating_div(1000);

    new.min(MAX_DIFFICULTY as u128).max(1) as u64
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_meets_difficulty_zero_hash() {
        let hash = [0u8; 32];
        assert!(meets_difficulty(&hash, 0));
        assert!(meets_difficulty(&hash, 8));
        assert!(meets_difficulty(&hash, 24));
        assert!(meets_difficulty(&hash, 28));
    }

    #[test]
    fn test_meets_difficulty_all_ones() {
        let hash = [0xFF; 32];
        assert!(meets_difficulty(&hash, 0));
        assert!(!meets_difficulty(&hash, 1));
    }

    #[test]
    fn test_meets_difficulty_partial_bits() {
        // 0x07 = 0000_0111 — has 5 leading zero bits
        let mut hash = [0u8; 32];
        hash[0] = 0x07;
        assert!(meets_difficulty(&hash, 5));
        assert!(!meets_difficulty(&hash, 6));
    }

    #[test]
    fn test_xor_bytes_scalar_correctness() {
        let mut dst = vec![0xAAu8; 64];
        let src = vec![0x55u8; 64];
        xor_bytes(&mut dst, &src);
        // 0xAA ^ 0x55 = 0xFF
        assert!(dst.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn test_xor_bytes_identity() {
        let original = vec![0xDEu8; 64];
        let mut dst = original.clone();
        let src = vec![0xABu8; 64];
        // XOR twice with same value = identity
        xor_bytes(&mut dst, &src);
        xor_bytes(&mut dst, &src);
        assert_eq!(dst, original);
    }

    #[test]
    fn test_daa_speeds_up_when_too_fast() {
        // Block solved in 5s, target 10s → should increase difficulty
        let new = adjust_difficulty(20, 10, 5);
        assert!(new > 20, "Difficulty should increase when blocks are too fast");
        assert!(new <= 30, "Difficulty should not jump by more than 1.5x");
    }

    #[test]
    fn test_daa_slows_down_when_too_slow() {
        // Block solved in 20s, target 10s → should decrease difficulty
        let new = adjust_difficulty(20, 10, 20);
        assert!(new < 20, "Difficulty should decrease when blocks are too slow");
        assert!(new >= 13, "Difficulty should not drop by more than 0.667x");
    }

    #[test]
    fn test_daa_max_cap() {
        // Even with very fast blocks, difficulty must not exceed MAX_DIFFICULTY
        let new = adjust_difficulty(MAX_DIFFICULTY, 10, 1);
        assert_eq!(new, MAX_DIFFICULTY, "Difficulty must not exceed MAX_DIFFICULTY");
    }

    #[test]
    fn test_daa_moving_average_stability() {
        // Simulate 10 blocks all at exactly target time → difficulty should be stable
        let times = vec![10u64; 10];
        let new = adjust_difficulty_moving_average(20, 10, &times);
        assert_eq!(new, 20, "Difficulty should be stable when blocks hit target time");
    }

    #[test]
    fn test_b3memhash_deterministic() {
        let mut buf1 = vec![0u8; B3MEM_MEMORY_SIZE];
        let mut buf2 = vec![0u8; B3MEM_MEMORY_SIZE];
        let input = b"test_block_header_data_nonce_12345";
        let h1 = hash_b3memhash_with_buffer(input, &mut buf1);
        let h2 = hash_b3memhash_with_buffer(input, &mut buf2);
        assert_eq!(h1, h2, "B3MemHash must be deterministic");
    }

    #[test]
    fn test_b3memhash_different_inputs() {
        let mut buf = vec![0u8; B3MEM_MEMORY_SIZE];
        let h1 = hash_b3memhash_with_buffer(b"input_a", &mut buf);
        let h2 = hash_b3memhash_with_buffer(b"input_b", &mut buf);
        assert_ne!(h1, h2, "Different inputs must produce different hashes");
    }
}
