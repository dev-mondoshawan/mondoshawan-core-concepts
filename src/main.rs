//! MondoShawan Core Concepts — Entry Point
//!
//! Run `cargo test` to execute the test suite for both modules.
//! See `src/pow_simd.rs` and `src/kyber_transport.rs` for the implementations.

mod pow_simd;
mod kyber_transport;

fn main() {
    println!("MondoShawan Core Concepts");
    println!("=========================");
    println!();
    println!("This crate contains two standalone algorithmic modules:");
    println!();
    println!("  pow_simd.rs       — B3MemHash memory-hard PoW with AVX2/SSE2 SIMD");
    println!("  kyber_transport.rs — ML-KEM-768 (Kyber) post-quantum P2P key exchange");
    println!();
    println!("Run `cargo test` to verify both modules.");
    println!();

    // Quick self-test: verify DAA stability
    let times = vec![10u64; 10];
    let new_diff = pow_simd::adjust_difficulty_moving_average(20, 10, &times);
    println!("DAA self-test: difficulty at target block time = {} (expected 20)", new_diff);
    assert_eq!(new_diff, 20);

    // Quick self-test: verify SIMD XOR identity property
    let original = vec![0xDEu8; 64];
    let mut dst = original.clone();
    let src = vec![0xABu8; 64];
    pow_simd::xor_bytes(&mut dst, &src);
    pow_simd::xor_bytes(&mut dst, &src);
    assert_eq!(dst, original);
    println!("SIMD XOR self-test: identity property verified");

    println!();
    println!("All self-tests passed.");
}
