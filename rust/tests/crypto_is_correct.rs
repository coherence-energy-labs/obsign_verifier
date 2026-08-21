//! The hand-written cryptography, held against published vectors.
//!
//! `ed25519.rs` exists so this crate owes nothing to a supply chain, and that choice is
//! only defensible if the arithmetic is checked rather than believed. These are the
//! offline half; the differential harness runs thousands more signatures through all
//! three implementations and requires the same accept/reject on every one.

use obsign_verify::ed25519;
use obsign_verify::sha2::{hex, sha256_hex, sha512, unhex};

#[test]
fn sha256_matches_fips_vectors() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    // A multi-block input, so the message schedule is exercised past one compression.
    let million_a = vec![b'a'; 1_000_000];
    assert_eq!(
        sha256_hex(&million_a),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn sha512_matches_fips_vectors() {
    assert_eq!(hex(&sha512(b"")),
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    assert_eq!(hex(&sha512(b"abc")),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

#[test]
fn curve_constants_are_the_real_ones() {
    // A plausible-looking typo in one of these constants would produce a verifier that
    // refuses every genuine signature -- or, far worse, accepts a forged one.
    assert!(ed25519::internals::constants_are_consistent());
    assert!(ed25519::internals::base_has_order_l());
    assert_eq!(
        hex(&ed25519::internals::d_bytes()),
        // d = -121665/121666, little-endian encoded
        "a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352"
    );
    assert_eq!(
        hex(&ed25519::internals::base_bytes()),
        "5866666666666666666666666666666666666666666666666666666666666666"
    );
}

/// RFC 8032 section 7.1 test vectors (ed25519, pure).
const RFC8032: &[(&str, &str, &str)] = &[
    // (public key, message hex, signature)
    (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
];

#[test]
fn rfc8032_vectors_verify() {
    for (pk, msg, sig) in RFC8032 {
        let pk = unhex(pk).unwrap();
        let msg = unhex(msg).unwrap();
        let sig = unhex(sig).unwrap();
        assert!(ed25519::verify(&pk, &sig, &msg), "RFC 8032 vector must verify");
    }
}

#[test]
fn a_flipped_bit_anywhere_is_refused() {
    // Soundness matters more than completeness here: a verifier that accepts a
    // corrupted signature is worse than one that refuses a good one.
    let (pk, msg, sig) = RFC8032[2];
    let pk = unhex(pk).unwrap();
    let msg = unhex(msg).unwrap();
    let good = unhex(sig).unwrap();
    for byte in 0..64usize {
        for bit in 0..8u32 {
            let mut bad = good.clone();
            bad[byte] ^= 1 << bit;
            assert!(
                !ed25519::verify(&pk, &bad, &msg),
                "signature with bit {bit} of byte {byte} flipped must NOT verify"
            );
        }
    }
    // ... and a flipped message bit, and a flipped key bit.
    let mut bad_msg = msg.clone();
    bad_msg[0] ^= 1;
    assert!(!ed25519::verify(&pk, &good, &bad_msg));
    let mut bad_pk = pk.clone();
    bad_pk[0] ^= 1;
    assert!(!ed25519::verify(&bad_pk, &good, &msg));
}

#[test]
fn malformed_key_and_signature_lengths_are_refused() {
    let (pk, msg, sig) = RFC8032[1];
    let pk = unhex(pk).unwrap();
    let msg = unhex(msg).unwrap();
    let sig = unhex(sig).unwrap();
    assert!(!ed25519::verify(&pk[..31], &sig, &msg));
    assert!(!ed25519::verify(&pk, &sig[..63], &msg));
    assert!(!ed25519::verify(&[], &[], &msg));
}
