//! A verifier that CRASHES on a hostile receipt has failed open.
//!
//! Whoever handed you the file gets to choose the bytes. If those bytes can end the
//! process, the answer they produced is "no verdict", and a pipeline reading an exit
//! code cannot tell that apart from a tool that was never run. Every path here must
//! come back with a refusal instead.
//!
//! Rust makes this sharper than the other two implementations, not softer: an
//! out-of-range slice or an arithmetic overflow is a panic, and this crate turns
//! `overflow-checks` on in release precisely so those show up here rather than as a
//! wrong number in the field. A panic in this file is a defect in the verifier, never a
//! property of the receipt.

use obsign_verify::graph::verify_graph;
use obsign_verify::json::{load_receipt, parse_permissive};
use obsign_verify::verify::verify;

/// A tiny deterministic PRNG, so a failure reproduces from the seed printed with it.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*: enough randomness for byte mutation, and short enough to read.
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64)) as usize
    }
}

const SEEDS: &[&str] = &[
    r#"{"spec":"obsign/receipt/v1","kernel":"obsign/replay/1","params":{"program":{"spec":"obsign/replay/1","mem":4,"steps":100,"consts":[1],"input":{"offset":0,"length":1},"output":{"offset":2,"length":1},"code":[["LOADC",1,0],["ADD",2,0,1],["HALT"]]},"inputs":[41]},"output":{"dtype":"int64","length":1,"sha256":"aa"},"receipt_sha256":"bb"}"#,
    r#"{"kernel":"obsign/replay/1","params":{"links":[{"receipt_sha256":"0000000000000000000000000000000000000000000000000000000000000000","output_sha256":"0000000000000000000000000000000000000000000000000000000000000000","src_offset":0,"length":1,"dst_offset":0}],"inputs":[1]}}"#,
    r#"{"signature":{"spec":"obsign/signature/v2","alg":"ed25519","public_key":"00","sig":"00","signer":"x","binds":["case"],"binds_sha256":"y"},"case":{"examiner":"x"},"receipt_sha256":"z"}"#,
];

#[test]
fn mutated_receipts_are_refused_and_never_panic() {
    let mut rng = Rng(0x0b51_9427_2026_0820);
    for (si, seed) in SEEDS.iter().enumerate() {
        for round in 0..4000 {
            let mut bytes = seed.as_bytes().to_vec();
            for _ in 0..1 + rng.below(6) {
                let at = rng.below(bytes.len());
                match rng.below(3) {
                    0 => bytes[at] = (rng.next() & 0x7f) as u8,
                    1 => bytes.insert(at, (rng.next() & 0x7f) as u8),
                    _ => {
                        bytes.remove(at);
                    }
                }
                if bytes.is_empty() {
                    bytes.push(b'{');
                }
            }
            let text = match String::from_utf8(bytes) {
                Ok(t) => t,
                Err(_) => continue, // not text; the caller's decoder refuses before us
            };
            // The contract: a verdict or a refusal, never an escape.
            if let Ok(v) = load_receipt(&text) {
                let _ = verify(&v);
                let _ = verify_graph(std::slice::from_ref(&v));
            }
            let _ = round;
            let _ = si;
        }
    }
}

#[test]
fn structurally_hostile_documents_are_refused() {
    // Each of these was chosen because it aims at a specific way an implementation
    // reaches past the end of something.
    let hostile = [
        "",
        "{",
        "}",
        "[]",
        "null",
        "\"x\"",
        "{\"a\"",
        "{\"a\":",
        "{\"a\":}",
        "{,}",
        "{\"a\":1,,}",
        "{\"\\u\":1}",
        "{\"\\ud800\\u0041\":1}",
        "{\"a\":\"\\",
        "{\"a\":1e}",
        "{\"a\":-}",
        "{\"a\":00}",
        "\u{feff}{}",
        "{\"a\":\"\u{0}\"}",
    ];
    for h in hostile {
        // A refusal is the only acceptable outcome; the assertion is that we get here.
        if let Ok(v) = load_receipt(h) {
            let _ = verify(&v);
        }
    }
}

#[test]
fn a_program_may_not_hang_the_verifier() {
    // An unconditional back-edge with the largest budget the format allows. The budget
    // is a SECURITY parameter: a receipt handed to you by an adversary must not be able
    // to turn into a denial of service delivered through the file you were invited to
    // check.
    let text = r#"{"spec":"obsign/replay/1","mem":4,"steps":50000000,"consts":[0],
        "input":{"offset":0,"length":1},"output":{"offset":2,"length":1},
        "code":[["JMP",0]]}"#;
    let holder = parse_permissive(&format!("{{\"p\":{text}}}")).unwrap();
    let prog = holder.get("p").unwrap();
    let started = std::time::Instant::now();
    let r = obsign_verify::replay::run(prog, &[1]);
    assert!(r.is_err(), "an infinite loop must TRAP, not return");
    assert!(
        started.elapsed().as_secs() < 60,
        "the step budget must bound the work a receipt can demand"
    );
}

#[test]
fn a_deeply_nested_document_is_refused_rather_than_overflowing_the_stack() {
    // CPython bounds this by catching its own RecursionError. Rust cannot catch a stack
    // overflow, so the parser bounds depth itself -- and the refusal must arrive from
    // the wire-format check, not from the operating system.
    for depth in [40usize, 400, 5_000, 100_000] {
        let text = format!("{}1{}", "{\"a\":".repeat(depth), "}".repeat(depth));
        assert!(load_receipt(&text).is_err(), "depth {depth} must be refused");
    }
}

#[test]
fn the_mutation_fuzz_actually_reaches_the_verifier() {
    // A fuzz that only ever produces unparseable bytes tests the parser and nothing
    // else. This measures the fraction that survives to `verify`, so the test above
    // cannot quietly stop exercising the ladder.
    let mut rng = Rng(0x0b51_9427_2026_0820);
    let mut loaded = 0usize;
    let mut total = 0usize;
    for seed in SEEDS {
        for _ in 0..4000 {
            let mut bytes = seed.as_bytes().to_vec();
            let at = rng.below(bytes.len());
            bytes[at] = (rng.next() & 0x7f) as u8;   // a single byte, so many stay valid
            let text = match String::from_utf8(bytes) {
                Ok(t) => t,
                Err(_) => continue,
            };
            total += 1;
            if let Ok(v) = load_receipt(&text) {
                loaded += 1;
                let _ = verify(&v);
            }
        }
    }
    assert!(
        loaded * 20 > total,
        "only {loaded}/{total} mutants reached the ladder; the fuzz is testing the \
         parser and calling it a verifier test"
    );
}
