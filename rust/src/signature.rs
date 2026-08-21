//! `obsign/signature/v2`, and the distinction that actually matters.
//!
//! docs/COMPAT.md fixes the envelope: Ed25519 over
//! `"obsign/signature/v2\0" + SHA-256(canonical({spec, alg, public_key,
//! receipt_sha256, signer, binds_sha256}))`, with `binds`/`binds_sha256` covering
//! named out-of-claim keys, and v1 signatures remaining verifiable and remaining
//! reported as not identity-bound. That is one of the better-specified surfaces here
//! and this file follows it directly.
//!
//! TWO PROPERTIES FOLLOW FROM WHAT THE SIGNATURE COVERS.
//!
//! * The attributed signer is INSIDE the signed set, so rewriting `signer`
//!   invalidates the signature. Legacy `obsign/signature/v1` signs the bare receipt
//!   hash, which covers neither the signer nor the `case` block -- so the name in such
//!   a file can be rewritten by anyone with a text editor and no key. It still
//!   verifies, and it attributes NOBODY.
//! * `binds_sha256` extends coverage to metadata that lives outside the claim hash but
//!   is still presented as fact. The recomputation runs UNCONDITIONALLY: `binds` is
//!   supplied by whoever hands you the file and is not itself signed, so a missing,
//!   empty or lying `binds` can only FAIL the comparison, never skip it.
//!
//! A FIELD OF THE WRONG JSON TYPE IS A MALFORMED BLOCK, NOT A HINT TO LOOK ELSEWHERE.
//! A `binds_sha256` that is a number is not a digest, and a `sig` that is a number is
//! not a signature. Both are refused. This file used to reproduce Python's truthiness
//! so that a falsy `sig` fell through to a `signature` member -- an emulation of a
//! synonym fallback that the reference has now DELETED, because a security envelope
//! with two spellings for one field is a forgery primitive: JavaScript skipped a
//! non-string `sig` and read the alternate member, so `{"sig": 5, "signature":
//! "<valid 128-hex>"}` verified there and was refused here. One field, one spelling,
//! one answer in three implementations.
//!
//! AN UNKNOWN `spec` IS UNSUPPORTED, NOT LEGACY v1. This file's own comment used to
//! record the fall-through as a known gap: an unrecognised spec landed in the v1
//! branch "which is what both shipped implementations do". All three now refuse it.
//! An unknown future version must never inherit the weakest historical semantics.

use crate::ed25519;
use crate::json::{canonical_sha256, integrity, JStr, Value};
use crate::sha2::unhex;

/// Only Ed25519 today. An unknown algorithm is UNVERIFIED, never "fine".
pub const SUPPORTED_ALGS: [&str; 1] = ["ed25519"];

/// The domain tag. Without it the signed bytes are a bare 64-char hex digest, which is
/// exactly what a v1 signature covers -- so the tag is what stops a v2 signature being
/// replayed as a v1 one. It is a cross-implementation contract, not a local choice:
/// producer and verifier disagreed about it for three releases and every genuine v2
/// receipt failed in the tool customers were told to run.
pub const SIG_DOMAIN_V2: &[u8] = b"obsign/signature/v2\x00";

/// Keys outside the claim hash that are still presented as fact. `case` (case id +
/// examiner) is rendered into a court-facing report, so a signature that does not bind
/// it leaves the two lines a court reads first attested by nothing.
pub const OUT_OF_CLAIM_FACT: [&str; 1] = ["case"];

/// The two signature envelopes this verifier knows how to read, and NOTHING ELSE. An
/// ABSENT spec still means v1 -- receipts minted before the field existed are real and
/// still verify -- but a spec that is present and unrecognised, including one that is
/// not even a string, is `unsupported`.
pub const SIG_SPEC_V1: &str = "obsign/signature/v1";
pub const SIG_SPEC_V2: &str = "obsign/signature/v2";

#[derive(Debug, Clone, PartialEq)]
pub struct SigCheck {
    pub present: bool,
    pub valid: bool,
    /// True only when the envelope names a spec this verifier does not implement.
    /// Distinct from `valid: false`, which means "I read it and it does not hold";
    /// this means "I did not read it, and nothing here is a verdict about it".
    pub unsupported: bool,
    pub identity_bound: bool,
    pub attributed_signer: Option<String>,
    pub claimed_signer: Option<String>,
    pub detail: String,
    pub bound_metadata: Vec<String>,
    pub unbound_metadata: Vec<String>,
}

impl Default for SigCheck {
    fn default() -> Self {
        SigCheck {
            present: false,
            valid: false,
            unsupported: false,
            identity_bound: false,
            attributed_signer: None,
            claimed_signer: None,
            detail: String::new(),
            bound_metadata: Vec::new(),
            unbound_metadata: Vec::new(),
        }
    }
}

/// Recompute the hash a signature's `binds_sha256` commits to.
///
/// The two details that look cosmetic are not: only keys actually PRESENT in the
/// receipt enter the hashed object (hashing a missing key as `null` would be a second,
/// silently different canonical form), and an empty selection is "no hash at all"
/// rather than the hash of `{}` -- so "this signature binds nothing" and "the bound
/// block was deleted" stay distinguishable.
pub fn binds_hash(receipt: &Value, keys: &[String]) -> Option<String> {
    let mut bound: Vec<(JStr, Value)> = Vec::new();
    for k in keys {
        if let Some(v) = receipt.get(k) {
            let ku: JStr = k.encode_utf16().collect();
            if !bound.iter().any(|(bk, _)| *bk == ku) {
                bound.push((ku, v.clone()));
            }
        }
    }
    if bound.is_empty() {
        return None;
    }
    canonical_sha256(&Value::Object(bound)).ok()
}

/// A short, safe rendering of an attacker-supplied JSON value, for a detail message.
fn describe(v: Option<&Value>) -> String {
    match v {
        None => "<absent>".into(),
        Some(Value::Null) => "null".into(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Str(_)) => format!("{:?}", v.and_then(|x| x.as_str()).unwrap_or_default()),
        Some(Value::Int(i)) => format!("<number {}>", i.text()),
        Some(Value::Float(f)) => format!("<number {f}>"),
        Some(Value::Array(_)) => "<array>".into(),
        Some(Value::Object(_)) => "<object>".into(),
    }
}

fn ed25519_ok(public_key_hex: &str, signature_hex: &str, message: &[u8]) -> (bool, String) {
    let pk = match unhex(public_key_hex) {
        Some(b) if b.len() == 32 => b,
        _ => return (false, "public key is not 32 raw Ed25519 bytes in hex".into()),
    };
    let sig = match unhex(signature_hex) {
        Some(b) if b.len() == 64 => b,
        _ => return (false, "signature is not 64 raw Ed25519 bytes in hex".into()),
    };
    if ed25519::verify(&pk, &sig, message) {
        (true, "signature verifies".into())
    } else {
        (false, "signature does NOT verify (InvalidSignature)".into())
    }
}

/// Step 3 of the ladder. Never fails on a hostile receipt; every anomaly is a verdict.
///
/// `identity_bound` is reported separately from `valid` on purpose: a caller that
/// reads only `valid` still cannot print a signer name, because `attributed_signer` is
/// `None` unless the signature actually covered it.
pub fn check(receipt: &Value) -> SigCheck {
    let mut out = SigCheck::default();

    let sig = match receipt.get("signature") {
        Some(v) if matches!(v, Value::Object(_)) => v,
        _ => {
            out.detail = "no signature (integrity and re-derivation still apply)".into();
            return out;
        }
    };
    out.present = true;
    out.claimed_signer = sig.get("signer").and_then(|v| v.as_str());

    // A signature attributes a NAME to a CLAIM. If the claim no longer hashes to
    // `receipt_sha256` there is no claim left to attribute, and reporting the
    // signature as valid would let a caller that reads only this block print a real
    // examiner's name over rewritten numbers.
    let (ok_integrity, integrity_detail) = integrity(receipt);
    if !ok_integrity {
        out.detail = format!("signature NOT evaluated - {integrity_detail}");
        return out;
    }

    // THE ALGORITHM TOKEN IS EXACT, NOT NORMALIZED. A receipt carrying "ED25519" is a
    // different receipt: the value is inside the signed attribute set, so accepting a
    // case-folded spelling would be one implementation verifying what another refuses.
    let alg = sig.get("alg").and_then(|v| v.as_str());
    match &alg {
        Some(a) if SUPPORTED_ALGS.contains(&a.as_str()) => {}
        _ => {
            out.detail = "unsupported algorithm - UNVERIFIED, not accepted".into();
            return out;
        }
    }

    // THE SPEC IS DECIDED BEFORE ANY OF THE BYTES IT DESCRIBES ARE READ.
    //
    // `sig`, `public_key` and `binds_sha256` only MEAN anything relative to a spec that
    // says what the signature covers. Reading them first and then discovering the spec
    // is unknown is the same mistake in a different order. A JSON `null` spec reads as
    // absent, because the reference cannot distinguish the two and the three
    // implementations must not split over it.
    let spec_value = match sig.get("spec") {
        Some(Value::Null) => None,
        other => other,
    };
    let spec: Option<String> = spec_value.and_then(|v| if v.is_str() { v.as_str() } else { None });
    let known = match spec.as_deref() {
        Some(SIG_SPEC_V1) | Some(SIG_SPEC_V2) => true,
        None => spec_value.is_none(), // absent is v1; a non-string spec is not
        _ => false,
    };
    if !known {
        out.unsupported = true;
        out.detail = format!(
            "unsupported signature spec {} - UNVERIFIED, not accepted",
            describe(spec_value)
        );
        return out;
    }

    // ONE SPELLING PER FIELD -- see the module header. `signature` as a synonym for
    // `sig` is deleted, and with it the truthiness emulation that existed only to
    // reproduce the fall-through.
    let sig_hex = sig.get("sig").and_then(|v| if v.is_str() { v.as_str() } else { None });
    let pub_hex = sig.get("public_key").and_then(|v| if v.is_str() { v.as_str() } else { None });
    let receipt_hash = receipt.get("receipt_sha256").and_then(|v| v.as_str());
    let (sig_hex, pub_hex, receipt_hash) = match (sig_hex, pub_hex, receipt_hash) {
        // NON-EMPTY, in all three. An empty string is not a 128-hex signature and not a
        // 64-hex key; treating it as merely "present" split the implementations, because
        // the reference then fell into the v1 branch (which populates
        // `unbound_metadata`) while the JavaScript port returned early (which does not).
        // Same file, same refusal, two different signature blocks reported.
        (Some(s), Some(p), Some(r)) if !r.is_empty() && !s.is_empty() && !p.is_empty() => (s, p, r),
        _ => {
            out.detail = "signature block is missing sig/public_key/receipt_sha256".into();
            return out;
        }
    };

    if spec.as_deref() == Some(SIG_SPEC_V2) {
        let covered = Value::Object(vec![
            ("spec".encode_utf16().collect(), Value::str_of("obsign/signature/v2")),
            ("alg".encode_utf16().collect(), sig.get("alg").cloned().unwrap_or(Value::Null)),
            ("public_key".encode_utf16().collect(), Value::str_of(&pub_hex)),
            ("receipt_sha256".encode_utf16().collect(), Value::str_of(&receipt_hash)),
            ("signer".encode_utf16().collect(), sig.get("signer").cloned().unwrap_or(Value::Null)),
            (
                "binds_sha256".encode_utf16().collect(),
                sig.get("binds_sha256").cloned().unwrap_or(Value::Null),
            ),
        ]);
        let digest = match canonical_sha256(&covered) {
            Ok(d) => d,
            Err(e) => {
                out.detail = format!("signed attribute set is not canonicalisable ({e})");
                return out;
            }
        };
        let mut message = SIG_DOMAIN_V2.to_vec();
        message.extend_from_slice(digest.as_bytes());
        let (ok, detail) = ed25519_ok(&pub_hex, &sig_hex, &message);
        out.valid = ok;
        out.detail = detail;
        if !ok {
            return out;
        }

        // THE COMPARISON BELOW RUNS UNCONDITIONALLY, AND THAT IS THE ENTIRE POINT.
        // Gating it on a value the attacker supplies means deleting one key skips the
        // check rather than failing it -- and `case.examiner` is excluded from
        // `receipt_sha256`, so that would make it a free-text field on a
        // cryptographically valid receipt.
        let binds_value = sig.get("binds");
        let binds: Vec<String> = match binds_value {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => {
                let mut ks = Vec::with_capacity(items.len());
                for it in items {
                    match it.as_str() {
                        Some(s) if it.is_str() => ks.push(s),
                        _ => {
                            out.valid = false;
                            out.detail = "signature `binds` is not a list of key names - REFUSED \
                                          (the bound metadata cannot be reproduced)"
                                .into();
                            return out;
                        }
                    }
                }
                ks
            }
            _ => {
                out.valid = false;
                out.detail = "signature `binds` is not a list of key names - REFUSED \
                              (the bound metadata cannot be reproduced)"
                    .into();
                return out;
            }
        };

        // A NAME THAT IS NOT THERE IS NOT A BINDING. `binds` lives inside the
        // `signature` block, which is excluded from `receipt_sha256` and is NOT in
        // the v2 covered set -- so an attacker rewrites it freely -- and
        // `binds_hash` skips keys the receipt does not carry. Padding the list with
        // a name that is absent therefore left the recomputed hash unchanged and
        // this port reported `bound_metadata: ["case"]` for a signature that bound
        // nothing, while the reference and the npm port both refused it. One file,
        // two verdicts, on the identity rung: a forger's choice of verifier.
        let missing: Vec<String> = binds
            .iter()
            .filter(|k| receipt.get(k.as_str()).is_none())
            .cloned()
            .collect();
        if !missing.is_empty() {
            out.valid = false;
            out.detail = format!(
                "signature `binds` names {} key(s) this receipt does not carry ({}) -                  REFUSED: the bound block was removed since signing, or the list was                  padded to claim a binding that was never hashed",
                missing.len(),
                missing.join(", ")
            );
            return out;
        }

        let recomputed = binds_hash(receipt, &binds);
        // A `binds_sha256` that is not a string is not a digest. Treating it as absent
        // would let `binds_sha256: 0` be "reproduced" by an empty `binds` list.
        let declared: Option<String> = match sig.get("binds_sha256") {
            None | Some(Value::Null) => None,
            Some(v) if v.is_str() => v.as_str(),
            Some(_) => {
                out.valid = false;
                out.detail = "signature binds_sha256 is not a digest string - REFUSED".into();
                return out;
            }
        };
        if recomputed != declared {
            out.valid = false;
            let mut sorted = binds.clone();
            sorted.sort();
            out.detail = format!(
                "signature verifies but its bound metadata {sorted:?} does NOT reproduce \
                 binds_sha256 - the bound block has been changed, removed, or the `binds` \
                 list was stripped since signing"
            );
            return out;
        }

        out.identity_bound = true;
        out.attributed_signer = sig.get("signer").and_then(|v| v.as_str());
        let mut sorted = binds.clone();
        sorted.sort();
        out.bound_metadata = sorted;

        // Out-of-claim facts the signature does NOT cover. Reported, never assumed
        // harmless: the signature vouches for the signer and for what it bound, and for
        // nothing else that happens to be in the file.
        out.unbound_metadata = OUT_OF_CLAIM_FACT
            .iter()
            .filter(|k| receipt.has(k) && !binds.iter().any(|b| b == *k))
            .map(|k| k.to_string())
            .collect();
        if !out.unbound_metadata.is_empty() {
            out.detail += &format!(
                "; WARNING: {} is present but NOT covered by this signature - it is an \
                 unattested annotation and must not be printed as if the signature \
                 vouched for it",
                out.unbound_metadata.join(", ")
            );
        }
        return out;
    }

    // Legacy v1 -- reached ONLY by `spec: "obsign/signature/v1"` and by an absent spec,
    // never by an unknown one (that returned above as UNSUPPORTED). Signs the bare
    // receipt hash: verifies, and attributes NOBODY.
    let (ok, detail) = ed25519_ok(&pub_hex, &sig_hex, receipt_hash.as_bytes());
    out.valid = ok;
    out.identity_bound = false;
    out.attributed_signer = None;
    out.bound_metadata = Vec::new();
    out.unbound_metadata = OUT_OF_CLAIM_FACT
        .iter()
        .filter(|k| receipt.has(k))
        .map(|k| k.to_string())
        .collect();
    out.detail = if ok {
        format!(
            "{detail}; legacy obsign/signature/v1 covers NEITHER the signer NOR the case \
             block - the name in this file can be rewritten by anyone with a text editor \
             and no key"
        )
    } else {
        detail
    };
    out
}
