//! An unknown format is a THIRD ANSWER -- the Rust half.
//!
//! The fixtures under `src/obsign_verify/data/conformance/unsupported/` each declare
//! their own expected verdict in a `_conformance` block, and the Python, JavaScript and
//! Rust suites all read the SAME block. Three implementations held to one WRITTEN
//! expectation is a different thing from three implementations held to each other:
//! agreement between three implementations that are all wrong is perfect agreement, and
//! this crate exists precisely because two implementations by one author can share a
//! misreading invisibly.
//!
//! WHAT THIS FILE IS ABOUT:
//!
//!   receipt spec     the ladder dispatched on `kernel` with no top-level format check,
//!                    so `obsign/receipt/v99` -- RE-SEALED, so its integrity holds --
//!                    was interpreted under today's v1 semantics.
//!   signature spec   `if spec == v2 {...} else { legacy v1 }`, so an unknown envelope
//!                    inherited the weakest semantics the format has ever had. This
//!                    file's own module header used to record that fall-through as a
//!                    known spec gap rather than refuse it.
//!   the `sig` member the reference's `sig.get("sig") or sig.get("signature")` was
//!                    emulated here with a `truthy()` helper reproducing Python's
//!                    notion of truth. The synonym is deleted in all three; so is the
//!                    emulation.

use obsign_verify::json::{load_receipt, Value};
use obsign_verify::verify::verify;

fn dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("src/obsign_verify/data/conformance/unsupported")
}

fn read(name: &str) -> String {
    std::fs::read_to_string(dir().join(name)).expect("fixture must be present")
}

fn parse(text: &str) -> Value {
    load_receipt(text).expect("fixture must load")
}

/// Read one field out of a fixture's declared `_conformance.expect` block.
///
/// A MISSPELLED OR MISTYPED EXPECTATION MUST NOT READ AS `false`. This was
/// `.map(|v| matches!(v, Value::Bool(true)))`, which silently turns a string, a number
/// or a null into `false` -- so `"verified": "true"` would be read as `false` here and
/// as truthy by the reference and the JavaScript port, and the "ONE written
/// expectation, three implementations" property would quietly stop holding for that
/// field. The whole point of the shared block is that all three read the same value.
fn expect_field<'a>(doc: &'a Value, field: &str) -> &'a Value {
    doc.get("_conformance")
        .and_then(|c| c.get("expect"))
        .and_then(|e| e.get(field))
        .unwrap_or_else(|| panic!("fixture declares no {field}"))
}

fn expect_bool(doc: &Value, field: &str) -> bool {
    match expect_field(doc, field) {
        Value::Bool(b) => *b,
        other => panic!("fixture field {field} is {other:?}, which is not a boolean"),
    }
}

/// `reproduced` is THREE-VALUED: null is "nothing was attempted" (an unrecognised
/// format, a kernel this verifier cannot run), which is a different fact from false
/// ("it was re-derived and it did not match"). Every harness used to coerce it to a
/// bool, which is exactly why the reference could say `false` while both ports said
/// `null` on the same bytes with all three suites green.
fn expect_tribool(doc: &Value, field: &str) -> Option<bool> {
    match expect_field(doc, field) {
        Value::Bool(b) => Some(*b),
        Value::Null => None,
        other => panic!("fixture field {field} is {other:?}, which is not a boolean or null"),
    }
}

fn fixture_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir())
        .expect("the fixture directory must be present")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    names
}

#[test]
fn the_unsupported_fixture_set_is_present_and_does_not_all_say_one_thing() {
    assert_eq!(
        fixture_names(),
        vec![
            "receipt_spec_v1_control.json",
            "receipt_spec_v99.json",
            "signature_spec_absent.json",
            "signature_spec_v1.json",
            "signature_spec_v9.json",
        ],
        "a fixture directory that quietly emptied would make every test below vacuous"
    );
    let verdicts: Vec<bool> = fixture_names()
        .iter()
        .map(|n| expect_bool(&parse(&read(n)), "verified"))
        .collect();
    assert!(
        verdicts.contains(&true) && verdicts.contains(&false),
        "every fixture declares the same verdict, so the reader below is a constant"
    );
}

#[test]
fn every_unsupported_fixture_gets_the_verdict_it_declares() {
    for name in fixture_names() {
        let doc = parse(&read(&name));
        let res = verify(&doc);
        let sig = res.signature.clone().unwrap_or_default();
        let got = (
            res.verified,
            res.unsupported,
            res.reproduced,
            sig.present,
            sig.valid,
            sig.unsupported,
            sig.identity_bound,
            sig.attributed_signer.is_some(),
        );
        let want = (
            expect_bool(&doc, "verified"),
            expect_bool(&doc, "unsupported"),
            expect_tribool(&doc, "reproduced"),
            expect_bool(&doc, "signature_present"),
            expect_bool(&doc, "signature_valid"),
            expect_bool(&doc, "signature_unsupported"),
            expect_bool(&doc, "identity_bound"),
            false, // every fixture declares attributed_signer: null
        );
        assert_eq!(got, want, "{name}: {:?}", res.notes);
    }
}

#[test]
fn the_only_difference_between_valid_and_unsupported_is_the_spec_string() {
    // Same claim, same key, SAME 128 hex characters of signature -- and that signature
    // really does verify under v1 rules, which is what made `else: legacy v1` report an
    // envelope nobody has implemented as a checked signature.
    let v1_text = read("signature_spec_v1.json");
    let v9_text = read("signature_spec_v9.json");
    let v1 = parse(&v1_text);
    let v9 = parse(&v9_text);
    assert_eq!(
        v1.get("signature").and_then(|s| s.get("sig")).and_then(|v| v.as_str()),
        v9.get("signature").and_then(|s| s.get("sig")).and_then(|v| v.as_str()),
        "precondition: the two fixtures carry the same signature bytes"
    );
    assert_eq!(
        v1.get("receipt_sha256").and_then(|v| v.as_str()),
        v9.get("receipt_sha256").and_then(|v| v.as_str()),
        "precondition: the two fixtures carry the same claim"
    );

    let a = verify(&v1);
    let b = verify(&v9);
    let asig = a.signature.clone().unwrap();
    let bsig = b.signature.clone().unwrap();
    assert!(asig.valid, "the v1 signature must really verify: {}", asig.detail);
    assert!(a.verified, "{:?}", a.notes);
    assert!(!bsig.valid);
    assert!(bsig.unsupported, "an unknown envelope must not be checked at all");
    assert!(bsig.attributed_signer.is_none());
    assert!(!b.verified);
}

/// Rebuild the v1 fixture with a different `spec` member, verbatim JSON.
fn with_sig_spec(spec_json: Option<&str>) -> Value {
    let doc: serde_free::Doc = serde_free::Doc::new(&read("signature_spec_v1.json"));
    doc.with_signature_spec(spec_json)
}

/// A tiny hand-rolled JSON rewriter. The crate carries no serde and this test needs to
/// change ONE member of one object without disturbing a byte of anything else -- which
/// is the whole point of the fixture pair: nothing but the spec string may differ.
mod serde_free {
    use obsign_verify::json::{load_receipt, Value};

    pub struct Doc {
        text: String,
    }

    impl Doc {
        pub fn new(text: &str) -> Doc {
            Doc { text: text.to_string() }
        }

        /// Replace `"spec": "obsign/signature/v1"` inside the signature block with the
        /// given raw JSON, or delete the member entirely when `None`.
        pub fn with_signature_spec(&self, spec_json: Option<&str>) -> Value {
            let needle = "\"spec\": \"obsign/signature/v1\"";
            assert!(
                self.text.contains(needle),
                "the fixture no longer spells its signature spec the way this rewriter expects"
            );
            let replaced = match spec_json {
                Some(json) => self.text.replace(needle, &format!("\"spec\": {json}")),
                // Deleting the member: drop the line, comma and all.
                None => self.text.replace(&format!("{needle},\n"), ""),
            };
            load_receipt(&replaced).expect("rewritten fixture must still load")
        }
    }
}

#[test]
fn no_spelling_but_the_two_tokens_reaches_a_signature_check() {
    for spec in [
        "\"obsign/signature/v3\"",
        "\"obsign/signature/v9\"",
        "\"OBSIGN/SIGNATURE/V2\"",
        "\"obsign/signature/v2 \"",
        "\"\"",
        "9",
        "true",
        "[\"v1\"]",
        "{\"v\": 1}",
    ] {
        let res = verify(&with_sig_spec(Some(spec)));
        let sig = res.signature.clone().unwrap();
        assert!(sig.unsupported, "spec {spec} was not reported unsupported: {}", sig.detail);
        assert!(!sig.valid);
        assert!(sig.attributed_signer.is_none());
        assert!(!res.verified);
    }

    // A JSON `null` spec is the one case that is NOT unsupported: the reference cannot
    // tell an absent key from a null value, so all three read `null` as absent, which
    // is legacy v1, which is valid. Pinned so the equivalence is a decision.
    let nulled = verify(&with_sig_spec(Some("null")));
    assert!(nulled.signature.clone().unwrap().valid, "a null spec is the absent spec");

    // ...and the genuinely absent one verifies too. Receipts minted before the field
    // existed are real and must not stop working.
    let absent = verify(&parse(&read("signature_spec_absent.json")));
    assert!(absent.signature.clone().unwrap().valid);
    assert!(absent.signature.clone().unwrap().attributed_signer.is_none());
}

#[test]
fn a_signature_member_is_not_a_synonym_for_sig() {
    // THE FORMER KNOWN DIVERGENCE. This crate emulated the reference's Python
    // truthiness with a `truthy()` helper so that a falsy `sig` fell through to a
    // `signature` member. All three implementations now read exactly one field.
    let text = read("signature_spec_v1.json");
    let real = parse(&text)
        .get("signature")
        .and_then(|s| s.get("sig"))
        .and_then(|v| v.as_str())
        .expect("the fixture carries a signature");
    assert!(
        verify(&parse(&text)).signature.unwrap().valid,
        "control: the same hex in `sig` DOES verify, so what fails below is the synonym"
    );

    for bad in ["5", "true", "\"\"", "null"] {
        let forged = text.replace(
            &format!("\"sig\": \"{real}\""),
            &format!("\"sig\": {bad},\n    \"signature\": \"{real}\""),
        );
        let res = verify(&load_receipt(&forged).expect("forged fixture must load"));
        let sig = res.signature.clone().unwrap();
        assert!(
            !sig.valid,
            "sig={bad} beside a valid `signature` member was accepted -- the synonym is back"
        );
        assert!(sig.attributed_signer.is_none());
        assert!(!res.verified);
    }
}

#[test]
fn an_unknown_receipt_spec_is_unsupported_while_the_same_claim_under_v1_verifies() {
    let control = verify(&parse(&read("receipt_spec_v1_control.json")));
    assert!(control.verified, "{:?}", control.notes);
    assert!(!control.unsupported);
    assert_eq!(control.reproduced, Some(true));

    let unknown = verify(&parse(&read("receipt_spec_v99.json")));
    assert!(
        unknown.integrity,
        "precondition: the v99 fixture is RE-SEALED, so only the spec gate stands in the way"
    );
    assert!(unknown.unsupported);
    assert!(!unknown.verified);
    assert_eq!(
        unknown.reproduced, None,
        "nothing may be re-executed under a format this implementation cannot read"
    );
}

#[test]
fn strict_liveness_and_the_approved_program_pin_are_library_arguments_here_too() {
    use obsign_verify::verify::verify_with;

    let doc = parse(&read("receipt_spec_v1_control.json"));
    let digest = doc
        .get("params")
        .and_then(|p| p.get("program_sha256"))
        .and_then(|v| v.as_str())
        .expect("the control declares its program digest");

    let plain = verify(&doc);
    assert_eq!(
        plain.approved_program, None,
        "None means NO EXPECTATION WAS SUPPLIED -- a different fact from 'not approved'"
    );
    assert_eq!(plain.input_liveness.as_deref(), Some("live"));

    assert_eq!(verify_with(&doc, Some(&digest), false).approved_program, Some(true));
    assert!(verify_with(&doc, Some(&digest), false).verified);

    let wrong = verify_with(&doc, Some(&"0".repeat(64)), false);
    assert_eq!(wrong.approved_program, Some(false));
    assert!(!wrong.verified);

    // A flag that refuses everything is not a stricter check, it is a broken one.
    assert!(verify_with(&doc, None, true).verified);
}

/// The receipt Python's `mint.replay_receipt(compile_source("output 7;"), [])` emits:
/// a program declaring ZERO inputs, whose liveness verdict is therefore "n/a".
const NO_INPUTS: &str = r#"{"spec": "obsign/receipt/v1", "kernel": "obsign/replay/1",
 "params": {"program": {"spec": "obsign/replay/1", "mem": 2, "steps": 3, "consts": [7],
 "input": {"offset": 0, "length": 0}, "output": {"offset": 0, "length": 1},
 "code": [["LOADC", 1, 0], ["MOV", 0, 1], ["HALT"]]},
 "program_sha256": "5d2444940b2081f7be4e82c9673f79a82652ff42ad45e9c632a4810a25e03ae8",
 "inputs": []},
 "output": {"sha256": "aae89fc0f03e2959ae4d701a80cc3915918c950b159f6abb6c92c1433b1a8534",
 "length": 1, "dtype": "int64"},
 "receipt_sha256": "546bf3b9ad55ffaee6f237a6e45ca86890dabb51b7b8c0699da4bc4207c45a02"}"#;

#[test]
fn strict_liveness_refuses_what_the_default_accepts() {
    use obsign_verify::verify::verify_with;

    // A FLAG WHOSE ONLY WITNESS IS SOMETHING IT ACCEPTS IS NOT TESTED. The check above
    // pins that strict mode does not refuse an honestly live receipt, which cannot fail
    // if `strict_liveness` is ignored entirely -- so this one pins the other direction
    // on a receipt whose verdict actually differs between the two modes.
    //
    // "n/a" is weaker than "live": a program declaring no inputs demonstrates nothing
    // about any, which is precisely what strict mode exists to require.
    let doc = load_receipt(NO_INPUTS).expect("the zero-input receipt loads");
    let lax = verify_with(&doc, None, false);
    assert_eq!(lax.input_liveness.as_deref(), Some("n/a"));
    assert!(lax.verified, "the default is unchanged: {:?}", lax.notes);

    let strict = verify_with(&doc, None, true);
    assert!(!strict.verified, "strict mode accepted a verdict weaker than 'live'");
    assert!(
        strict.notes.iter().any(|n| n.contains("only 'live' is accepted in strict mode")),
        "{:?}",
        strict.notes
    );
}

#[test]
fn the_pin_compares_the_computed_digest_not_the_stated_one() {
    use obsign_verify::verify::verify_with;

    // A forger who types the approved digest into `params.program_sha256` beside a
    // different program must not thereby own the approval.
    let text = read("receipt_spec_v1_control.json");
    let doc = parse(&text);
    let approved = doc
        .get("params")
        .and_then(|p| p.get("program_sha256"))
        .and_then(|v| v.as_str())
        .unwrap();
    // Change the program without touching the stated digest.
    let swapped = text.replace("\"consts\": [\n        1\n      ]", "\"consts\": [\n        2\n      ]");
    assert_ne!(swapped, text, "the rewriter must actually change the program");
    let res = verify_with(&load_receipt(&swapped).unwrap(), Some(&approved), false);
    assert_eq!(
        res.approved_program,
        Some(false),
        "the pin read the STATED digest, so writing the approved value satisfied it"
    );
    assert!(!res.verified);
}

#[test]
fn the_liveness_probe_reaches_the_scale_of_its_own_input() {
    // The half of the port that is not about protocol: the ladder was seven fixed
    // ABSOLUTE deltas, the largest 1,000,000, so a figure held in cents and reported in
    // hundreds of millions never moved and was refused as "a constant dressed as a
    // computation". `cents / 100_000_000`, with 743,215,600,000 cents -- 15,600,000
    // clear of a rounding boundary, so nothing the old ladder tried could move it.
    //
    // This is what the three-way differential SOFTENED two whole columns to avoid, on
    // 37 of 364 receipts. It is an honest receipt, and it must verify.
    let program = r#"{"spec":"obsign/replay/1","mem":4,"steps":100,
        "consts":[100000000],"input":{"offset":0,"length":1},
        "output":{"offset":2,"length":1},
        "code":[["LOADC",1,0],["DIV",2,0,1],["HALT"]]}"#;
    let holder = load_receipt(&format!("{{\"p\":{program}}}")).expect("program loads");
    let prog = holder.get("p").unwrap();
    let out = obsign_verify::replay::run(prog, &[743_215_600_000]).expect("runs");
    let digest = obsign_verify::replay::output_sha256(&out);
    let prog_digest = obsign_verify::replay::program_sha256(prog).unwrap();

    let claim = format!(
        "{{\"spec\":\"obsign/receipt/v1\",\"kernel\":\"obsign/replay/1\",\
         \"params\":{{\"program\":{program},\"program_sha256\":\"{prog_digest}\",\
         \"inputs\":[743215600000]}},\
         \"output\":{{\"dtype\":\"int64\",\"length\":1,\"sha256\":\"{digest}\"}}}}"
    );
    let parsed = load_receipt(&claim).expect("claim loads");
    let seal = obsign_verify::json::canonical_sha256(
        &obsign_verify::json::claim_of(&parsed),
    )
    .unwrap();
    let sealed = format!("{}{}{}", &claim[..claim.len() - 1], format_args!(",\"receipt_sha256\":\"{seal}\""), "}");

    let res = verify(&load_receipt(&sealed).expect("sealed receipt loads"));
    assert!(res.integrity, "precondition: the receipt is sealed: {:?}", res.notes);
    assert_eq!(
        res.input_liveness.as_deref(),
        Some("live"),
        "a figure reported in hundreds of millions was called a hardcoded constant: {:?}",
        res.notes
    );
    assert!(res.verified, "{:?}", res.notes);
}
