//! The Rust witness port, checked against PYTHON'S ACTUAL ANSWERS.
//!
//! WHY FIXTURES AND NOT ONLY THE LIVE DIFFERENTIAL.
//! `tests/test_the_two_ports_agree_about_a_witness.py` runs all three implementations
//! over one corpus and compares them field for field -- which is the real check, and
//! which needs the coherence_compute producer checkout to BUILD the documents. CI does
//! not have it, so there that test skips. A skip is never a pass, and it would leave
//! this port's most important property dark everywhere except one workstation.
//!
//! So the corpus and Python's verdicts are frozen into
//! `js/test/fixtures/witness_corpus.json` -- shared with the JavaScript leg, because two
//! ports checked against two different corpora are not being held to the same standard
//! -- and replayed here with no producer present.
//!
//! The pairing matters in both directions: fixtures alone freeze whatever was true the
//! day they were written, and the live differential alone runs on one machine. The
//! Python side carries `test_the_frozen_fixtures_still_match_live_python`, which fails
//! when these answers drift from the implementation.

use obsign_verify::json::{load_receipt, parse_permissive, Value};
use obsign_verify::witness;

fn fixtures() -> Value {
    // CARGO_MANIFEST_DIR is rust/, so the shared corpus is one level up.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("rust/ has a parent")
        .join("js/test/fixtures/witness_corpus.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read the shared witness corpus at {}: {e}. Without it this port has \
             nothing to check against, and the test would pass by having nothing to do.",
            path.display()
        )
    });
    // The corpus is this harness's own plumbing, not a receipt: it carries the case
    // texts as strings and legitimately exceeds the limits a receipt is held to.
    parse_permissive(&text).expect("the witness corpus is not JSON")
}

fn get<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.get(k)
}

fn as_bool(v: Option<&Value>) -> Option<bool> {
    match v {
        Some(Value::Bool(b)) => Some(*b),
        _ => None,
    }
}

fn as_string(v: Option<&Value>) -> Option<String> {
    v.and_then(|x| x.as_str())
}

/// Every case in the corpus, as (name, [document text, ...]).
fn cases(fx: &Value) -> Vec<(String, Vec<String>)> {
    get(fx, "cases")
        .and_then(|c| c.as_array())
        .expect("corpus has no `cases`")
        .iter()
        .map(|pair| {
            let a = pair.as_array().expect("a case is [name, [texts]]");
            let name = a[0].as_str().expect("case name is a string");
            let texts = a[1]
                .as_array()
                .expect("case payload is a list of document texts")
                .iter()
                .map(|t| t.as_str().expect("a document text is a string"))
                .collect();
            (name, texts)
        })
        .collect()
}

#[test]
fn the_corpus_exercises_both_outcomes() {
    // CALIBRATION. A corpus of exclusively valid documents would prove this port agrees
    // about the easy half.
    let fx = fixtures();
    let pv = get(&fx, "python_verdicts").expect("corpus has no `python_verdicts`");
    let obj = pv.as_object().expect("python_verdicts is an object");
    let mut any_pass = false;
    let mut any_fail = false;
    for (_, v) in obj {
        if as_string(get(v, "kind")).as_deref() == Some("single") {
            match as_bool(get(v, "verified")) {
                Some(true) => any_pass = true,
                Some(false) => any_fail = true,
                None => {}
            }
        }
    }
    assert!(any_pass, "no document in the corpus verifies");
    assert!(any_fail, "no document in the corpus fails");
}

#[test]
fn every_rung_appears_in_the_corpus() {
    // The ladder is the triplicated logic; a differential that never exercises a rung
    // cannot detect a drift on it.
    let fx = fixtures();
    let pv = get(&fx, "python_verdicts").unwrap();
    let mut seen: Vec<String> = Vec::new();
    for (_, v) in pv.as_object().unwrap() {
        if let Some(d) = as_string(get(v, "derived")) {
            if !seen.contains(&d) {
                seen.push(d);
            }
        }
    }
    for rung_name in [witness::CUSTODY, witness::ASSERTED, witness::WITNESSED] {
        assert!(
            seen.iter().any(|x| x == rung_name),
            "the corpus never produces a {rung_name} document: {seen:?}"
        );
    }
}

#[test]
fn the_hashed_binary_decision_is_isolated_by_a_one_field_pair() {
    // The gap a mutation test found in the JavaScript leg: without this pair, a port
    // that dropped the hashed-binary requirement agreed with Python on every other
    // document, and the drift was invisible. Rung coverage is not decision coverage.
    let fx = fixtures();
    let pv = get(&fx, "python_verdicts").unwrap();
    let unhashable = get(pv, "argv_with_unhashable_binary")
        .expect("the corpus lost its unhashable-binary case");
    let hashed = get(pv, "argv_with_hashed_binary")
        .expect("the corpus lost its hashed-binary case");
    assert_eq!(as_string(get(unhashable, "derived")).as_deref(), Some("asserted"));
    assert_eq!(as_string(get(hashed, "derived")).as_deref(), Some("witnessed"));
}

#[test]
fn the_rust_port_reproduces_python_verdicts_on_every_fixture() {
    let fx = fixtures();
    let pv = get(&fx, "python_verdicts").unwrap();
    let mut mismatches: Vec<String> = Vec::new();

    for (name, texts) in cases(&fx) {
        let expected = get(pv, &name)
            .unwrap_or_else(|| panic!("no python verdict recorded for case {name}"));
        let docs: Vec<Value> = texts
            .iter()
            .map(|t| load_receipt(t).unwrap_or_else(|e| panic!("case {name} did not load: {}", e.0)))
            .collect();

        if docs.len() == 1 {
            let v = witness::verify_witness(&docs[0]);
            let want_verified = as_bool(get(expected, "verified"));
            let want_integrity = as_bool(get(expected, "integrity"));
            let want_assurance = as_string(get(expected, "assurance"));
            let want_derived = as_string(get(expected, "derived"));
            let want_sig = as_bool(get(expected, "signature_valid"));

            if Some(v.verified) != want_verified
                || Some(v.integrity) != want_integrity
                || v.assurance != want_assurance
                || Some(v.derived.to_string()) != want_derived
                || v.signature_valid != want_sig
            {
                mismatches.push(format!(
                    "\n  {name}\n    python: verified={want_verified:?} integrity={want_integrity:?} \
                     assurance={want_assurance:?} derived={want_derived:?} sig={want_sig:?}\
                     \n    rust  : verified={:?} integrity={:?} assurance={:?} derived={:?} sig={:?}",
                    v.verified, v.integrity, v.assurance, v.derived, v.signature_valid
                ));
            }
            // Never re-executed, and never accused of failing a test that did not run.
            assert!(v.reproduced.is_none(), "{name}: reproduced must stay None");
        } else {
            let c = witness::verify_chain(&docs);
            let want_ok = as_bool(get(expected, "ok"));
            let want_eff = as_string(get(expected, "effective_assurance"));
            // `complete` is compared too. A chain is verified only when nothing
            // referenced is absent -- withholding a weaker parent is how a chain is made
            // to look stronger than it is -- so a port checked on `ok` alone is not
            // being held to the rule that makes `ok` mean anything.
            let want_complete = as_bool(get(expected, "complete"));
            let want_missing = get(expected, "missing")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            if Some(c.ok) != want_ok
                || c.effective_assurance != want_eff
                || Some(c.complete) != want_complete
                || c.missing.len() != want_missing
            {
                mismatches.push(format!(
                    "\n  {name}\n    python: ok={want_ok:?} effective={want_eff:?} \
                     complete={want_complete:?} missing={want_missing}\
                     \n    rust  : ok={:?} effective={:?} complete={:?} missing={}",
                    c.ok,
                    c.effective_assurance,
                    c.complete,
                    c.missing.len()
                ));
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "the Rust port disagrees with Python. Two verdicts from one vendor on the same \
         bytes is the split a forger farms.{}",
        mismatches.join("")
    );
}

#[test]
fn the_ladder_order_is_the_semantics() {
    // Comparisons are by index, so a reordering silently changes what counts as an
    // overclaim in this port alone.
    assert_eq!(
        witness::LADDER,
        ["custody", "asserted", "witnessed", "environment-pinned"]
    );
    assert!(witness::rung(Some("custody")) < witness::rung(Some("asserted")));
    assert!(witness::rung(Some("asserted")) < witness::rung(Some("witnessed")));
    assert!(witness::rung(Some("witnessed")) < witness::rung(Some("environment-pinned")));
    // An unknown rung, and a MISSING one, sort below the weakest.
    assert!(witness::rung(Some("bit-exact-quantum")) < witness::rung(Some("custody")));
    assert!(witness::rung(None) < witness::rung(Some("custody")));
}
