//! Assertions taken from the DOCUMENTS, not from the other implementations.
//!
//! This distinction is the only reason a third implementation is worth writing. A test
//! that says "Rust agrees with Python" catches a typo; it cannot catch a misreading,
//! because the misreading is on both sides of the comparison. A test that quotes
//! docs/COMPAT.md and checks the sentence can. Where a rule below has no sentence to
//! quote, that is recorded in rust/README.md as a spec gap rather than smoothed over
//! here.

use obsign_verify::json::{canonical_string, claim_of, load_receipt, Value};
use obsign_verify::replay;
use obsign_verify::signature;

fn parse(text: &str) -> Value {
    load_receipt(text).expect("must load")
}

fn canon(text: &str) -> String {
    canonical_string(&parse(text)).expect("must canonicalise")
}

// --------------------------------------------------------------------- canonical JSON
//
// docs/COMPAT.md: "Exactly CPython's json.dumps(obj, sort_keys=True,
// separators=(",", ":"), ensure_ascii=True, allow_nan=False), UTF-8 encoded: keys
// sorted by Unicode code point, non-ASCII escaped, 1 and 1.0 distinct, NaN/Infinity
// unrepresentable -- refused at load, even in non-claim fields."

#[test]
fn keys_sort_by_code_point_and_separators_carry_no_space() {
    assert_eq!(canon(r#"{"b":1,"a":2,"C":3}"#), r#"{"C":3,"a":2,"b":1}"#);
}

#[test]
fn an_astral_key_sorts_above_a_bmp_key_not_below_it() {
    // The trap: sorting UTF-16 code UNITS puts an astral key's lead surrogate
    // (U+D800..U+DBFF) below a BMP key in U+E000..U+FFFF, while sorting CODE POINTS --
    // which is what Python does -- puts it above. Both orders are "sorted"; only one
    // hashes the same as the reference.
    let out = canon("{\"\\ue000\":1,\"\\ud83d\\ude00\":2}");
    assert_eq!(out, r#"{"\ue000":1,"\ud83d\ude00":2}"#);
}

#[test]
fn non_ascii_is_escaped_and_a_non_bmp_char_becomes_a_surrogate_pair() {
    // ensure_ascii=True writes an escaped PAIR, not a single \U escape.
    assert_eq!(canon("{\"a\":\"\\ud83d\\ude00\"}"), r#"{"a":"\ud83d\ude00"}"#);
    // U+007F (DEL) is outside printable ASCII, so CPython escapes it too.
    assert_eq!(canon("{\"a\":\"\\u007f\"}"), r#"{"a":"\u007f"}"#);
    assert_eq!(canon("{\"a\":\"~\"}"), r#"{"a":"~"}"#);
    // The short escapes CPython prefers over the numeric form.
    assert_eq!(canon("{\"a\":\"\\u000a\\u0009\\u0008\"}"), r#"{"a":"\n\t\b"}"#);
    assert_eq!(canon("{\"a\":\"\\u0001\"}"), r#"{"a":"\u0001"}"#);
}

#[test]
fn one_and_one_point_zero_are_different_receipts() {
    // The distinction the whole format depends on, and the one a value-only parser
    // destroys.
    assert_eq!(canon(r#"{"a":1}"#), r#"{"a":1}"#);
    assert_eq!(canon(r#"{"a":1.0}"#), r#"{"a":1.0}"#);
    assert_ne!(canon(r#"{"a":1}"#), canon(r#"{"a":1.0}"#));
    // ... and the literal's SHAPE decides, not its value: 1e2 is a float.
    assert_eq!(canon(r#"{"a":1e2}"#), r#"{"a":100.0}"#);
    assert_eq!(canon(r#"{"a":-0}"#), r#"{"a":0}"#);
    assert_eq!(canon(r#"{"a":-0.0}"#), r#"{"a":-0.0}"#);
}

#[test]
fn floats_are_written_the_way_cpython_repr_writes_them() {
    for (input, expect) in [
        ("0.0", "0.0"),
        ("-0.0", "-0.0"),
        ("1.0", "1.0"),
        ("100.0", "100.0"),
        ("0.0001", "0.0001"),
        ("0.00001", "1e-05"),
        ("1e-06", "1e-06"),
        ("1e-7", "1e-07"),
        ("1e16", "1e+16"),
        ("1e15", "1000000000000000.0"),
        ("1.7976931348623157e308", "1.7976931348623157e+308"),
        ("5e-324", "5e-324"),
        ("1234567890123456.0", "1234567890123456.0"),
        ("2211529743968985.2", "2211529743968985.2"),
    ] {
        assert_eq!(
            canon(&format!(r#"{{"v":{input}}}"#)),
            format!(r#"{{"v":{expect}}}"#),
            "float {input}"
        );
    }
}

#[test]
fn non_finite_numbers_are_refused_at_load_even_outside_the_claim() {
    // "refused at load, even in non-claim fields, so all implementations agree on what
    // LOADS" -- so `env`, which no hash covers, still refuses.
    for text in [
        r#"{"env":{"x":NaN}}"#,
        r#"{"env":{"x":Infinity}}"#,
        r#"{"env":{"x":-Infinity}}"#,
        r#"{"env":{"x":1e400}}"#,
        r#"{"env":{"x":-1e400}}"#,
    ] {
        assert!(load_receipt(text).is_err(), "{text} must not load");
    }
}

// ------------------------------------------------------------------------- the claim
//
// docs/COMPAT.md: "The claim is every top-level key except receipt_sha256, env,
// signature, case, and `_`-prefixed helpers."

#[test]
fn the_claim_excludes_exactly_the_named_keys_and_underscore_helpers() {
    let r = parse(
        r#"{"spec":"x","receipt_sha256":"h","env":{},"signature":{},"case":{},
            "_helper":1,"params":{"a":1},"output":{"b":2}}"#,
    );
    assert_eq!(
        canonical_string(&claim_of(&r)).unwrap(),
        r#"{"output":{"b":2},"params":{"a":1},"spec":"x"}"#
    );
}

#[test]
fn an_underscore_prefix_only_excludes_at_the_top_level() {
    // A nested `_x` is inside the claim: the rule is about top-level helpers, and a
    // reader who applied it recursively would compute a different hash for every
    // receipt carrying a nested private field.
    let r = parse(r#"{"params":{"_x":1,"y":2}}"#);
    assert_eq!(canonical_string(&claim_of(&r)).unwrap(), r#"{"params":{"_x":1,"y":2}}"#);
}

#[test]
fn new_top_level_keys_land_inside_the_claim() {
    // "New top-level keys may be added -- they land inside the claim by default, which
    // is the safe direction (they are covered, not ignorable)."
    let r = parse(r#"{"brand_new_field":7}"#);
    assert_eq!(canonical_string(&claim_of(&r)).unwrap(), r#"{"brand_new_field":7}"#);
}

// -------------------------------------------------------------------- the wire limits
//
// Stated in src/obsign_verify/canonical.py and NOWHERE in docs/. See rust/README.md.

#[test]
fn duplicate_object_members_are_refused_rather_than_resolved() {
    assert!(load_receipt(r#"{"a":1,"a":2}"#).is_err());
    assert!(load_receipt(r#"{"p":{"x":1,"x":2}}"#).is_err());
}

#[test]
fn the_stated_limits_are_the_ones_enforced() {
    use obsign_verify::json::{MAX_DEPTH, MAX_INT_DIGITS, MAX_MEMBERS_PER_OBJECT};
    let at = "1".repeat(MAX_INT_DIGITS);
    assert!(load_receipt(&format!(r#"{{"a":{at}}}"#)).is_ok());
    assert!(load_receipt(&format!(r#"{{"a":{at}1}}"#)).is_err());

    let members = |n: usize| {
        let body: Vec<String> = (0..n).map(|i| format!(r#""k{i}":1"#)).collect();
        format!("{{{}}}", body.join(","))
    };
    assert!(load_receipt(&members(MAX_MEMBERS_PER_OBJECT)).is_ok());
    assert!(load_receipt(&members(MAX_MEMBERS_PER_OBJECT + 1)).is_err());

    // The depth rule caps the depth a VALUE sits at, so the top-level object is 0.
    let nest = |n: usize| format!("{}1{}", "{\"a\":".repeat(n), "}".repeat(n));
    assert!(load_receipt(&nest(MAX_DEPTH)).is_ok());
    assert!(load_receipt(&nest(MAX_DEPTH + 1)).is_err());
}

// -------------------------------------------------------------------- obsign/replay/1
//
// docs/COMPAT.md freezes "the 31-opcode instruction set, wrapping int64 arithmetic,
// truncate-toward-zero division, MULFX's exact-then-truncate-then-wrap order, total
// operations (every partial case a Trap), the step budget, the {spec, mem, steps,
// consts, input, output, code} program shape, and little-endian-int64 output_sha256".

fn run1(code: &str, consts: &str, inputs: &[i64], mem: usize, steps: u64)
    -> Result<Vec<i64>, String>
{
    let text = format!(
        r#"{{"p":{{"spec":"obsign/replay/1","mem":{mem},"steps":{steps},"consts":{consts},
            "input":{{"offset":0,"length":{}}},"output":{{"offset":{},"length":1}},
            "code":{code}}}}}"#,
        inputs.len(),
        mem - 1
    );
    let holder = obsign_verify::json::parse_permissive(&text).unwrap();
    replay::run(holder.get("p").unwrap(), inputs).map_err(|t| t.to_string())
}

#[test]
fn the_instruction_set_has_exactly_thirty_one_opcodes() {
    // docs/COMPAT.md says 31. docs/RL.md says the machine "has 26 opcodes". Both
    // implementations say 31, so the RL document is wrong -- recorded in
    // rust/README.md rather than silently followed.
    let known = [
        "LOADC", "MOV", "ADD", "SUB", "MUL", "DIV", "MOD", "MIN", "MAX", "AND", "OR",
        "XOR", "SHL", "SHR", "EQ", "NE", "LT", "LE", "GT", "GE", "MULFX", "SEL", "NEG",
        "ABS", "NOT", "LOAD", "STORE", "JMP", "JMPZ", "JMPNZ", "HALT",
    ];
    assert_eq!(known.len(), 31);
    for op in known {
        let arity = match op {
            "HALT" => 0,
            "JMP" => 1,
            "MOV" | "NEG" | "ABS" | "NOT" | "LOAD" | "STORE" | "LOADC" | "JMPZ"
            | "JMPNZ" => 2,
            "MULFX" | "SEL" => 4,
            _ => 3,
        };
        let args: Vec<String> = (0..arity).map(|_| "0".to_string()).collect();
        let code = format!(
            r#"[["{op}"{}{}],["HALT"]]"#,
            if arity > 0 { "," } else { "" },
            args.join(",")
        );
        let r = run1(&code, "[0]", &[0], 4, 8);
        assert!(!matches!(&r, Err(e) if e.contains("unknown opcode")), "{op} must exist");
    }
    assert!(run1(r#"[["NOPE",0],["HALT"]]"#, "[0]", &[0], 4, 8)
        .unwrap_err()
        .contains("unknown opcode"));
}

#[test]
fn arithmetic_wraps_at_int64() {
    // "INT64_MAX + 1 is INT64_MIN", stated rather than assumed.
    assert_eq!(
        run1(r#"[["ADD",3,0,1],["HALT"]]"#, "[0]", &[i64::MAX, 1], 4, 8).unwrap(),
        vec![i64::MIN]
    );
    assert_eq!(
        run1(r#"[["MUL",3,0,1],["HALT"]]"#, "[0]", &[i64::MAX, 2], 4, 8).unwrap(),
        vec![-2]
    );
    assert_eq!(
        run1(r#"[["NEG",3,0],["HALT"]]"#, "[0]", &[i64::MIN], 4, 8).unwrap(),
        vec![i64::MIN]
    );
    assert_eq!(
        run1(r#"[["ABS",3,0],["HALT"]]"#, "[0]", &[i64::MIN], 4, 8).unwrap(),
        vec![i64::MIN]
    );
}

#[test]
fn division_truncates_toward_zero_and_int64_min_over_minus_one_wraps() {
    assert_eq!(run1(r#"[["DIV",3,0,1],["HALT"]]"#, "[0]", &[-7, 2], 4, 8).unwrap(), vec![-3]);
    assert_eq!(run1(r#"[["DIV",3,0,1],["HALT"]]"#, "[0]", &[7, -2], 4, 8).unwrap(), vec![-3]);
    assert_eq!(run1(r#"[["MOD",3,0,1],["HALT"]]"#, "[0]", &[-7, 2], 4, 8).unwrap(), vec![-1]);
    // The one genuinely nasty case: it overflows the range and WRAPS, it does not trap.
    assert_eq!(
        run1(r#"[["DIV",3,0,1],["HALT"]]"#, "[0]", &[i64::MIN, -1], 4, 8).unwrap(),
        vec![i64::MIN]
    );
    assert_eq!(
        run1(r#"[["MOD",3,0,1],["HALT"]]"#, "[0]", &[i64::MIN, -1], 4, 8).unwrap(),
        vec![0]
    );
}

#[test]
fn mulfx_multiplies_exactly_before_it_truncates() {
    // The classic fixed-point porting bug is to multiply in int64 and shift after,
    // which loses exactly the high bits the shift exists to discard. 2^62 * 4 has no
    // int64 intermediate at all.
    let got = run1(r#"[["MULFX",3,0,1,32],["HALT"]]"#, "[0]", &[1 << 62, 4], 4, 8).unwrap();
    assert_eq!(got, vec![((1i128 << 62) * 4 / (1i128 << 32)) as i64]);
    // Truncation toward zero applies to a negative product too.
    let got = run1(r#"[["MULFX",3,0,1,1],["HALT"]]"#, "[0]", &[-3, 1], 4, 8).unwrap();
    assert_eq!(got, vec![-1]);
}

#[test]
fn every_partial_operation_is_a_trap() {
    let cases: [(&str, [i64; 2]); 6] = [
        (r#"[["DIV",3,0,1],["HALT"]]"#, [1, 0]),
        (r#"[["MOD",3,0,1],["HALT"]]"#, [1, 0]),
        (r#"[["SHL",3,0,1],["HALT"]]"#, [1, 64]),
        (r#"[["SHR",3,0,1],["HALT"]]"#, [1, -1]),
        (r#"[["LOAD",3,0],["HALT"]]"#, [9_999, 0]),
        (r#"[["STORE",0,1],["HALT"]]"#, [9_999, 0]),
    ];
    for (code, inputs) in cases {
        assert!(run1(code, "[0]", &inputs, 4, 8).is_err(), "{code} must trap");
    }
    // An exhausted budget is a trap too, not a partial answer.
    assert!(run1(r#"[["JMP",0]]"#, "[0]", &[0], 4, 1000).is_err());
}

#[test]
fn the_step_budget_is_checked_before_each_instruction_and_halt_costs_one() {
    // A three-instruction program needs a budget of three. At two it traps -- which is
    // what pins that HALT is counted like any other instruction.
    assert!(run1(r#"[["MOV",3,0],["MOV",3,0],["HALT"]]"#, "[0]", &[5], 4, 3).is_ok());
    assert!(run1(r#"[["MOV",3,0],["MOV",3,0],["HALT"]]"#, "[0]", &[5], 4, 2).is_err());
}

#[test]
fn output_is_hashed_as_little_endian_int64() {
    // One hashing rule for every kernel; length and dtype ride outside the digest.
    assert_eq!(
        replay::output_sha256(&[1]),
        obsign_verify::sha2::sha256_hex(&1i64.to_le_bytes())
    );
    assert_eq!(
        replay::output_sha256(&[-1, 2]),
        obsign_verify::sha2::sha256_hex(&[(-1i64).to_le_bytes(), 2i64.to_le_bytes()].concat())
    );
}

#[test]
fn a_zero_length_output_is_refused_because_every_such_program_shares_one_digest() {
    let text = r#"{"p":{"spec":"obsign/replay/1","mem":4,"steps":8,"consts":[0],
        "input":{"offset":0,"length":1},"output":{"offset":0,"length":0},
        "code":[["HALT"]]}}"#;
    let holder = obsign_verify::json::parse_permissive(text).unwrap();
    assert!(replay::run(holder.get("p").unwrap(), &[0]).is_err());
}

#[test]
fn an_unknown_program_spec_is_refused_not_guessed() {
    let text = r#"{"p":{"spec":"obsign/replay/2","mem":4,"steps":8,"consts":[0],
        "input":{"offset":0,"length":1},"output":{"offset":2,"length":1},
        "code":[["HALT"]]}}"#;
    let holder = obsign_verify::json::parse_permissive(text).unwrap();
    let err = replay::run(holder.get("p").unwrap(), &[0]).unwrap_err().to_string();
    assert!(err.contains("unknown program spec"), "{err}");
}

#[test]
fn structural_scalars_must_be_json_integers() {
    // docs/COMPAT.md, "Refusals added under the guarantee": mem, steps, the window
    // bounds and every instruction operand must be written as an integer literal.
    for bad in ["true", "4.0", "\"4\"", "null"] {
        let text = format!(
            r#"{{"p":{{"spec":"obsign/replay/1","mem":{bad},"steps":8,"consts":[0],
               "input":{{"offset":0,"length":1}},"output":{{"offset":2,"length":1}},
               "code":[["HALT"]]}}}}"#
        );
        let holder = obsign_verify::json::parse_permissive(&text).unwrap();
        assert!(replay::run(holder.get("p").unwrap(), &[0]).is_err(), "mem: {bad}");
    }
    for bad in ["true", "1.0"] {
        let text = format!(
            r#"{{"p":{{"spec":"obsign/replay/1","mem":4,"steps":8,"consts":[{bad}],
               "input":{{"offset":0,"length":1}},"output":{{"offset":2,"length":1}},
               "code":[["HALT"]]}}}}"#
        );
        let holder = obsign_verify::json::parse_permissive(&text).unwrap();
        assert!(replay::run(holder.get("p").unwrap(), &[0]).is_err(), "const: {bad}");
    }
}

// --------------------------------------------------------------- obsign/signature/v2
//
// docs/COMPAT.md: Ed25519 over "obsign/signature/v2\0" + SHA-256(canonical({spec, alg,
// public_key, receipt_sha256, signer, binds_sha256})).

#[test]
fn the_domain_tag_is_the_literal_string_followed_by_a_nul() {
    // A NUL that silently became a space would look right in every diff while making
    // this implementation reject every genuine receipt.
    assert_eq!(signature::SIG_DOMAIN_V2, b"obsign/signature/v2\x00");
    assert_eq!(*signature::SIG_DOMAIN_V2.last().unwrap(), 0u8);
    assert_eq!(signature::SIG_DOMAIN_V2.len(), 20);
}

#[test]
fn an_absent_signature_is_not_a_refusal() {
    // "VERIFIED without a signature is not a weaker result": integrity and
    // re-derivation stand alone. A signature that is PRESENT and does not verify is a
    // refusal; one that is absent is not.
    let unsigned = parse(r#"{"spec":"obsign/receipt/v1"}"#);
    let c = signature::check(&unsigned);
    assert!(!c.present && !c.valid && c.attributed_signer.is_none());
}

#[test]
fn binds_of_nothing_is_no_hash_at_all_not_the_hash_of_an_empty_object() {
    // "an empty selection is None, not the hash of {} -- so 'this signature binds
    // nothing' and 'the bound block was deleted' stay distinguishable."
    let r = parse(r#"{"case":{"examiner":"x"}}"#);
    assert!(signature::binds_hash(&r, &[]).is_none());
    assert!(signature::binds_hash(&r, &["absent".into()]).is_none());
    assert!(signature::binds_hash(&r, &["case".into()]).is_some());
}

#[test]
fn only_keys_present_in_the_receipt_enter_the_bound_hash() {
    // Hashing a missing key as null would be a second, silently different canonical form.
    let r = parse(r#"{"case":{"examiner":"x"}}"#);
    let with_absent = signature::binds_hash(&r, &["case".into(), "nope".into()]);
    let just_case = signature::binds_hash(&r, &["case".into()]);
    assert_eq!(with_absent, just_case);
}

// -------------------------------------------------------------------- the shipped data

#[test]
fn the_committed_conformance_chain_verifies() {
    // COMPAT.md calls data/conformance/ "the freeze made executable": those bytes must
    // verify, byte-identically, forever. An implementation written from the spec that
    // could not re-derive them would mean the spec and the data disagree.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("src/obsign_verify/data/conformance/chain");
    let mut receipts = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("chain fixtures must be present") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            receipts.push(parse(&std::fs::read_to_string(&path).unwrap()));
        }
    }
    assert_eq!(receipts.len(), 4, "the frozen chain is four nodes");
    let g = obsign_verify::graph::verify_graph(&receipts);
    assert!(g.graph_verified, "the shipped chain must verify: {:?}", g.notes);
    assert!(g.complete);
}

#[test]
fn the_producer_signed_receipt_verifies_with_its_signer_bound() {
    // Signed by the PRODUCER, not by this crate. Two implementations that only ever
    // check their own output agree about their own mistakes.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("src/obsign_verify/data/conformance/producer_signed_replay.json");
    let r = parse(&std::fs::read_to_string(path).unwrap());
    let v = obsign_verify::verify::verify(&r);
    assert!(v.verified, "{:?}", v.notes);
    let sig = v.signature.unwrap();
    assert!(sig.valid && sig.identity_bound);
    assert_eq!(sig.attributed_signer.as_deref(), Some("A. Chen, Coherence Energy Labs"));
}
