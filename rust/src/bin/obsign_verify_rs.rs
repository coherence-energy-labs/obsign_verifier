//! The command-line verifier, plus the machine-readable modes the cross-language
//! differential drives.
//!
//! Exit code `0` if every receipt verified, `1` otherwise. That is the whole
//! interface, and it is the part a pipeline actually reads -- a note printed on stdout
//! is documentation, and documentation is not a control.
//!
//! WHY int64 VALUES LEAVE HERE AS STRINGS. The harness output is read by a JavaScript
//! runner, and `JSON.parse` turns every number into a double: an output value above
//! 2^53 would be compared after being rounded, which is the precise failure this
//! format exists to make impossible. Digits in quotes cross safely.

use obsign_verify::graph::{verify_graph, verify_graph_with, LinksOk};
use obsign_verify::json::{canonical_string, load_receipt, parse_permissive, Value};
use obsign_verify::replay;
use obsign_verify::verify::{verify, verify_with, Verdict};
use obsign_verify::witness;
use std::process::ExitCode;

fn s(v: &str) -> Value {
    Value::str_of(v)
}

fn obj(pairs: Vec<(&str, Value)>) -> Value {
    Value::Object(pairs.into_iter().map(|(k, v)| (k.encode_utf16().collect(), v)).collect())
}

fn strings(items: &[String]) -> Value {
    Value::Array(items.iter().map(|x| s(x)).collect())
}

fn opt_str(v: &Option<String>) -> Value {
    match v {
        Some(x) => s(x),
        None => Value::Null,
    }
}

fn verdict_to_json(v: &Verdict) -> Value {
    let sig = match &v.signature {
        None => Value::Null,
        Some(c) => obj(vec![
            ("present", Value::Bool(c.present)),
            ("valid", Value::Bool(c.valid)),
            ("unsupported", Value::Bool(c.unsupported)),
            ("identity_bound", Value::Bool(c.identity_bound)),
            ("attributed_signer", opt_str(&c.attributed_signer)),
            ("claimed_signer", opt_str(&c.claimed_signer)),
            ("bound_metadata", strings(&c.bound_metadata)),
            ("unbound_metadata", strings(&c.unbound_metadata)),
        ]),
    };
    obj(vec![
        ("integrity", Value::Bool(v.integrity)),
        (
            "reproduced",
            match v.reproduced {
                None => Value::Null,
                Some(b) => Value::Bool(b),
            },
        ),
        ("verified", Value::Bool(v.verified)),
        ("unsupported", Value::Bool(v.unsupported)),
        (
            "approved_program",
            match v.approved_program {
                None => Value::Null,
                Some(b) => Value::Bool(b),
            },
        ),
        ("input_liveness", opt_str(&v.input_liveness)),
        ("input_liveness_by_input", strings(&v.input_liveness_by_input)),
        ("output_liveness_by_cell", strings(&v.output_liveness_by_cell)),
        ("signature", sig),
        ("notes", strings(&v.notes)),
    ])
}

/// Re-run the receipt's own program on its own inputs, INDEPENDENTLY of the verdict.
///
/// This used to report `Verdict.output`, which is only populated by the replay rung --
/// so on any receipt the ladder declines to re-execute (an unsupported `spec`, an
/// unknown kernel) Rust reported `null` while the Python and JavaScript legs, which
/// have always run the program separately, reported the numbers. That is a difference
/// between three HARNESSES, not between three verifiers, and a differential that
/// cannot tell those apart reports the wrong finding. All three legs now answer the
/// same question: "what does this program compute on these inputs", asked of the
/// receipt and not of the verdict. `null` whenever that cannot be done -- which is a
/// fact all three must agree on too.
fn outputs_of(receipt: &Value) -> Value {
    let params = match receipt.get("params") {
        Some(p) => p,
        None => return Value::Null,
    };
    let prog = match params.get("program") {
        Some(p) => p,
        None => return Value::Null,
    };
    let inputs = match params.get("inputs").map(replay::read_inputs) {
        Some(Ok(v)) => v,
        _ => return Value::Null,
    };
    match replay::run(prog, &inputs) {
        Ok(o) => Value::Array(o.iter().map(|x| s(&x.to_string())).collect()),
        Err(_) => Value::Null,
    }
}

/// How ONE graph node is serialised. Extracted so the `--harness graph` mode and the
/// CLI's `--json` cannot drift about what `links_ok` is called -- `incomplete` is a
/// STRING beside two booleans, and two spellings of that in one binary is exactly the
/// kind of divergence this crate exists to prevent.
fn graph_nodes_json(g: &obsign_verify::graph::GraphVerdict) -> Value {
    Value::Object(
        g.nodes
            .iter()
            .map(|(d, n)| {
                (
                    d.encode_utf16().collect::<Vec<u16>>(),
                    obj(vec![
                        ("verified", Value::Bool(n.verified)),
                        (
                            "links_ok",
                            match n.links_ok {
                                LinksOk::NotApplicable => Value::Null,
                                LinksOk::Ok => Value::Bool(true),
                                LinksOk::Bad => Value::Bool(false),
                                LinksOk::Incomplete => s("incomplete"),
                            },
                        ),
                        (
                            "envelopes",
                            Value::Int(obsign_verify::json::Int::from_i64(n.envelopes as i64)),
                        ),
                        ("notes", strings(&n.notes)),
                    ]),
                )
            })
            .collect(),
    )
}

/// The `--chain --json` document. Mirrors `src/obsign_verify/cli.py::_chain`, which
/// prints `{**graph_verdict, "unreadable": [...]}`: a caller that parses one CLI's
/// chain output must be able to parse another's.
fn graph_to_json(g: &obsign_verify::graph::GraphVerdict) -> Value {
    let mut roots = g.roots.clone();
    roots.sort();
    obj(vec![
        ("graph_verified", Value::Bool(g.graph_verified)),
        ("complete", Value::Bool(g.complete)),
        ("missing", strings(&g.missing)),
        ("roots", strings(&roots)),
        ("order", strings(&g.order)),
        ("nodes", graph_nodes_json(g)),
        ("notes", strings(&g.notes)),
    ])
}

/// A harness job file is `[[name, payload], ...]`, mirroring the shape the repository's
/// existing cross-language runners already use.
fn read_cases(path: &str) -> Vec<(String, Value)> {
    let text = std::fs::read_to_string(path).expect("cannot read job file");
    // The job file is this harness's own plumbing, not a receipt: it legitimately
    // carries oversized strings and deep nesting as the TEXT OF A CASE, and applying
    // the receipt limits to it would make the corpus unable to describe its own edges.
    let parsed = parse_permissive(&text).expect("job file is not JSON");
    let arr = parsed.as_array().expect("job file must be an array");
    arr.iter()
        .map(|pair| {
            let a = pair.as_array().expect("case must be [name, payload]");
            (a[0].as_str().expect("case name must be a string"), a[1].clone())
        })
        .collect()
}

fn print_json(v: &Value) {
    println!("{}", canonical_string(v).expect("harness output is serialisable"));
}

fn harness(mode: &str, path: &str) {
    let cases = read_cases(path);
    let mut out: Vec<(&str, Value)> = Vec::new();
    let mut owned_names: Vec<String> = Vec::new();
    for (name, _) in &cases {
        owned_names.push(name.clone());
    }
    for (i, (_, payload)) in cases.iter().enumerate() {
        let name: &str = &owned_names[i];
        let value = match mode {
            // Does the text LOAD? The verifiers must agree on what a receipt IS, not
            // merely on what a receipt hashes to.
            "load" => match payload.as_str() {
                Some(text) => Value::Bool(load_receipt(&text).is_ok()),
                None => Value::Bool(false),
            },
            // The canonical bytes, which every implementation must produce identically.
            "canon" => match payload.as_str().map(|t| load_receipt(&t)) {
                Some(Ok(v)) => match canonical_string(&v) {
                    Ok(c) => s(&c),
                    Err(_) => Value::Null,
                },
                _ => Value::Null,
            },
            "verify" => match payload.as_str().map(|t| load_receipt(&t)) {
                Some(Ok(v)) => {
                    let mut verdict = verdict_to_json(&verify(&v));
                    if let Value::Object(fields) = &mut verdict {
                        fields.push(("output".encode_utf16().collect(), outputs_of(&v)));
                    }
                    obj(vec![("loaded", Value::Bool(true)), ("verdict", verdict)])
                }
                _ => obj(vec![("loaded", Value::Bool(false)), ("verdict", Value::Null)]),
            },
            "graph" => {
                let texts = payload.as_array().expect("graph case payload must be a list");
                let mut receipts = Vec::new();
                let mut all_loaded = true;
                for t in texts {
                    match t.as_str().map(|x| load_receipt(&x)) {
                        Some(Ok(v)) => receipts.push(v),
                        _ => all_loaded = false,
                    }
                }
                if !all_loaded {
                    obj(vec![("loaded", Value::Bool(false))])
                } else {
                    let g = verify_graph(&receipts);
                    let nodes = Value::Object(
                        g.nodes
                            .iter()
                            .map(|(d, n)| {
                                (
                                    d.encode_utf16().collect::<Vec<u16>>(),
                                    obj(vec![
                                        ("verified", Value::Bool(n.verified)),
                                        (
                                            "links_ok",
                                            match n.links_ok {
                                                LinksOk::NotApplicable => Value::Null,
                                                LinksOk::Ok => Value::Bool(true),
                                                LinksOk::Bad => Value::Bool(false),
                                                LinksOk::Incomplete => s("incomplete"),
                                            },
                                        ),
                                        ("envelopes", Value::Int(obsign_verify::json::Int::from_i64(n.envelopes as i64))),
                                    ]),
                                )
                            })
                            .collect(),
                    );
                    let mut roots = g.roots.clone();
                    roots.sort();
                    obj(vec![
                        ("loaded", Value::Bool(true)),
                        ("graph_verified", Value::Bool(g.graph_verified)),
                        ("complete", Value::Bool(g.complete)),
                        ("missing", strings(&g.missing)),
                        ("roots", strings(&roots)),
                        ("nodes", nodes),
                    ])
                }
            }
            // obsign/witness/v1: a single document, or a chain when the payload is a
            // list of more than one. Field names mirror the Python and JavaScript
            // runners exactly, so the comparator compares three dictionaries rather
            // than three prose reports.
            "witness" => {
                let texts = payload
                    .as_array()
                    .expect("witness case payload must be a list of document texts");
                let mut docs = Vec::new();
                let mut all_loaded = true;
                for t in texts {
                    match t.as_str().map(|x| load_receipt(&x)) {
                        Some(Ok(v)) => docs.push(v),
                        _ => all_loaded = false,
                    }
                }
                if !all_loaded {
                    obj(vec![("loaded", Value::Bool(false))])
                } else if docs.len() == 1 {
                    let v = witness::verify_witness(&docs[0]);
                    obj(vec![
                        ("kind", s("single")),
                        ("verified", Value::Bool(v.verified)),
                        ("integrity", Value::Bool(v.integrity)),
                        // Always null: nothing was re-executed, and `false` would
                        // accuse the document of failing a test that never ran.
                        ("reproduced", Value::Null),
                        ("assurance", match &v.assurance {
                            Some(a) => s(a),
                            None => Value::Null,
                        }),
                        ("derived", s(v.derived)),
                        ("signature_valid", match v.signature_valid {
                            Some(b) => Value::Bool(b),
                            None => Value::Null,
                        }),
                    ])
                } else {
                    let c = witness::verify_chain(&docs);
                    let nodes = Value::Object(
                        c.nodes
                            .iter()
                            .map(|(d, n)| {
                                (
                                    d.encode_utf16().collect::<Vec<u16>>(),
                                    obj(vec![
                                        ("verified", Value::Bool(n.verified)),
                                        (
                                            "links_ok",
                                            match n.links_ok {
                                                witness::LinksOk::None => Value::Null,
                                                witness::LinksOk::Yes => Value::Bool(true),
                                                witness::LinksOk::No => Value::Bool(false),
                                                witness::LinksOk::Incomplete => s("incomplete"),
                                            },
                                        ),
                                        ("assurance", match &n.assurance {
                                            Some(a) => s(a),
                                            None => Value::Null,
                                        }),
                                    ]),
                                )
                            })
                            .collect(),
                    );
                    obj(vec![
                        ("kind", s("chain")),
                        ("ok", Value::Bool(c.ok)),
                        ("effective_assurance", match &c.effective_assurance {
                            Some(a) => s(a),
                            None => Value::Null,
                        }),
                        ("nodes", nodes),
                    ])
                }
            }
            // Raw machine: (program, inputs) -> output values, or a trap.
            "vm" => {
                let prog_text = payload.get("program").and_then(|v| v.as_str()).expect("vm case needs program");
                let inputs: Vec<i64> = payload
                    .get("inputs")
                    .and_then(|v| v.as_array())
                    .expect("vm case needs inputs")
                    .iter()
                    .map(|x| x.as_str().expect("inputs cross as strings").parse::<i64>().expect("input is an i64"))
                    .collect();
                match load_receipt(&format!("{{\"p\":{prog_text}}}")) {
                    Err(e) => obj(vec![("ok", Value::Bool(false)), ("trap", s(&format!("load: {e}")))]),
                    Ok(holder) => {
                        let prog = holder.get("p").unwrap();
                        match replay::run(prog, &inputs) {
                            Ok(o) => obj(vec![
                                ("ok", Value::Bool(true)),
                                ("out", Value::Array(o.iter().map(|x| s(&x.to_string())).collect())),
                                ("output_sha256", s(&replay::output_sha256(&o))),
                                (
                                    "program_sha256",
                                    match replay::program_sha256(prog) {
                                        Some(d) => s(&d),
                                        None => Value::Null,
                                    },
                                ),
                            ]),
                            Err(t) => obj(vec![("ok", Value::Bool(false)), ("trap", s(&t.to_string()))]),
                        }
                    }
                }
            }
            other => panic!("unknown harness mode {other}"),
        };
        out.push((name, value));
    }
    print_json(&Value::Object(
        out.into_iter().map(|(k, v)| (k.encode_utf16().collect(), v)).collect(),
    ));
}

fn usage() {
    eprintln!(
        "usage: obsign-verify-rs [--chain] [--expect-program HEX] [--strict-liveness]\n\
        \x20                       [--chain-list FILE] [--json] RECEIPT.json...\n\
        \x20      obsign-verify-rs --harness MODE JOBFILE\n\
        \n\
        \x20 --chain            verify the receipts as a GRAPH (docs/GRAPHS.md): every\n\
        \x20                    node re-derived, every params.links slice compared\n\
        \x20                    value-for-value against a fresh re-derivation of the\n\
        \x20                    child it names. Exit 0 only if the whole chain holds.\n\
        \x20 --expect-program   require the replay program to be the one your validator\n\
        \x20                    approved (its program_sha256).\n\
        \x20 --strict-liveness  refuse a receipt whose input-liveness probe ended\n\
        \x20                    'indeterminate'. Reaches chain nodes and link slices too.\n\
        \x20 --chain-list FILE  read receipt paths from FILE, one per line.\n\
        \x20 --json             machine-readable output.\n\
        \x20 --help             this text."
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
        return ExitCode::from(2);
    }
    // `--help` PRINTED "cannot read --help" AND EXITED 1, because the catch-all below
    // treated it as a filename. The other two CLIs answer it and exit 0; a tool whose
    // help is an error is a tool a first-time user concludes is broken.
    if args.iter().any(|a| a == "--help" || a == "-h") {
        usage();
        return ExitCode::SUCCESS;
    }
    if args[0] == "--harness" {
        harness(&args[1], &args[2]);
        return ExitCode::SUCCESS;
    }

    let mut chain = false;
    let mut as_json = false;
    let mut strict_liveness = false;
    let mut expect_program: Option<String> = None;
    let mut files: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--chain" => chain = true,
            // MACHINE-READABLE OUTPUT, WHICH THIS CLI SIMPLY DID NOT HAVE. The other
            // two both take --json; here it fell through the catch-all, was read as a
            // FILENAME, and printed "[REFUSED] --json  cannot read" beside a verdict
            // for the real receipt. Any script that pipes this binary to a parser got
            // human prose plus a fabricated refusal line.
            "--json" => as_json = true,
            "--strict-liveness" => strict_liveness = true,
            "--expect-program" => {
                i += 1;
                // A FLAG WITH NO VALUE MUST NOT SILENTLY MEAN "NO PIN". This was
                // `args.get(i).cloned()`, so `--expect-program` at the end of argv
                // set None and the run printed VERIFIED with the pin absent -- the
                // one flag whose whole purpose is to turn "did this re-derive?"
                // into "did this re-derive from the program my validator approved?"
                // A wrapper or CI matrix that builds argv programmatically could
                // drop it with no diagnostic. The reference CLI (argparse) has
                // always refused this; now so does this one.
                match args.get(i) {
                    Some(v) if !v.starts_with("--") => expect_program = Some(v.clone()),
                    _ => {
                        eprintln!(
                            "--expect-program needs a program digest; none was given.                              Refusing to run WITHOUT the pin rather than silently                              verifying without it."
                        );
                        std::process::exit(2);
                    }
                }
            }
            // THE SAME ARGUMENT LIST, DELIVERED THROUGH A CHANNEL WITH NO LIMIT. A
            // chain of thousands of nodes cannot be named in argv on Windows (8191
            // characters), and a refusal to RUN is not a verdict -- while the
            // deep-chain property is exactly the one that needs thousands of nodes.
            "--chain-list" => {
                i += 1;
                let path = match args.get(i) {
                    Some(p) => p.clone(),
                    None => {
                        eprintln!("--chain-list needs a file");
                        return ExitCode::from(2);
                    }
                };
                match std::fs::read_to_string(&path) {
                    Ok(text) => {
                        for line in text.lines() {
                            let t = line.trim();
                            if !t.is_empty() && !t.starts_with('#') {
                                files.push(t.to_string());
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("cannot read --chain-list {path}: {e}");
                        return ExitCode::from(2);
                    }
                }
            }
            // AN UNKNOWN SWITCH IS AN ERROR, NOT A FILENAME.
            //
            // The catch-all pushed EVERYTHING here, so `--strict-livenes` (one letter
            // short) became a path, failed to open, and printed
            //
            //     [REFUSED] --strict-livenes
            //         cannot read: The system cannot find the file specified.
            //
            // with exit 1. It fails closed, which is the only reason this is a defect
            // and not a breach -- but the diagnosis is wrong in the direction that
            // matters: the strictness the operator asked for WAS NEVER APPLIED, and
            // the run reports "a file failed". In a multi-receipt run that reads as
            // one bad receipt among many. It is the same class as the
            // `--expect-program` fail-open directly above: a security switch that is
            // accepted and ignored. The reference CLI (argparse) has always exited 2
            // with "unrecognized arguments"; now so does this one.
            //
            // A single "-" is left alone: it is a conventional stdin sentinel, not a
            // switch, and refusing it here would be a new incompatibility.
            f if f.starts_with('-') && f != "-" => {
                eprintln!(
                    "unrecognized argument {f:?}. Refusing to run rather than treat a \
                     switch as a filename -- a mistyped flag must not silently mean \
                     the flag was never given."
                );
                usage();
                return ExitCode::from(2);
            }
            f => files.push(f.to_string()),
        }
        i += 1;
    }

    let mut loaded = Vec::new();
    let mut failed = false;
    for f in &files {
        let text = match std::fs::read_to_string(f) {
            Ok(t) => t,
            Err(e) => {
                println!("  [REFUSED] {f}\n      cannot read: {e}");
                failed = true;
                continue;
            }
        };
        match load_receipt(&text) {
            Ok(v) => loaded.push((f.clone(), v)),
            Err(e) => {
                // Outside the wire format is a REFUSAL with a reason, never a crash: a
                // verifier that dies on a hostile receipt has failed open in the eyes
                // of whoever handed it the file.
                println!("  [REFUSED] {f}\n      not a receipt: {e}");
                failed = true;
            }
        }
    }

    if chain {
        let receipts: Vec<Value> = loaded.iter().map(|(_, v)| v.clone()).collect();
        let g = verify_graph_with(&receipts, strict_liveness);
        if as_json {
            print_json(&graph_to_json(&g));
            return if g.graph_verified && !failed { ExitCode::SUCCESS } else { ExitCode::from(1) };
        }
        for (d, n) in &g.nodes {
            println!(
                "  {} {}  verified={} links_ok={}",
                if n.verified { "ok  " } else { "FAIL" },
                &d[..16.min(d.len())],
                n.verified,
                match n.links_ok {
                    LinksOk::NotApplicable => "n/a".to_string(),
                    LinksOk::Ok => "true".to_string(),
                    LinksOk::Bad => "false".to_string(),
                    LinksOk::Incomplete => "incomplete".to_string(),
                }
            );
            for note in &n.notes {
                println!("        {note}");
            }
        }
        for note in &g.notes {
            println!("      {note}");
        }
        if !g.complete {
            for m in &g.missing {
                println!("      MISSING {m} -- incomplete, which is not the same as forged");
            }
        }
        println!(
            "\n{} chain: {}",
            g.nodes.len(),
            if g.graph_verified { "GRAPH VERIFIED" } else { "NOT VERIFIED" }
        );
        return if g.graph_verified && !failed { ExitCode::SUCCESS } else { ExitCode::from(1) };
    }

    if as_json {
        let mut report: Vec<Value> = Vec::new();
        for (f, v) in &loaded {
            let res = verify_with(v, expect_program.as_deref(), strict_liveness);
            if !res.verified {
                failed = true;
            }
            let mut verdict = verdict_to_json(&res);
            if let Value::Object(fields) = &mut verdict {
                fields.insert(0, ("file".encode_utf16().collect(), s(f)));
            }
            report.push(verdict);
        }
        print_json(&Value::Array(report));
        return if failed { ExitCode::from(1) } else { ExitCode::SUCCESS };
    }

    let mut verified = 0usize;
    for (f, v) in &loaded {
        // PROGRAM PINNING AND STRICT LIVENESS ARE LIBRARY ARGUMENTS, not CLI
        // post-processing. Living in three CLIs meant every caller that links the crate
        // instead of shelling out silently got the weaker question, with no field in
        // the verdict to say so.
        let res = verify_with(v, expect_program.as_deref(), strict_liveness);
        if res.verified {
            verified += 1;
        }
        // A HEADLINE THAT HIDES AN UNPROVEN RUNG IS THE DEFECT, NOT THE VERDICT.
        let tag = if res.verified && res.input_liveness.as_deref() == Some("indeterminate") {
            "  (inputs unproven)"
        } else if res.unsupported {
            "  (unsupported format - NOT verified)"
        } else {
            ""
        };
        println!("  [{}] {f}{tag}", if res.verified { "VERIFIED" } else { "REFUSED " });
        println!("      integrity   {}", if res.integrity { "ok" } else { "FAILED" });
        println!(
            "      re-derived  {}",
            match res.reproduced {
                Some(true) => "ok",
                Some(false) => "FAILED",
                None => "not attempted",
            }
        );
        match res.input_liveness.as_deref() {
            None | Some("n/a") => {}
            Some(live) => println!(
                "      inputs      {}",
                match live {
                    "live" => "ok - the output depends on the declared inputs",
                    "dead" => "FAIL - the output ignores every declared input",
                    "guarded" => "FAIL - the program trapped on every perturbation, so \
                                  nothing was shown to reach the output",
                    "indeterminate" =>
                        "UNPROVEN (probe budget reached) - semantic validity not established",
                    other => other,
                }
            ),
        }
        if let Some(approved) = res.approved_program {
            println!(
                "      program     {}",
                if approved {
                    "ok - matches the approved digest"
                } else {
                    "FAIL - not the approved program"
                }
            );
        }
        match &res.signature {
            Some(c) if c.present && c.unsupported => {
                // "I did not read it" is a THIRD answer; printing FAILED would claim
                // the signature was checked and found wanting.
                println!("      signature   UNSUPPORTED spec - nothing was checked");
            }
            Some(c) if c.present => println!(
                "      signature   {}{}",
                if c.valid { "ok" } else { "FAILED" },
                match (&c.attributed_signer, c.valid) {
                    (Some(n), true) => format!(", signer BOUND ({n})"),
                    (None, true) => ", attributes NOBODY (v1 covers no name)".to_string(),
                    _ => String::new(),
                }
            ),
            _ => println!("      signature   absent (integrity and re-derivation still hold)"),
        }
        for note in &res.notes {
            println!("      - {note}");
        }
    }

    println!("\n{verified}/{} receipt(s) verified on THIS machine.", loaded.len());
    if failed || verified != loaded.len() || loaded.is_empty() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
