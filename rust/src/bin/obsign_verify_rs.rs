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

use obsign_verify::graph::{verify_graph, LinksOk};
use obsign_verify::json::{canonical_string, load_receipt, parse_permissive, Value};
use obsign_verify::replay;
use obsign_verify::verify::{verify, Verdict};
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
        ("input_liveness", opt_str(&v.input_liveness)),
        ("input_liveness_by_input", strings(&v.input_liveness_by_input)),
        ("signature", sig),
        (
            "output",
            match &v.output {
                None => Value::Null,
                Some(o) => Value::Array(o.iter().map(|x| s(&x.to_string())).collect()),
            },
        ),
        ("notes", strings(&v.notes)),
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
                Some(Ok(v)) => obj(vec![("loaded", Value::Bool(true)), ("verdict", verdict_to_json(&verify(&v)))]),
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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!(
            "usage: obsign-verify-rs [--chain] [--expect-program HEX] RECEIPT.json...\n       \
             obsign-verify-rs --harness MODE JOBFILE"
        );
        return ExitCode::from(2);
    }
    if args[0] == "--harness" {
        harness(&args[1], &args[2]);
        return ExitCode::SUCCESS;
    }

    let mut chain = false;
    let mut expect_program: Option<String> = None;
    let mut files: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--chain" => chain = true,
            "--expect-program" => {
                i += 1;
                expect_program = args.get(i).cloned();
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
        let g = verify_graph(&receipts);
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

    let mut verified = 0usize;
    for (f, v) in &loaded {
        let mut res = verify(v);
        // Re-derivation proves the output follows FROM THE PROGRAM. It does not prove
        // the program computes what its name claims. Pinning the digest a validator
        // approved after READING it is what answers that question.
        if let Some(want) = &expect_program {
            let got = v
                .get("params")
                .and_then(|p| p.get("program"))
                .and_then(replay::program_sha256);
            if got.as_deref() != Some(want.as_str()) {
                res.verified = false;
                res.notes.push(format!(
                    "program is not the approved one: expected {want}, receipt carries {}",
                    got.as_deref().unwrap_or("<no program>")
                ));
            }
        }
        if res.verified {
            verified += 1;
        }
        println!("  [{}] {f}", if res.verified { "VERIFIED" } else { "REFUSED " });
        println!("      integrity   {}", if res.integrity { "ok" } else { "FAILED" });
        println!(
            "      re-derived  {}",
            match res.reproduced {
                Some(true) => "ok",
                Some(false) => "FAILED",
                None => "not attempted",
            }
        );
        match &res.signature {
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
