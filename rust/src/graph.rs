//! Receipt graphs -- a supply chain of computation, leaf to root.
//!
//! docs/GRAPHS.md is the contract and this file only implements it. It is the
//! best-specified surface in the estate: the six numbered rules there were enough to
//! write this from, which is not true of the VM or the wire format.
//!
//! VERDICTS STAY SPLIT AND HONEST. A node can be `verified` (internally true) while
//! its `links_ok` is false (it lied about where its inputs came from). A missing child
//! makes the graph `incomplete` -- reported with the digest, and spelled differently
//! from FORGED in both directions, because "I could not check this" and "this is
//! false" are different facts. `graph_verified` is the conjunction.
//!
//! A NODE IS A CLAIM; A RECEIPT IS AN ENVELOPE AROUND ONE. `signature`, `case`, `env`
//! and `receipt_sha256` are all outside the claim, so two documents can index to the
//! same node -- one genuine, one re-enveloped by whoever handed you the set. Every
//! supplied envelope runs the ladder and the node's verdict is their conjunction, so a
//! hostile copy is a supplied failure rather than an accident of list order.

use crate::json::{canonical_string, claim_of, Value};
use crate::replay;
use crate::verify::verify_with;
use std::collections::{BTreeMap, BTreeSet};

/// The first 16 CHARACTERS of a digest, for notes.
///
/// A link's digest is only checked for length 64, which is a count of BYTES -- so a
/// 64-byte string of two-byte characters passes that check and then panics a
/// byte-slice. A note is not worth a crash.
fn head16(s: &str) -> String {
    s.chars().take(16).collect()
}

const LINK_FIELDS: [&str; 5] =
    ["receipt_sha256", "output_sha256", "src_offset", "length", "dst_offset"];

/// `true`, `false`, or the third answer the rule needs: a link whose child was never
/// supplied is not a lie, it is an absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinksOk {
    NotApplicable,
    Ok,
    Incomplete,
    Bad,
}

#[derive(Debug, Clone)]
pub struct NodeVerdict {
    pub verified: bool,
    pub links_ok: LinksOk,
    pub envelopes: usize,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct GraphVerdict {
    pub graph_verified: bool,
    pub complete: bool,
    pub missing: Vec<String>,
    pub roots: Vec<String>,
    pub order: Vec<String>,
    pub nodes: Vec<(String, NodeVerdict)>,
    pub notes: Vec<String>,
}

fn links_of(receipt: &Value) -> Vec<&Value> {
    match receipt.get("params").and_then(|p| p.get("links")).and_then(|l| l.as_array()) {
        Some(a) => a.iter().collect(),
        None => Vec::new(),
    }
}

/// `None` if the link has the spec'd shape, else the reason it does not.
fn well_formed_link(ln: &Value) -> Option<String> {
    if !matches!(ln, Value::Object(_)) {
        return Some("link is not an object".into());
    }
    for f in LINK_FIELDS {
        if !ln.has(f) {
            return Some(format!("link is missing '{f}'"));
        }
    }
    for f in ["receipt_sha256", "output_sha256"] {
        match ln.get(f).and_then(|v| v.as_str()) {
            Some(s) if s.len() == 64 => {}
            _ => return Some(format!("link.{f} must be a 64-hex digest")),
        }
    }
    for f in ["src_offset", "length", "dst_offset"] {
        match ln.get(f).and_then(|v| v.as_i64()) {
            Some(v) if v >= 0 => {}
            _ => return Some(format!("link.{f} must be a non-negative integer")),
        }
    }
    if ln.get("length").and_then(|v| v.as_i64()) == Some(0) {
        return Some("link.length must be > 0".into());
    }
    None
}

struct Node<'a> {
    receipt: Option<&'a Value>,
    /// Keyed by canonical document bytes, so two documents carrying the same claim but
    /// differing outside it are two envelopes and not one.
    envelopes: BTreeMap<String, Option<&'a Value>>,
    verified: bool,
    links_ok: LinksOk,
    notes: Vec<String>,
    /// `output_liveness_by_cell` from this node's standalone ladder -- which output
    /// cells a perturbation of the declared inputs was ever seen to move. The link
    /// rule below reads it; without it this implementation accepted a chain the
    /// reference refuses, which is the one disagreement the format cannot absorb.
    cells: Vec<String>,
}

/// What tells two receipts carrying the SAME claim apart. A document that will not
/// canonicalise gets a key unique to its position, so it counts as its own envelope
/// instead of being merged into another receipt's verdict.
fn envelope_key(receipt: &Value, index: usize) -> String {
    canonical_string(receipt).unwrap_or_else(|_| format!("<uncanonicalisable envelope #{index}>"))
}

/// Verify RECEIPTS individually and transitively, with the default liveness policy.
///
/// Never fails on hostile input -- an exception is not a refusal, on a graph exactly
/// as on a single receipt.
pub fn verify_graph(receipts: &[Value]) -> GraphVerdict {
    verify_graph_with(receipts, false)
}

/// As `verify_graph`, with the `--strict-liveness` switch.
///
/// It reaches BOTH rungs of the chain: each node's standalone ladder, and the rule
/// that asks whether the slice a link carries was ever shown to move. `--chain
/// --strict-liveness` used to parse the flag and change nothing, in this
/// implementation and in the reference alike.
pub fn verify_graph_with(receipts: &[Value], strict_liveness: bool) -> GraphVerdict {
    let mut graph_notes: Vec<String> = Vec::new();
    let mut order_of_insertion: Vec<String> = Vec::new();
    let mut nodes: BTreeMap<String, Node> = BTreeMap::new();
    let mut canon: BTreeMap<String, String> = BTreeMap::new();

    // Index by RECOMPUTED claim hash: a link names content, not a self-description.
    for (i, r) in receipts.iter().enumerate() {
        if !matches!(r, Value::Object(_)) {
            let key = format!("<non-object #{i}>");
            graph_notes.push(format!(
                "receipts[{i}] is not an object; ignored as a node (and the graph cannot \
                 be green with it supplied)"
            ));
            let mut env = BTreeMap::new();
            env.insert(key.clone(), None);
            nodes.insert(
                key.clone(),
                Node {
                    receipt: None,
                    envelopes: env,
                    verified: false,
                    links_ok: LinksOk::NotApplicable,
                    notes: vec!["not a JSON object".into()],
                    cells: Vec::new(),
                },
            );
            order_of_insertion.push(key);
            continue;
        }
        let claim = claim_of(r);
        let cstr = match canonical_string(&claim) {
            Ok(s) => s,
            Err(e) => {
                let key = format!("<uncanonicalisable #{i}>");
                let mut env = BTreeMap::new();
                env.insert(key.clone(), None);
                nodes.insert(
                    key.clone(),
                    Node {
                        receipt: None,
                        envelopes: env,
                        verified: false,
                        links_ok: LinksOk::NotApplicable,
                        notes: vec![format!("claim is not canonicalisable ({e})")],
                        cells: Vec::new(),
                    },
                );
                order_of_insertion.push(key);
                continue;
            }
        };
        let digest = crate::sha2::sha256_hex(cstr.as_bytes());
        if let Some(node) = nodes.get_mut(&digest) {
            if canon.get(&digest).map(|s| s.as_str()) != Some(cstr.as_str()) {
                // Two different claims, one hash: that is a SHA-256 collision.
                graph_notes.push(format!(
                    "COLLISION: two different claims share digest {}.. -- refusing the \
                     whole graph",
                    head16(&digest)
                ));
                node.notes.push("digest collision".into());
                node.links_ok = LinksOk::Bad;
                continue;
            }
            // Same claim, a DIFFERENT document. Dropping it here would run the
            // standalone ladder on whichever copy arrived first and never examine the
            // other, so a forged re-envelope supplied second would be invisible and the
            // same set of receipts would come out green or red depending on list order.
            node.envelopes.entry(envelope_key(r, i)).or_insert(Some(r));
            continue;
        }
        let mut env = BTreeMap::new();
        env.insert(envelope_key(r, i), Some(r));
        nodes.insert(
            digest.clone(),
            Node {
                receipt: Some(r),
                envelopes: env,
                verified: false,
                links_ok: LinksOk::NotApplicable,
                notes: Vec::new(),
                cells: Vec::new(),
            },
        );
        canon.insert(digest.clone(), cstr);
        order_of_insertion.push(digest);
    }

    for digest in &order_of_insertion {
        let n = &nodes[digest];
        if n.envelopes.len() > 1 {
            graph_notes.push(format!(
                "DUPLICATE ENVELOPE: claim {}.. was supplied as {} documents differing \
                 outside the claim (signature/case/env/receipt_sha256); each is verified \
                 and this node's verdict is their conjunction",
                head16(digest),
                n.envelopes.len()
            ));
        }
    }

    // Every supplied node runs the FULL standalone ladder, on EVERY envelope, in
    // canonical order rather than arrival order, so the notes read identically however
    // the list was shuffled.
    for digest in &order_of_insertion {
        let node = nodes.get(digest).unwrap();
        if node.receipt.is_none() {
            continue;
        }
        let envelopes: Vec<&Value> = node.envelopes.values().flatten().copied().collect();
        let mut all_ok = true;
        let mut new_notes = Vec::new();
        let mut cells: Vec<String> = Vec::new();
        for (n, env) in envelopes.iter().enumerate() {
            let res = verify_with(env, None, strict_liveness);
            if n == 0 {
                // Every envelope carries the SAME claim, so the program, the inputs and
                // therefore the cell verdict are identical; the first is representative.
                cells = res.output_liveness_by_cell.clone();
            }
            if !res.verified {
                all_ok = false;
                let head: Vec<String> = res.notes.iter().take(2).cloned().collect();
                new_notes.push(format!("does not verify standalone: {}", head.join("; ")));
            }
        }
        let node = nodes.get_mut(digest).unwrap();
        node.verified = all_ok;
        node.notes.extend(new_notes);
        node.cells = cells;
    }

    // Re-derive outputs once per node that anything links to.
    let mut out_cache: BTreeMap<String, Option<Vec<i64>>> = BTreeMap::new();
    let digests: Vec<String> = order_of_insertion.clone();
    for d in &digests {
        let r = match nodes[d].receipt {
            Some(r) => r,
            None => continue,
        };
        let computed = (|| {
            let params = r.get("params")?;
            let prog = params.get("program")?;
            let inputs = replay::read_inputs(params.get("inputs")?).ok()?;
            replay::run(prog, &inputs).ok()
        })();
        out_cache.insert(d.clone(), computed);
    }

    // Walk the links: ranges, overlaps, missing children, value binding.
    let mut missing: BTreeSet<String> = BTreeSet::new();
    for d in &digests {
        let r = match nodes[d].receipt {
            Some(r) => r,
            None => continue,
        };
        let links = links_of(r);
        if links.is_empty() {
            continue;
        }
        let mut links_ok = LinksOk::Ok; // until a link says otherwise
        let mut notes: Vec<String> = Vec::new();
        if r.get("kernel").and_then(|v| v.as_str()).as_deref() != Some(replay::SPEC) {
            nodes.get_mut(d).unwrap().links_ok = LinksOk::Bad;
            nodes.get_mut(d).unwrap().notes.push(
                "links on a non-replay parent are not supported in graphs v1 \
                 (docs/GRAPHS.md)"
                    .into(),
            );
            continue;
        }
        let parent_inputs = r.get("params").and_then(|p| p.get("inputs")).and_then(|v| v.as_array());
        let mut taken: BTreeSet<i64> = BTreeSet::new();
        for ln in links {
            if let Some(why) = well_formed_link(ln) {
                links_ok = LinksOk::Bad;
                notes.push(why);
                continue;
            }
            let child_digest = ln.get("receipt_sha256").and_then(|v| v.as_str()).unwrap();
            if !nodes.contains_key(&child_digest) {
                missing.insert(child_digest.clone());
                if links_ok == LinksOk::Ok {
                    links_ok = LinksOk::Incomplete;
                }
                notes.push(format!(
                    "link target {}.. was not supplied -- the graph is incomplete, not forged",
                    head16(&child_digest)
                ));
                continue;
            }
            if let Some(child_r) = nodes[&child_digest].receipt {
                if child_r.get("kernel").and_then(|v| v.as_str()).as_deref() != Some(replay::SPEC) {
                    links_ok = LinksOk::Bad;
                    notes.push(format!(
                        "link target {}.. is not an obsign/replay/1 receipt (unsupported in v1)",
                        head16(&child_digest)
                    ));
                    continue;
                }
            }
            let dst = ln.get("dst_offset").and_then(|v| v.as_i64()).unwrap();
            let len = ln.get("length").and_then(|v| v.as_i64()).unwrap();
            let src = ln.get("src_offset").and_then(|v| v.as_i64()).unwrap();
            // Ranges are STRICT: malformed ranges refuse, they do not clamp.
            let parent_len = parent_inputs.map(|a| a.len() as i64).unwrap_or(-1);
            if parent_len < 0 || dst.saturating_add(len) > parent_len {
                links_ok = LinksOk::Bad;
                notes.push(format!(
                    "link destination {dst}..{} is outside this receipt's inputs",
                    dst.saturating_add(len)
                ));
                continue;
            }
            let mut overlapped = None;
            for k in dst..dst.saturating_add(len) {
                if taken.contains(&k) {
                    overlapped = Some(k);
                    break;
                }
            }
            if let Some(k) = overlapped {
                links_ok = LinksOk::Bad;
                notes.push(format!("link destinations overlap at input {k}"));
                continue;
            }
            for k in dst..dst.saturating_add(len) {
                taken.insert(k);
            }
            let child_out = match out_cache.get(&child_digest).and_then(|o| o.as_ref()) {
                Some(o) => o,
                None => {
                    links_ok = LinksOk::Bad;
                    notes.push(format!(
                        "link target {}.. cannot be re-executed, so the link cannot bind",
                        head16(&child_digest)
                    ));
                    continue;
                }
            };
            if src.saturating_add(len) > child_out.len() as i64 {
                links_ok = LinksOk::Bad;
                notes.push(format!(
                    "link source {src}..{} is outside the child's output (length {})",
                    src.saturating_add(len),
                    child_out.len()
                ));
                continue;
            }
            // The stated hash must hold -- redundant against rule 2 for a tamperer, and
            // exactly the redundancy that catches honest mistakes loudly.
            if replay::output_sha256(child_out) != ln.get("output_sha256").and_then(|v| v.as_str()).unwrap() {
                links_ok = LinksOk::Bad;
                notes.push("link.output_sha256 does not match the child's re-derived output".into());
                continue;
            }
            // THE LINK BINDS VALUES, NOT HASHES. The parent must have consumed exactly
            // what the child produced, established by re-derivation on both sides.
            let parent = parent_inputs.unwrap();
            let mut equal = true;
            for k in 0..len {
                let pv = parent[(dst + k) as usize].as_i64();
                let cv = Some(child_out[(src + k) as usize]);
                if pv != cv {
                    equal = false;
                    break;
                }
            }
            if !equal {
                links_ok = LinksOk::Bad;
                notes.push(format!(
                    "inputs[{dst}..{}) do not equal the child's re-derived output[{src}..{}) \
                     -- this receipt did NOT consume what {}.. produced",
                    dst + len,
                    src + len,
                    head16(&child_digest)
                ));
                continue;
            }

            // THE SLICE THAT TRAVELS MUST BE THE PART THAT DEPENDS ON THE INPUTS.
            //
            // This rule did not exist here at all. `verify` refuses a node whose whole
            // output ignores every declared input, and an output window is a VECTOR, so
            // that check is passed by appending one decoy cell and linking only the
            // constant one: every input is live, the node verifies, and a hardcoded
            // value travels the chain. The reference refused exactly that; this
            // implementation returned exit 0 on the same bytes, which hands a forger a
            // choice of verifier on the one rung a supply chain exists to establish.
            //
            // The verdict is THREE-VALUED, because the cell verdict is:
            //
            //   any cell live  -> the link binds something that demonstrably moved
            //   else any indeterminate (or the probe did not cover the slice)
            //                  -> INCOMPLETE: not forged, not established either
            //   else all dead  -> FORGED: the values are constants
            //
            // `Incomplete` is what this graph already says for "a child was not
            // supplied": out of green without calling the producer a forger, which is
            // right for an honest receipt too expensive to sweep. A rule keyed on
            // `dead` alone would be switchable off by the party it constrains -- one
            // long enough spin loop in the child moves its laundered cell to
            // `indeterminate`. Under strict liveness there is no benefit of the doubt.
            let child_cells = &nodes[&child_digest].cells;
            let lo = src as usize;
            let hi = lo.saturating_add(len as usize);
            let covered = hi <= child_cells.len();
            let slice: &[String] = if covered { &child_cells[lo..hi] } else { &[] };
            let all_dead = covered && !slice.is_empty() && slice.iter().all(|s| s == "dead");
            let any_live = slice.iter().any(|s| s == "live");
            if all_dead {
                links_ok = LinksOk::Bad;
                notes.push(format!(
                    "link source output[{src}..{}) of {}.. never moved under ANY \
                     perturbation of that receipt's inputs: the values this link carries \
                     are constants, so the chain proves nothing about them however well \
                     every node re-derives",
                    src + len,
                    head16(&child_digest)
                ));
            } else if !any_live {
                let why = if covered {
                    "the probe hit its budget before deciding these cells"
                } else {
                    "the probe's cell verdict does not cover this slice"
                };
                if strict_liveness {
                    links_ok = LinksOk::Bad;
                    notes.push(format!(
                        "--strict-liveness: link source output[{src}..{}) of {}.. was \
                         never shown to move under ANY perturbation ({why}) - REFUSED \
                         without a positive demonstration that the values this link \
                         carries are derived",
                        src + len,
                        head16(&child_digest)
                    ));
                } else {
                    if links_ok == LinksOk::Ok {
                        links_ok = LinksOk::Incomplete;
                    }
                    notes.push(format!(
                        "link source output[{src}..{}) of {}.. was not shown to depend on \
                         that receipt's inputs ({why}), so the chain does not establish \
                         that these values were computed rather than hardcoded -- \
                         incomplete, not forged",
                        src + len,
                        head16(&child_digest)
                    ));
                }
            }
        }
        let node = nodes.get_mut(d).unwrap();
        node.links_ok = links_ok;
        node.notes.extend(notes);
    }

    // Cycles are unconstructible for integrity-valid receipts -- a link names the
    // child's claim hash, and a cycle would need a SHA-256 fixed point. The guard is
    // defense in depth for a broken-hash world, and it also gives the children-first
    // order the verdict reports.
    const WHITE: u8 = 0;
    const GREY: u8 = 1;
    const BLACK: u8 = 2;
    let mut color: BTreeMap<String, u8> = digests.iter().map(|d| (d.clone(), WHITE)).collect();
    let mut order: Vec<String> = Vec::new();
    let mut cycle_hits: Vec<(String, String)> = Vec::new();

    // Iterative DFS: a recursive one would put an attacker-chosen chain length on the
    // stack, and a stack overflow is a crash rather than a refusal.
    for start in &digests {
        if color[start] != WHITE {
            continue;
        }
        let mut stack: Vec<(String, usize)> = vec![(start.clone(), 0)];
        color.insert(start.clone(), GREY);
        while let Some((cur, idx)) = stack.pop() {
            let children: Vec<String> = match nodes[&cur].receipt {
                Some(r) => links_of(r)
                    .iter()
                    .filter_map(|ln| ln.get("receipt_sha256").and_then(|v| v.as_str()))
                    .collect(),
                None => Vec::new(),
            };
            if idx < children.len() {
                stack.push((cur.clone(), idx + 1));
                let child = &children[idx];
                if nodes.contains_key(child) {
                    match color[child] {
                        GREY => cycle_hits.push((cur.clone(), child.clone())),
                        WHITE => {
                            color.insert(child.clone(), GREY);
                            stack.push((child.clone(), 0));
                        }
                        _ => {}
                    }
                }
            } else {
                color.insert(cur.clone(), BLACK);
                order.push(cur);
            }
        }
    }
    for (parent, child) in cycle_hits {
        graph_notes.push(format!(
            "CYCLE through {}.. -- a receipt cannot depend on its own consequence; refused",
            head16(&child)
        ));
        nodes.get_mut(&parent).unwrap().links_ok = LinksOk::Bad;
        nodes.get_mut(&child).unwrap().links_ok = LinksOk::Bad;
    }

    // Roots: nodes nothing supplied links to. For display; not a verdict input.
    let mut referenced: BTreeSet<String> = BTreeSet::new();
    for d in &digests {
        if let Some(r) = nodes[d].receipt {
            for ln in links_of(r) {
                if let Some(s) = ln.get("receipt_sha256").and_then(|v| v.as_str()) {
                    referenced.insert(s);
                }
            }
        }
    }
    let roots: Vec<String> =
        digests.iter().filter(|d| !referenced.contains(*d)).cloned().collect();

    let complete = missing.is_empty();
    let all_nodes_ok = digests.iter().all(|d| nodes[d].verified);
    let all_links_ok = digests
        .iter()
        .all(|d| matches!(nodes[d].links_ok, LinksOk::NotApplicable | LinksOk::Ok));
    let no_graph_faults =
        !graph_notes.iter().any(|g| g.contains("COLLISION") || g.contains("CYCLE"));
    let graph_verified =
        !digests.is_empty() && complete && all_nodes_ok && all_links_ok && no_graph_faults;

    let node_out = digests
        .iter()
        .map(|d| {
            let n = &nodes[d];
            (
                d.clone(),
                NodeVerdict {
                    verified: n.verified,
                    links_ok: n.links_ok,
                    envelopes: n.envelopes.len(),
                    notes: n.notes.clone(),
                },
            )
        })
        .collect();

    GraphVerdict {
        graph_verified,
        complete,
        missing: missing.into_iter().collect(),
        roots,
        order,
        nodes: node_out,
        notes: graph_notes,
    }
}
