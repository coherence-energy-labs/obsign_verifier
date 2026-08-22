//! `obsign/witness/v1` -- provenance for work Obsign did NOT perform.
//!
//! WHY A THIRD PORT. Two implementations that agree prove less than they appear to: the
//! agreement can be inherited from a shared assumption neither one questions. The
//! receipt path already carries three, and the witness path had two -- and the two it
//! had are both garbage-collected languages with the same JSON habits. Rust reads the
//! bytes differently enough to be worth having: no `JSON.parse`, no dict ordering to
//! rely on, integers held as text so nothing rounds.
//!
//! THE LADDER IS NOW WRITTEN THREE TIMES, WHICH IS THE COST. A drift is one port calling
//! a document `witnessed` while another calls it `asserted` -- two verdicts from one
//! vendor on the same bytes, which is the split a forger farms. `derive_assurance`
//! mirrors `obsign/witness.py::derive_assurance` decision for decision, and the corpus
//! harness runs all three over the same documents.
//!
//! NO FLOATS. A witness carries none by construction (durations are integer
//! milliseconds), so the int/float trap that forces receipts through a text-level parser
//! does not arise here. This port still reads through `load_receipt`, so a float that
//! ever crept in would be preserved and would surface as a hash mismatch rather than
//! being silently rounded into agreement.

use crate::json::{canonical_sha256, claim_of, Value};
use crate::signature;

pub const SPEC: &str = "obsign/witness/v1";

/// Weakest first. The ORDER is the semantics: comparisons are by index, so inserting a
/// rung anywhere but its true strength silently changes what counts as an overclaim.
pub const LADDER: [&str; 4] = ["custody", "asserted", "witnessed", "environment-pinned"];

pub const CUSTODY: &str = "custody";
pub const ASSERTED: &str = "asserted";
pub const WITNESSED: &str = "witnessed";
pub const ENVIRONMENT_PINNED: &str = "environment-pinned";

/// What each rung means, in the words a reader gets. Byte-identical to the Python
/// `MEANING` table and the JavaScript one, so a verdict does not change tone with the
/// port that produced it.
pub fn meaning(rung_name: &str) -> &'static str {
    match rung_name {
        "environment-pinned" => {
            "the tool, its argv and a pinned image are recorded: a verifier can re-run \
             this in that image. NOT re-executed here."
        }
        "witnessed" => {
            "input, output, tool and actor are bound. NOT re-executed, and NOT \
             reproducible from this record: it does not prove the tool did what it says."
        }
        "asserted" => {
            "input, output and actor are bound, but the operation is SELF-DECLARED: no \
             argv and no hashed binary identify what actually ran. NOT re-executed."
        }
        "custody" => {
            "these bytes existed at this time under this identity, and are unchanged \
             since. No transformation is claimed."
        }
        _ => "",
    }
}

/// Position on the ladder. An unknown or MISSING rung sorts below the weakest (-1), so
/// an unrecognised value can never compare as stronger than a real one.
pub fn rung(level: Option<&str>) -> i32 {
    match level {
        Some(s) => LADDER.iter().position(|x| *x == s).map(|i| i as i32).unwrap_or(-1),
        None => -1,
    }
}

fn arr_len(doc: &Value, key: &str) -> usize {
    doc.get(key).and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0)
}

/// The rung a document can actually support, from what it carries.
///
/// NEVER consults `doc["assurance"]`. A producer's claim about its own strength is
/// exactly the thing that must not be load-bearing.
pub fn derive_assurance(doc: &Value) -> &'static str {
    let inputs = arr_len(doc, "inputs");
    let outputs = arr_len(doc, "outputs");
    if outputs == 0 || inputs == 0 {
        return CUSTODY;
    }

    // Is the operation IDENTIFIED, or merely named? An argv with a hashed binary points
    // at a specific executable a verifier can compare against; a library name and a
    // version string are whatever the caller typed.
    let tool = doc.get("tool");
    let argv_len = tool
        .and_then(|t| t.get("argv"))
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let has_hash = tool
        .and_then(|t| t.get("binary"))
        .and_then(|b| b.get("sha256"))
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    if argv_len == 0 || !has_hash {
        return ASSERTED;
    }

    let env = doc.get("environment");
    let container = env
        .and_then(|e| e.get("kind"))
        .and_then(|v| v.as_str())
        .map(|s| s == "container")
        .unwrap_or(false);
    let digest = env
        .and_then(|e| e.get("digest"))
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    if container && digest {
        ENVIRONMENT_PINNED
    } else {
        WITNESSED
    }
}

/// Three-valued, matching the other ports. `Incomplete` is NOT `No`: a parent that was
/// not supplied is unchecked, and accusing a chain because a file is absent is the same
/// error as reporting `reproduced: false` for a run nobody attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinksOk {
    None,
    Yes,
    Incomplete,
    No,
}

#[derive(Debug, Clone)]
pub struct WitnessVerdict {
    pub integrity: bool,
    /// Always `None`. Nothing is re-executed here, and `Some(false)` would accuse the
    /// document of failing a test that was never run.
    pub reproduced: Option<bool>,
    pub signature_valid: Option<bool>,
    pub verified: bool,
    pub assurance: Option<String>,
    pub derived: &'static str,
    pub notes: Vec<String>,
}

/// Verify one witness for what it CAN be checked for, and be explicit about the rest.
pub fn verify_witness(doc: &Value) -> WitnessVerdict {
    let mut out = WitnessVerdict {
        integrity: false,
        reproduced: None,
        signature_valid: None,
        verified: false,
        assurance: None,
        derived: CUSTODY,
        notes: Vec::new(),
    };

    let spec = doc.get("spec").and_then(|v| v.as_str());
    if spec.as_deref() != Some(SPEC) {
        out.notes.push(format!(
            "not a {} document (spec={:?}); nothing was checked",
            SPEC, spec
        ));
        return out;
    }

    let claimed = doc.get("assurance").and_then(|v| v.as_str());
    let actual = derive_assurance(doc);
    out.assurance = claimed.clone();
    out.derived = actual;
    if rung(claimed.as_deref()) > rung(Some(actual)) {
        out.notes.push(format!(
            "OVERCLAIM: document says {:?} but carries only {:?}",
            claimed, actual
        ));
        return out;
    }

    let recomputed = match canonical_sha256(&claim_of(doc)) {
        Ok(h) => h,
        Err(e) => {
            out.notes.push(format!("could not canonicalise the claim: {}", e.0));
            return out;
        }
    };
    let stated = doc.get("receipt_sha256").and_then(|v| v.as_str());
    out.integrity = stated.as_deref() == Some(recomputed.as_str());
    if !out.integrity {
        out.notes
            .push("receipt_sha256 does not match the claim it covers".to_string());
        return out;
    }

    if doc.has("signature") {
        let s = signature::check(doc);
        out.signature_valid = Some(s.valid);
        // The verifier package's rule, word for word: (not present) or valid.
        if !s.valid {
            out.notes
                .push("signature present and does not verify".to_string());
            return out;
        }
    }

    out.verified = true;
    out.notes
        .push(format!("NOT RE-EXECUTED -- {}", meaning(actual)));
    out
}

#[derive(Debug, Clone)]
pub struct ChainNode {
    pub spec: Option<String>,
    pub verified: bool,
    pub links_ok: LinksOk,
    pub assurance: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ChainVerdict {
    pub ok: bool,
    /// False when a referenced `prior` was not supplied. Load-bearing, not decorative:
    /// taking the MINIMUM rung only defends against a weak link that is PRESENT, and
    /// withholding one beats it. `verify_graph` already requires completeness for
    /// `graph_verified`; a truncated chain is a fragment, not a verified chain.
    pub complete: bool,
    pub missing: Vec<String>,
    pub effective_assurance: Option<String>,
    pub nodes: Vec<(String, ChainNode)>,
    pub notes: Vec<String>,
}

fn digests_of(doc: &Value, key: &str) -> Vec<String> {
    doc.get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.get("sha256").and_then(|s| s.as_str()))
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Verify linked documents as ONE chain.
///
/// A `prior` reference alone proves nothing -- any two unrelated documents can be
/// stapled together and read as descent. The handoff must bind on BYTES: some input
/// digest of the child must appear among the parent's artifact digests. That is the
/// laundering move this exists to stop.
///
/// `effective_assurance` is the MINIMUM rung over the chain. Reporting the best, or the
/// last, would let one strong step vouch for everything behind it.
pub fn verify_chain(docs: &[Value]) -> ChainVerdict {
    let mut out = ChainVerdict {
        ok: false,
        complete: false,
        missing: Vec::new(),
        effective_assurance: None,
        nodes: Vec::new(),
        notes: Vec::new(),
    };

    // Index by receipt_sha256, first occurrence wins.
    let mut by_hash: Vec<(String, &Value)> = Vec::new();
    for d in docs {
        let h = match d.get("receipt_sha256").and_then(|v| v.as_str()) {
            Some(h) if !h.is_empty() => h,
            _ => {
                out.notes
                    .push("a document carries no receipt_sha256; ignored".to_string());
                continue;
            }
        };
        if by_hash.iter().any(|(k, _)| *k == h) {
            out.notes.push(format!(
                "duplicate document {}..; the later one is ignored",
                &h[..h.len().min(16)]
            ));
            continue;
        }
        by_hash.push((h.to_string(), d));
    }
    if by_hash.is_empty() {
        out.notes.push("no usable documents".to_string());
        return out;
    }

    let mut weakest: Option<i32> = None;
    let mut missing: Vec<String> = Vec::new();
    for (h, d) in &by_hash {
        let is_witness = d.get("spec").and_then(|v| v.as_str()).as_deref() == Some(SPEC);
        // A non-witness document is NOT judged here: a witness verifier rendering a
        // verdict on a receipt is the cross-contamination the separate document types
        // exist to prevent.
        let (verified, assurance) = if is_witness {
            let v = verify_witness(d);
            (v.verified, v.assurance)
        } else {
            (false, None)
        };
        let r = rung(assurance.as_deref());
        weakest = Some(match weakest {
            None => r,
            Some(w) => w.min(r),
        });
        out.nodes.push((
            h.clone(),
            ChainNode {
                spec: d.get("spec").and_then(|v| v.as_str()),
                verified,
                links_ok: LinksOk::None,
                assurance,
                notes: Vec::new(),
            },
        ));
    }

    for (idx, (_h, d)) in by_hash.iter().enumerate() {
        let priors: Vec<&Value> = d
            .get("prior")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().collect())
            .unwrap_or_default();
        if priors.is_empty() {
            continue;
        }
        out.nodes[idx].1.links_ok = LinksOk::Yes;
        let child_inputs = digests_of(d, "inputs");
        for p in priors {
            let ph = p.get("receipt_sha256").and_then(|v| v.as_str());
            let parent = ph
                .as_ref()
                .and_then(|x| by_hash.iter().find(|(k, _)| k == x).map(|(_, v)| *v));
            let short = ph
                .as_deref()
                .map(|s| s[..s.len().min(16)].to_string())
                .unwrap_or_else(|| "?".to_string());
            match parent {
                None => {
                    if let Some(x) = ph.as_deref() {
                        if !x.is_empty() && !missing.iter().any(|m| m == x) {
                            missing.push(x.to_string());
                        }
                    }
                    if out.nodes[idx].1.links_ok == LinksOk::Yes {
                        out.nodes[idx].1.links_ok = LinksOk::Incomplete;
                    }
                    out.nodes[idx].1.notes.push(format!(
                        "prior {}.. was not supplied; the handoff is unchecked",
                        short
                    ));
                }
                Some(parent) => {
                    let parent_arts = digests_of(parent, "outputs");
                    if child_inputs.is_empty() {
                        if out.nodes[idx].1.links_ok == LinksOk::Yes {
                            out.nodes[idx].1.links_ok = LinksOk::Incomplete;
                        }
                        out.nodes[idx].1.notes.push(
                            "this document declares no inputs, so the handoff cannot be \
                             bound to the parent's bytes"
                                .to_string(),
                        );
                    } else if !child_inputs.iter().any(|x| parent_arts.contains(x)) {
                        out.nodes[idx].1.links_ok = LinksOk::No;
                        out.nodes[idx].1.notes.push(format!(
                            "BROKEN HANDOFF: no input of this document matches any \
                             artifact of prior {}... The link asserts a lineage the \
                             bytes do not support.",
                            short
                        ));
                    }
                }
            }
        }
    }

    if has_cycle(&by_hash) {
        out.notes
            .push("the prior references contain a cycle; this is not a chain".to_string());
        return out;
    }

    out.effective_assurance = match weakest {
        Some(w) if w >= 0 => Some(LADDER[w as usize].to_string()),
        _ => None,
    };
    missing.sort();
    out.complete = missing.is_empty();
    out.missing = missing;
    let every_node_ok = out
        .nodes
        .iter()
        .all(|(_, n)| n.verified && n.links_ok != LinksOk::No);
    out.ok = !out.nodes.is_empty() && out.complete && every_node_ok;
    if !out.complete {
        out.notes.push(format!(
            "INCOMPLETE: {} referenced document(s) were not supplied, so the chain's              origin is unknown and {:?} is the assurance of the FRAGMENT provided, not              of the chain. Withholding a weaker parent is how a chain is made to look              stronger than it is. This is not a forgery finding -- produce the missing              documents to settle it.",
            out.missing.len(),
            out.effective_assurance.clone().unwrap_or_default()
        ));
    } else if out.ok {
        let eff = out.effective_assurance.clone().unwrap_or_default();
        out.notes.push(format!(
            "chain of {} document(s); effective assurance is the WEAKEST link: {:?} -- {}",
            out.nodes.len(),
            eff,
            meaning(&eff)
        ));
    }
    out
}

fn has_cycle(by_hash: &[(String, &Value)]) -> bool {
    fn walk(
        h: &str,
        by_hash: &[(String, &Value)],
        seen: &mut Vec<String>,
        stack: &mut Vec<String>,
    ) -> bool {
        if stack.iter().any(|x| x == h) {
            return true;
        }
        let doc = match by_hash.iter().find(|(k, _)| k == h) {
            Some((_, d)) => *d,
            None => return false,
        };
        if seen.iter().any(|x| x == h) {
            return false;
        }
        seen.push(h.to_string());
        stack.push(h.to_string());
        let priors: Vec<&Value> = doc
            .get("prior")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().collect())
            .unwrap_or_default();
        for p in priors {
            if let Some(ph) = p.get("receipt_sha256").and_then(|v| v.as_str()) {
                if walk(&ph, by_hash, seen, stack) {
                    return true;
                }
            }
        }
        stack.pop();
        false
    }

    let mut seen = Vec::new();
    for (h, _) in by_hash {
        let mut stack = Vec::new();
        if walk(h, by_hash, &mut seen, &mut stack) {
            return true;
        }
    }
    false
}
