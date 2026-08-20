//! The trust ladder.
//!
//! ```text
//! 1. integrity      `receipt_sha256` recomputes from the claim
//! 2. reproduced     re-running the kernel reproduces `output.sha256`
//! 3. signature      the signature verifies, and covers what it claims to cover
//! 4. issuer trust   OUT OF SCOPE -- a key being valid says nothing about whose it is
//! ```
//!
//! Step 4 is deliberately not implemented, in every implementation. Deciding that a
//! public key belongs to an organisation you should trust is an identity question, and
//! a verifier that answered it from a bundled list would be asserting a social fact as
//! a cryptographic one.
//!
//! VERIFIED IS NOT THE SAME AS SIGNED. An unsigned receipt can still be `verified`
//! here: integrity holds and the number re-derived on your machine. A signature adds
//! *who*, not *whether*.
//!
//! WHAT THIS IMPLEMENTATION DOES NOT DO, said plainly rather than discovered. It does
//! not re-execute `tau_field_fixed` -- that kernel needs an array pipeline this crate
//! deliberately does not carry, and the JavaScript port does not carry either. Such
//! receipts report `reproduced: null` with a note, and are NOT reported as verified.
//! "I cannot check this" is a third answer, and collapsing it into pass or fail is how
//! a verifier starts lying.

use crate::json::{integrity, Value};
use crate::replay;
use crate::signature::{self, SigCheck};

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub integrity: bool,
    /// `None` means NOT ATTEMPTED, which is a different fact from `Some(false)`.
    pub reproduced: Option<bool>,
    pub signature: Option<SigCheck>,
    pub verified: bool,
    pub input_liveness: Option<String>,
    pub input_liveness_by_input: Vec<String>,
    pub notes: Vec<String>,
    /// Re-derived output values, for the differential harness. Not part of the verdict
    /// the CLI prints: it exists so another implementation can compare the numbers and
    /// not merely the digest of the numbers.
    pub output: Option<Vec<i64>>,
}

impl Default for Verdict {
    fn default() -> Self {
        Verdict {
            integrity: false,
            reproduced: None,
            signature: None,
            verified: false,
            input_liveness: None,
            input_liveness_by_input: Vec::new(),
            notes: Vec::new(),
            output: None,
        }
    }
}

/// Run step 3 and return whether it permits a `verified` verdict.
///
/// ONE place, because the fixed-kernel path and the replay path each had their own
/// copy of this rule in the reference at one point -- and a rule with two copies is a
/// rule that gets fixed in one of them.
///
/// A signature that is PRESENT but does not verify is a refusal. A signature that is
/// ABSENT is not: the replay rung stands on its own, which is the whole argument for a
/// verifier a stranger can run.
fn signature_gate(receipt: &Value, result: &mut Verdict) -> bool {
    let sig = signature::check(receipt);
    if sig.present && !sig.valid {
        result.notes.push(sig.detail.clone());
    }
    for key in &sig.unbound_metadata {
        result.notes.push(format!(
            "'{key}' is present but NOT covered by the signature - unattested \
             annotation, not an attested fact"
        ));
    }
    let ok = !sig.present || sig.valid;
    result.signature = Some(sig);
    ok
}

/// Perturbations tried per input. Small, mixed sign and magnitude, so an input that
/// only matters above some threshold is still caught.
const LIVENESS_DELTAS: [i64; 7] = [1, -1, 7, -7, 1000, -1000, 1_000_000];

/// What evidence is there that the output depends on the declared inputs?
///
/// A receipt proves "re-run this program on these inputs and you get this hash". That
/// is empty if the program ignores the inputs: a two-instruction program that loads a
/// constant and halts re-derives PERFECTLY and establishes nothing about the inputs it
/// names.
///
/// WHAT THIS CAN AND CANNOT ESTABLISH. Perturbing an input and watching the output
/// move is EVIDENCE OF DEPENDENCE. It is not, and cannot be, proof that the program
/// computes the formula its name claims -- `if inputs == this_quarter { return the
/// number I want } else { run the real formula }` behaves correctly under every
/// perturbation anyone thinks to try. The semantic boundary is an approved program
/// identity (`--expect-program`), and this probe is diagnostic evidence beneath it.
///
/// A TRAP IS NOT EVIDENCE OF DEPENDENCE. The attacker controls when the program traps,
/// so counting a trap as "live" hands the hardcoded-constant attack a way straight back
/// through the check. A trap says only that the program REFUSED TO RUN, which is not
/// information about the output, so it is recorded as "guarded" and never as evidence.
///
/// Only "dead" and "guarded" refuse, and both are sound NEGATIVES. "indeterminate"
/// never refuses -- a verifier must not reject an honest receipt merely because it was
/// expensive to probe. Fail towards not accusing.
fn input_liveness(
    prog: &replay::Program,
    inputs: &[i64],
    base_out: &[i64],
    base_steps: u64,
) -> (String, Vec<String>) {
    let n = inputs.len();
    if n == 0 {
        // A program with no declared inputs makes no claim about any.
        return ("n/a".into(), Vec::new());
    }

    // Cap ONE perturbation run, and cap the TOTAL, so the probe can never be turned
    // into a denial-of-service amplifier: a hostile program is handed a bounded probe,
    // not an open one.
    let per_run_cap = replay::MAX_STEPS.min(base_steps.max(100_000));
    let total_budget = (base_steps.saturating_mul(8)).max(4_000_000);
    let mut spent: u64 = 0;

    let mut per_input = Vec::with_capacity(n);
    for i in 0..n {
        let original = inputs[i] as i128;
        let mut state = "dead";
        let mut trapped = false;
        let mut exhausted = false;
        for d in LIVENESS_DELTAS {
            let probed = original + d as i128;
            // Keep the perturbation a valid int64: an ingest rejection is not evidence
            // about the program's use of the value. Computed wide, because wrapping
            // here would silently probe a different number than intended.
            if probed < i64::MIN as i128 || probed > i64::MAX as i128 {
                continue;
            }
            if spent >= total_budget {
                exhausted = true;
                break;
            }
            let mut trial = inputs.to_vec();
            trial[i] = probed as i64;
            match replay::run_validated(prog, &trial, Some(per_run_cap)) {
                Ok((out, used)) => {
                    spent = spent.saturating_add(used);
                    if out != base_out {
                        state = "live"; // the value moved the answer: real evidence
                        break;
                    }
                }
                Err(_) => {
                    spent = spent.saturating_add(per_run_cap); // unknown cost; charge the cap
                    trapped = true; // the program declined to run: NOT evidence
                }
            }
        }
        if state != "live" {
            // An exhausted budget is the weakest thing we can say, so it wins over
            // "guarded"; both are weaker than a definite "dead", which requires every
            // perturbation to have actually RUN and left the output alone.
            state = if exhausted {
                "indeterminate"
            } else if trapped {
                "guarded"
            } else {
                "dead"
            };
        }
        per_input.push(state.to_string());
    }

    let verdict = if per_input.iter().any(|s| s == "live") {
        "live"
    } else if per_input.iter().any(|s| s == "indeterminate") {
        "indeterminate"
    } else if per_input.iter().any(|s| s == "guarded") {
        "guarded"
    } else {
        "dead"
    };
    (verdict.to_string(), per_input)
}

fn verify_replay(receipt: &Value, result: &mut Verdict) {
    let params = match receipt.get("params") {
        Some(p) if matches!(p, Value::Object(_)) => p,
        _ => {
            result.notes.push("replay receipt carries no params; nothing to re-execute".into());
            signature_gate(receipt, result);
            return;
        }
    };
    let prog_v = params.get("program");
    let inputs_v = params.get("inputs");
    let (prog_v, inputs_v) = match (prog_v, inputs_v) {
        (Some(p), Some(i)) if matches!(p, Value::Object(_)) && matches!(i, Value::Array(_)) => (p, i),
        _ => {
            result.notes.push("replay params must carry {program: object, inputs: [int]}".into());
            signature_gate(receipt, result);
            return;
        }
    };

    // The program's own digest must match `params.program_sha256` when the receipt
    // states one. `params` is already inside the claim, so this is redundant against a
    // tamperer -- but it gives a stranger a short string to compare with a published
    // one, and it catches an honest producer shipping a stale digest.
    let actual_digest = replay::program_sha256(prog_v);
    let stated = params.get("program_sha256");
    let digest_ok = match (stated, &actual_digest) {
        (None, _) | (Some(Value::Null), _) => true,
        (Some(v), Some(actual)) => v.as_str().as_deref() == Some(actual.as_str()),
        (Some(_), None) => false,
    };
    if !digest_ok {
        result.notes.push(format!(
            "program digest mismatch: computes {}..",
            actual_digest.as_deref().unwrap_or("<uncanonicalisable>").chars().take(16).collect::<String>()
        ));
    }

    // Validate BEFORE reading the inputs, the same order the reference runs them in, so
    // a receipt that is wrong in both places is refused for the same reason everywhere.
    let program = match replay::validate(prog_v) {
        Ok(p) => p,
        Err(t) => {
            result.notes.push(format!("program refused: {t}"));
            signature_gate(receipt, result);
            return;
        }
    };
    let inputs = match replay::read_inputs(inputs_v) {
        Ok(v) => v,
        Err(t) => {
            result.notes.push(format!("program refused: {t}"));
            signature_gate(receipt, result);
            return;
        }
    };
    let (out, base_steps) = match replay::run_validated(&program, &inputs, None) {
        Ok(x) => x,
        Err(t) => {
            result.notes.push(format!("program refused: {t}"));
            signature_gate(receipt, result);
            return;
        }
    };

    let got = replay::output_sha256(&out);
    let declared = receipt.get("output");
    let want = declared.and_then(|d| d.get("sha256")).and_then(|v| v.as_str());
    result.reproduced = Some(Some(got.clone()) == want);
    result.output = Some(out.clone());
    if result.reproduced != Some(true) {
        result.notes.push(format!(
            "output mismatch: claim {}.., recomputed {}..",
            want.as_deref().unwrap_or("<none>").chars().take(16).collect::<String>(),
            &got[..16]
        ));
    }

    // Length rides OUTSIDE the byte hash, exactly as shape and dtype do for the array
    // kernel, so it is compared explicitly rather than trusted. It must BE a JSON
    // integer: a boolean there is not a length, and reading `true` as 1 is the exact
    // confusion docs/COMPAT.md closed for the program's own structural scalars.
    let len_ok = match declared.and_then(|d| d.get("length")) {
        None | Some(Value::Null) => true,
        Some(v) => v.as_i64() == Some(out.len() as i64),
    };
    if !len_ok {
        result.notes.push("output length does not match the re-executed result".into());
    }

    let (liveness, per_input) = input_liveness(&program, &inputs, &out, base_steps);
    let live_ok = liveness != "dead" && liveness != "guarded";
    result.input_liveness = Some(liveness.clone());
    result.input_liveness_by_input = per_input.clone();
    match liveness.as_str() {
        "dead" => result.notes.push(
            "the output does not depend on ANY declared input: every input was perturbed \
             and the result never changed. This program ignores its inputs, so re-deriving \
             it proves nothing about them -- a constant dressed as a computation. REFUSED."
                .into(),
        ),
        "guarded" => result.notes.push(
            "no declared input was shown to reach the output, and the program TRAPPED on \
             every perturbation that did not. A program that refuses to run on anything but \
             its own receipted inputs yields no evidence that those inputs produced this \
             answer -- the shape of a hardcoded result behind an equality guard. REFUSED."
                .into(),
        ),
        "indeterminate" => result.notes.push(
            "input-liveness probe hit its budget before proving dependence either way; not \
             treated as a failure (a verifier must not refuse an honest receipt for being \
             expensive to probe)"
                .into(),
        ),
        "live" => {
            let dark: Vec<usize> = per_input
                .iter()
                .enumerate()
                .filter(|(_, s)| *s != "live")
                .map(|(i, _)| i)
                .collect();
            let mut note = String::from(
                "input-liveness is EVIDENCE, not proof: perturbing an input moved the output, \
                 which shows dependence but cannot show the program computes the formula its \
                 name claims. Pin an approved program digest (--expect-program) for that.",
            );
            if !dark.is_empty() {
                note += &format!(" Inputs {dark:?} were not shown to reach the output.");
            }
            result.notes.push(note);
        }
        _ => {}
    }

    let sig_ok = signature_gate(receipt, result);
    result.verified =
        result.integrity && result.reproduced == Some(true) && digest_ok && len_ok && live_ok && sig_ok;
}

/// Run the ladder. Never fails on a hostile receipt -- an exception is not a refusal.
pub fn verify(receipt: &Value) -> Verdict {
    let mut result = Verdict::default();
    let (ok, detail) = integrity(receipt);
    result.integrity = ok;
    if !ok {
        result.notes.push(detail);
    }

    let kernel = receipt.get("kernel").and_then(|v| v.as_str());
    if kernel.as_deref() == Some(replay::SPEC) {
        verify_replay(receipt, &mut result);
        return result;
    }

    result.notes.push(format!(
        "kernel {} cannot be re-executed by this implementation (Rust re-derives \
         obsign/replay/1 only) - NOT verified by re-derivation",
        kernel.as_deref().unwrap_or("<absent>")
    ));
    signature_gate(receipt, &mut result);
    result
}
