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

/// The ONE receipt envelope this verifier implements.
///
/// The first decision in verification is "do I know what these bytes are?", and it was
/// never asked: the ladder dispatched on `kernel` alone, so a document declaring
/// `spec: "obsign/receipt/v99"` -- a format whose claim boundary, whose params schema
/// and whose output block nobody here has ever seen -- was interpreted under today's v1
/// semantics. Unknown format means "I do not know what these bytes mean", not "I will
/// interpret them as whatever my current implementation does".
pub const RECEIPT_SPEC_V1: &str = "obsign/receipt/v1";

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub integrity: bool,
    /// `None` means NOT ATTEMPTED, which is a different fact from `Some(false)`.
    pub reproduced: Option<bool>,
    pub signature: Option<SigCheck>,
    pub verified: bool,
    /// "This verifier does not implement this format" -- never "this is forged".
    pub unsupported: bool,
    /// `None` means NO EXPECTATION WAS SUPPLIED, a different fact from `Some(false)`.
    pub approved_program: Option<bool>,
    pub input_liveness: Option<String>,
    pub input_liveness_by_input: Vec<String>,
    /// Which output CELLS any perturbation ever moved. A whole-window verdict cannot
    /// see a constant hiding beside a decoy that echoes an input.
    pub output_liveness_by_cell: Vec<String>,
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
            unsupported: false,
            approved_program: None,
            input_liveness: None,
            input_liveness_by_input: Vec::new(),
            output_liveness_by_cell: Vec::new(),
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

// ---------------------------------------------------------------- the liveness probe
//
// PORTED FROM `src/obsign_verify/verify.py`, VALUE FOR VALUE. This file used to carry
// the pre-fix probe: seven fixed ABSOLUTE perturbations capped at 1,000,000, and a
// budget denominated in VM STEPS. Both halves were wrong in ways that show up as a
// SPLIT VERDICT rather than as a slow test:
//
//   * a fixed ladder can only exercise a program at the resolution of its largest
//     step, so any computation coarser than 1,000,000 in its inputs' own units --
//     money held in cents and reported in hundreds of millions, a byte count reported
//     in gigabytes, any bucketed figure -- never moved and was reported "dead", which
//     REFUSES. Honest receipts accused of being "a constant dressed as a computation",
//     here and nowhere else.
//   * steps are the one thing a probe run need not spend. Before a program executes
//     its first instruction a run allocates `mem` cells, re-validates every
//     instruction and every constant, and copies every declared input; a program that
//     HALTs immediately pays all of that and retires ONE step. A 4,000,000-step budget
//     therefore bought four million full machine instantiations.
//
// The reference and the JavaScript port fixed both; this file did not, and the
// three-way differential had to SOFTEN the two liveness columns to stay green -- on 37
// of 364 replay receipts. A softened column is a dark column. Every constant, every
// ladder and every accounting rule below is the reference's, so the softening is gone.

/// Small absolute perturbations, mixed sign, tried first: an honest program usually
/// moves on the very first one, so the cheap probes come before the expensive ones.
const LIVENESS_DELTAS: [i64; 8] = [1, -1, 7, -7, 1000, -1000, 1_000_000, -1_000_000];

/// Perturbations SCALED TO THE INPUT ITSELF, for a computation coarser than any fixed
/// step. See the note above.
const LIVENESS_FRACTIONS: [i128; 4] = [2, 8, 64, 1024];

/// ...and perturbations scaled to the MACHINE, for the mirror-image case: an input
/// whose own magnitude is small but which is multiplied up before it reaches the
/// output, where a relative step is no bigger than the absolute one.
const LIVENESS_SHIFTS: [u32; 4] = [20, 32, 48, 62];

/// Replacements rather than deltas: the values a program is likeliest to treat
/// specially, and the edges of the type.
const LIVENESS_EDGES: [i64; 3] = [0, 1, -1];

// What one unit of each kind of per-run work costs, in units of "zeroing one memory
// cell" -- the cheapest thing a run does, and therefore the natural denominator. These
// are ORDERS OF MAGNITUDE measured on the reference implementation, rounded UP to
// powers of two: under-charging is what turns a budget into an amplifier, and
// over-charging only costs a hostile receipt some probes.
const COST_CELL: u64 = 1;
const COST_INPUT: u64 = 16;
const COST_CONST: u64 = 8;
const COST_CODE: u64 = 128;
const COST_STEP: u64 = 64;

/// The floor, in the same units: the budget a program gets however cheap it is, so a
/// small constant program with many declared inputs is still swept exhaustively rather
/// than reported "indeterminate" (which does not refuse).
const LIVENESS_FLOOR: u64 = 32_000_000;

/// The values one input is re-run with, cheapest and likeliest first.
///
/// Computed in `i128` and clipped to int64, because Python computes these in
/// arbitrary precision and DROPS anything out of range: a perturbation that wrapped
/// here would silently probe a different number than the reference probes, which is a
/// divergence in the one place a divergence cannot be seen from the outside.
fn probe_values(x: i64) -> Vec<i64> {
    let mut seen: Vec<i64> = vec![x];
    let mut values: Vec<i64> = Vec::new();
    let add = |v: i128, seen: &mut Vec<i64>, values: &mut Vec<i64>| {
        if v < i64::MIN as i128 || v > i64::MAX as i128 {
            return;
        }
        let v = v as i64;
        if !seen.contains(&v) {
            seen.push(v);
            values.push(v);
        }
    };
    let wide = x as i128;
    for d in LIVENESS_DELTAS {
        add(wide + d as i128, &mut seen, &mut values);
    }
    let magnitude = wide.abs();
    for f in LIVENESS_FRACTIONS {
        let step = magnitude / f;
        if step != 0 {
            add(wide + step, &mut seen, &mut values);
            add(wide - step, &mut seen, &mut values);
        }
    }
    for k in LIVENESS_SHIFTS {
        add(wide + (1i128 << k), &mut seen, &mut values);
        add(wide - (1i128 << k), &mut seen, &mut values);
    }
    for v in LIVENESS_EDGES {
        add(v as i128, &mut seen, &mut values);
    }
    add(i64::MAX as i128, &mut seen, &mut values);
    add(i64::MIN as i128, &mut seen, &mut values);
    values
}

/// What ONE run of `prog` costs the verifier -- all of it, not just what it retires.
///
/// Charging the fixed cost is what makes the documented bound real: every probe run
/// costs at least what the base run cost, so "a small multiple of the base run"
/// becomes arithmetic rather than aspiration, in every dimension a receipt can inflate
/// -- memory, code length, constant pool, input count, steps.
fn probe_cost(prog: &replay::Program, n_inputs: usize, steps: u64) -> u64 {
    steps
        .saturating_mul(COST_STEP)
        .saturating_add((prog.mem as u64).saturating_mul(COST_CELL))
        .saturating_add((n_inputs as u64).saturating_mul(COST_INPUT))
        .saturating_add((prog.code_len() as u64).saturating_mul(COST_CODE))
        .saturating_add((prog.consts.len() as u64).saturating_mul(COST_CONST))
}

/// What one probe run answered.
#[derive(PartialEq, Clone, Copy)]
enum Outcome {
    Moved,
    Same,
    Trap,
    /// Budget exhausted; NOTHING was run.
    Exhausted,
}

/// What evidence is there that the output depends on the declared inputs?
///
/// See the reference's `_input_liveness` docstring for the full argument. Three things
/// matter here and must stay identical to it:
///
///  * A TRAP IS NOT EVIDENCE OF DEPENDENCE. The attacker controls when the program
///    traps, so counting a trap as "live" hands the hardcoded-constant attack a way
///    straight back through the check. A trap says only that the program REFUSED TO
///    RUN, so it is recorded as "guarded" and never as evidence.
///  * A PERTURBATION MUST REACH THE SCALE OF THE THING IT PERTURBS.
///  * "THE OUTPUT" IS NOT ONE NUMBER. The verdict is about the output WINDOW, so a
///    hardcoded figure passes it by sitting beside one decoy cell that echoes an
///    input. The sweep therefore also records which output CELLS ever moved, and the
///    per-cell answer only exists when the ladder was EXHAUSTIVE.
///
/// Returns (verdict, per_input, per_cell). Only "dead" and "guarded" refuse, and both
/// are sound NEGATIVES. "indeterminate" never refuses by default -- a verifier must
/// not reject an honest receipt merely because it was expensive to probe.
fn input_liveness(
    prog: &replay::Program,
    inputs: &[i64],
    base_out: &[i64],
    base_steps: u64,
) -> (String, Vec<String>, Vec<String>) {
    let n = inputs.len();
    if n == 0 {
        // A program with no declared inputs makes no claim about any -- and with
        // nothing to perturb, nothing is known about its cells either.
        return (
            "n/a".into(),
            Vec::new(),
            vec!["indeterminate".to_string(); base_out.len()],
        );
    }

    // Cap ONE perturbation run, and cap the TOTAL. A single probe never runs longer
    // than the base did (plus a small floor for near-instant programs); the total is a
    // small multiple of the base COST -- not of the base step count, which a hostile
    // program sets to one and leaves there.
    let per_run_cap = replay::MAX_STEPS.min(base_steps.max(100_000));
    let base_cost = probe_cost(prog, n, base_steps);
    let total_budget = base_cost.saturating_mul(8).max(LIVENESS_FLOOR);

    let mut cell_moved = vec![false; base_out.len()];

    // Rust has no closure that can borrow the budget, the "did anything run" flag and
    // `cell_moved` mutably while the loops below also read them, so the probe is a
    // plain fn over an explicit state struct. `spent` is verifier-internal: it is the
    // bound the probe promises, and nothing outside this function reads it.
    struct State {
        spent: u64,
        ran: bool,
    }
    let mut state = State { spent: 0, ran: false };

    fn probe(
        prog: &replay::Program,
        inputs: &[i64],
        base_out: &[i64],
        n: usize,
        per_run_cap: u64,
        total_budget: u64,
        cell_moved: &mut [bool],
        state: &mut State,
        i: usize,
        value: i64,
    ) -> Outcome {
        if state.spent >= total_budget {
            return Outcome::Exhausted;
        }
        let mut trial = inputs.to_vec();
        trial[i] = value;
        let (result, used) = replay::run_probed(prog, &trial, Some(per_run_cap));
        match result {
            Err(_) => {
                // A refused run still cost the fixed per-run work, plus however many
                // instructions it retired before refusing. Charging the CAP instead
                // over-bills an early trap enormously, and an over-billed budget runs
                // out and reports "indeterminate", which does not refuse, in place of
                // the "guarded" that does.
                state.spent = state.spent.saturating_add(probe_cost(prog, n, used));
                Outcome::Trap
            }
            Ok(out) => {
                state.spent = state.spent.saturating_add(probe_cost(prog, n, used));
                state.ran = true;
                if out == base_out {
                    return Outcome::Same;
                }
                for c in 0..out.len().min(cell_moved.len()) {
                    if out[c] != base_out[c] {
                        cell_moved[c] = true;
                    }
                }
                Outcome::Moved
            }
        }
    }

    // ---- pass 1: the per-input verdict. Stops at the first perturbation that moves
    // the output, because that is all it takes to establish dependence.
    //
    // The ladder for input i is built ONLY when there is budget left to spend on it.
    // Building all of them up front is n * ~30 integers before a single probe runs, and
    // `inputs` is attacker-controlled up to 2^20 -- the same "work nobody charged for"
    // that `probe_cost` exists to close, reintroduced in the bookkeeping.
    let mut tried = vec![0usize; n];
    let mut per_input: Vec<String> = Vec::with_capacity(n);
    for i in 0..n {
        if state.spent >= total_budget {
            per_input.push("indeterminate".into());
            continue;
        }
        let mut verdict_i = "dead";
        let mut trapped = false;
        let mut exhausted = false;
        for probed in probe_values(inputs[i]) {
            let outcome = probe(
                prog,
                inputs,
                base_out,
                n,
                per_run_cap,
                total_budget,
                &mut cell_moved,
                &mut state,
                i,
                probed,
            );
            if outcome == Outcome::Exhausted {
                exhausted = true;
                break;
            }
            tried[i] += 1;
            if outcome == Outcome::Trap {
                trapped = true; // the program declined to run: NOT evidence
            } else if outcome == Outcome::Moved {
                verdict_i = "live"; // the value moved the answer: real evidence
                break;
            }
        }
        if verdict_i != "live" {
            // An exhausted budget is the weakest thing we can say, so it wins over
            // "guarded"; both are weaker than a definite "dead", which requires every
            // perturbation to have actually RUN and left the output alone.
            verdict_i = if exhausted {
                "indeterminate"
            } else if trapped {
                "guarded"
            } else {
                "dead"
            };
        }
        per_input.push(verdict_i.into());
    }

    // ---- pass 2: finish the ladder, for the CELL answer only. Pass 1's early stop is
    // right for "does this input matter" and useless for "does this cell move": the
    // perturbation that proved the input live may have moved a different cell entirely.
    // A cell may only be called dead once every perturbation has actually been run.
    let mut swept = true;
    for i in 0..n {
        if state.spent >= total_budget {
            swept = false;
            break;
        }
        for probed in probe_values(inputs[i]).into_iter().skip(tried[i]) {
            let outcome = probe(
                prog,
                inputs,
                base_out,
                n,
                per_run_cap,
                total_budget,
                &mut cell_moved,
                &mut state,
                i,
                probed,
            );
            if outcome == Outcome::Exhausted {
                swept = false;
                break;
            }
        }
        if !swept {
            break;
        }
    }

    let ran = state.ran;

    let per_cell: Vec<String> = cell_moved
        .iter()
        .map(|moved| {
            if *moved {
                "live".to_string()
            } else if ran && swept {
                "dead".to_string()
            } else {
                // Nothing completed, or the ladder was cut short: no cell may be
                // called dead.
                "indeterminate".to_string()
            }
        })
        .collect();

    let verdict = if per_input.iter().any(|s| s == "live") {
        "live"
    } else if per_input.iter().any(|s| s == "indeterminate") {
        "indeterminate"
    } else if per_input.iter().any(|s| s == "guarded") {
        "guarded"
    } else {
        "dead"
    };
    (verdict.to_string(), per_input, per_cell)
}

fn verify_replay(receipt: &Value, result: &mut Verdict, strict_liveness: bool) {
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

    let (liveness, per_input, per_cell) = input_liveness(&program, &inputs, &out, base_steps);
    // THE DEFAULT ACCEPTS `indeterminate`, AND THE STRICT MODE DOES NOT. The default
    // must accept it -- a verifier that refused an honest receipt for being costly to
    // probe would be accusing producers of forgery on a timing measurement -- and an
    // auditor of a regulated program must be able to switch that off. Strict demands a
    // positive "live": nothing weaker, and "n/a" (a program declaring no inputs at all)
    // is weaker.
    let live_ok = if strict_liveness {
        liveness == "live"
    } else {
        liveness != "dead" && liveness != "guarded"
    };
    if strict_liveness && liveness != "live" {
        result.notes.push(format!(
            "--strict-liveness: input-liveness is '{liveness}' and only 'live' is \
             accepted in strict mode - REFUSED without a positive demonstration that a \
             declared input reaches the output"
        ));
    }
    result.input_liveness = Some(liveness.clone());
    result.input_liveness_by_input = per_input.clone();
    result.output_liveness_by_cell = per_cell.clone();
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
            let dead_cells: Vec<usize> = per_cell
                .iter()
                .enumerate()
                .filter(|(_, s)| *s == "dead")
                .map(|(c, _)| c)
                .collect();
            let mut note = String::from(
                "input-liveness is EVIDENCE, not proof: perturbing an input moved the output, \
                 which shows dependence but cannot show the program computes the formula its \
                 name claims. Pin an approved program digest (--expect-program) for that.",
            );
            if !dark.is_empty() {
                note += &format!(" Inputs {dark:?} were not shown to reach the output.");
            }
            if !dead_cells.is_empty() {
                note += &format!(
                    " Output cells {dead_cells:?} never moved under ANY perturbation - a \
                     constant beside a live one still proves nothing about the constant."
                );
            }
            result.notes.push(note);
        }
        _ => {}
    }

    let sig_ok = signature_gate(receipt, result);
    result.verified =
        result.integrity && result.reproduced == Some(true) && digest_ok && len_ok && live_ok && sig_ok;
}

/// The digest of the program this receipt actually carries, or None.
///
/// COMPUTED, never read out of `params.program_sha256`. The stated field is a
/// convenience a producer can get wrong and a forger can simply write: pinning against
/// it would let anyone claim the approved program by typing its digest into the file
/// beside a different program.
fn program_digest(receipt: &Value) -> Option<String> {
    let params = receipt.get("params")?;
    if !matches!(params, Value::Object(_)) {
        return None;
    }
    let prog = params.get("program")?;
    if !matches!(prog, Value::Object(_)) {
        return None;
    }
    replay::program_sha256(prog)
}

/// Run the ladder. Never fails on a hostile receipt -- an exception is not a refusal.
pub fn verify(receipt: &Value) -> Verdict {
    verify_with(receipt, None, false)
}

/// Run the ladder, with the two decisions a caller is allowed to make.
///
/// `expect_program` PINS THE SEMANTIC BOUNDARY, and it lives here rather than in the
/// CLI. Re-derivation proves the output follows FROM THE PROGRAM; it cannot prove the
/// program computes what its name claims, and no finite black-box probe can. That was
/// CLI post-processing in three implementations, which meant every LIBRARY caller got
/// the weaker question and no field telling them so. `approved_program` is now part of
/// the verdict: `None` when no expectation was supplied, `Some(_)` when one was.
///
/// `strict_liveness` turns an `indeterminate` liveness verdict into a refusal. The
/// default is unchanged and still accepts it.
pub fn verify_with(receipt: &Value, expect_program: Option<&str>, strict_liveness: bool) -> Verdict {
    let mut result = Verdict::default();
    let (ok, detail) = integrity(receipt);
    result.integrity = ok;
    if !ok {
        result.notes.push(detail);
    }

    // THE FIRST DECISION IS THE FORMAT, AND IT COMES BEFORE KERNEL SELECTION. An
    // unrecognised `spec` is not re-executed under v1 semantics and is not accused of
    // anything either: nothing here knows what it claims. The signature gate still
    // runs, because "who signed this file" is answerable without knowing what the file
    // means -- but it can only ever attribute, never verify.
    let receipt_spec = receipt.get("spec").and_then(|v| if v.is_str() { v.as_str() } else { None });
    if receipt_spec.as_deref() != Some(RECEIPT_SPEC_V1) {
        result.notes.push(format!(
            "receipt spec {} is not supported by this verifier - UNSUPPORTED, not verified",
            match receipt.get("spec") {
                None => "<absent>".to_string(),
                Some(v) => match v.as_str() {
                    Some(s) => format!("{s:?}"),
                    None => "<non-string>".to_string(),
                },
            }
        ));
        result.unsupported = true;
        signature_gate(receipt, &mut result);
        return finish(receipt, result, expect_program);
    }

    let kernel = receipt.get("kernel").and_then(|v| v.as_str());
    if kernel.as_deref() == Some(replay::SPEC) {
        verify_replay(receipt, &mut result, strict_liveness);
        return finish(receipt, result, expect_program);
    }

    result.notes.push(format!(
        "kernel {} cannot be re-executed by this implementation (Rust re-derives \
         obsign/replay/1 only) - NOT verified by re-derivation",
        kernel.as_deref().unwrap_or("<absent>")
    ));
    signature_gate(receipt, &mut result);
    finish(receipt, result, expect_program)
}

/// Apply the approved-program pin, whichever rung returned.
///
/// It runs on EVERY path, including the ones that could not re-execute: a receipt whose
/// kernel this implementation cannot run is not thereby an approved program, and
/// returning `None` there would read as "no expectation was supplied" when one was.
fn finish(receipt: &Value, mut result: Verdict, expect_program: Option<&str>) -> Verdict {
    let want = match expect_program {
        None => return result,
        Some(w) => w,
    };
    let actual = program_digest(receipt);
    let ok = actual.as_deref() == Some(want);
    result.approved_program = Some(ok);
    if !ok {
        result.verified = false;
        result.notes.push(format!(
            "program is not the approved one: expected {}.., receipt carries {}..",
            want.chars().take(16).collect::<String>(),
            actual
                .as_deref()
                .unwrap_or("None")
                .chars()
                .take(16)
                .collect::<String>()
        ));
    }
    result
}
