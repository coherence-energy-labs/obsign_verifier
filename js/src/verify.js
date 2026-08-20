'use strict';
/**
 * The trust ladder, in JavaScript.
 *
 *   1. integrity    `receipt_sha256` recomputes from the claim   -- every receipt
 *   2. reproduced   re-running the program reproduces the output -- replay receipts
 *   3. signature    Ed25519 over what the signature actually covers -- see signature.js
 *   4. issuer trust out of scope, deliberately, in every implementation
 *
 * WHAT THIS IMPLEMENTATION DOES NOT DO, said plainly rather than discovered.
 *
 * It does not re-execute `tau_field_fixed`. That kernel needs an array pipeline this
 * package deliberately does not carry, so such receipts report `reproduced: null` and
 * an explicit note. They are NOT reported as verified, and they are not reported as
 * forged either -- "I cannot check this" is a third answer and collapsing it into
 * either of the other two is how a verifier starts lying.
 *
 * IT USED NOT TO CHECK SIGNATURES, AND THAT IS THE BUG THIS HEADER NOW RECORDS.
 * The omission was disclosed in a note, which was honest and useless: `verified` was
 * computed WITHOUT the signature, so a receipt carrying a signature over nothing at
 * all printed VERIFIED and exited 0. Documentation is not a control. Whatever this
 * file declines to check, it must also decline to PASS.
 */

const { integrity } = require('./canonical.js');
const sigmod = require('./signature.js');
const replay = require('./replay.js');

const plain = (v) => {
  // Unwrap the tagged parse tree into ordinary JS values for the interpreter.
  //
  // THE INTEGER STAYS A BigInt. This line used to read `Number(v.v)`, and that
  // coercion was a false VERIFIED: canonical.js parses JSON integers as BigInt
  // precisely because int64 does not fit a double, and then this function handed
  // the interpreter a rounded copy. Above 2^53 the claim hash and the Ed25519
  // signature still verified -- they are computed over the exact tree -- while the
  // RE-DERIVATION ran on different numbers. A receipt whose true output was
  // 1,000,000,000,000 and which claimed 0 printed [VERIFIED] here and REFUSED in
  // the Python reference verifier, and pinning the program digest did not help:
  // the rounded value was an input, outside `program`.
  //
  // replay.js's own header calls Numbers "the worst failure shape available"
  // because they "agree with the reference on small portfolios and silently
  // diverge on large ones". That was this line.
  //
  // Keeping the tag also makes floats detectable downstream: after this, a
  // BigInt is a JSON integer and a Number is a JSON float, so `consts: [7.0]`
  // can be refused as the spec requires instead of passing as 7.
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return v;
  if (v && typeof v === 'object' && '__n' in v) {
    return v.v;
  }
  if (Array.isArray(v)) return v.map(plain);
  if (v && v.__obj instanceof Map) {
    const o = {};
    for (const [k, val] of v.__obj) o[k] = plain(val);
    return o;
  }
  return v;
};

/**
 * Run step 3 and return whether it permits a `verified` verdict. ONE place, so the
 * rule cannot be fixed in one branch and left standing in another.
 *
 * A signature that is PRESENT but does not verify is a refusal. A signature that is
 * ABSENT is not: the replay rung stands on its own, which is the whole argument for a
 * verifier a stranger can run.
 */
function signatureGate(receipt, result, notes) {
  const sig = sigmod.check(receipt);
  result.signature = sig;
  if (sig.present && !sig.valid) notes.push(sig.detail);
  for (const key of sig.unbound_metadata || []) {
    notes.push(`'${key}' is present but NOT covered by the signature - `
      + 'unattested annotation, not an attested fact');
  }
  return !sig.present || sig.valid;
}

function verify(receipt) {
  const notes = [];
  const result = { integrity: false, reproduced: null, signature: null, verified: false, notes };

  try {
    const [ok, detail] = integrity(receipt);
    result.integrity = ok;
    if (!ok) notes.push(detail);

    const kernel = receipt.__obj.get('kernel');
    if (kernel !== replay.SPEC) {
      notes.push(`kernel ${kernel} cannot be re-executed by this implementation `
        + '(JavaScript re-derives obsign/replay/1 only) - NOT verified by re-derivation');
      signatureGate(receipt, result, notes);
      return result;
    }

    const params = plain(receipt.__obj.get('params'));
    if (params === null || typeof params !== 'object') {
      notes.push('replay receipt carries no params; nothing to re-execute');
      signatureGate(receipt, result, notes);
      return result;
    }
    const { program, inputs } = params;
    if (program === null || typeof program !== 'object' || !Array.isArray(inputs)) {
      notes.push('replay params must carry {program: object, inputs: [int]}');
      signatureGate(receipt, result, notes);
      return result;
    }

    const stated = params.program_sha256;
    const actual = replay.programSha256(program);
    const digestOk = stated === undefined || stated === null || stated === actual;
    if (!digestOk) {
      notes.push(`program digest mismatch: states ${String(stated).slice(0, 16)}.., computes ${actual.slice(0, 16)}..`);
    }

    let out, baseSteps;
    try {
      ({ out, steps: baseSteps } = replay.runCounted(program, inputs));
    } catch (e) {
      if (!(e instanceof replay.Trap)) throw e;
      notes.push(`program refused: ${e.message}`);
      signatureGate(receipt, result, notes);
      return result;
    }

    const declared = plain(receipt.__obj.get('output')) || {};
    const got = replay.outputSha256(out);
    result.reproduced = got === declared.sha256;
    if (!result.reproduced) {
      notes.push(`output mismatch: claim ${String(declared.sha256).slice(0, 16)}.., recomputed ${got.slice(0, 16)}..`);
    }

    // A re-derivation that does not depend on the inputs proves nothing about them.
    // Mirror of the Python verifier's rule, so the two agree byte-for-byte on the
    // trivial-constant attack: only "dead" (every declared input perturbed, none
    // moved the outcome) refuses; "indeterminate" never does.
    const liveness = inputLiveness(program, inputs, out, baseSteps);
    result.input_liveness = liveness;
    const liveOk = liveness !== 'dead';
    if (liveness === 'dead') {
      notes.push('the output does not depend on ANY declared input: every input was '
        + 'perturbed and the result never changed. This program ignores its inputs, '
        + 'so re-deriving it proves nothing about them -- a constant dressed as a '
        + 'computation. REFUSED.');
    } else if (liveness === 'indeterminate') {
      notes.push('input-liveness probe hit its budget before proving dependence either '
        + 'way; not treated as a failure');
    }

    // `declared.length` is a JSON integer, so it arrives as a BigInt and `1n === 1`
    // is false -- comparing it to `out.length` with `===` would refuse every honest
    // receipt. Compare on one type, and require the declared value to BE an integer:
    // a float or a string there is malformed, and malformed is refused, not ignored.
    // (`declared.length === undefined` also covers a receipt that declares no length;
    // that is the only shape allowed to skip the check.)
    const declaredLen = declared.length;
    const lenOk = declaredLen === undefined || declaredLen === null
      ? true
      : typeof declaredLen === 'bigint' && declaredLen === BigInt(out.length);
    if (!lenOk) notes.push('output length does not match the re-executed result');

    // `sigOk` is a TERM IN THE CONJUNCTION, which is the entire fix. It was absent,
    // and the exit code -- the thing a pipeline reads -- said VERIFIED over a
    // signature nobody had checked.
    const sigOk = signatureGate(receipt, result, notes);

    result.verified = Boolean(result.integrity && result.reproduced && digestOk && lenOk
      && liveOk && sigOk);
    return result;
  } catch (e) {
    notes.push(`verification error, treated as NOT verified: ${e.name}: ${e.message}`);
    return result;
  }
}

// Perturbations tried per input, mirroring the Python verifier exactly so both land
// on the same "live"/"dead"/"indeterminate" verdict for the same receipt.
const LIVENESS_DELTAS = [1n, -1n, 7n, -7n, 1000n, -1000n, 1000000n];

/** Does the output depend on the declared inputs? See the Python `_input_liveness`
 * docstring for the full argument. Bounded so it cannot become a DoS amplifier:
 * each perturbation run is capped, and so is the total. Only "dead" -- every input
 * exercised within budget, none moved the outcome -- ever refuses. */
function inputLiveness(program, inputs, baseOut, baseSteps) {
  const n = inputs.length;
  if (n === 0) return 'n/a';

  const sameOut = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
  const perRunCap = Math.min(replay.MAX_STEPS, Math.max(baseSteps, 100000));
  const totalBudget = Math.max(baseSteps * 8, 4000000);
  let spent = 0;

  for (let i = 0; i < n; i++) {
    const original = inputs[i];
    for (const d of LIVENESS_DELTAS) {
      const probed = original + d;
      if (probed < replay.INT64_MIN || probed > replay.INT64_MAX) continue;
      if (spent >= totalBudget) return 'indeterminate';
      const trial = inputs.slice();
      trial[i] = probed;
      try {
        const { out, steps } = replay.runCounted(program, trial, perRunCap);
        spent += steps;
        if (!sameOut(out, baseOut)) return 'live';
      } catch (e) {
        if (!(e instanceof replay.Trap)) throw e;
        spent += perRunCap;
        // valid int64 in, so a Trap here is the program's own guard/arithmetic: the
        // value controls whether an output exists at all, which is dependence.
        return 'live';
      }
    }
  }
  return 'dead';
}

module.exports = { verify, plain };
