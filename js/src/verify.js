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
    // Object.create(null), NOT {}. On a normal object `o["__proto__"] = x` is a
    // SETTER, not an assignment: it reparents the object instead of adding a
    // member. A receipt whose program was {"__proto__": {...a real program...}}
    // therefore produced an object with ZERO own members that answered .spec,
    // .code and .steps through the prototype chain -- so this verifier executed
    // and REPRODUCED a program that Python and Rust cannot even read, and
    // programSha256 hashed the empty own-property set, giving every such program
    // the same digest (sha256("{}")) and defeating --expect-program pinning.
    // A null-prototype object has no such setter and no inherited anything.
    const o = Object.create(null);
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
    const { verdict: liveness, perInput, perCell } = inputLiveness(program, inputs, out, baseSteps);
    result.input_liveness = liveness;
    result.input_liveness_by_input = perInput;
    // Which output CELLS a perturbation ever moved. A whole-window verdict cannot see
    // a constant hiding beside a decoy that echoes an input; graph.js refuses a link
    // whose source slice is entirely dead.
    result.output_liveness_by_cell = perCell;
    const liveOk = liveness !== 'dead' && liveness !== 'guarded';
    if (liveness === 'dead') {
      notes.push('the output does not depend on ANY declared input: every input was '
        + 'perturbed and the result never changed. This program ignores its inputs, '
        + 'so re-deriving it proves nothing about them -- a constant dressed as a '
        + 'computation. REFUSED.');
    } else if (liveness === 'guarded') {
      notes.push('no declared input was shown to reach the output, and the program '
        + 'TRAPPED on every perturbation that did not. A program that refuses to run '
        + 'on anything but its own receipted inputs yields no evidence that those '
        + 'inputs produced this answer -- the shape of a hardcoded result behind an '
        + 'equality guard. REFUSED.');
    } else if (liveness === 'indeterminate') {
      notes.push('input-liveness probe hit its budget before proving dependence either '
        + 'way; not treated as a failure');
    }
    if (liveness === 'live') {
      const dark = perInput.map((st, i) => (st === 'live' ? -1 : i)).filter(i => i >= 0);
      const deadCells = perCell.map((st, c) => (st === 'dead' ? c : -1)).filter(c => c >= 0);
      notes.push('input-liveness is EVIDENCE, not proof: perturbing an input moved the '
        + 'output, which shows dependence but cannot show the program computes the '
        + 'formula its name claims. Pin an approved program digest (--expect-program) '
        + 'for that.' + (dark.length ? ` Inputs ${JSON.stringify(dark)} were not shown `
        + 'to reach the output.' : '')
        + (deadCells.length ? ` Output cells ${JSON.stringify(deadCells)} never moved `
        + 'under ANY perturbation - a constant beside a live one still proves nothing '
        + 'about the constant.' : ''));
    }

    // `declared.length` is a JSON integer, so it arrives as a BigInt and `1n === 1`
    // is false -- comparing it to `out.length` with `===` would refuse every honest
    // receipt. Compare on one type, and require the declared value to BE an integer:
    // a float or a string there is malformed, and malformed is refused, not ignored.
    // (`declared.length === undefined` also covers a receipt that declares no length;
    // that is the only shape allowed to skip the check.)
    // (The Python reference read this with `in (None, len(out))`, and `in` is `==`:
    // `True == 1` and `1.0 == 1`, so `"length": true` verified THERE and was refused
    // here. Both sides now require a JSON integer.)
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

// Perturbations tried per input, mirroring the Python verifier EXACTLY -- both sides
// must land on the same "live"/"dead"/"guarded"/"indeterminate" verdict for the same
// receipt, or a coarse-grained honest receipt is refused by one implementation and
// accepted by the other.
const LIVENESS_DELTAS = [1n, -1n, 7n, -7n, 1000n, -1000n, 1000000n, -1000000n];

// Scaled to the INPUT: a fixed ladder can only exercise a program at the resolution
// of its largest step, so anything coarser -- cents reported in hundreds of millions,
// bytes reported in gigabytes, any bucketed figure -- never moved and was called
// "dead", which REFUSES. Honest receipts were being accused of being constants.
const LIVENESS_FRACTIONS = [2n, 8n, 64n, 1024n];
// ...and scaled to the MACHINE, for the mirror case: a small input multiplied up
// before it reaches the output.
const LIVENESS_SHIFTS = [20n, 32n, 48n, 62n];
const LIVENESS_EDGES = [0n, 1n, -1n];

/** The values one input is re-run with, cheapest and likeliest first. */
function probeValues(x) {
  const seen = new Set([x]);
  const values = [];
  const add = (v) => {
    if (v >= replay.INT64_MIN && v <= replay.INT64_MAX && !seen.has(v)) {
      seen.add(v);
      values.push(v);
    }
  };
  for (const d of LIVENESS_DELTAS) add(x + d);
  const magnitude = x < 0n ? -x : x;
  for (const f of LIVENESS_FRACTIONS) {
    const step = magnitude / f;
    if (step !== 0n) { add(x + step); add(x - step); }
  }
  for (const k of LIVENESS_SHIFTS) { add(x + (1n << k)); add(x - (1n << k)); }
  for (const v of LIVENESS_EDGES) add(v);
  add(replay.INT64_MAX);
  add(replay.INT64_MIN);
  return values;
}

// What one unit of each kind of per-run work costs, in units of "zeroing one memory
// cell". Identical to the Python reference's table, because the two must exhaust the
// budget at the same point or they disagree about which receipts verify.
const COST_CELL = 1, COST_INPUT = 16, COST_CONST = 8, COST_CODE = 128, COST_STEP = 64;
const LIVENESS_FLOOR = 32000000;

/** What ONE run of PROGRAM costs -- all of it, not just the steps it retires. The
 * budget used to count steps alone, and a program that HALTs immediately retires one
 * step per probe while re-allocating `mem` cells, re-validating every instruction and
 * re-loading every input: a 4,000,000-step budget bought four million full machine
 * instantiations. Measured before the fix: 14.0 s in Node for a 1.7 KB receipt whose
 * claim hash was garbage, and hours at the wire limit. */
function probeCost(program, nInputs, steps) {
  return steps * COST_STEP
    + Number(program.mem) * COST_CELL
    + nInputs * COST_INPUT
    + program.code.length * COST_CODE
    + program.consts.length * COST_CONST;
}

/** What evidence is there that the output depends on the declared inputs?
 *
 * See the Python `_input_liveness` docstring for the full argument. Two things
 * matter here and must stay identical to it:
 *
 *  - A TRAP IS NOT EVIDENCE. This returned 'live' on a trapped perturbation,
 *    reasoning that the value controls whether an output exists. The attacker
 *    chooses when to trap, so that let a hardcoded constant behind an equality
 *    guard (`if inputs == receipted { ok = 1 } ; 1/ok ; output 424242`) pass the
 *    check it exists to fail. A trap now records 'guarded' -- the program declined
 *    to run, which says nothing about the output.
 *  - A 'live' is EVIDENCE, never a semantic guarantee: no finite black-box probe
 *    can show a program computes the formula its name claims.
 *
 * Returns {verdict, perInput}; only 'dead' and 'guarded' refuse, and both are
 * sound negatives. Bounded so it cannot become a DoS amplifier. */
function inputLiveness(program, inputs, baseOut, baseSteps) {
  const n = inputs.length;
  if (n === 0) {
    // Nothing to perturb, so nothing is known about the cells either.
    return { verdict: 'n/a', perInput: [], perCell: baseOut.map(() => 'indeterminate') };
  }

  const sameOut = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
  const perRunCap = Math.min(replay.MAX_STEPS, Math.max(baseSteps, 100000));
  const baseCost = probeCost(program, n, baseSteps);
  const totalBudget = Math.max(baseCost * 8, LIVENESS_FLOOR);
  let spent = 0;
  let ran = false;
  const cellMoved = baseOut.map(() => false);

  /** 'moved' | 'same' | 'trap' | null (budget exhausted, nothing run). */
  const probe = (i, value) => {
    if (spent >= totalBudget) return null;
    const trial = inputs.slice();
    trial[i] = value;
    let out;
    try {
      const r = replay.runCounted(program, trial, perRunCap);
      out = r.out;
      spent += probeCost(program, n, r.steps);
    } catch (e) {
      if (!(e instanceof replay.Trap)) throw e;
      // A refused run still cost the fixed per-run work plus what it retired; the
      // Trap carries the count. Charging the CAP over-bills an early trap enormously
      // and an over-billed budget reports 'indeterminate', which does not refuse.
      spent += probeCost(program, n, e.steps || 0);
      return 'trap';
    }
    ran = true;
    if (sameOut(out, baseOut)) return 'same';
    for (let c = 0; c < Math.min(out.length, cellMoved.length); c++) {
      if (out[c] !== baseOut[c]) cellMoved[c] = true;
    }
    return 'moved';
  };

  // pass 1: the per-input verdict, stopping at the first perturbation that moves the
  // output -- that is all it takes to establish dependence.
  //
  // The ladder for input i is built ONLY when there is budget left to spend on it:
  // building all of them up front is n * ~30 BigInts before a single probe runs, and
  // `inputs` is attacker-controlled up to 2^20 -- the same uncharged work `probeCost`
  // exists to close, reintroduced in the bookkeeping.
  const tried = new Array(n).fill(0);
  const perInput = [];
  for (let i = 0; i < n; i++) {
    if (spent >= totalBudget) { perInput.push('indeterminate'); continue; }
    let state = 'dead';
    let trapped = false;
    let exhausted = false;
    for (const probed of probeValues(inputs[i])) {
      const outcome = probe(i, probed);
      if (outcome === null) { exhausted = true; break; }
      tried[i] += 1;
      if (outcome === 'trap') trapped = true;
      else if (outcome === 'moved') { state = 'live'; break; }
    }
    if (state !== 'live') {
      state = exhausted ? 'indeterminate' : (trapped ? 'guarded' : 'dead');
    }
    perInput.push(state);
  }

  // pass 2: finish the ladder for the CELL answer only. Pass 1's early stop is right
  // for "does this input matter" and useless for "does this cell move": the
  // perturbation that proved the input live may have moved a different cell entirely.
  let swept = true;
  for (let i = 0; i < n && swept; i++) {
    if (spent >= totalBudget) { swept = false; break; }
    for (const probed of probeValues(inputs[i]).slice(tried[i])) {
      if (probe(i, probed) === null) { swept = false; break; }
    }
  }
  const perCell = cellMoved.map((moved) => (moved ? 'live'
    : (ran && swept ? 'dead' : 'indeterminate')));

  let verdict;
  if (perInput.includes('live')) verdict = 'live';
  else if (perInput.includes('indeterminate')) verdict = 'indeterminate';
  else if (perInput.includes('guarded')) verdict = 'guarded';
  else verdict = 'dead';
  return { verdict, perInput, perCell };
}


module.exports = { verify, plain };
