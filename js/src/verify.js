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
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return v;
  if (v && typeof v === 'object' && '__n' in v) {
    return v.__n === 'i' ? Number(v.v) : v.v;
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

    let out;
    try {
      out = replay.run(program, inputs);
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

    const lenOk = declared.length === undefined || declared.length === null || declared.length === out.length;
    if (!lenOk) notes.push('output length does not match the re-executed result');

    // `sigOk` is a TERM IN THE CONJUNCTION, which is the entire fix. It was absent,
    // and the exit code -- the thing a pipeline reads -- said VERIFIED over a
    // signature nobody had checked.
    const sigOk = signatureGate(receipt, result, notes);

    result.verified = Boolean(result.integrity && result.reproduced && digestOk && lenOk && sigOk);
    return result;
  } catch (e) {
    notes.push(`verification error, treated as NOT verified: ${e.name}: ${e.message}`);
    return result;
  }
}

module.exports = { verify };
