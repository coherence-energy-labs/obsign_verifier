'use strict';
/**
 * The trust ladder, in JavaScript.
 *
 *   1. integrity    `receipt_sha256` recomputes from the claim   -- every receipt
 *   2. reproduced   re-running the program reproduces the output -- replay receipts
 *   3. signature    NOT IMPLEMENTED HERE, and reported as such
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
 * It does not check signatures. Rather than ship a half-checked signature, the field
 * is reported `null` with a note pointing at the Python implementation. An unsigned
 * PASS on the replay rung is still meaningful: you recomputed the number yourself.
 */

const { integrity } = require('./canonical.js');
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
      return result;
    }

    const params = plain(receipt.__obj.get('params'));
    if (params === null || typeof params !== 'object') {
      notes.push('replay receipt carries no params; nothing to re-execute');
      return result;
    }
    const { program, inputs } = params;
    if (program === null || typeof program !== 'object' || !Array.isArray(inputs)) {
      notes.push('replay params must carry {program: object, inputs: [int]}');
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

    if (receipt.__obj.has('signature')) {
      notes.push('signature present but NOT checked by this implementation - use the Python package');
    }

    result.verified = Boolean(result.integrity && result.reproduced && digestOk && lenOk);
    return result;
  } catch (e) {
    notes.push(`verification error, treated as NOT verified: ${e.name}: ${e.message}`);
    return result;
  }
}

module.exports = { verify };
