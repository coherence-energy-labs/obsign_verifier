'use strict';
/**
 * Signature checking in the JavaScript port, against receipts the PRODUCER signed.
 *
 * TWO DEFECTS ARE PINNED HERE, AND NEITHER WAS A MISSING ASSERTION.
 *
 * 1. `verified` was `integrity && reproduced && digestOk && lenOk`. The signature was
 *    not a term in that conjunction, so a receipt carrying a signature made by nobody's
 *    key printed VERIFIED and exited 0. The gap was disclosed in a note -- and a note
 *    is not a control. The exit code is the interface.
 *
 * 2. `binds` was used to decide whether the bound-metadata check ran at all, so
 *    deleting one key from the JSON skipped it. `case` is excluded from
 *    `receipt_sha256`, so `case.examiner` -- the line a court report prints first --
 *    could then be rewritten to any name on a cryptographically valid receipt.
 *
 * The fixtures are bytes from the producer, not from this package. Two implementations
 * that only ever check their own output agree about their own mistakes.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { loadReceipt } = require('../src/canonical.js');
const { verify } = require('../src/verify.js');

const REPO = path.resolve(__dirname, '..', '..');
const CONFORMANCE = path.join(REPO, 'src', 'obsign_verify', 'data', 'conformance');

const load = (name) => loadReceipt(fs.readFileSync(path.join(CONFORMANCE, name), 'utf8'));

/** Round-trip a receipt through plain JSON so a test can tamper with it. */
function reparse(obj) {
  return loadReceipt(JSON.stringify(obj));
}

/** Unwrap the tagged tree far enough to edit, then re-parse. Strings only -- the
 *  fields these tests touch are all strings, so no int/float information is lost. */
function mutate(name, fn) {
  const raw = JSON.parse(fs.readFileSync(path.join(CONFORMANCE, name), 'utf8'));
  fn(raw);
  return reparse(raw);
}

test('a receipt the PRODUCER signed is accepted here', () => {
  const res = verify(load('producer_signed_replay.json'));
  assert.strictEqual(res.integrity, true, res.notes.join('; '));
  assert.strictEqual(res.reproduced, true, res.notes.join('; '));
  assert.strictEqual(res.signature.valid, true, res.signature.detail);
  assert.strictEqual(res.signature.identity_bound, true);
  assert.strictEqual(res.signature.attributed_signer, 'A. Chen, Coherence Energy Labs');
  assert.deepStrictEqual(res.signature.bound_metadata, ['case']);
  assert.strictEqual(res.verified, true, res.notes.join('; '));
});

test('an unbound case verifies but is reported as unattested', () => {
  const res = verify(load('producer_signed_case_unbound.json'));
  assert.strictEqual(res.verified, true, res.notes.join('; '));
  assert.deepStrictEqual(res.signature.bound_metadata, []);
  assert.deepStrictEqual(res.signature.unbound_metadata, ['case']);
  assert.ok(res.notes.some((n) => n.includes('NOT covered by the signature')));
});

test('a forged signature CANNOT produce a verified verdict', () => {
  // The original defect, exactly: integrity holds, the program re-derives, and the
  // signature is nonsense. Before the fix this returned verified:true and exit 0.
  const r = mutate('producer_signed_replay.json', (raw) => {
    raw.signature.sig = 'ab'.repeat(64);
  });
  const res = verify(r);
  assert.strictEqual(res.integrity, true, 'the forgery must survive step 1');
  assert.strictEqual(res.reproduced, true, 'and step 2, or it proves nothing');
  assert.strictEqual(res.signature.valid, false);
  assert.strictEqual(res.verified, false, 'a bad signature must sink the verdict');
});

test('deleting the binds key is a REJECT, not a skip', () => {
  const r = mutate('producer_signed_replay.json', (raw) => {
    delete raw.signature.binds;
    raw.case.examiner = 'Dr. J. Smith, FBI Digital Forensics';
  });
  const res = verify(r);
  assert.strictEqual(res.signature.valid, false);
  assert.strictEqual(res.signature.attributed_signer, null);
  assert.strictEqual(res.verified, false);
  // Refused BY THE BINDS CHECK -- not incidentally by the signature step.
  assert.ok(res.signature.detail.includes('binds_sha256'), res.signature.detail);
});

for (const [label, value] of [
  ['null', null], ['empty list', []], ['a missing key', ['nonexistent']],
  ['a string', 'case'], ['non-strings', [1, 2]],
]) {
  test(`binds = ${label} cannot suppress the check`, () => {
    const r = mutate('producer_signed_replay.json', (raw) => {
      raw.signature.binds = value;
      raw.case.examiner = 'Dr. J. Smith, FBI Digital Forensics';
    });
    const res = verify(r);
    assert.strictEqual(res.signature.valid, false, `binds=${label} suppressed the check`);
    assert.strictEqual(res.verified, false);
  });
}

test('rewriting the bound case is a REJECT', () => {
  const r = mutate('producer_signed_replay.json', (raw) => {
    raw.case.examiner = 'Dr. J. Smith, FBI Digital Forensics';
  });
  assert.strictEqual(verify(r).signature.valid, false);
});

test('rewriting the signer is a REJECT', () => {
  const r = mutate('producer_signed_replay.json', (raw) => {
    raw.signature.signer = 'Dr. J. Smith, FBI Digital Forensics';
  });
  const res = verify(r);
  assert.strictEqual(res.signature.valid, false);
  assert.strictEqual(res.signature.attributed_signer, null);
});

test('a signature from a different key is a REJECT', () => {
  const r = mutate('producer_signed_replay.json', (raw) => {
    raw.signature.public_key = '00'.repeat(32);
  });
  assert.strictEqual(verify(r).signature.valid, false);
});

test('a broken claim means the signature attributes NOBODY', () => {
  const r = mutate('producer_signed_replay.json', (raw) => {
    raw.output.sha256 = '00'.repeat(32);              // not resealed
  });
  const res = verify(r);
  assert.strictEqual(res.signature.valid, false);
  assert.strictEqual(res.signature.attributed_signer, null);
  assert.strictEqual(res.verified, false);
});

test('an unsupported algorithm is refused, not ignored', () => {
  const r = mutate('producer_signed_replay.json', (raw) => {
    raw.signature.alg = 'rot13';
  });
  const res = verify(r);
  assert.strictEqual(res.signature.valid, false);
  assert.ok(res.signature.detail.includes('UNVERIFIED'));
  assert.strictEqual(res.verified, false);
});

test('an unsigned receipt still verifies -- a signature adds who, not whether', () => {
  const r = mutate('producer_signed_replay.json', (raw) => {
    delete raw.signature;
    delete raw.case;
  });
  const res = verify(r);
  assert.strictEqual(res.signature.present, false);
  assert.strictEqual(res.verified, true, res.notes.join('; '));
});

test('this implementation reaches the SAME signature verdict as Python', () => {
  // The verdicts Python produces for the whole conformance corpus, checked in as
  // literals. Two ports that only ever agree with themselves prove nothing.
  const expected = {
    'producer_signed_replay.json': { valid: true, identity_bound: true, bound: ['case'] },
    'producer_signed_case_unbound.json': { valid: true, identity_bound: true, bound: [] },
    'producer_signed_tau_field_fixed.json': { valid: true, identity_bound: true, bound: ['case'] },
  };
  for (const [name, want] of Object.entries(expected)) {
    const sig = verify(load(name)).signature;
    assert.strictEqual(sig.valid, want.valid, name);
    assert.strictEqual(sig.identity_bound, want.identity_bound, name);
    assert.deepStrictEqual(sig.bound_metadata, want.bound, name);
  }
});

test('tau_field_fixed is still NOT re-derived here, and is not reported verified', () => {
  // The signature verifies, but this implementation cannot re-execute the kernel.
  // "I checked who signed it" must not be allowed to stand in for "I recomputed it".
  const res = verify(load('producer_signed_tau_field_fixed.json'));
  assert.strictEqual(res.signature.valid, true, res.signature.detail);
  assert.strictEqual(res.reproduced, null);
  assert.strictEqual(res.verified, false, 'an un-re-derived receipt is never verified');
});
