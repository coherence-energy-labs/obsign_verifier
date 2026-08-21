'use strict';
/**
 * An unknown format is a THIRD ANSWER -- the JavaScript half.
 *
 * The fixtures under `src/obsign_verify/data/conformance/unsupported/` each declare
 * their own expected verdict in a `_conformance` block, and the Python, JavaScript and
 * Rust suites all read the SAME block. Three implementations held to one written
 * expectation is a different thing from three implementations held to each other:
 * agreement between three implementations that are all wrong is perfect agreement.
 *
 * WHAT THIS FILE IS ABOUT, in one line each:
 *
 *   receipt spec     the ladder dispatched on `kernel` with no top-level format check,
 *                    so `obsign/receipt/v99` -- RE-SEALED, so its integrity holds --
 *                    was interpreted under today's v1 semantics.
 *   signature spec   `if (spec === SIG_SPEC_V2) {...} else { legacy v1 }`, so an
 *                    unknown envelope inherited the weakest semantics the format has.
 *   the `sig` member `str(sig,'sig') || str(sig,'signature')` skipped a non-STRING
 *                    `sig` and read a synonym, so `{"sig": 5, "signature": "<valid
 *                    128-hex>"}` VERIFIED HERE and was refused by Python and Rust.
 *                    That one was a live entry in KNOWN_DIVERGENCES, with an executed
 *                    witness, in a signature envelope, on a field a forger controls.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { loadReceipt } = require('../src/canonical.js');
const { verify } = require('../src/verify.js');

const REPO = path.resolve(__dirname, '..', '..');
const DIR = path.join(REPO, 'src', 'obsign_verify', 'data', 'conformance', 'unsupported');

const read = (name) => JSON.parse(fs.readFileSync(path.join(DIR, name), 'utf8'));
const verifyDoc = (doc) => verify(loadReceipt(JSON.stringify(doc)));

test('the unsupported fixture set is present and does not all say one thing', () => {
  const names = fs.readdirSync(DIR).filter((n) => n.endsWith('.json')).sort();
  assert.deepStrictEqual(names, [
    'receipt_spec_v1_control.json', 'receipt_spec_v99.json',
    'signature_spec_absent.json', 'signature_spec_v1.json', 'signature_spec_v9.json',
  ]);
  const verdicts = new Set(names.map((n) => read(n)._conformance.expect.verified));
  assert.deepStrictEqual([...verdicts].sort(), [false, true],
    'every fixture declares the same verdict, so the reader below is a constant');
});

test('every unsupported fixture gets the verdict it declares', () => {
  for (const name of fs.readdirSync(DIR).filter((n) => n.endsWith('.json'))) {
    const doc = read(name);
    const want = doc._conformance.expect;
    const res = verifyDoc(doc);
    const s = res.signature || {};
    const got = {
      verified: res.verified,
      unsupported: res.unsupported,
      // NOT Boolean(...). `reproduced` is three-valued -- null is "nothing was
      // attempted", a different fact from false ("re-derived, did not match") -- and
      // coercing it here is what let the reference say `false` and both ports say
      // `null` on the same bytes with every suite green.
      reproduced: res.reproduced ?? null,
      signature_present: s.present || false,
      signature_valid: s.valid || false,
      signature_unsupported: s.unsupported || false,
      identity_bound: s.identity_bound || false,
      attributed_signer: s.attributed_signer ?? null,
    };
    const expected = { ...want };
    delete expected.requires_crypto;
    assert.deepStrictEqual(got, expected, `${name}: ${doc._conformance.note}`);
  }
});

test('the only difference between valid and unsupported is the spec string', () => {
  // Same claim, same key, SAME 128 hex characters of signature -- and that signature
  // really does verify under v1 rules, which is what made the old `else: legacy v1`
  // dispatch report an envelope nobody has implemented as a checked signature.
  const v1 = read('signature_spec_v1.json');
  const v9 = read('signature_spec_v9.json');
  assert.strictEqual(v1.signature.sig, v9.signature.sig, 'precondition: same bytes');
  assert.strictEqual(v1.receipt_sha256, v9.receipt_sha256, 'precondition: same claim');

  const a = verifyDoc(v1);
  const b = verifyDoc(v9);
  assert.strictEqual(a.signature.valid, true, 'the v1 signature must really verify');
  assert.strictEqual(a.verified, true);
  assert.strictEqual(b.signature.valid, false);
  assert.strictEqual(b.signature.unsupported, true);
  assert.strictEqual(b.verified, false);
});

test('no spelling but the two tokens reaches a signature check', () => {
  const base = read('signature_spec_v1.json');
  for (const spec of ['obsign/signature/v3', 'obsign/signature/v9', 'OBSIGN/SIGNATURE/V2',
    'obsign/signature/v2 ', '', 9, true, ['v1'], { v: 1 }]) {
    const doc = { ...base, signature: { ...base.signature, spec } };
    const res = verifyDoc(doc);
    assert.strictEqual(res.signature.unsupported, true,
      `spec ${JSON.stringify(spec)} was not reported unsupported: ${res.signature.detail}`);
    assert.strictEqual(res.signature.valid, false);
    assert.strictEqual(res.signature.attributed_signer, null);
    assert.strictEqual(res.verified, false);
  }
  // A JSON `null` spec is the one case that is NOT unsupported: the reference cannot
  // tell an absent key from a null value, so all three read `null` as absent, which is
  // legacy v1, which is valid. Pinned so the equivalence is a decision, not a drift.
  const nulled = { ...base, signature: { ...base.signature, spec: null } };
  assert.strictEqual(verifyDoc(nulled).signature.valid, true);
});

test('a `signature` member is not a synonym for `sig`', () => {
  // THE FORMER KNOWN DIVERGENCE, with the witness the audit named. This implementation
  // is the one that accepted it.
  const doc = read('signature_spec_v1.json');
  const real = doc.signature.sig;
  assert.strictEqual(verifyDoc(doc).signature.valid, true,
    'control: the same hex in `sig` DOES verify, so what fails below is the synonym');

  for (const bad of [5, true, '', null]) {
    const forged = { ...doc, signature: { ...doc.signature, sig: bad, signature: real } };
    const res = verifyDoc(forged);
    assert.strictEqual(res.signature.valid, false,
      `sig=${JSON.stringify(bad)} beside a valid \`signature\` member was accepted`);
    assert.strictEqual(res.signature.attributed_signer, null);
    assert.strictEqual(res.verified, false);
  }
});

test('an unknown receipt spec is unsupported while the same claim under v1 verifies', () => {
  const control = verifyDoc(read('receipt_spec_v1_control.json'));
  assert.strictEqual(control.verified, true, control.notes.join('; '));
  assert.strictEqual(control.unsupported, false);

  const unknown = verifyDoc(read('receipt_spec_v99.json'));
  assert.strictEqual(unknown.integrity, true,
    'precondition: the v99 fixture is RE-SEALED, so only the spec gate stands in the way');
  assert.strictEqual(unknown.unsupported, true);
  assert.strictEqual(unknown.verified, false);
  assert.strictEqual(unknown.reproduced, null,
    'nothing may be re-executed under a format this implementation cannot read');
});

test('strict liveness and the approved-program pin are LIBRARY arguments here too', () => {
  const doc = read('receipt_spec_v1_control.json');
  const digest = doc.params.program_sha256;

  const plainRun = verifyDoc(doc);
  assert.strictEqual(plainRun.approved_program, null,
    'null means NO EXPECTATION WAS SUPPLIED -- a different fact from "not approved"');
  assert.strictEqual(plainRun.input_liveness, 'live');

  const r = loadReceipt(JSON.stringify(doc));
  assert.strictEqual(verify(r, digest).approved_program, true);
  assert.strictEqual(verify(r, digest).verified, true);
  const wrong = verify(r, '0'.repeat(64));
  assert.strictEqual(wrong.approved_program, false);
  assert.strictEqual(wrong.verified, false);

  // A flag that refuses everything is not a stricter check, it is a broken one.
  assert.strictEqual(verify(r, null, true).verified, true);
});

// The receipt Python's `mint.replay_receipt(compile_source("output 7;"), [])` emits:
// a program declaring ZERO inputs, whose liveness verdict is therefore 'n/a'.
const NO_INPUTS = {
  spec: 'obsign/receipt/v1',
  kernel: 'obsign/replay/1',
  params: {
    program: {
      spec: 'obsign/replay/1', mem: 2, steps: 3, consts: [7],
      input: { offset: 0, length: 0 }, output: { offset: 0, length: 1 },
      code: [['LOADC', 1, 0], ['MOV', 0, 1], ['HALT']],
    },
    program_sha256: '5d2444940b2081f7be4e82c9673f79a82652ff42ad45e9c632a4810a25e03ae8',
    inputs: [],
  },
  output: {
    sha256: 'aae89fc0f03e2959ae4d701a80cc3915918c950b159f6abb6c92c1433b1a8534',
    length: 1, dtype: 'int64',
  },
  receipt_sha256: '546bf3b9ad55ffaee6f237a6e45ca86890dabb51b7b8c0699da4bc4207c45a02',
};

test('strict liveness refuses what the default accepts', () => {
  // A FLAG WHOSE ONLY WITNESS IS SOMETHING IT ACCEPTS IS NOT TESTED. The check above
  // pins that strict mode does not refuse an honestly live receipt, which cannot fail
  // if `strictLiveness` is ignored entirely -- so this one pins the other direction on
  // a receipt whose verdict actually differs between the two modes.
  //
  // 'n/a' is weaker than 'live': a program declaring no inputs demonstrates nothing
  // about any, which is precisely what strict mode exists to require.
  const r = loadReceipt(JSON.stringify(NO_INPUTS));
  const lax = verify(r);
  assert.strictEqual(lax.input_liveness, 'n/a');
  assert.strictEqual(lax.verified, true, `the default is unchanged: ${lax.notes.join('; ')}`);

  const strict = verify(r, null, true);
  assert.strictEqual(strict.verified, false,
    'strict mode accepted a verdict weaker than live');
  assert.ok(strict.notes.some((n) => n.includes("only 'live' is accepted in strict mode")),
    strict.notes.join('; '));
});

test('the pin compares the COMPUTED digest, not the stated one', () => {
  // A forger who types the approved digest into `params.program_sha256` beside a
  // different program must not thereby own the approval. The JavaScript CLI used to
  // read the stated field, which is exactly that.
  const doc = read('receipt_spec_v1_control.json');
  const approved = doc.params.program_sha256;
  const other = JSON.parse(JSON.stringify(doc));
  other.params.program.consts = [2];          // a DIFFERENT program...
  other.params.program_sha256 = approved;     // ...wearing the approved digest
  const res = verify(loadReceipt(JSON.stringify(other)), approved);
  assert.strictEqual(res.approved_program, false,
    'the pin read the STATED digest, so writing the approved value satisfied it');
  assert.strictEqual(res.verified, false);
});
