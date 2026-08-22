'use strict';
/**
 * The JavaScript witness port, checked against PYTHON'S ACTUAL ANSWERS.
 *
 * WHY FIXTURES AND NOT ONLY THE LIVE DIFFERENTIAL. `tests/test_the_two_ports_agree_
 * about_a_witness.py` runs both implementations over one corpus and compares them field
 * for field -- which is the real check, and which needs the coherence_compute producer
 * checkout to build the documents. CI does not have it, so there that test SKIPS. A skip
 * is never a pass, and it would have left the port's most important property dark
 * everywhere except one workstation.
 *
 * So the corpus and Python's verdicts are FROZEN into fixtures/witness_corpus.json and
 * replayed here, with no producer present. The pairing matters in both directions:
 *
 *   this file            the JS port must reproduce Python's recorded answers, anywhere
 *   the live differential when the producer IS present, it regenerates and compares,
 *                        which is what catches these fixtures going stale
 *
 * Neither alone is enough. Fixtures alone freeze a bug as the expected answer; the live
 * differential alone runs on one machine.
 */

const test = require('node:test');
const assert = require('node:assert');
const { readFileSync } = require('node:fs');
const path = require('node:path');

const { loadReceipt } = require('../src/canonical.js');
const { verifyWitness, verifyChain, deriveAssurance, LADDER } = require('../src/witness.js');

const FIX = JSON.parse(
  readFileSync(path.join(__dirname, 'fixtures', 'witness_corpus.json'), 'utf8'),
);

/** Exactly the summary the JS runner produces for the live differential, so the two
 *  comparisons are of the same shape and cannot quietly diverge. */
function summarise(name, texts) {
  const docs = texts.map((t) => loadReceipt(t));
  if (docs.length === 1) {
    const v = verifyWitness(docs[0]);
    return {
      kind: 'single',
      verified: v.verified,
      integrity: v.integrity,
      reproduced: v.reproduced,
      assurance: v.assurance === undefined ? null : v.assurance,
      derived: deriveAssurance(docs[0]),
      signature_valid: v.signature === null ? null : v.signature.valid,
    };
  }
  const c = verifyChain(docs);
  const nodes = {};
  for (const [h, n] of Object.entries(c.nodes)) {
    nodes[h] = { verified: n.verified, links_ok: n.links_ok, assurance: n.assurance };
  }
  return { kind: 'chain', ok: c.ok, effective_assurance: c.effective_assurance, nodes };
}

test('the corpus exercises both outcomes', () => {
  // CALIBRATION. A fixture set of exclusively valid documents would prove the port
  // agrees about the easy half.
  const singles = Object.values(FIX.python_verdicts).filter((v) => v.kind === 'single');
  assert.ok(singles.some((v) => v.verified), 'no fixture verifies');
  assert.ok(singles.some((v) => !v.verified), 'no fixture fails');
  const chains = Object.values(FIX.python_verdicts).filter((v) => v.kind === 'chain');
  assert.ok(chains.some((c) => c.ok) && chains.some((c) => !c.ok),
    'the chain fixtures do not cover both outcomes');
});

test('every rung appears in the corpus', () => {
  const seen = new Set(
    Object.values(FIX.python_verdicts).filter((v) => v.kind === 'single').map((v) => v.derived),
  );
  for (const rung of ['custody', 'asserted', 'witnessed']) {
    assert.ok(seen.has(rung), `the corpus never produces a ${rung} document`);
  }
});

test('the hashed-binary decision is isolated by a one-field pair', () => {
  // The gap a mutation test found: without this pair, a port that dropped the
  // hashed-binary requirement agreed with Python on every other document.
  assert.equal(FIX.python_verdicts.argv_with_unhashable_binary.derived, 'asserted');
  assert.equal(FIX.python_verdicts.argv_with_hashed_binary.derived, 'witnessed');
});

test('the JS port reproduces Python verdicts on every fixture', () => {
  const mismatches = [];
  for (const [name, texts] of FIX.cases) {
    const expected = FIX.python_verdicts[name];
    const got = summarise(name, texts);
    if (JSON.stringify(got) !== JSON.stringify(expected)) {
      mismatches.push(`\n  ${name}:\n    python: ${JSON.stringify(expected)}\n    js    : ${JSON.stringify(got)}`);
    }
  }
  assert.equal(mismatches.length, 0,
    'the JavaScript port disagrees with Python. Two verdicts from one vendor on the '
    + 'same bytes is the split a forger farms.' + mismatches.join(''));
});

test('a witness carries no float, so both ports canonicalise it identically', () => {
  // The int/float distinction is the documented cross-implementation trap: Python
  // writes 1.0 where JSON.parse reads 1. A witness avoids the class entirely, and this
  // is where that guarantee is checked on the wire format rather than in the producer.
  const floats = [];
  const walk = (v, p) => {
    if (v === null || typeof v !== 'object') return;
    if (v.__n === 'f') { floats.push(p); return; }
    if (v.__obj instanceof Map) { for (const [k, x] of v.__obj) walk(x, `${p}.${k}`); return; }
    if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${p}[${i}]`));
  };
  for (const [name, texts] of FIX.cases) {
    texts.forEach((t, i) => walk(loadReceipt(t), `${name}[${i}]`));
  }
  assert.equal(floats.length, 0, `float(s) in a witness document: ${floats.join(', ')}`);
});

test('the ladder order is the semantics', () => {
  assert.deepEqual(LADDER, ['custody', 'asserted', 'witnessed', 'environment-pinned']);
});
