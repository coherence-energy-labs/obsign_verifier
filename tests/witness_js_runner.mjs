// Run witness documents and chains through the JavaScript port, for the
// cross-implementation differential in test_the_two_ports_agree_about_a_witness.py.
//
// Documents cross as TEXT and are parsed by canonical.js, so the int/float distinction
// survives and nothing rounds through a double. A witness carries no floats by
// construction -- that is the point -- and passing text is how this harness would
// NOTICE if one ever crept back in, rather than silently agreeing because both sides
// were handed the same already-parsed object.
//
// Input : a JSON file of [name, [docText, ...]] cases
// Output: per-case verdict summaries the Python side compares field for field
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { loadReceipt } = require('../js/src/canonical.js');
const { verifyWitness, verifyChain, deriveAssurance } = require('../js/src/witness.js');

const cases = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const out = {};

for (const [name, texts] of cases) {
  const docs = texts.map((t) => loadReceipt(t));
  if (docs.length === 1) {
    const v = verifyWitness(docs[0]);
    out[name] = {
      kind: 'single',
      verified: v.verified,
      integrity: v.integrity,
      reproduced: v.reproduced,
      assurance: v.assurance === undefined ? null : v.assurance,
      derived: deriveAssurance(docs[0]),
      signature_valid: v.signature === null ? null : v.signature.valid,
    };
  } else {
    const c = verifyChain(docs);
    const nodes = {};
    for (const [h, n] of Object.entries(c.nodes)) {
      nodes[h] = { verified: n.verified, links_ok: n.links_ok, assurance: n.assurance };
    }
    out[name] = {
      kind: 'chain',
      ok: c.ok,
      effective_assurance: c.effective_assurance,
      nodes,
    };
  }
}

process.stdout.write(JSON.stringify(out, null, 2));
