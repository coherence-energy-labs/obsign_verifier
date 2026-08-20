// Run receipt graphs through the JavaScript verifyGraph, for the cross-language
// differential in test_graph_fuzz.py. Input: a JSON file of [name, [receiptText,..]]
// cases -- receipts cross as TEXT and are parsed by canonical.js, so integers arrive
// as BigInt and nothing rounds through a double. Output: per-case verdict summaries
// the Python side compares field-for-field against its own.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { loadReceipt } = require('../js/src/canonical.js');
const { verifyGraph } = require('../js/src/graph.js');

const cases = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const out = {};
for (const [name, texts] of cases) {
  const receipts = texts.map((t) => loadReceipt(t));
  const g = verifyGraph(receipts);
  const nodes = {};
  for (const [d, n] of Object.entries(g.nodes)) {
    nodes[d] = { verified: n.verified, links_ok: n.links_ok === null ? null : n.links_ok,
                 envelopes: n.envelopes };
  }
  out[name] = {
    graph_verified: g.graph_verified,
    complete: g.complete,
    missing: g.missing,
    roots: g.roots.slice().sort(),
    nodes,
  };
}
console.log(JSON.stringify(out));
