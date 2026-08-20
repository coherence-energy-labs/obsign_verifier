'use strict';
/**
 * The chain rule, cross-checked: this implementation must reach the SAME graph
 * verdicts as the Python reference on the SAME receipts -- the shipped conformance
 * chain for the green path, and surgical tampering of it for every refusal class,
 * including the split verdicts (verified node, lying links) and INCOMPLETE vs forged.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { loadReceipt, canonicalSha256, claimOf } = require('../src/canonical.js');
const { verify, plain } = require('../src/verify.js');
const { verifyGraph } = require('../src/graph.js');
const replay = require('../src/replay.js');

const CHAIN = path.resolve(__dirname, '..', '..', 'src', 'obsign_verify', 'data', 'conformance', 'chain');

const load = (name) => loadReceipt(fs.readFileSync(path.join(CHAIN, name), 'utf8'));
const chain = () => ['desk_credit.json', 'desk_lending.json', 'desk_rates.json', 'firm_root.json'].map(load);

// boxed-tree surgery: fetch nested Map entries, then reseal the claim hash
const get = (boxed, ...keys) => keys.reduce((v, k) => v.__obj.get(k), boxed);
const reseal = (boxed) => { boxed.__obj.set('receipt_sha256', canonicalSha256(claimOf(boxed))); return boxed; };

test('the shipped conformance chain verifies transitively', () => {
  const g = verifyGraph(chain());
  assert.strictEqual(g.graph_verified, true, JSON.stringify(g.notes));
  assert.strictEqual(g.complete, true);
  assert.strictEqual(Object.keys(g.nodes).length, 4);
  assert.strictEqual(g.roots.length, 1);
  // children-first order: every desk finishes before the firm root
  const rootDigest = g.roots[0];
  for (const d of Object.keys(g.nodes)) {
    if (d !== rootDigest) assert.ok(g.order.indexOf(d) < g.order.indexOf(rootDigest));
  }
});

test('a linked receipt still verifies standalone (links are additive)', () => {
  const res = verify(load('firm_root.json'));
  assert.strictEqual(res.verified, true, res.notes.join('; '));
});

test('a withheld child makes the graph INCOMPLETE, never forged', () => {
  const rs = chain().filter((_, i) => i !== 2);        // withhold desk_rates
  const g = verifyGraph(rs);
  assert.strictEqual(g.graph_verified, false);
  assert.strictEqual(g.complete, false);
  assert.strictEqual(g.missing.length, 1);
  const root = g.nodes[canonicalSha256(claimOf(load('firm_root.json')))];
  assert.strictEqual(root.verified, true);
  assert.strictEqual(root.links_ok, 'incomplete');
  assert.ok(root.notes.some((n) => n.includes('incomplete, not forged')));
});

test('a root that lies about its inputs: verified standalone, links_ok false', () => {
  const rs = chain();
  const root = rs[3];
  const inputs = get(root, 'params', 'inputs');
  inputs[1] = { __n: 'i', v: inputs[1].v + 100n };      // skim $1.00 into desk B's number
  // an INTERNALLY CONSISTENT forgery, like a real one: re-run the (forged) inputs
  // and record the matching output hash, so only the LINK can catch the lie
  const rp = plain(root);
  const out = replay.run(rp.params.program, rp.params.inputs);
  get(root, 'output').__obj.set('sha256', replay.outputSha256(out));
  reseal(root);
  const g = verifyGraph(rs);
  const node = g.nodes[root.__obj.get('receipt_sha256')];
  assert.strictEqual(node.verified, true);              // internally consistent
  assert.strictEqual(node.links_ok, false);             // provenance is a lie
  assert.ok(node.notes.some((n) => n.includes('did NOT consume')));
  assert.strictEqual(g.graph_verified, false);
});

test('tampering a leaf disconnects the chain (history is immutable)', () => {
  const rs = chain();
  const book = get(rs[0], 'params', 'inputs');
  book[3] = { __n: 'i', v: book[3].v + 1n };            // cook the book, no reseal
  const g = verifyGraph(rs);
  assert.strictEqual(g.graph_verified, false);
  assert.strictEqual(g.complete, false, 'the orphaned link must be reported missing');
});

test('a wrong output_sha256 inside a link is refused', () => {
  const rs = chain();
  const root = rs[3];
  const link0 = get(root, 'params', 'links')[0];
  link0.__obj.set('output_sha256', '0'.repeat(64));
  reseal(root);
  const g = verifyGraph(rs);
  const node = g.nodes[root.__obj.get('receipt_sha256')];
  assert.strictEqual(node.links_ok, false);
  assert.ok(node.notes.some((n) => n.includes('output_sha256')));
});

test('hostile garbage in the receipt list never throws', () => {
  const g = verifyGraph([null, 42, 'x', chain()[0]]);
  assert.strictEqual(g.graph_verified, false);
  assert.ok(g.notes.length >= 1);
});
