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

// A well-formed Ed25519 public key (RFC 8032 7.1) under a signature nobody made, so
// the refusal comes from the crypto rather than from a malformed field.
const FORGED_SIGNATURE = () => ({ __obj: new Map(Object.entries({
  spec: 'obsign/signature/v2', alg: 'ed25519', signer: 'Desk A',
  public_key: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
  sig: '00'.repeat(64), binds: [], binds_sha256: null,
})) });

test('a hostile re-envelope of a claim is a supplied failure, whatever the order', () => {
  // `signature` is outside the claim, so wrapping an honest receipt in a signature
  // nobody's key made produces a DIFFERENT document with the SAME claim digest --
  // the digest the graph indexes by. Deduping on it ran the ladder on whichever copy
  // arrived first and dropped the other unexamined, so the same four documents came
  // out green or red depending on list order. Both languages must refuse both orders.
  const honest = load('desk_credit.json');
  const forged = load('desk_credit.json');
  forged.__obj.set('signature', FORGED_SIGNATURE());
  const digest = canonicalSha256(claimOf(honest));
  assert.strictEqual(canonicalSha256(claimOf(forged)), digest,
    'the re-envelope must not move the claim digest, or it proves nothing');

  const rest = () => ['desk_lending.json', 'desk_rates.json', 'firm_root.json'].map(load);
  const first = verifyGraph([forged, honest, ...rest()]);
  const last = verifyGraph([honest, ...rest(), forged]);
  for (const [label, g] of [['forged first', first], ['forged last', last]]) {
    assert.strictEqual(Object.keys(g.nodes).length, 4, `${label}: one claim, one node`);
    assert.strictEqual(g.nodes[digest].verified, false, label);
    assert.strictEqual(g.nodes[digest].envelopes, 2, label);
    assert.strictEqual(g.graph_verified, false, label);
    assert.ok(g.notes.some((n) => n.includes('DUPLICATE ENVELOPE')),
      `${label}: the second envelope must be reported, not silently dropped`);
  }
  assert.deepStrictEqual(first.nodes[digest], last.nodes[digest],
    'the node verdict, notes included, must not depend on arrival order');
});

test('a second HONEST envelope is reported but is not an accusation', () => {
  // `env` records the platform and is outside the claim, so one computation logged on
  // two machines is two envelopes of one claim and both are true.
  const twin = load('desk_credit.json');
  twin.__obj.set('env', { __obj: new Map(Object.entries({ platform: 'aarch64' })) });
  const digest = canonicalSha256(claimOf(twin));
  const g = verifyGraph([load('desk_credit.json'), twin,
    ...['desk_lending.json', 'desk_rates.json', 'firm_root.json'].map(load)]);
  assert.strictEqual(g.graph_verified, true, JSON.stringify(g.notes));
  assert.strictEqual(Object.keys(g.nodes).length, 4);
  assert.strictEqual(g.nodes[digest].envelopes, 2);
  assert.ok(g.notes.some((n) => n.includes('DUPLICATE ENVELOPE')));
});

test('hostile garbage in the receipt list never throws', () => {
  const g = verifyGraph([null, 42, 'x', chain()[0]]);
  assert.strictEqual(g.graph_verified, false);
  assert.ok(g.notes.length >= 1);
});
