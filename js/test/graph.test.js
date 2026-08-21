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

// ---------------------------------------------------------------------------
// THE SLICE THAT TRAVELS, AND THE THIRD VALUE ITS VERDICT HAS
//
// `verify` refuses a node whose whole output ignores every declared input. An output
// window is a VECTOR, so that is passed by one decoy cell and then linking only the
// constant one. The rule that closes it -- "the slice a link carries must be the part
// that depends on the inputs" -- read `every(st === 'dead')`, and a cell the probe ran
// out of budget on is 'indeterminate', not 'dead'. So the rule was switchable off by
// the party it constrains: the same child program with ONE constant changed (a spin
// loop long enough to cut the cell sweep short) moved its laundered cell from 'dead'
// to 'indeterminate', and a chain carrying a literal went from refused to
// graph_verified. Cost decided it, not evidence.
//
// Both directions here, because a rule that only ever refuses is not a rule.

const os = require('node:os');
const { execFileSync } = require('node:child_process');

const SPIN = 20000;          // measured to cut the cell sweep short
const N_IN = 8, IN_BASE = 16;

function launderProgram(spin, constantCell) {
  // cell 1 is the accumulator (always live); cell 0 is a literal, or a copy of it.
  const tail = constantCell ? [['LOADC', 0, 0]] : [['MOV', 0, 1]];
  return {
    spec: 'obsign/replay/1', mem: 64, steps: 8000000,
    consts: [424242, 0, 1, spin, IN_BASE, N_IN],
    input: { offset: IN_BASE, length: N_IN },
    output: { offset: 0, length: 2 },
    code: [
      ['LOADC', 1, 1], ['LOADC', 2, 4], ['LOADC', 3, 1], ['LOADC', 4, 2],
      ['LOADC', 5, 5], ['LOAD', 6, 2], ['ADD', 1, 1, 6], ['ADD', 2, 2, 4],
      ['ADD', 3, 3, 4], ['LT', 7, 3, 5], ['JMPNZ', 7, 5], ['LOADC', 8, 3],
      ['JMPZ', 8, 15], ['SUB', 8, 8, 4], ['JMP', 12], ...tail, ['HALT'],
    ],
  };
}

/** Boxed form of a JSON-shaped object, which is what the library reads. */
const box = (obj) => loadReceipt(JSON.stringify(obj));

/** Stamp a plain receipt object with its own claim hash, in place. */
function seal(obj) {
  obj.receipt_sha256 = canonicalSha256(claimOf(box(obj)));
  return obj;
}

/**
 * A two-node chain, as PLAIN JSON-shaped objects: the library takes them through
 * `box`, and the CLI test writes the same bytes to disk. One source of truth, so the
 * in-process verdict and the subprocess verdict cannot be about different receipts.
 */
function launderChain(spin, constantCell) {
  const program = launderProgram(spin, constantCell);
  const inputs = Array.from({ length: N_IN }, (_, i) => 3 + i);
  const out = replay.run(plain(box(program)), inputs.map((v) => BigInt(v)));
  const child = seal({
    spec: 'obsign/receipt/v1', kernel: 'obsign/replay/1',
    params: { program, inputs, program_sha256: canonicalSha256(box(program)) },
    output: { sha256: replay.outputSha256(out), length: out.length },
  });

  const pprog = {
    spec: 'obsign/replay/1', mem: 32, steps: 100, consts: [IN_BASE],
    input: { offset: IN_BASE, length: 1 }, output: { offset: 0, length: 1 },
    code: [['LOADC', 1, 0], ['LOAD', 0, 1], ['ADD', 0, 0, 0], ['HALT']],
  };
  const pin = [Number(out[0])];
  const pout = replay.run(plain(box(pprog)), pin.map((v) => BigInt(v)));
  const parent = seal({
    spec: 'obsign/receipt/v1', kernel: 'obsign/replay/1',
    params: {
      program: pprog, inputs: pin, program_sha256: canonicalSha256(box(pprog)),
      links: [{
        receipt_sha256: child.receipt_sha256, dst_offset: 0, length: 1, src_offset: 0,
        output_sha256: replay.outputSha256(out),
      }],
    },
    output: { sha256: replay.outputSha256(pout), length: pout.length },
  });
  return [child, parent];
}

const boxedChain = (spin, constantCell) => launderChain(spin, constantCell).map(box);

test('the probe budget is what separates dead from indeterminate', () => {
  const [cheap] = boxedChain(0, true);
  const [costly] = boxedChain(SPIN, true);
  assert.deepStrictEqual(verify(cheap).output_liveness_by_cell, ['dead', 'live']);
  assert.deepStrictEqual(verify(costly).output_liveness_by_cell,
    ['indeterminate', 'live'],
    `spin=${SPIN} no longer exhausts the cell sweep -- raise it, or every test below `
    + 'is testing something other than what its name says');
  // ...and both receipts still verify STANDALONE. The chain is the only rung that can
  // tell them apart, which is why a CLI without --chain was silent rather than wrong.
  assert.strictEqual(verify(cheap).verified, true);
  assert.strictEqual(verify(costly).verified, true);
});

test('a link carrying a provably constant slice is FORGED', () => {
  const g = verifyGraph(boxedChain(0, true));
  assert.strictEqual(g.graph_verified, false);
  assert.ok(Object.values(g.nodes).some((n) => n.links_ok === false),
    JSON.stringify(g.nodes));
});

test('a link carrying an UNDECIDED slice is INCOMPLETE, not accepted', () => {
  const g = verifyGraph(boxedChain(SPIN, true));
  assert.strictEqual(g.graph_verified, false,
    'an expensive child laundered a constant through a verified chain');
  assert.ok(Object.values(g.nodes).some((n) => n.links_ok === 'incomplete'),
    JSON.stringify(g.nodes));
});

test('an expensive HONEST chain is still accepted, in both modes', () => {
  assert.strictEqual(verifyGraph(boxedChain(SPIN, false)).graph_verified, true);
  assert.strictEqual(verifyGraph(boxedChain(SPIN, false), true).graph_verified, true);
});

test('strictLiveness reaches the chain and is not merely refuse-everything', () => {
  assert.strictEqual(verifyGraph(boxedChain(SPIN, true), true).graph_verified, false);
  assert.strictEqual(verifyGraph(boxedChain(0, false), true).graph_verified, true);
});

test('the CLI has a --chain subcommand and reaches the same verdicts', () => {
  // `verifyGraph` shipped in this package all along; only the binary could not reach
  // it. Verifying the same files one at a time exits 0 and prints VERIFIED for each,
  // because a link naming a receipt the standalone ladder was never handed is not
  // examined -- so the absent subcommand agreed with the forgery rather than refusing
  // to answer. That is what the precondition assert below pins.
  const cli = path.join(__dirname, '..', 'bin', 'obsign-verify.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'obsign-chain-'));
  const runCli = (argv) => {
    try {
      execFileSync(process.execPath, [cli, ...argv], { encoding: 'utf8' });
      return 0;
    } catch (e) {
      return e.status;
    }
  };
  for (const [tag, spin, constantCell, want] of [
    ['forged', 0, true, 1],
    ['unproven', SPIN, true, 1],
    ['honest', SPIN, false, 0],
  ]) {
    const files = launderChain(spin, constantCell).map((r, i) => {
      const p = path.join(dir, `${tag}_${i}.json`);
      fs.writeFileSync(p, JSON.stringify(r));
      return p;
    });
    assert.strictEqual(runCli(['--chain', ...files]), want,
      `--chain gave the wrong verdict for ${tag}`);
    if (want === 1) {
      assert.strictEqual(runCli(files), 0,
        `precondition: ${tag} must verify node-by-node, or the chain rung is not what `
        + 'is being tested here');
    }
  }
});
