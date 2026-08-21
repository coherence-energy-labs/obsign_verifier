'use strict';
/**
 * Receipt graphs in JavaScript -- the second implementation of docs/GRAPHS.md.
 *
 * The Python module is the reference; this port exists so the chain rule, like every
 * other rule in this package, is enforced by two independently written programs that
 * must agree receipt-for-receipt -- including on the SPLIT verdicts (a node can be
 * internally `verified` while its `links_ok` is false because it lied about where its
 * inputs came from) and on INCOMPLETE vs forged (a missing child is "I could not
 * check this", never "this is false").
 *
 * Values are BigInt end to end: the parent's declared inputs and the child's
 * re-derived outputs are compared as exact int64s, never through doubles.
 *
 * A NODE IS A CLAIM; A RECEIPT IS AN ENVELOPE AROUND ONE. `signature`, `case`, `env`
 * and `receipt_sha256` are all outside the claim, so two documents can index to the
 * same node -- one genuine, one re-enveloped by whoever handed you the set. Every
 * supplied envelope runs the ladder and the node's verdict is their conjunction, so a
 * hostile copy is a supplied failure rather than an accident of list order.
 */

const { canonicalSha256, canonicalString, claimOf } = require('./canonical.js');
const replay = require('./replay.js');
const { verify, plain } = require('./verify.js');

const LINK_FIELDS = ['receipt_sha256', 'output_sha256', 'src_offset', 'length', 'dst_offset'];

function linksOf(receiptPlain) {
  const params = receiptPlain && receiptPlain.params;
  const links = params && params.links;
  return Array.isArray(links) ? links : [];
}

function wellFormedLink(ln) {
  if (ln === null || typeof ln !== 'object' || Array.isArray(ln)) return 'link is not an object';
  for (const f of LINK_FIELDS) {
    if (!(f in ln)) return `link is missing '${f}'`;
  }
  for (const f of ['receipt_sha256', 'output_sha256']) {
    if (typeof ln[f] !== 'string' || ln[f].length !== 64) return `link.${f} must be a 64-hex digest`;
  }
  for (const f of ['src_offset', 'length', 'dst_offset']) {
    const v = ln[f];
    if (typeof v !== 'bigint' || v < 0n) return `link.${f} must be a non-negative integer`;
  }
  if (ln.length === 0n) return 'link.length must be > 0';
  return null;
}

const num = (b) => Number(b);   // link offsets are bounded by MAX_MEM, lossless

/** What tells two receipts carrying the SAME claim apart. `signature`, `case`, `env`,
 * `receipt_sha256` and `_`-prefixed helpers are outside the claim, so re-enveloping a
 * receipt leaves the claim digest this graph indexes by exactly where it was;
 * canonicalising the whole document is what distinguishes the copies. One that will
 * not canonicalise gets a key unique to its position rather than merging into another
 * receipt's verdict. Canonical JSON is pure ASCII, so sorting these strings by UTF-16
 * unit is the same order Python gets sorting the bytes. */
const envelopeKey = (receipt, index) => {
  try {
    return canonicalString(receipt);
  } catch (e) {
    return `<uncanonicalisable envelope #${index}>`;
  }
};

/** A supplied item that never became a receipt. Still ONE document, so it carries one
 * envelope under a key unique to it -- it must never merge with anything. */
const placeholder = (key, note) => ({
  receipt: null, verified: false, linksOk: null, notes: [note],
  envelopes: new Map([[key, null]]),
});

/** Verify RECEIPTS (boxed, as loadReceipt returns them) individually and
 * transitively. Never throws on hostile input. */
/**
 * Verify RECEIPTS individually and transitively.
 *
 * `strictLiveness` is the same switch `verify` takes, and it reaches BOTH rungs of the
 * chain: each node's standalone ladder, and the rule below that asks whether the slice
 * a link carries was ever shown to move.
 */
function verifyGraph(receipts, strictLiveness = false) {
  const graphNotes = [];
  const nodes = new Map();       // digest -> {receipt, receiptPlain, envelopes, verified, ...}
  const canon = new Map();       // digest -> canonical claim string (collision check)

  receipts.forEach((r, i) => {
    if (r === null || typeof r !== 'object' || !(r.__obj instanceof Map)) {
      graphNotes.push(`receipts[${i}] is not a receipt object; the graph cannot be green`);
      nodes.set(`<non-object #${i}>`, placeholder(`<non-object #${i}>`, 'not a receipt object'));
      return;
    }
    let digest, cstr;
    try {
      digest = canonicalSha256(claimOf(r));
      cstr = canonicalString(claimOf(r));
    } catch (e) {
      nodes.set(`<uncanonicalisable #${i}>`,
                placeholder(`<uncanonicalisable #${i}>`,
                            `claim is not canonicalisable (${e.message})`));
      return;
    }
    if (nodes.has(digest)) {
      const node = nodes.get(digest);
      if (canon.get(digest) !== cstr) {
        graphNotes.push(`COLLISION: two different claims share digest ${digest.slice(0, 16)}.. -- refusing the whole graph`);
        node.notes.push('digest collision');
        node.linksOk = false;
        return;
      }
      // Same claim, a DIFFERENT document. Dropping it here ran the standalone ladder
      // on whichever copy arrived first and never examined the other, so a forged
      // re-envelope supplied second was invisible and the same set of receipts came
      // out green or red depending on list order.
      const key = envelopeKey(r, i);
      if (!node.envelopes.has(key)) node.envelopes.set(key, r);
      return;
    }
    nodes.set(digest, { receipt: r, receiptPlain: plain(r), verified: null, linksOk: null,
                        notes: [], envelopes: new Map([[envelopeKey(r, i), r]]) });
    canon.set(digest, cstr);
  });

  for (const [digest, node] of nodes) {
    if (node.envelopes.size > 1) {
      graphNotes.push(`DUPLICATE ENVELOPE: claim ${digest.slice(0, 16)}.. was supplied as `
        + `${node.envelopes.size} documents differing outside the claim `
        + '(signature/case/env/receipt_sha256); each is verified and this node\'s '
        + 'verdict is their conjunction');
    }
  }

  for (const node of nodes.values()) {
    if (node.receipt === null) continue;
    // EVERY envelope, in canonical order rather than arrival order, so the notes read
    // identically however the list was shuffled. docs/GRAPHS.md rule 1 is "every node
    // verifies standalone", and a receipt deduped away never ran the ladder at all --
    // so the verdict is the conjunction over the documents actually supplied, and one
    // hostile copy cannot hide behind an honest one.
    node.verified = true;
    let first = true;
    for (const key of [...node.envelopes.keys()].sort()) {
      const res = verify(node.envelopes.get(key), null, strictLiveness);
      if (first) { node.standalone = res; first = false; }
      if (res.verified !== true) {
        node.verified = false;
        node.notes.push('does not verify standalone: ' + (res.notes || []).slice(0, 2).join('; '));
      }
    }
  }

  const outCache = new Map();
  const outputsOf = (digest) => {
    if (!outCache.has(digest)) {
      const p = nodes.get(digest).receiptPlain;
      try {
        outCache.set(digest, replay.run(p.params.program, p.params.inputs));
      } catch (e) {
        outCache.set(digest, null);
      }
    }
    return outCache.get(digest);
  };

  const missing = new Set();

  for (const [digest, node] of nodes) {
    const rp = node.receiptPlain;
    if (!rp) continue;
    const links = linksOf(rp);
    if (!links.length) continue;
    node.linksOk = true;
    if (rp.kernel !== replay.SPEC) {
      node.linksOk = false;
      node.notes.push('links on a non-replay parent are not supported in graphs v1 (docs/GRAPHS.md)');
      continue;
    }
    const parentInputs = rp.params && rp.params.inputs;
    const taken = new Set();
    for (const ln of links) {
      const why = wellFormedLink(ln);
      if (why) { node.linksOk = false; node.notes.push(why); continue; }
      const childDigest = ln.receipt_sha256;
      if (!nodes.has(childDigest)) {
        missing.add(childDigest);
        if (node.linksOk === true) node.linksOk = 'incomplete';
        node.notes.push(`link target ${childDigest.slice(0, 16)}.. was not supplied -- the graph is incomplete, not forged`);
        continue;
      }
      const child = nodes.get(childDigest);
      if (child.receiptPlain && child.receiptPlain.kernel !== replay.SPEC) {
        node.linksOk = false;
        node.notes.push(`link target ${childDigest.slice(0, 16)}.. is not an obsign/replay/1 receipt (unsupported in v1)`);
        continue;
      }
      const d = num(ln.dst_offset), L = num(ln.length), s = num(ln.src_offset);
      if (!Array.isArray(parentInputs) || d + L > parentInputs.length) {
        node.linksOk = false;
        node.notes.push(`link destination ${d}..${d + L} is outside this receipt's inputs`);
        continue;
      }
      let overlapped = false;
      for (let k = d; k < d + L; k++) {
        if (taken.has(k)) { overlapped = true; break; }
        taken.add(k);
      }
      if (overlapped) {
        node.linksOk = false;
        node.notes.push('link destinations overlap');
        continue;
      }
      const childOut = outputsOf(childDigest);
      if (childOut === null) {
        node.linksOk = false;
        node.notes.push(`link target ${childDigest.slice(0, 16)}.. cannot be re-executed, so the link cannot bind`);
        continue;
      }
      if (s + L > childOut.length) {
        node.linksOk = false;
        node.notes.push(`link source ${s}..${s + L} is outside the child's output (length ${childOut.length})`);
        continue;
      }
      if (replay.outputSha256(childOut) !== ln.output_sha256) {
        node.linksOk = false;
        node.notes.push("link.output_sha256 does not match the child's re-derived output");
        continue;
      }
      let equal = true;
      for (let k = 0; k < L; k++) {
        if (parentInputs[d + k] !== childOut[s + k]) { equal = false; break; }
      }
      if (!equal) {
        node.linksOk = false;
        node.notes.push(`inputs[${d}..${d + L}) do not equal the child's re-derived output[${s}..${s + L}) -- this receipt did NOT consume what ${childDigest.slice(0, 16)}.. produced`);
        continue;
      }
      // THE SLICE THAT TRAVELS MUST BE THE PART THAT DEPENDS ON THE INPUTS. verify()
      // refuses a node whose whole output ignores every declared input; an output
      // window is a VECTOR, so `output 424242, a + b;` passes that and then links only
      // cell 0, carrying a hardcoded constant down a chain that prints CHAIN VERIFIED.
      //
      // THE SLICE VERDICT IS THREE-VALUED, BECAUSE THE CELL VERDICT IS.
      //
      // This read `every(st === 'dead')`, and a cell the probe ran out of budget on is
      // 'indeterminate', not 'dead' -- so the rule was switchable off by the party it
      // constrains. The same child program with ONE constant changed (a spin loop long
      // enough to cut the cell sweep short) moved its laundered cell from 'dead' to
      // 'indeterminate', and a chain carrying a literal went from REFUSED to
      // graph_verified. Cost decided it, not evidence.
      //
      //   any cell live -> the link binds something that demonstrably moved
      //   else any indeterminate (or the slice is not covered) -> INCOMPLETE
      //   else all dead -> FORGED
      //
      // 'incomplete' is what this graph already says for "a child was not supplied":
      // out of green without calling the producer a forger, which is right for an
      // honest receipt too expensive to sweep. Under strict liveness there is no such
      // benefit of the doubt.
      const cells = (nodes.get(childDigest).standalone || {}).output_liveness_by_cell || [];
      const sliceStates = cells.slice(s, s + L);
      const covered = sliceStates.length === L;
      if (covered && sliceStates.length && sliceStates.every((st) => st === 'dead')) {
        node.linksOk = false;
        node.notes.push(`link source output[${s}..${s + L}) of ${childDigest.slice(0, 16)}.. never moved under ANY perturbation of that receipt's inputs: the values this link carries are constants, so the chain proves nothing about them however well every node re-derives`);
      } else if (!covered || !sliceStates.some((st) => st === 'live')) {
        const why = covered
          ? 'the probe hit its budget before deciding these cells'
          : "the probe's cell verdict does not cover this slice";
        if (strictLiveness) {
          node.linksOk = false;
          node.notes.push(`--strict-liveness: link source output[${s}..${s + L}) of ${childDigest.slice(0, 16)}.. was never shown to move under ANY perturbation (${why}) - REFUSED without a positive demonstration that the values this link carries are derived`);
        } else {
          if (node.linksOk === true) node.linksOk = 'incomplete';
          node.notes.push(`link source output[${s}..${s + L}) of ${childDigest.slice(0, 16)}.. was not shown to depend on that receipt's inputs (${why}), so the chain does not establish that these values were computed rather than hardcoded -- incomplete, not forged`);
        }
      }
    }
  }

  // cycles are unconstructible for integrity-valid receipts (a link cannot name its
  // own future hash); this guard is defense in depth, mirroring the reference
  const WHITE = 0, GREY = 1, BLACK = 2;
  const color = new Map([...nodes.keys()].map((d) => [d, WHITE]));
  const order = [];
  // ITERATIVE, because the depth used to be the length of the chain the SUPPLIER
  // chose: ~20,000 linked receipts of 200 bytes each threw `RangeError: Maximum call
  // stack size exceeded` out of a function whose whole contract is that a hostile
  // graph is REFUSED, not fatal. Visit order, finish order and the cycle rule are
  // unchanged; only the stack moved from the engine's to ours.
  const dfs = (start) => {
    color.set(start, GREY);
    const stack = [[start, 0]];
    while (stack.length) {
      const frame = stack.pop();
      const digest = frame[0];
      const i = frame[1];
      const rp = nodes.get(digest).receiptPlain;
      const links = rp ? linksOf(rp) : [];
      if (i >= links.length) {
        color.set(digest, BLACK);
        order.push(digest);
        continue;
      }
      stack.push([digest, i + 1]);
      const ln = links[i];
      const child = ln && typeof ln.receipt_sha256 === 'string' ? ln.receipt_sha256 : null;
      if (child !== null && nodes.has(child)) {
        if (color.get(child) === GREY) {
          graphNotes.push(`CYCLE through ${String(child).slice(0, 16)}.. -- refused`);
          nodes.get(digest).linksOk = false;
          nodes.get(child).linksOk = false;
        } else if (color.get(child) === WHITE) {
          color.set(child, GREY);
          stack.push([child, 0]);
        }
      }
    }
  };
  for (const d of nodes.keys()) {
    if (color.get(d) === WHITE) dfs(d);
  }

  const referenced = new Set();
  for (const node of nodes.values()) {
    for (const ln of node.receiptPlain ? linksOf(node.receiptPlain) : []) {
      if (ln && typeof ln.receipt_sha256 === 'string') referenced.add(ln.receipt_sha256);
    }
  }
  const roots = [...nodes.keys()].filter((d) => !referenced.has(d));

  const complete = missing.size === 0;
  const allNodesOk = [...nodes.values()].every((n) => n.verified === true);
  const allLinksOk = [...nodes.values()].every((n) => n.linksOk === null || n.linksOk === true);
  const noFaults = !graphNotes.some((g) => g.includes('COLLISION') || g.includes('CYCLE'));
  const graphVerified = nodes.size > 0 && complete && allNodesOk && allLinksOk && noFaults;

  const nodeOut = {};
  for (const [d, n] of nodes) {
    nodeOut[d] = { verified: n.verified, links_ok: n.linksOk,
                   envelopes: n.envelopes.size, notes: n.notes };
  }
  return {
    graph_verified: graphVerified,
    complete,
    missing: [...missing].sort(),
    roots,
    order,
    nodes: nodeOut,
    notes: graphNotes,
  };
}

module.exports = { verifyGraph };
