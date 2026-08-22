'use strict';
/**
 * obsign/witness/v1 -- verify provenance for work Obsign did NOT perform.
 *
 * WHY A SECOND PORT AT ALL. A witness is the rung a stranger is most likely to be
 * handed: an evidence clerk's intake record, or an ffmpeg step from a lab. The person
 * who most needs to check it is the one it is being used against, and telling them to
 * install Python first is how a verification story dies. A witness needs no
 * re-execution -- it is a canonical hash, a signature, and a set of file digests --
 * which is exactly why it can live here at all, where receipt replay is heavy.
 *
 * THE RUNG LOGIC IS DUPLICATED, AND THAT IS THE RISK. Two implementations of the same
 * ladder can drift, and a drift here is not cosmetic: it is one port calling a document
 * `witnessed` while the other calls it `asserted`, which is two verdicts from one
 * vendor on the same bytes -- the split a forger farms. `deriveAssurance` below mirrors
 * `obsign/witness.py::derive_assurance` decision for decision, and the conformance test
 * runs BOTH over the same documents and requires identical answers.
 *
 * NO FLOATS. A witness carries none by construction (durations are integer
 * milliseconds), which is what lets this port canonicalise identically without the
 * int/float text parsing that receipts require. `loadReceipt` still preserves the
 * distinction; the guarantee is that a witness never exercises it.
 */

const { integrity, claimOf, canonicalSha256 } = require('./canonical.js');
const sigmod = require('./signature.js');
const { plain } = require('./verify.js');

// HOW A PARSED DOCUMENT IS SHAPED HERE. `loadReceipt` does not return plain JS: objects
// arrive as `{__obj: Map}` and numbers as `{__n, v}` so that key order, duplicate keys
// and the int/float distinction all survive parsing -- the properties canonicalisation
// depends on. Integrity and the signature are therefore checked against the WRAPPED
// document, and only the field reads below go through `plain()`.
//
// Reading fields straight off the wrapped object is a silent failure, not a loud one:
// every lookup returns undefined, so every document derives `custody` and fails
// integrity. The cross-implementation differential caught exactly that on the first
// run, which is the argument for the differential.

const SPEC = 'obsign/witness/v1';

// Weakest first. Order IS the semantics: comparisons are by index.
const CUSTODY = 'custody';
const ASSERTED = 'asserted';
const WITNESSED = 'witnessed';
const ENVIRONMENT_PINNED = 'environment-pinned';
const LADDER = [CUSTODY, ASSERTED, WITNESSED, ENVIRONMENT_PINNED];

/** What each rung means, in the words a reader gets. Kept identical to the Python
 *  MEANING table so a verdict does not change tone with the port that produced it. */
const MEANING = {
  [ENVIRONMENT_PINNED]:
    'the tool, its argv and a pinned image are recorded: a verifier can re-run this in '
    + 'that image. NOT re-executed here.',
  [WITNESSED]:
    'input, output, tool and actor are bound. NOT re-executed, and NOT reproducible '
    + 'from this record: it does not prove the tool did what it says.',
  [ASSERTED]:
    'input, output and actor are bound, but the operation is SELF-DECLARED: no argv '
    + 'and no hashed binary identify what actually ran. NOT re-executed.',
  [CUSTODY]:
    'these bytes existed at this time under this identity, and are unchanged since. '
    + 'No transformation is claimed.',
};

/** Position on the ladder. An unknown or missing rung sorts BELOW the weakest, so it
 *  can never compare as stronger than a real one. */
function rung(level) {
  const i = LADDER.indexOf(level);
  return i === -1 ? -1 : i;
}

function isObj(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
function arr(v) { return Array.isArray(v) ? v : []; }

/** A plain-JS view of a possibly-wrapped document. Idempotent, so callers may pass
 *  either a `loadReceipt` result or an ordinary object parsed with JSON.parse. */
function view(doc) {
  if (doc !== null && typeof doc === 'object' && doc.__obj instanceof Map) return plain(doc);
  return doc;
}

/**
 * The rung a document can actually support, from what it carries.
 * NEVER consults doc.assurance -- a producer's claim about its own strength is the one
 * thing that must not be load-bearing.
 */
function deriveAssurance(rawDoc) {
  const doc = view(rawDoc) || {};
  const tool = isObj(doc.tool) ? doc.tool : {};
  const argv = arr(tool.argv);
  const inputs = arr(doc.inputs);
  const outputs = arr(doc.outputs);

  if (outputs.length === 0 || inputs.length === 0) return CUSTODY;

  // An argv with a hashed binary points at a specific executable. A library name and a
  // version string are whatever the caller typed.
  const binary = isObj(tool.binary) ? tool.binary : {};
  if (argv.length === 0 || !binary.sha256) return ASSERTED;

  const env = isObj(doc.environment) ? doc.environment : {};
  const pinned = env.kind === 'container' && !!env.digest;
  return pinned ? ENVIRONMENT_PINNED : WITNESSED;
}

function digestsOf(doc, key) {
  const out = new Set();
  for (const a of arr(doc[key])) {
    if (isObj(a) && typeof a.sha256 === 'string' && a.sha256) out.add(a.sha256);
  }
  return out;
}

/**
 * Verify one witness for what it CAN be checked for, and be explicit about the rest.
 *
 * `reproduced` is always null -- never false. Nothing was re-executed, and false would
 * accuse the document of failing a test that was never run.
 *
 * @param {object} doc  parsed with loadReceipt (or JSON.parse -- a witness has no floats)
 * @param {object} [opts.digests]  {refOrPath: sha256hex} already computed by the caller
 */
function verifyWitness(rawDoc, opts) {
  const o = opts || {};
  const doc = view(rawDoc) || {};
  const out = {
    integrity: false, reproduced: null, signature: null, verified: false,
    assurance: null, meaning: null, bytes_checked: null, notes: [],
  };
  try {
    if (!isObj(doc) || doc.spec !== SPEC) {
      out.notes.push(`not a ${SPEC} document (spec=${JSON.stringify(isObj(doc) ? doc.spec : null)}); nothing was checked`);
      return out;
    }

    const claimed = doc.assurance;
    const actual = deriveAssurance(doc);
    out.assurance = claimed === undefined ? null : claimed;
    out.meaning = MEANING[claimed] || null;
    if (rung(claimed) > rung(actual)) {
      out.notes.push(`OVERCLAIM: document says ${JSON.stringify(claimed)} but carries only ${JSON.stringify(actual)}`);
      return out;
    }

    const [ok, detail] = integrity(rawDoc);
    out.integrity = !!ok;
    if (!ok) { out.notes.push(detail || 'receipt_sha256 does not match the claim it covers'); return out; }

    if (doc.signature !== undefined && doc.signature !== null) {
      const s = sigmod.check(rawDoc);
      out.signature = s;
      // The verifier package's rule, word for word: (not present) or valid.
      if (!s.valid) { out.notes.push('signature present and does not verify'); return out; }
    }

    const digests = o.digests;
    if (digests && Object.keys(digests).length) {
      let checked = 0; const bad = [];
      for (const a of arr(doc.inputs).concat(arr(doc.outputs))) {
        if (!isObj(a)) continue;
        const got = digests[a.ref] !== undefined ? digests[a.ref] : digests[a.path];
        if (got === undefined) continue;
        checked += 1;
        if (got !== a.sha256) bad.push(a.ref);
      }
      out.bytes_checked = checked;
      if (bad.length) { out.notes.push(`bytes do not match the witness for: ${JSON.stringify(bad)}`); return out; }
      if (checked === 0) out.notes.push('no supplied file matched a recorded artifact');
    } else {
      out.notes.push('no files supplied: the recorded hashes were not re-checked');
    }

    out.verified = true;
    out.notes.push(`NOT RE-EXECUTED -- ${MEANING[claimed] || ''}`);
    return out;
  } catch (e) {
    out.notes.push(`verification error (treated as not verified): ${e && e.message ? e.message : e}`);
    out.verified = false;
    return out;
  }
}

/**
 * Verify linked documents as ONE chain.
 *
 * A `prior` reference alone proves nothing -- any two unrelated documents can be
 * stapled together and read as descent. The handoff must bind on BYTES: some input
 * digest of the child must appear among the parent's artifact digests. That is the
 * laundering move this exists to stop.
 *
 * `effective_assurance` is the MINIMUM rung over the chain. Reporting the best, or the
 * last, would let one strong step vouch for everything behind it.
 */
function verifyChain(docs, opts) {
  const out = { ok: false, complete: false, missing: [], effective_assurance: null, nodes: {}, notes: [] };
  try {
    const byHash = new Map();      // hash -> {raw, v} : raw for integrity, v for fields
    for (const raw of arr(docs)) {
      const d = view(raw) || {};
      const h = isObj(d) ? d.receipt_sha256 : null;
      if (typeof h !== 'string' || !h) { out.notes.push('a document carries no receipt_sha256; ignored'); continue; }
      if (byHash.has(h)) { out.notes.push(`duplicate document ${h.slice(0, 16)}..; the later one is ignored`); continue; }
      byHash.set(h, { raw, v: d });
    }
    if (byHash.size === 0) { out.notes.push('no usable documents'); return out; }

    let weakest = null;
    const missing = new Set();
    for (const [h, entry] of byHash) {
      const d = entry.v;
      const v = d.spec === SPEC
        ? verifyWitness(entry.raw, opts)
        // A non-witness document is NOT judged here. A witness verifier rendering a
        // verdict on a receipt is the cross-contamination the separate document types
        // exist to prevent.
        : { verified: false, assurance: null };
      out.nodes[h] = {
        spec: isObj(d) ? d.spec : null, verified: v.verified,
        assurance: v.assurance, links_ok: null, notes: [],
      };
      const r = rung(v.assurance);
      weakest = weakest === null ? r : Math.min(weakest, r);
    }

    for (const [h, entry] of byHash) {
      const d = entry.v;
      const node = out.nodes[h];
      const priors = arr(d.prior);
      if (priors.length === 0) continue;
      node.links_ok = true;
      const childInputs = digestsOf(d, 'inputs');
      for (const p of priors) {
        const ph = isObj(p) ? p.receipt_sha256 : null;
        const parentEntry = byHash.get(ph);
        if (parentEntry === undefined && typeof ph === 'string' && ph) missing.add(ph);
        if (parentEntry === undefined) {
          // INCOMPLETE, not false: the parent may simply not have been supplied.
          if (node.links_ok === true) node.links_ok = 'incomplete';
          node.notes.push(`prior ${String(ph).slice(0, 16)}.. was not supplied; the handoff is unchecked`);
          continue;
        }
        const parentArts = digestsOf(parentEntry.v, 'outputs');
        if (childInputs.size === 0) {
          if (node.links_ok === true) node.links_ok = 'incomplete';
          node.notes.push('this document declares no inputs, so the handoff cannot be bound to the parent\'s bytes');
        } else {
          let shared = false;
          for (const x of childInputs) if (parentArts.has(x)) { shared = true; break; }
          if (!shared) {
            node.links_ok = false;
            node.notes.push(`BROKEN HANDOFF: no input of this document matches any artifact of prior ${String(ph).slice(0, 16)}... The link asserts a lineage the bytes do not support.`);
          }
        }
      }
    }

    if (hasCycle(byHash)) { out.notes.push('the prior references contain a cycle; this is not a chain'); return out; }

    out.effective_assurance = (weakest !== null && weakest >= 0) ? LADDER[weakest] : null;
    out.missing = Array.from(missing).sort();
    out.complete = missing.size === 0;
    let allOk = true;
    for (const n of Object.values(out.nodes)) if (!n.verified || n.links_ok === false) allOk = false;
    // `complete` is load-bearing: taking the minimum only defends against a weak link
    // that is PRESENT. Withholding one beats it.
    out.ok = Object.keys(out.nodes).length > 0 && out.complete && allOk;
    if (!out.complete) {
      out.notes.push(`INCOMPLETE: ${missing.size} referenced document(s) were not supplied, so the chain's origin is unknown and ${JSON.stringify(out.effective_assurance)} is the assurance of the FRAGMENT provided, not of the chain. Withholding a weaker parent is how a chain is made to look stronger than it is. This is not a forgery finding -- produce the missing documents to settle it.`);
    } else if (out.ok) {
      out.notes.push(`chain of ${Object.keys(out.nodes).length} document(s); effective assurance is the WEAKEST link: ${JSON.stringify(out.effective_assurance)} -- ${MEANING[out.effective_assurance] || ''}`);
    }
    return out;
  } catch (e) {
    out.notes.push(`chain verification error (treated as not verified): ${e && e.message ? e.message : e}`);
    out.ok = false;
    return out;
  }
}

function hasCycle(byHash) {
  const seen = new Set(); const stack = new Set();
  function walk(h) {
    if (stack.has(h)) return true;
    if (seen.has(h) || !byHash.has(h)) return false;
    seen.add(h); stack.add(h);
    for (const p of arr(byHash.get(h).v.prior)) {
      if (walk(p && p.receipt_sha256)) return true;
    }
    stack.delete(h);
    return false;
  }
  for (const h of byHash.keys()) if (walk(h)) return true;
  return false;
}

module.exports = {
  verifyWitness, verifyChain, deriveAssurance, rung,
  SPEC, LADDER, MEANING, CUSTODY, ASSERTED, WITNESSED, ENVIRONMENT_PINNED,
  claimOf, canonicalSha256,
};
