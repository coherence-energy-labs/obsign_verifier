// The JavaScript leg of the three-way differential.
//
// Modes mirror `obsign-verify-rs --harness MODE JOBFILE` exactly, field for field, so
// the Python side can compare three dictionaries rather than three prose reports.
//
// int64 VALUES CROSS AS STRINGS, in both directions. This runner's own output is read
// by `JSON.parse` on nobody's part -- but the Python comparator reads all three, and a
// value above 2^53 emitted as a bare JSON number would be compared after rounding,
// which is the precise failure the format exists to make impossible.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
// `fileURLToPath`, NOT `.pathname`. On Windows a file: URL's pathname is `/C:/...`,
// with a leading slash and percent-escapes intact, so every `require` below failed
// with `Cannot find module '/C:/.../canonical.js'` -- the JavaScript leg of the
// three-way differential could not start at all on the platform the CI matrix
// declares, and the whole suite reported that as seven failing tests rather than as
// "the harness never ran". `fileURLToPath` is the only correct URL-to-path conversion.
const ROOT = fileURLToPath(new URL('../../js/src/', import.meta.url));
const { loadReceipt, canonicalString } = require(`${ROOT}canonical.js`);
const { verify, plain } = require(`${ROOT}verify.js`);
const { verifyGraph } = require(`${ROOT}graph.js`);
const replay = require(`${ROOT}replay.js`);

const mode = process.argv[2];
const cases = JSON.parse(readFileSync(process.argv[3], 'utf8'));

/** Re-run the receipt's own program on its own inputs, independently of the verdict.
 *  null whenever that cannot be done -- which is a fact all three must agree on too. */
function outputsOf(receipt) {
  try {
    const p = plain(receipt.__obj.get('params'));
    if (!p || typeof p !== 'object') return null;
    const out = replay.run(p.program, p.inputs);
    return out.map((v) => v.toString());
  } catch (e) {
    return null;
  }
}

const out = {};
for (const [name, payload] of cases) {
  if (mode === 'load') {
    try { loadReceipt(payload); out[name] = true; } catch (e) { out[name] = false; }
  } else if (mode === 'canon') {
    try { out[name] = canonicalString(loadReceipt(payload)); } catch (e) { out[name] = null; }
  } else if (mode === 'verify') {
    let r;
    try { r = loadReceipt(payload); } catch (e) { out[name] = { loaded: false, verdict: null }; continue; }
    const v = verify(r);
    const s = v.signature;
    out[name] = {
      loaded: true,
      verdict: {
        integrity: v.integrity,
        reproduced: v.reproduced === undefined ? null : v.reproduced,
        verified: v.verified,
        unsupported: v.unsupported ?? false,
        approved_program: v.approved_program ?? null,
        input_liveness: v.input_liveness ?? null,
        input_liveness_by_input: v.input_liveness_by_input ?? [],
        output_liveness_by_cell: v.output_liveness_by_cell ?? [],
        signature: s === null || s === undefined ? null : {
          present: s.present, valid: s.valid, unsupported: s.unsupported ?? false,
          identity_bound: s.identity_bound,
          attributed_signer: s.attributed_signer ?? null,
          claimed_signer: s.claimed_signer ?? null,
          bound_metadata: s.bound_metadata ?? [],
          unbound_metadata: s.unbound_metadata ?? [],
        },
        output: outputsOf(r),
        notes: v.notes,
      },
    };
  } else if (mode === 'graph') {
    let receipts;
    try { receipts = payload.map((t) => loadReceipt(t)); }
    catch (e) { out[name] = { loaded: false }; continue; }
    const g = verifyGraph(receipts);
    const nodes = {};
    for (const [d, n] of Object.entries(g.nodes)) {
      nodes[d] = { verified: n.verified, links_ok: n.links_ok === null ? null : n.links_ok,
                   envelopes: n.envelopes };
    }
    out[name] = { loaded: true, graph_verified: g.graph_verified, complete: g.complete,
                  missing: g.missing.slice().sort(), roots: g.roots.slice().sort(), nodes };
  } else if (mode === 'vm') {
    try {
      const holder = loadReceipt(`{"p":${payload.program}}`);
      const prog = plain(holder.__obj.get('p'));
      const inputs = payload.inputs.map((x) => BigInt(x));
      try {
        const o = replay.run(prog, inputs);
        out[name] = { ok: true, out: o.map((v) => v.toString()),
                      output_sha256: replay.outputSha256(o),
                      program_sha256: replay.programSha256(prog) };
      } catch (e) {
        if (!(e instanceof replay.Trap)) throw e;
        out[name] = { ok: false, trap: e.message };
      }
    } catch (e) {
      out[name] = { ok: false, trap: `load: ${e.message}` };
    }
  } else {
    throw new Error(`unknown harness mode ${mode}`);
  }
}
console.log(JSON.stringify(out));
