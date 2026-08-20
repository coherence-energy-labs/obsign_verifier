// Report, per raw receipt TEXT, what each JavaScript parser does with it.
//
// Two columns. `npm` is js/src/canonical.js, the parser that ships to `npm i
// obsign-verify`. `browser` is web/verify/verify-core.js from the PRODUCER's
// repository -- the parser a stranger actually runs when they open the public verify
// page, and the one this package cannot see from its own CI. Its path is handed in on
// argv[3]; without it that column is simply absent, and the Python side skips those
// comparisons rather than inventing agreement.
//
// Per case we report three things, and the Python side compares all three:
//   loads  -- did the parser accept these bytes at all
//   sha    -- sha256 of the canonical string, plus its length and a prefix. Hashing
//             keeps the transport bounded when a case is 4 MB wide; the prefix is what
//             makes a failure message readable.
//   fatal  -- true when the parser died in a way that is NOT a refusal. A JsonError or
//             a SyntaxError is the parser doing its job. A RangeError from a blown
//             stack, or a TypeError from reading a field off undefined, is a verifier
//             crashing on hostile input, which reads as failing open to whoever handed
//             it the file.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const npm = require('../js/src/canonical.js');

let browser = null;
if (process.argv[3]) {
  try { browser = require(process.argv[3]); } catch (e) { browser = null; }
}

function failure(e) {
  const name = (e && e.constructor && e.constructor.name) || 'unknown';
  const msg = String((e && e.message) || e).slice(0, 160);
  // A RangeError here is a blown call stack, not a bounds check: the parser recursed
  // until V8 stopped it. That is exactly the failure Python's load_receipt converts
  // into a WireFormatError on purpose, so it is reported as fatal rather than as a
  // refusal.
  return { err: `${name}: ${msg}`, fatal: name !== 'JsonError' && name !== 'SyntaxError' };
}

function column(load, canon, text) {
  let v;
  try { v = load(text); } catch (e) { return { loads: false, ...failure(e) }; }
  let s;
  // Loaded but not canonicalisable is its own state, reported separately: a document
  // an implementation can read but cannot hash is not the same as one it refuses.
  try { s = canon(v); } catch (e) { return { loads: true, sha: null, ...failure(e) }; }
  const b = Buffer.from(s, 'utf8');
  return { loads: true, sha: createHash('sha256').update(b).digest('hex'),
           len: b.length, head: s.slice(0, 120) };
}

const cases = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const out = cases.map(({ id, text, file }) => {
  const row = { id };
  // A case may name a FILE instead of carrying text, and then it is read exactly the
  // way bin/obsign-verify.js reads a receipt. That is deliberate: `readFileSync(f,
  // 'utf8')` substitutes U+FFFD for any byte sequence that is not valid UTF-8, and a
  // test that pre-decoded the bytes in Python would step over the one seam it is
  // trying to measure.
  const src = file === undefined ? text : readFileSync(file, 'utf8');
  row.npm = column((t) => npm.loadReceipt(t), (v) => npm.canonicalString(v), src);
  if (browser) {
    row.browser = column((t) => browser.parseReceipt(t), (v) => browser.canon(v), src);
  }
  return row;
});
process.stdout.write(JSON.stringify(out));
