'use strict';
/**
 * Canonical JSON and the claim hash, in JavaScript.
 *
 * THE TRAP THIS FILE EXISTS TO SURVIVE, and it is aimed squarely at this language.
 *
 * `JSON.parse` turns every number into a double, so `1` and `1.0` become the same
 * value. Python's canonical form writes `1` for an int and `1.0` for a float, and
 * those hash differently. A JavaScript verifier built on `JSON.parse` therefore
 * reports every honest receipt containing a whole-numbered float as TAMPERED --
 * confidently, and for a reason its author would never think to look for.
 *
 * So this does not use `JSON.parse`. It parses the TEXT and remembers, per number
 * literal, whether it was written as an integer or as a float. That information
 * exists nowhere else once the value is a double.
 *
 * The serializer is equally unusable off the shelf: `JSON.stringify` does not sort
 * keys, does not escape non-ASCII (Python's `ensure_ascii=True` does), and formats
 * floats by JavaScript's rules rather than Python's `repr`. All three are
 * reimplemented here and checked against real receipts produced by the Python
 * implementation.
 */

const { createHash } = require('node:crypto');

const INT = 'i';
const FLOAT = 'f';

const mkInt = (v) => ({ __n: INT, v });      // v: BigInt -- JSON integers are unbounded
const mkFloat = (v) => ({ __n: FLOAT, v });  // v: Number
const isNum = (x) => x !== null && typeof x === 'object' && '__n' in x;
const isObj = (x) => x !== null && typeof x === 'object' && x.__obj instanceof Map;

class JsonError extends Error {}

// WIRE-FORMAT LIMITS -- the same table as src/obsign_verify/canonical.py.
//
// "Valid JSON" is not one thing across languages, and every place two parsers
// disagree about what LOADS is a place one implementation verifies a document the
// other cannot read. Two such splits were measured against Python: a 5000-digit
// integer literal parsed here as an unbounded BigInt and was refused there
// (CPython caps decimal integer conversion at 4300 digits), and 2000-level nesting
// parsed here and raised RecursionError there. Same class as the NaN / 1e400
// divergence already closed, same fix: state the limits and apply them identically.
//
// Duplicate object members are refused rather than resolved. Last-value-wins is a
// parser convention, not a guarantee, and downstream readers do not all share it.
const MAX_RECEIPT_BYTES = 4 * 1024 * 1024;
const MAX_DEPTH = 32;
const MAX_MEMBERS_PER_OBJECT = 1024;
const MAX_ARRAY_LENGTH = 1 << 20;
const MAX_STRING_BYTES = 65536;
const MAX_INT_DIGITS = 4300;      // exactly CPython's default, so both sides agree

class Parser {
  constructor(s) { this.s = s; this.i = 0; this.depth = 0; }

  err(m) { throw new JsonError(`${m} at offset ${this.i}`); }

  skipWs() {
    while (this.i < this.s.length && ' \t\n\r'.includes(this.s[this.i])) this.i++;
  }

  parseValue() {
    this.skipWs();
    if (this.i >= this.s.length) this.err('unexpected end of input');
    const c = this.s[this.i];
    if (c === '{') return this.parseObject();
    if (c === '[') return this.parseArray();
    if (c === '"') return this.parseString();
    if (c === 't') { this.lit('true'); return true; }
    if (c === 'f') { this.lit('false'); return false; }
    if (c === 'n') { this.lit('null'); return null; }
    return this.parseNumber();
  }

  lit(word) {
    if (!this.s.startsWith(word, this.i)) this.err('invalid literal');
    this.i += word.length;
  }

  parseObject() {
    const out = new Map();
    if (++this.depth > MAX_DEPTH) this.err(`nesting deeper than ${MAX_DEPTH}`);
    this.i++;
    this.skipWs();
    if (this.s[this.i] === '}') { this.i++; this.depth--; return { __obj: out }; }
    for (;;) {
      this.skipWs();
      if (this.s[this.i] !== '"') this.err('expected a string key');
      const k = this.parseString();
      this.skipWs();
      if (this.s[this.i] !== ':') this.err('expected :');
      this.i++;
        if (k === '__proto__' || k === 'constructor' || k === 'prototype') {
          // These are not ordinary names in JavaScript: assigning them reparents
          // or shadows the receiving object. A receipt is data, and a data format
          // whose meaning depends on the reader's object model is ambiguous by
          // construction -- so they are refused at the door, in every
          // implementation, rather than sanitised differently by each one.
          this.err(`object member ${JSON.stringify(k)} is refused: it names a `
            + `JavaScript object-model slot, not a data field`);
        }
      if (out.has(k)) {
        this.err(`duplicate object member ${JSON.stringify(k)}: last-value-wins is a `
          + 'parser convention, not a guarantee, and two readers may disagree about '
          + 'which value this document contains');
      }
      if (out.size >= MAX_MEMBERS_PER_OBJECT) {
        this.err(`object has more than ${MAX_MEMBERS_PER_OBJECT} members`);
      }
      out.set(k, this.parseValue());
      this.skipWs();
      if (this.s[this.i] === ',') { this.i++; continue; }
      if (this.s[this.i] === '}') { this.i++; this.depth--; return { __obj: out }; }
      this.err('expected , or }');
    }
  }

  parseArray() {
    const out = [];
    if (++this.depth > MAX_DEPTH) this.err(`nesting deeper than ${MAX_DEPTH}`);
    this.i++;
    this.skipWs();
    if (this.s[this.i] === ']') { this.i++; this.depth--; return out; }
    for (;;) {
      if (out.length >= MAX_ARRAY_LENGTH) this.err(`array longer than ${MAX_ARRAY_LENGTH}`);
      out.push(this.parseValue());
      this.skipWs();
      if (this.s[this.i] === ',') { this.i++; continue; }
      if (this.s[this.i] === ']') { this.i++; this.depth--; return out; }
      this.err('expected , or ]');
    }
  }

  parseString() {
    this.i++;
    let out = '';
    for (;;) {
      if (this.i >= this.s.length) this.err('unterminated string');
      const c = this.s[this.i];
      if (c === '"') {
        this.i++;
        // MAX_STRING_BYTES was DECLARED here and never read -- the one limit in
        // the table that existed only as a number. Python and Rust refused a
        // 65537-byte string while this parser loaded it, so the constant that was
        // supposed to prove agreement was the proof that there wasn't any.
        // An unpaired surrogate has no UTF-8 encoding, so a document containing one
        // cannot have a canonical form at all. Both JS parsers loaded them while
        // Python refused; agreeing on what LOADS is the point of this table.
        for (let k = 0; k < out.length; k++) {
          const cp = out.charCodeAt(k);
          if (cp >= 0xD800 && cp <= 0xDBFF) {
            const next = k + 1 < out.length ? out.charCodeAt(k + 1) : 0;
            if (!(next >= 0xDC00 && next <= 0xDFFF)) this.err('unpaired surrogate in string');
            k++;
          } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            this.err('unpaired surrogate in string');
          }
        }
        const n = Buffer.byteLength(out, 'utf8');
        if (n > MAX_STRING_BYTES) {
          this.err(`string is ${n} bytes, limit is ${MAX_STRING_BYTES}`);
        }
        return out;
      }
      // RFC 8259 forbids a raw control character (< U+0020) inside a string; it must
      // be escaped. Python's json and the browser parser both reject it, so this
      // parser was the odd one out -- it accepted a raw U+001F and canonicalised it,
      // making a receipt only IT could load. Reject, matching the others.
      if (c < ' ') this.err('unescaped control character in string');
      if (c !== '\\') { out += c; this.i++; continue; }
      this.i++;
      const e = this.s[this.i++];
      const simple = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
      if (e in simple) { out += simple[e]; continue; }
      if (e === 'u') {
        const hex = this.s.slice(this.i, this.i + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.err('bad \\u escape');
        out += String.fromCharCode(parseInt(hex, 16));
        this.i += 4;
        continue;
      }
      this.err('bad escape');
    }
  }

  parseNumber() {
    const start = this.i;
    if (this.s[this.i] === '-') this.i++;
    while (this.i < this.s.length && this.s[this.i] >= '0' && this.s[this.i] <= '9') this.i++;
    let isFloat = false;
    if (this.s[this.i] === '.') {
      isFloat = true;
      this.i++;
      while (this.i < this.s.length && this.s[this.i] >= '0' && this.s[this.i] <= '9') this.i++;
    }
    if (this.s[this.i] === 'e' || this.s[this.i] === 'E') {
      isFloat = true;
      this.i++;
      if (this.s[this.i] === '+' || this.s[this.i] === '-') this.i++;
      while (this.i < this.s.length && this.s[this.i] >= '0' && this.s[this.i] <= '9') this.i++;
    }
    const lit = this.s.slice(start, this.i);
    if (!/^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?$/.test(lit)) this.err(`bad number ${lit}`);
    // THE WHOLE POINT: the literal's SHAPE decides the type, not its value.
    if (isFloat) {
      const f = Number(lit);
      // A literal like 1e400 parses to Infinity. Python's load_receipt rejects it
      // HERE, at parse, via parse_float. If this parser instead accepted it and only
      // failed later at serialisation, the two verifiers would disagree on what LOADS:
      // a receipt with 1e400 in `env` (excluded from the claim) loads in JS -- the
      // Infinity never reaches the canonicaliser -- while Python refuses it outright.
      // The verifiers must agree on loadability, not just on the claim hash.
      if (!Number.isFinite(f)) this.err(`non-finite float literal ${lit}`);
      return mkFloat(f);
    }
    // A literal CPython refuses to convert must not build a BigInt here, or the
    // same bytes load in JavaScript and are refused in Python.
    const digits = lit.replace(/^-/, '').length;
    if (digits > MAX_INT_DIGITS) this.err(`integer with more than ${MAX_INT_DIGITS} digits`);
    return mkInt(BigInt(lit));
  }
}

/** Parse receipt TEXT, preserving the int/float distinction. */
function loadReceipt(text) {
  // BYTES ARE THE DOCUMENT. Accept them, and decode STRICTLY.
  //
  // Node's fs.readFileSync(f, 'utf8') and the browser's FileReader.readAsText
  // both SUBSTITUTE U+FFFD for every invalid byte instead of failing. So three
  // genuinely different files -- {"a":"\xff"}, {"a":"\x80"}, {"a":"\xc3"} --
  // arrive as one identical string, canonicalise to one form, and hash to one
  // receipt_sha256. That destroys the defining property of a canonical form, one
  // layer ABOVE every limit this parser checks, and it does it silently. Python
  // and Rust refuse these bytes at the decoder.
  //
  // A caller who hands us a string has already lost that information, so the only
  // place the check can live is here, on the bytes.
  if (text instanceof Uint8Array) {
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(text);
    } catch (e) {
      throw new JsonError('receipt is not valid UTF-8: ' + e.message);
    }
  } else if (typeof text !== 'string') {
    throw new JsonError(`receipt must be text or bytes, got ${typeof text}`);
  }
  // Cheapest refusal first: everything below walks the document.
  if (Buffer.byteLength(text, 'utf8') > MAX_RECEIPT_BYTES) {
    throw new JsonError(`receipt larger than ${MAX_RECEIPT_BYTES} bytes`);
  }
  const p = new Parser(text);
  const v = p.parseValue();
  p.skipWs();
  if (p.i !== p.s.length) throw new JsonError('trailing data after JSON value');
  if (!isObj(v)) throw new JsonError('a receipt must be a JSON object');
  return v;
}

/**
 * Format a float exactly as CPython's `repr` does.
 *
 * Both languages emit the shortest round-tripping decimal, but they disagree on
 * presentation in three ways that change bytes and therefore hashes:
 *   whole-numbered float: Python `1.0`, JS `1`
 *   exponent threshold:   Python switches at 1e16, JS at 1e21
 *   exponent padding:     Python `1e-07`, JS `1e-7`
 */
function pyFloatRepr(x) {
  if (!Number.isFinite(x)) {
    throw new JsonError('NaN and Infinity have no JSON form (allow_nan=False)');
  }
  if (Object.is(x, -0)) return '-0.0';
  if (x === 0) return '0.0';

  const abs = Math.abs(x);
  if (abs >= 1e16 || abs < 1e-4) {
    // NO `.0` PADDING ON THE MANTISSA. Python's repr pads a whole float in
    // POSITIONAL form (`1.0`, handled below) and never in exponential form: it
    // writes `1e-06`, not `1.0e-06`. Padding here made this verifier recompute a
    // different claim hash than the producer for any float with an integral
    // mantissa outside 1e-4..1e16 -- so `obsign-verify` from npm reported the
    // producer's own committed fixture (web/verify/_testdata/tiny_receipt.json,
    // metrics 1e-06 / 5e-05 / -3e-05) as INTEGRITY FAIL. Accusing an honest
    // receipt of forgery is the worst verdict this tool can return, and forensic
    // metrics, tolerances and p-values live in exactly that range.
    const [mant, expRaw] = x.toExponential().split('e');
    const sign = expRaw[0] === '-' ? '-' : '+';
    const digits = expRaw.replace(/^[+-]/, '').padStart(2, '0');
    return `${mant}e${sign}${digits}`;
  }
  const s = String(x);
  return s.includes('.') || s.includes('e') ? s : `${s}.0`;
}

/** Escape a string the way Python's json with ensure_ascii=True does. */
function pyStringRepr(s) {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (ch === '\b') out += '\\b';
    else if (ch === '\f') out += '\\f';
    else if (c < 0x20) out += `\\u${c.toString(16).padStart(4, '0')}`;
    else if (c < 0x7f) out += ch;
    else if (c <= 0xffff) out += `\\u${c.toString(16).padStart(4, '0')}`;
    else {
      // Non-BMP: Python emits an escaped surrogate PAIR, not one \U escape.
      const v = c - 0x10000;
      out += `\\u${(0xd800 + (v >> 10)).toString(16).padStart(4, '0')}`;
      out += `\\u${(0xdc00 + (v & 0x3ff)).toString(16).padStart(4, '0')}`;
    }
  }
  return `${out}"`;
}

/** Canonical JSON: sorted keys, no spaces, ASCII-escaped, no NaN/Infinity. */
function canonicalString(v) {
  if (v === null) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (typeof v === 'string') return pyStringRepr(v);
  if (isNum(v)) return v.__n === INT ? v.v.toString() : pyFloatRepr(v.v);
  if (Array.isArray(v)) return `[${v.map(canonicalString).join(',')}]`;
  if (isObj(v)) {
    // Python sorts keys by Unicode CODE POINT. JS's default .sort() is by UTF-16
    // code UNIT, and the two DISAGREE whenever a BMP key in U+E000..U+FFFF meets an
    // astral key: the astral key's lead surrogate (0xD800..0xDBFF) sorts below the
    // BMP key by unit but above it by code point. (The old comment here claimed
    // agreement "for every key that is not an unpaired surrogate" -- wrong; paired
    // surrogates diverge too.) Compare by code point to match Python exactly.
    const cpCmp = (a, b) => {
      const A = [...a], B = [...b], n = Math.min(A.length, B.length);
      for (let k = 0; k < n; k++) { const d = A[k].codePointAt(0) - B[k].codePointAt(0); if (d) return d; }
      return A.length - B.length;
    };
    const keys = [...v.__obj.keys()].sort(cpCmp);
    return `{${keys.map((k) => `${pyStringRepr(k)}:${canonicalString(v.__obj.get(k))}`).join(',')}}`;
  }
  throw new JsonError('value is not JSON-serialisable');
}

/** Fields the spec excludes from the claim. Must match the Python NON_CLAIM. */
const NON_CLAIM = new Set(['receipt_sha256', 'env', 'signature', 'case']);

function claimOf(receipt) {
  const out = new Map();
  for (const [k, val] of receipt.__obj) {
    if (NON_CLAIM.has(k) || k.startsWith('_')) continue;
    out.set(k, val);
  }
  return { __obj: out };
}

const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');

function canonicalSha256(v) {
  return sha256Hex(Buffer.from(canonicalString(v), 'utf8'));
}

/** Step 1 of the ladder. Never throws on a hostile receipt. */
function integrity(receipt) {
  const stated = receipt.__obj.get('receipt_sha256');
  if (typeof stated !== 'string' || !stated) {
    return [false, 'no receipt_sha256 to check against'];
  }
  let recomputed;
  try {
    recomputed = canonicalSha256(claimOf(receipt));
  } catch (e) {
    return [false, `claim is not canonicalisable (${e.message})`];
  }
  if (recomputed !== stated) {
    return [false, `INTEGRITY FAIL - states ${stated.slice(0, 16)}.., recomputes ${recomputed.slice(0, 16)}..`];
  }
  return [true, 'integrity OK'];
}

module.exports = {
  loadReceipt, claimOf, canonicalString, canonicalSha256, integrity,
  pyFloatRepr, pyStringRepr, sha256Hex, isNum, isObj, INT, FLOAT, JsonError, NON_CLAIM,
};
