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

class Parser {
  constructor(s) { this.s = s; this.i = 0; }

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
    this.i++;
    this.skipWs();
    if (this.s[this.i] === '}') { this.i++; return { __obj: out }; }
    for (;;) {
      this.skipWs();
      if (this.s[this.i] !== '"') this.err('expected a string key');
      const k = this.parseString();
      this.skipWs();
      if (this.s[this.i] !== ':') this.err('expected :');
      this.i++;
      out.set(k, this.parseValue());
      this.skipWs();
      if (this.s[this.i] === ',') { this.i++; continue; }
      if (this.s[this.i] === '}') { this.i++; return { __obj: out }; }
      this.err('expected , or }');
    }
  }

  parseArray() {
    const out = [];
    this.i++;
    this.skipWs();
    if (this.s[this.i] === ']') { this.i++; return out; }
    for (;;) {
      out.push(this.parseValue());
      this.skipWs();
      if (this.s[this.i] === ',') { this.i++; continue; }
      if (this.s[this.i] === ']') { this.i++; return out; }
      this.err('expected , or ]');
    }
  }

  parseString() {
    this.i++;
    let out = '';
    for (;;) {
      if (this.i >= this.s.length) this.err('unterminated string');
      const c = this.s[this.i];
      if (c === '"') { this.i++; return out; }
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
    return isFloat ? mkFloat(Number(lit)) : mkInt(BigInt(lit));
  }
}

/** Parse receipt TEXT, preserving the int/float distinction. */
function loadReceipt(text) {
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
    const [mantRaw, expRaw] = x.toExponential().split('e');
    const mant = mantRaw.includes('.') ? mantRaw : `${mantRaw}.0`;
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
    // Python sorts by the string key; JS's default sort is by UTF-16 code unit,
    // which agrees for every key that is not an unpaired surrogate.
    const keys = [...v.__obj.keys()].sort();
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
