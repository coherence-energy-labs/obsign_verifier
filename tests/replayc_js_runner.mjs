// Run compiled replay programs on the JS VM, for the three-way differential in
// test_replayc.py. Reads a JSON array of {program, inputs} from argv[2], runs each on
// js/src/replay.js exactly as a real receipt reaches it -- parsed by canonical.js (so
// integers arrive as BigInt, the int/float distinction the machine turns on) and
// unwrapped by the same `plain` bridge verify.js uses -- and prints, per case, the
// output as decimal strings or the string "TRAP". The Python side compares.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const canonical = require('../js/src/canonical.js');
const replay = require('../js/src/replay.js');

const plain = (v) => {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return v;
  if (v && typeof v === 'object' && '__n' in v) return v.__n === 'i' ? v.v : Number(v.v);
  if (Array.isArray(v)) return v.map(plain);
  if (v && v.__obj instanceof Map) {
    const o = {};
    for (const [k, val] of v.__obj) o[k] = plain(val);
    return o;
  }
  return v;
};

const cases = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const out = cases.map(({ programText, inputs }) => {
  try {
    const prog = plain(canonical.loadReceipt(programText));
    // inputs arrive as DECIMAL STRINGS, not JSON numbers: an int64 above 2^53 would
    // lose precision through JSON.parse (the exact trap this whole system guards),
    // so BigInt each string directly.
    const res = replay.run(prog, inputs.map((s) => BigInt(s)));
    return { ok: res.map(String) };
  } catch (e) {
    if (e instanceof replay.Trap) return { trap: true };
    return { error: String(e && e.message || e) };
  }
});
console.log(JSON.stringify(out));
