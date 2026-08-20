'use strict';
/**
 * The only test that matters here: does this implementation agree with the reference?
 *
 * Every receipt below was produced by the PYTHON implementation. Nothing in this
 * directory generated them. If these two programs -- one in a language with 64-bit
 * integers and one in a language whose numbers are doubles -- disagree on a single
 * byte, either this port is wrong or the spec is ambiguous, and both are worth
 * knowing before anyone is invited to depend on it.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { loadReceipt, canonicalSha256, canonicalString, claimOf } = require('../src/canonical.js');
const { verify, plain } = require('../src/verify.js');
const replay = require('../src/replay.js');

const REPO = path.resolve(__dirname, '..', '..');
const readReceipt = (p) => loadReceipt(fs.readFileSync(p, 'utf8'));

const ECL = path.join(REPO, 'examples', 'ecl_receipt.json');
const BUNDLES = path.join(REPO, 'src', 'obsign_verify', 'data', 'challenge', 'bundles');

test('the ECL receipt Python produced re-derives here, byte for byte', () => {
  const r = readReceipt(ECL);
  const res = verify(r);
  assert.strictEqual(res.integrity, true, res.notes.join('; '));
  assert.strictEqual(res.reproduced, true, res.notes.join('; '));
  assert.strictEqual(res.verified, true, res.notes.join('; '));
});

test('input-liveness agrees with Python: genuine live, constant refused', () => {
  // The genuine program depends on all its inputs.
  assert.strictEqual(verify(readReceipt(ECL)).input_liveness, 'live');

  // A constant program that re-derives the true answer but ignores every input is
  // REFUSED here exactly as it is in Python -- the two verifiers must not disagree
  // on the trivial-program attack, or a forger picks whichever one clears it.
  const doc = JSON.parse(fs.readFileSync(ECL, 'utf8'));
  const n = doc.params.inputs.length;
  // consts are VALUES, so BigInt -- a Number const is now (correctly) refused as a
  // float. JSON has no BigInt, so serialize through a replacer; loadReceipt turns
  // the numbers back into BigInt via the tagged parser, exactly as in the field.
  const J = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? Number(v) : v));
  // Structural scalars are JSON INTEGERS, so they reach the machine as BigInt too --
  // a Number in one of them means the JSON carried a float, which has no int64 form.
  const cp = {
    spec: replay.SPEC, mem: 2048n, steps: 50n, consts: [38922496n],
    input: { offset: 1024n, length: BigInt(n) }, output: { offset: 0n, length: 1n },
    code: [['LOADC', 0n, 0n], ['HALT']],
  };
  const out = replay.run(cp, doc.params.inputs.map(BigInt));
  doc.params.program = cp;
  doc.params.program_sha256 = replay.programSha256(cp);
  doc.output.sha256 = replay.outputSha256(out);
  doc.receipt_sha256 = canonicalSha256(claimOf(loadReceipt(J(doc))));
  const res = verify(loadReceipt(J(doc)));
  assert.strictEqual(res.input_liveness, 'dead', res.notes.join('; '));
  assert.strictEqual(res.verified, false);
});

test('the claim hash agrees with the digest Python wrote into the file', () => {
  const r = readReceipt(ECL);
  // Recomputed here, from the same bytes, by a different canonicaliser.
  assert.strictEqual(canonicalSha256(claimOf(r)), r.__obj.get('receipt_sha256'));
});

test('the program digest agrees with the one Python computed', () => {
  const r = readReceipt(ECL);
  const params = r.__obj.get('params').__obj;
  const plainProgram = JSON.parse(JSON.stringify(
    (function unwrap(v) {
      if (v && typeof v === 'object' && '__n' in v) return v.__n === 'i' ? Number(v.v) : v.v;
      if (Array.isArray(v)) return v.map(unwrap);
      if (v && v.__obj instanceof Map) {
        const o = {};
        for (const [k, val] of v.__obj) o[k] = unwrap(val);
        return o;
      }
      return v;
    })(params.get('program')),
  ));
  assert.strictEqual(replay.programSha256(plainProgram), params.get('program_sha256'));
});

test('a resealed forgery passes integrity here too, and still fails re-derivation', () => {
  // Integrity is recomputed independently, so a forgery that is internally consistent
  // must look consistent to BOTH implementations -- that is the point of the case.
  const raw = JSON.parse(fs.readFileSync(ECL, 'utf8'));
  raw.params.inputs[3] = 100000000;
  delete raw.receipt_sha256;
  const rebuilt = loadReceipt(JSON.stringify(raw));
  raw.receipt_sha256 = canonicalSha256(claimOf(rebuilt));
  const res = verify(loadReceipt(JSON.stringify(raw)));
  assert.strictEqual(res.integrity, true, 'a resealed forgery should look internally consistent');
  assert.strictEqual(res.reproduced, false);
  assert.strictEqual(res.verified, false);
});

test('canonicalisation matches Python on the adversarial corpus', () => {
  // Each case is [json text, expected canonical string] where the expected value is
  // exactly what CPython json.dumps(sort_keys=True, ...) produces. These are the
  // inputs a hostile receipt author uses to make two verifiers disagree; all were
  // divergent before the fixes and must now agree byte-for-byte.
  const canon = (t) => canonicalString(loadReceipt(t));
  const cases = [
    // astral vs BMP key -- code-point order, not UTF-16 code-unit order
    ['{"\\ue000":1,"\\ud83d\\ude00":2}', '{"\\ue000":1,"\\ud83d\\ude00":2}'],
    ['{"\\uff00":1,"\\ud800\\udc00":2}', '{"\\uff00":1,"\\ud800\\udc00":2}'],
    // DEL (U+007F) must be escaped, like Python ensure_ascii
    ['{"k":"\\u007f"}', '{"k":"\\u007f"}'],
    ['{"\\u007f":1,"a":2}', '{"a":2,"\\u007f":1}'],
    // __proto__ is an ordinary key, not the prototype accessor
    ['{"__proto__":424242,"real":1.0}', '{"__proto__":424242,"real":1.0}'],
  ];
  for (const [text, want] of cases) {
    assert.strictEqual(canon(text), want, `canon(${text})`);
  }
});

test('canonicalisation REFUSES what Python and the browser refuse', () => {
  const refuse = [
    '{"k":"ab"}',   // raw control char in a string (RFC 8259 forbids)
    '{"m":1e400}',        // overflows to Infinity
    '{"m":NaN}',          // bare non-finite token
    '{"m":Infinity}',
  ];
  for (const text of refuse) {
    assert.throws(() => canonicalString(loadReceipt(text)), undefined,
      `must refuse to load ${JSON.stringify(text)}`);
  }
});

test('a non-finite float in a NON-claim field is refused at LOAD, not merely at canon', () => {
  // The subtle N-version split: `env` is excluded from the claim, so a canon-only
  // check of the claim would never see an Infinity hidden in env and would ACCEPT the
  // receipt -- while Python's load_receipt refuses it outright at parse. If the two
  // verifiers disagree on what LOADS, a forger ships a receipt one accepts and the
  // other rejects. loadReceipt itself must throw, before claimOf ever drops env.
  for (const text of [
    '{"spec":"x","a":1,"env":{"p":1e400}}',
    '{"spec":"x","a":1,"env":{"p":NaN}}',
    '{"spec":"x","a":1,"env":{"p":Infinity}}',
  ]) {
    assert.throws(() => loadReceipt(text), undefined,
      `loadReceipt must refuse ${JSON.stringify(text)} at parse, not defer to canon`);
  }
});

test('this implementation reaches the SAME integrity verdict as Python, bundle by bundle', () => {
  // The bundles carry `_challenge.expect_verified`, written by the producer. Where a
  // bundle is expected to verify, its claim must be internally consistent -- so
  // integrity, computed here by a different canonicaliser, must agree.
  const dirs = fs.readdirSync(BUNDLES, { withFileTypes: true }).filter((d) => d.isDirectory());
  assert.ok(dirs.length >= 9, `only ${dirs.length} bundles found -- this check would be vacuous`);

  let checked = 0;
  let honest = 0;
  for (const d of dirs) {
    const p = path.join(BUNDLES, d.name, 'receipt.json');
    if (!fs.existsSync(p)) continue;
    const r = readReceipt(p);
    const [ok] = require('../src/canonical.js').integrity(r);
    const marker = r.__obj.get('_challenge');
    const expectVerified = marker && marker.__obj ? marker.__obj.get('expect_verified') : undefined;

    if (expectVerified === true) {
      // An honest receipt MUST canonicalise to its own stated hash here too. This is
      // where a JS canonicaliser that mishandles int/float or non-ASCII would break.
      assert.strictEqual(ok, true, `${d.name}: honest receipt failed integrity in JS`);
      honest += 1;
    }
    checked += 1;
  }
  assert.ok(checked >= 9, `only ${checked} bundles read`);
  assert.ok(honest >= 1, 'no honest bundle was exercised -- the check would be one-sided');
});

test('int and float are NOT the same value here, which JSON.parse cannot express', () => {
  // The whole reason this package does not use JSON.parse.
  const a = loadReceipt('{"x": 1}');
  const b = loadReceipt('{"x": 1.0}');
  assert.notStrictEqual(canonicalSha256(a), canonicalSha256(b));
  assert.strictEqual(require('../src/canonical.js').canonicalString(a), '{"x":1}');
  assert.strictEqual(require('../src/canonical.js').canonicalString(b), '{"x":1.0}');
});

test('exponential floats canonicalise the way Python repr does', () => {
  // Python pads a whole float in POSITIONAL form (`1.0`) and never in exponential
  // form (`1e-06`, not `1.0e-06`). This verifier padded both, so it recomputed a
  // different claim hash than the producer for any float with an integral mantissa
  // outside 1e-4..1e16 -- and reported the producer's own committed fixture as
  // INTEGRITY FAIL. Forensic metrics, tolerances and p-values live in that range.
  const { pyFloatRepr } = require('../src/canonical.js');
  const cases = [
    [1e-6, '1e-06'], [5e-5, '5e-05'], [-3e-5, '-3e-05'],
    [1e16, '1e+16'], [1e21, '1e+21'], [5e-324, '5e-324'], [1e-5, '1e-05'],
    [1.5e-7, '1.5e-07'],            // fractional mantissa: unchanged
    [0.0001, '0.0001'],             // just inside the positional threshold
    [1e15, '1000000000000000.0'],   // positional, and here the `.0` IS correct
    [1.0, '1.0'], [0.0, '0.0'], [-0.0, '-0.0'], [0.5, '0.5'],
  ];
  for (const [v, want] of cases) {
    assert.strictEqual(pyFloatRepr(v), want, `pyFloatRepr(${v})`);
  }
});

test('wrapping int64 and truncate-toward-zero match the reference', () => {
  const prog = (code, consts) => ({
    spec: replay.SPEC, mem: 8n, steps: 100n, consts,
    input: { offset: 6n, length: 1n }, output: { offset: 0n, length: 1n },
    // operands are JSON integers, so they arrive as BigInt like every other one
    code: code.map(([op, ...args]) => [op, ...args.map(BigInt)]),
  });
  const INT64_MAX = 9223372036854775807n;
  const INT64_MIN = -9223372036854775808n;

  // A const is a VALUE, so it is a BigInt. This test used to pass Numbers and reach
  // the int64 edge only through the program's own arithmetic -- deliberately, per the
  // comment it carried -- and that detour is exactly why the lossy JSON->interpreter
  // boundary went unseen: `Number(2n**53n+1n)` rounds, so the receipt hash and the
  // signature verified over exact values while the re-derivation ran on rounded ones.
  // The edge is now placed directly in the constant pool, where the defect lived.
  const wrapProg = prog(
    [['LOADC', 0, 0], ['LOADC', 1, 1], ['ADD', 0, 0, 1], ['HALT']],
    [BigInt(Number.MAX_SAFE_INTEGER), 1n],
  );
  const got = replay.run(wrapProg, [0n]);
  assert.strictEqual(got[0], BigInt(Number.MAX_SAFE_INTEGER) + 1n);

  // Values that a double cannot hold, carried as constants and as inputs. Every one
  // of these was either silently rounded or falsely refused before the fix.
  for (const v of [INT64_MAX, INT64_MIN, 2n ** 53n + 1n, 2n ** 53n + 3n,
                   -(2n ** 53n) - 1n, 2n ** 62n + 12345n]) {
    const asConst = prog([['LOADC', 0, 0], ['HALT']], [v]);
    assert.strictEqual(replay.run(asConst, [0n])[0], v, `const ${v}`);

    const asInput = prog([['MOV', 0, 6], ['HALT']], [0n]);
    assert.strictEqual(replay.run(asInput, [v])[0], v, `input ${v}`);
  }

  // A float in the constant pool has no int64 form and must be refused, not coerced.
  // `Number.isInteger(7.0)` is true, so the old number-based check accepted it.
  assert.throws(
    () => replay.run(prog([['LOADC', 0, 0], ['HALT']], [7.0]), [0n]),
    /floats are not representable/,
    'a float const must trap, matching the Python reference');
  assert.throws(
    () => replay.run(prog([['LOADC', 0, 0], ['HALT']], [1n]), [7.5]),
    /input\[0\] is not an integer/,
    'a float input must trap');

  for (const [a, b, want] of [[-7n, 2n, -3n], [7n, -2n, -3n], [-7n, -2n, 3n], [7n, 2n, 3n]]) {
    const p = prog([['LOADC', 0, 0], ['LOADC', 1, 1], ['DIV', 0, 0, 1], ['HALT']], [a, b]);
    assert.strictEqual(replay.run(p, [0n])[0], want, `${a}/${b}`);
  }
});

test('a JSON float in a STRUCTURAL scalar is refused, as the Python reference refuses it', () => {
  // `mem`, `steps`, the window bounds and every operand are JSON INTEGERS. Python's
  // `isinstance(4.0, int)` is False, so it refuses `"mem": 4.0`; this file's check was
  // `Number.isSafeInteger`, and after canonical.js an integer literal is a BigInt while
  // a float literal is a Number -- so a Number-accepting check admitted the float and
  // ran the program. Each implementation therefore loaded programs the other refused,
  // and a forger picks whichever verifier loads the receipt they built.
  //
  // These are built as TEXT: `JSON.stringify(4.0)` is "4", so the `.0` a receipt
  // actually carries cannot be expressed any other way in this language.
  const SOUND = '{"spec":"obsign/replay/1","mem":4,"steps":8,"consts":[0],'
    + '"input":{"offset":2,"length":1},"output":{"offset":0,"length":1},"code":[["HALT"]]}';
  const load = (text) => plain(loadReceipt(text));
  assert.deepStrictEqual(replay.run(load(SOUND), [0n]), [0n],
    'the sound program must RUN, or this test passes by refusing everything');

  const floats = [
    ['mem', '"mem":4', '"mem":4.0'],
    ['steps', '"steps":8', '"steps":8.0'],
    ['input.offset', '"input":{"offset":2', '"input":{"offset":2.0'],
    ['input.length', '"input":{"offset":2,"length":1}', '"input":{"offset":2,"length":1.0}'],
    ['output.offset', '"output":{"offset":0', '"output":{"offset":0.0'],
    ['output.length', '"output":{"offset":0,"length":1}', '"output":{"offset":0,"length":1.0}'],
    ['operand', '[["HALT"]]', '[["MOV",0.0,2],["HALT"]]'],
    ['jump target', '[["HALT"]]', '[["JMP",1.0],["HALT"]]'],
  ];
  for (const [name, from, to] of floats) {
    const text = SOUND.replace(from, to);
    assert.notStrictEqual(text, SOUND, `${name}: the substitution did not apply`);
    assert.throws(() => replay.run(load(text), [0n]), replay.Trap,
      `${name}: a JSON float must be refused, not read as the integer beside it`);
  }

  // The other direction, which this implementation always had right and which the
  // Python reference did not: a JSON boolean is not an integer either.
  for (const [name, from, to] of [
    ['mem', '"mem":4,"steps":8', '"mem":true,"steps":8'],
    ['steps', '"steps":8', '"steps":true'],
    ['input.offset', '"input":{"offset":2', '"input":{"offset":true'],
    ['output.length', '"output":{"offset":0,"length":1}', '"output":{"offset":0,"length":true}'],
  ]) {
    const text = SOUND.replace(from, to);
    assert.notStrictEqual(text, SOUND, `${name}: the substitution did not apply`);
    assert.throws(() => replay.run(load(text), [0n]), replay.Trap, `${name}: bool`);
  }
});

test('a hostile program is refused, not thrown past the caller', () => {
  const raw = JSON.parse(fs.readFileSync(ECL, 'utf8'));
  raw.params.program = {
    spec: replay.SPEC, mem: 8, steps: 500, consts: [0],
    input: { offset: 4, length: raw.params.inputs.length },
    output: { offset: 0, length: 1 },
    code: [['LOADC', 0, 0], ['JMP', 0]],
  };
  raw.params.program_sha256 = replay.programSha256(raw.params.program);
  const res = verify(loadReceipt(JSON.stringify(raw)));
  assert.strictEqual(res.verified, false);
  assert.ok(res.notes.some((n) => /refused|budget|window/.test(n)), res.notes.join('; '));
});
