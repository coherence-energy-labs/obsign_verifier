'use strict';
/**
 * The replay machine, in JavaScript.
 *
 * A second implementation of `obsign/replay/1`, written from the spec in the Python
 * module's docstring. It exists to make the portability claim checkable rather than
 * asserted: if two independently written interpreters disagree on any receipt, one of
 * them is wrong and the spec is ambiguous.
 *
 * BE CLEAR ABOUT WHAT THIS IS NOT. It is a PORT BY THE SAME AUTHOR, not the
 * independent second implementation the spec's recognition offer is about. It cannot
 * discharge the independence claim and must never be presented as if it did
 * (ADR-0003). What it does prove is narrower and still worth having: the instruction
 * set is small enough, and specified tightly enough, to be re-implemented in another
 * language with different integer semantics and land on the same bytes.
 *
 * WHY BigInt EVERYWHERE
 *
 * JavaScript numbers are doubles: exact only to 2^53. This machine is int64, and the
 * worked example's intermediates reach 4e20 -- `MULFX` multiplies EXACTLY and then
 * truncates, so the product must survive at full width before the shift. Using
 * Numbers would agree with the reference on small portfolios and silently diverge on
 * large ones, which is the worst failure shape available.
 */

const { createHash } = require('node:crypto');

const SPEC = 'obsign/replay/1';

const MASK = (1n << 64n) - 1n;
const INT64_MIN = -(1n << 63n);
const INT64_MAX = (1n << 63n) - 1n;

const MAX_MEM = 1 << 20;
const MAX_STEPS = 50_000_000;
const MAX_CODE = 1 << 16;

class Trap extends Error {}

/** Wrap into int64. Forget this and a port disagrees on the first overflow. */
function wrap(v) {
  v &= MASK;
  return v >= (1n << 63n) ? v - (1n << 64n) : v;
}

/** Truncate toward ZERO. BigInt `/` already truncates; this names the intent. */
function truncDiv(a, b) {
  if (b === 0n) throw new Trap('division by zero');
  return a / b;
}

//  name -> [arity, kind]
const OPS = {
  LOADC: [2, 'loadc'], MOV: [2, 'alu1'],
  ADD: [3, 'alu2'], SUB: [3, 'alu2'], MUL: [3, 'alu2'],
  DIV: [3, 'alu2'], MOD: [3, 'alu2'], MIN: [3, 'alu2'], MAX: [3, 'alu2'],
  AND: [3, 'alu2'], OR: [3, 'alu2'], XOR: [3, 'alu2'],
  SHL: [3, 'alu2'], SHR: [3, 'alu2'],
  EQ: [3, 'alu2'], NE: [3, 'alu2'], LT: [3, 'alu2'],
  LE: [3, 'alu2'], GT: [3, 'alu2'], GE: [3, 'alu2'],
  MULFX: [4, 'mulfx'], SEL: [4, 'sel'],
  NEG: [2, 'alu1'], ABS: [2, 'alu1'], NOT: [2, 'alu1'],
  LOAD: [2, 'alu1'], STORE: [2, 'store'],
  JMP: [1, 'jump'], JMPZ: [2, 'jcc'], JMPNZ: [2, 'jcc'],
  HALT: [0, 'halt'],
};

// A JSON integer reaches this file as a BigInt -- canonical.js parses it that way and
// verify.js no longer flattens it to a double -- while a JSON float reaches it as a
// Number. The two are distinguishable HERE and nowhere upstream, which is what lets
// `consts: [7.0]` be refused as this file's own header requires. The previous test,
// `typeof x === 'number' && Number.isInteger(x)`, could not: `Number.isInteger(7.0)`
// is true, so a float was accepted as an integer, and an exact int64 above 2^53 was
// rejected as "not fitting in int64" after being silently rounded on the way in.
//
// Structural fields (mem, steps, operands, offsets) index JS arrays, so they must be
// USED as Numbers -- but they must ARRIVE as BigInt like everything else, or a JSON
// float passes for the integer beside it. Every one is bounded far below 2^53 by
// MAX_MEM / MAX_STEPS / MAX_CODE, so runCounted's narrowing is lossless -- and that
// is CHECKED below, not assumed. Values (consts, inputs, memory) are never narrowed.
const SAFE = BigInt(Number.MAX_SAFE_INTEGER);

/** A structural integer. BigInt ONLY, for the reason `isValueInt` is: a JSON float
 * arrives here as a Number and `Number.isSafeInteger(4)` cannot tell `4.0` from `4`.
 * Accepting Numbers accepted `{"mem": 4.0}`, `{"steps": 8.0}` and `["MOV", 0.0, 2]`,
 * every one of which Python's `isinstance(x, int)` refuses -- programs that loaded
 * HERE and nowhere else, the mirror image of the reference reading `true` as 1. */
const isStructInt = (x) => typeof x === 'bigint' && x >= -SAFE && x <= SAFE;

/** A value integer. A Number here means the JSON carried a float, which has no int64 form. */
const isValueInt = (x) => typeof x === 'bigint';

const isPlainInt = isStructInt;

/** Reject anything malformed BEFORE executing a single instruction. */
function validate(prog) {
  if (prog === null || typeof prog !== 'object' || Array.isArray(prog)) {
    throw new Trap('program must be a JSON object');
  }
  if (prog.spec !== SPEC) throw new Trap(`unknown program spec ${prog.spec}, expected ${SPEC}`);

  for (const f of ['mem', 'steps', 'code', 'consts', 'input', 'output']) {
    if (!(f in prog)) throw new Trap(`program is missing ${f}`);
  }
  // Nothing is narrowed and written back here, and that is now load-bearing: every
  // liveness probe calls `validate` again on the SAME program object, and a validator
  // that rewrote a BigInt field into the Number form its own type check refuses would
  // pass on the first run and trap on the second. `runCounted` narrows into a local
  // copy instead, once this has proved the narrowing lossless.
  const { mem, steps, consts, code } = prog;
  if (!isStructInt(mem) || mem < 1n || mem > BigInt(MAX_MEM)) {
    throw new Trap(`mem must be an int in 1..${MAX_MEM}`);
  }
  if (!isStructInt(steps) || steps < 1n || steps > BigInt(MAX_STEPS)) {
    throw new Trap(`steps must be an int in 1..${MAX_STEPS}`);
  }
  if (!Array.isArray(consts) || consts.length > MAX_MEM) throw new Trap('consts must be a list');

  consts.forEach((c, i) => {
    // A float in the constant pool is how a libm would sneak back in. There is no
    // float anywhere in this machine, so it is rejected rather than coerced.
    if (typeof c === 'boolean' || !isValueInt(c)) {
      throw new Trap(`consts[${i}] is not an integer (floats are not representable)`);
    }
    const b = c;
    if (b < INT64_MIN || b > INT64_MAX) throw new Trap(`consts[${i}] does not fit in int64`);
  });

  for (const name of ['input', 'output']) {
    const spec = prog[name];
    if (spec === null || typeof spec !== 'object' || !isStructInt(spec.offset) || !isStructInt(spec.length)) {
      throw new Trap(`${name} must be {offset:int, length:int}`);
    }
    if (spec.offset < 0n || spec.length < 0n || spec.offset + spec.length > mem) {
      throw new Trap(`${name} window ${spec.offset}..${spec.offset + spec.length} is outside mem (${mem})`);
    }
  }
  // Every zero-length output would hash the empty string -- a collision by construction.
  if (prog.output.length === 0n) throw new Trap('output length must be > 0');

  if (!Array.isArray(code) || code.length === 0 || code.length > MAX_CODE) {
    throw new Trap(`code must be a non-empty list of at most ${MAX_CODE} instructions`);
  }

  code.forEach((ins, pc) => {
    if (!Array.isArray(ins) || ins.length === 0 || typeof ins[0] !== 'string') {
      throw new Trap(`code[${pc}] is not an instruction`);
    }
    const op = ins[0];
    if (!(op in OPS)) throw new Trap(`code[${pc}] unknown opcode ${op}`);
    const [arity, kind] = OPS[op];
    const args = ins.slice(1);
    if (args.length !== arity) throw new Trap(`code[${pc}] ${op} takes ${arity} operand(s), got ${args.length}`);
    for (const a of args) {
      if (typeof a === 'boolean' || !isStructInt(a)) throw new Trap(`code[${pc}] ${op} has a non-integer operand`);
    }
    const inMem = (a) => a >= 0n && a < mem;

    if (kind === 'loadc') {
      if (!inMem(args[0])) throw new Trap(`code[${pc}] ${op} dst ${args[0]} out of range`);
      if (args[1] < 0n || args[1] >= BigInt(consts.length)) throw new Trap(`code[${pc}] ${op} const index ${args[1]} out of range`);
    } else if (kind === 'jump' || kind === 'jcc') {
      const target = args[args.length - 1];
      if (target < 0n || target >= BigInt(code.length)) throw new Trap(`code[${pc}] ${op} jumps to ${target}, outside the program`);
      for (const a of args.slice(0, -1)) {
        if (!inMem(a)) throw new Trap(`code[${pc}] ${op} register ${a} out of range`);
      }
    } else if (kind === 'mulfx') {
      for (const a of args.slice(0, 3)) {
        if (!inMem(a)) throw new Trap(`code[${pc}] ${op} register ${a} out of range`);
      }
      if (args[3] < 0n || args[3] > 63n) throw new Trap(`code[${pc}] MULFX frac ${args[3]} must be 0..63`);
    } else if (kind !== 'halt') {
      for (const a of args) {
        if (!inMem(a)) throw new Trap(`code[${pc}] ${op} register ${a} out of range`);
      }
    }
  });

  return prog;
}

/** Canonical JSON of the program, hashed. Must agree with the Python digest. */
function programSha256(prog) {
  const { canonicalString } = require('./canonical.js');
  const wrapPlain = (v) => {
    if (v === null || typeof v === 'boolean' || typeof v === 'string') return v;
    if (typeof v === 'bigint') return { __n: 'i', v };
    // A Number reaching here is, by plain()'s documented invariant, a JSON FLOAT
    // (integers arrive as BigInt). Re-typing the whole-valued ones to integer
    // collapsed `1.0` into `1` -- the exact distinction the canonical form fixes
    // as load-bearing -- so an honest receipt whose program contained 1.0 got a
    // digest this implementation alone computed, and was called tampered.
    if (typeof v === 'number') return { __n: 'f', v };
    if (Array.isArray(v)) return v.map(wrapPlain);
    const m = new Map();
    for (const k of Object.keys(v)) m.set(k, wrapPlain(v[k]));
    return { __obj: m };
  };
  return createHash('sha256').update(Buffer.from(canonicalString(wrapPlain(prog)), 'utf8')).digest('hex');
}

/** Execute a validated program. Throws only `Trap`. Returns the output window. */
function run(prog, inputs) {
  return runCounted(prog, inputs).out;
}

/** `run`, plus the number of instructions executed (`steps`).
 *
 * The count is verifier-internal, NOT part of the cross-implementation contract --
 * a caller uses it to bound its own work when it re-runs a program many times
 * (input-liveness probing), since the declared `steps` budget is only an upper
 * bound. `stepCap`, when given, lowers the budget for THIS call only. The `out`
 * of an uncapped call is byte-identical to `run`'s. */
function runCounted(prog, inputs, stepCap) {
  validate(prog);

  // Narrowed into locals, leaving the caller's program object untouched. `validate`
  // has just proved every one of these is a BigInt inside the safe-integer range, so
  // Number() is lossless here and nowhere else.
  const declaredSteps = Number(prog.steps);
  const mem = new Array(Number(prog.mem)).fill(0n);
  const code = prog.code.map((ins) => [ins[0], ...ins.slice(1).map(Number)]);
  const budget = stepCap === undefined ? declaredSteps : Math.min(declaredSteps, stepCap);
  const consts = prog.consts;

  const inOff = Number(prog.input.offset);
  const inLen = Number(prog.input.length);
  if (inputs.length !== inLen) throw new Trap(`program expects ${inLen} input(s), got ${inputs.length}`);
  inputs.forEach((v, i) => {
    if (typeof v === 'boolean' || !isValueInt(v)) throw new Trap(`input[${i}] is not an integer`);
    const b = v;
    if (b < INT64_MIN || b > INT64_MAX) throw new Trap(`input[${i}] does not fit in int64`);
    mem[inOff + i] = b;
  });

  let pc = 0;
  let steps = 0;
  for (;;) {
    if (steps >= budget) throw new Trap(`step budget exhausted after ${budget} steps`);
    steps++;
    if (pc < 0 || pc >= code.length) throw new Trap(`pc ${pc} left the program`);

    const ins = code[pc];
    const op = ins[0];
    pc++;

    if (op === 'HALT') break;
    else if (op === 'LOADC') mem[ins[1]] = consts[ins[2]];
    else if (op === 'MOV') mem[ins[1]] = mem[ins[2]];
    else if (op === 'NEG') mem[ins[1]] = wrap(-mem[ins[2]]);
    else if (op === 'ABS') { const x = mem[ins[2]]; mem[ins[1]] = wrap(x < 0n ? -x : x); }
    else if (op === 'NOT') mem[ins[1]] = wrap(~mem[ins[2]]);
    else if (op === 'LOAD') {
      const addr = mem[ins[2]];
      if (addr < 0n || addr >= BigInt(mem.length)) throw new Trap(`LOAD address ${addr} out of bounds`);
      mem[ins[1]] = mem[Number(addr)];
    } else if (op === 'STORE') {
      const addr = mem[ins[1]];
      if (addr < 0n || addr >= BigInt(mem.length)) throw new Trap(`STORE address ${addr} out of bounds`);
      mem[Number(addr)] = mem[ins[2]];
    } else if (op === 'JMP') pc = ins[1];
    else if (op === 'JMPZ') { if (mem[ins[1]] === 0n) pc = ins[2]; }
    else if (op === 'JMPNZ') { if (mem[ins[1]] !== 0n) pc = ins[2]; }
    else if (op === 'SEL') mem[ins[1]] = mem[ins[2]] !== 0n ? mem[ins[3]] : mem[ins[4]];
    else if (op === 'MULFX') {
      // Exact product FIRST, then truncate, then wrap.
      mem[ins[1]] = wrap(truncDiv(mem[ins[2]] * mem[ins[3]], 1n << BigInt(ins[4])));
    } else {
      const a = mem[ins[2]];
      const b = mem[ins[3]];
      let v;
      if (op === 'ADD') v = wrap(a + b);
      else if (op === 'SUB') v = wrap(a - b);
      else if (op === 'MUL') v = wrap(a * b);
      else if (op === 'DIV') v = wrap(truncDiv(a, b));
      else if (op === 'MOD') {
        if (b === 0n) throw new Trap('modulo by zero');
        v = wrap(a - truncDiv(a, b) * b);
      } else if (op === 'MIN') v = a < b ? a : b;
      else if (op === 'MAX') v = a > b ? a : b;
      else if (op === 'AND') v = wrap(a & b);
      else if (op === 'OR') v = wrap(a | b);
      else if (op === 'XOR') v = wrap(a ^ b);
      else if (op === 'SHL' || op === 'SHR') {
        if (b < 0n || b > 63n) throw new Trap(`${op} shift amount ${b} must be 0..63`);
        v = op === 'SHL' ? wrap(a << b) : wrap(a >> b);
      } else if (op === 'EQ') v = a === b ? 1n : 0n;
      else if (op === 'NE') v = a !== b ? 1n : 0n;
      else if (op === 'LT') v = a < b ? 1n : 0n;
      else if (op === 'LE') v = a <= b ? 1n : 0n;
      else if (op === 'GT') v = a > b ? 1n : 0n;
      else v = a >= b ? 1n : 0n;   // GE -- the table is exhaustive
      mem[ins[1]] = v;
    }
  }

  const outOff = Number(prog.output.offset);
  const outLen = Number(prog.output.length);
  return { out: mem.slice(outOff, outOff + outLen), steps };
}

/** SHA-256 over the output as little-endian int64, matching `array_sha256`. */
function outputSha256(values) {
  const buf = Buffer.alloc(values.length * 8);
  values.forEach((v, i) => buf.writeBigInt64LE(BigInt.asIntN(64, wrap(v)), i * 8));
  return createHash('sha256').update(buf).digest('hex');
}

module.exports = { SPEC, Trap, validate, run, runCounted, outputSha256, programSha256,
  wrap, INT64_MIN, INT64_MAX, MAX_STEPS };
