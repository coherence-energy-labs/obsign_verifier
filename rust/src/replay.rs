//! `obsign/replay/1` -- the deterministic integer machine that travels inside a receipt.
//!
//! WHAT THE SPECIFICATION FIXES, and it is less than you would want.
//!
//! docs/COMPAT.md freezes "the 31-opcode instruction set, wrapping int64 arithmetic,
//! truncate-toward-zero division, MULFX's exact-then-truncate-then-wrap order, total
//! operations (every partial case a Trap), the step budget, the `{spec, mem, steps,
//! consts, input, output, code}` program shape, and little-endian-int64
//! `output_sha256`". Every one of those is honoured here.
//!
//! It does not name the 31 opcodes, give their arities, say how an instruction is
//! encoded, or state MAX_MEM / MAX_STEPS / MAX_CODE. docs/RL.md contradicts it and
//! says the machine has 26. Those had to come from `src/obsign_verify/replay.py`, and
//! every one of them is listed in rust/README.md as a place the spec ran out -- a
//! third implementation cannot be written from the documents alone, which is itself
//! the most useful thing this exercise measured.
//!
//! WRAPPING IS ALWAYS SPELLED. The crate builds with `overflow-checks = true` even in
//! release, so an arithmetic overflow this file did not explicitly ask to wrap is a
//! panic in testing rather than a silent divergence in the field. Every `wrapping_*`
//! below is a deliberate statement about the format, not a way to quiet the compiler.

use crate::json::{canonical_sha256, Value};
use crate::sha2::{hex, sha256};

pub const SPEC: &str = "obsign/replay/1";

pub const INT64_MIN: i64 = i64::MIN;
pub const INT64_MAX: i64 = i64::MAX;

/// A receipt is a document, not a workload. These bound the work a hostile receipt can
/// demand; they are stated in `replay.py` and nowhere in docs/.
pub const MAX_MEM: usize = 1 << 20;
pub const MAX_STEPS: u64 = 50_000_000;
pub const MAX_CODE: usize = 1 << 16;

/// A refusal with a reason. Never allowed to escape as anything else -- a trap is a
/// verdict about the receipt, and a panic would be a verdict about the verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trap(pub String);

impl std::fmt::Display for Trap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

type T<X> = Result<X, Trap>;

fn trap<X>(msg: impl Into<String>) -> T<X> {
    Err(Trap(msg.into()))
}

/// How an instruction's operands are read. One table, so the validator and the
/// interpreter cannot drift into disagreeing about what an operand means.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    LoadC,
    Alu1,
    Alu2,
    Mulfx,
    Sel,
    Store,
    Jump,
    Jcc,
    Halt,
}

/// The 31 opcodes. COMPAT.md fixes the count; the names, arities and operand kinds are
/// not written down anywhere but the reference implementation.
const OPS: [(&str, usize, Kind); 31] = [
    ("LOADC", 2, Kind::LoadC),
    ("MOV", 2, Kind::Alu1),
    ("ADD", 3, Kind::Alu2),
    ("SUB", 3, Kind::Alu2),
    ("MUL", 3, Kind::Alu2),
    ("DIV", 3, Kind::Alu2),
    ("MOD", 3, Kind::Alu2),
    ("MIN", 3, Kind::Alu2),
    ("MAX", 3, Kind::Alu2),
    ("AND", 3, Kind::Alu2),
    ("OR", 3, Kind::Alu2),
    ("XOR", 3, Kind::Alu2),
    ("SHL", 3, Kind::Alu2),
    ("SHR", 3, Kind::Alu2),
    ("EQ", 3, Kind::Alu2),
    ("NE", 3, Kind::Alu2),
    ("LT", 3, Kind::Alu2),
    ("LE", 3, Kind::Alu2),
    ("GT", 3, Kind::Alu2),
    ("GE", 3, Kind::Alu2),
    ("MULFX", 4, Kind::Mulfx),
    ("SEL", 4, Kind::Sel),
    ("NEG", 2, Kind::Alu1),
    ("ABS", 2, Kind::Alu1),
    ("NOT", 2, Kind::Alu1),
    ("LOAD", 2, Kind::Alu1),
    ("STORE", 2, Kind::Store),
    ("JMP", 1, Kind::Jump),
    ("JMPZ", 2, Kind::Jcc),
    ("JMPNZ", 2, Kind::Jcc),
    ("HALT", 0, Kind::Halt),
];

fn lookup(op: &str) -> Option<(usize, Kind)> {
    OPS.iter().find(|(n, _, _)| *n == op).map(|(_, a, k)| (*a, *k))
}

/// One decoded instruction. Operands are `i64` because that is what the format says
/// they are; the validator has already proved each one indexes something real.
#[derive(Debug, Clone)]
struct Ins {
    op: &'static str,
    args: [i64; 4],
}

/// A program that has passed `validate`: every opcode known, every register index in
/// range, every jump target a real instruction, every constant an int64.
///
/// Validation is separate from execution so that `run` can be small and total. A
/// validator that ran alongside execution would have to be re-checked on every path.
#[derive(Debug, Clone)]
pub struct Program {
    pub mem: usize,
    pub steps: u64,
    pub consts: Vec<i64>,
    pub in_off: usize,
    pub in_len: usize,
    pub out_off: usize,
    pub out_len: usize,
    code: Vec<Ins>,
}

/// A STRUCTURAL integer: a memory size, a step budget, a window bound, an operand.
///
/// It must be a JSON integer literal. Reading a JSON `true` as 1 (which Python's
/// `bool` subclassing invites) or a JSON `4.0` as 4 (which any parser that keeps only
/// the value invites) each made one implementation load programs the other refused --
/// docs/COMPAT.md, "structural scalars are JSON integers, in both languages". Rust has
/// neither temptation, and the check is written out anyway so that the refusal is a
/// stated rule rather than an accident of the type system.
fn struct_int(v: Option<&Value>) -> Option<i64> {
    v?.as_int()?.as_i64()
}

pub fn validate(prog: &Value) -> T<Program> {
    if !matches!(prog, Value::Object(_)) {
        return trap("program must be a JSON object");
    }
    match prog.get("spec").and_then(|v| v.as_str()) {
        Some(s) if s == SPEC => {}
        other => {
            return trap(format!(
                "unknown program spec {:?}, expected {SPEC:?}",
                other.unwrap_or_default()
            ))
        }
    }
    for field in ["mem", "steps", "code", "consts", "input", "output"] {
        if !prog.has(field) {
            return trap(format!("program is missing {field:?}"));
        }
    }

    let mem = match struct_int(prog.get("mem")) {
        Some(m) if (1..=MAX_MEM as i64).contains(&m) => m as usize,
        _ => return trap(format!("mem must be an int in 1..{MAX_MEM}")),
    };
    let steps = match struct_int(prog.get("steps")) {
        Some(s) if (1..=MAX_STEPS as i64).contains(&s) => s as u64,
        _ => return trap(format!("steps must be an int in 1..{MAX_STEPS}")),
    };

    let consts_v = match prog.get("consts").and_then(|v| v.as_array()) {
        Some(c) if c.len() <= MAX_MEM => c,
        _ => return trap("consts must be a list"),
    };
    let mut consts = Vec::with_capacity(consts_v.len());
    for (i, c) in consts_v.iter().enumerate() {
        // A float in the constant pool is how a libm would sneak back into a machine
        // whose entire determinism argument is that there are no floats anywhere.
        let int = match c.as_int() {
            Some(n) => n,
            None => {
                return trap(format!(
                    "consts[{i}] is not an integer (floats are not representable)"
                ))
            }
        };
        match int.as_i64() {
            Some(v) => consts.push(v),
            None => return trap(format!("consts[{i}] does not fit in int64")),
        }
    }

    let window = |name: &str| -> T<(usize, usize)> {
        let spec = match prog.get(name) {
            Some(s) if matches!(s, Value::Object(_)) => s,
            _ => return trap(format!("{name} must be {{offset:int, length:int}}")),
        };
        let (off, len) = match (struct_int(spec.get("offset")), struct_int(spec.get("length"))) {
            (Some(o), Some(l)) => (o, l),
            _ => return trap(format!("{name} must be {{offset:int, length:int}}")),
        };
        if off < 0 || len < 0 || off.saturating_add(len) > mem as i64 {
            return trap(format!(
                "{name} window {off}..{} is outside mem ({mem})",
                off.saturating_add(len)
            ));
        }
        Ok((off as usize, len as usize))
    };
    let (in_off, in_len) = window("input")?;
    let (out_off, out_len) = window("output")?;
    if out_len == 0 {
        // Every zero-length output hashes the empty string, so all such programs would
        // share one output digest. That is a collision by construction.
        return trap("output length must be > 0");
    }

    let code_v = match prog.get("code").and_then(|v| v.as_array()) {
        Some(c) if !c.is_empty() && c.len() <= MAX_CODE => c,
        _ => {
            return trap(format!(
                "code must be a non-empty list of at most {MAX_CODE} instructions"
            ))
        }
    };

    let mut code: Vec<Ins> = Vec::with_capacity(code_v.len());
    for (pc, ins_v) in code_v.iter().enumerate() {
        let items = match ins_v.as_array() {
            Some(a) if !a.is_empty() => a,
            _ => return trap(format!("code[{pc}] is not an instruction")),
        };
        let op_name = match items[0].as_str() {
            Some(s) => s,
            None => return trap(format!("code[{pc}] is not an instruction")),
        };
        let (arity, kind) = match lookup(&op_name) {
            Some(x) => x,
            None => return trap(format!("code[{pc}] unknown opcode {op_name:?}")),
        };
        let args_v = &items[1..];
        if args_v.len() != arity {
            return trap(format!(
                "code[{pc}] {op_name} takes {arity} operand(s), got {}",
                args_v.len()
            ));
        }
        let mut args = [0i64; 4];
        for (n, a) in args_v.iter().enumerate() {
            match a.as_int().and_then(|i| i.as_i64()) {
                Some(v) => args[n] = v,
                None => return trap(format!("code[{pc}] {op_name} has a non-integer operand")),
            }
        }
        let in_mem = |a: i64| a >= 0 && a < mem as i64;
        match kind {
            Kind::LoadC => {
                if !in_mem(args[0]) {
                    return trap(format!("code[{pc}] {op_name} dst {} out of range", args[0]));
                }
                if args[1] < 0 || args[1] >= consts.len() as i64 {
                    return trap(format!(
                        "code[{pc}] {op_name} const index {} out of range",
                        args[1]
                    ));
                }
            }
            Kind::Jump | Kind::Jcc => {
                let target = args[arity - 1];
                if target < 0 || target >= code_v.len() as i64 {
                    return trap(format!(
                        "code[{pc}] {op_name} jumps to {target}, outside the program"
                    ));
                }
                for a in &args[..arity - 1] {
                    if !in_mem(*a) {
                        return trap(format!("code[{pc}] {op_name} register {a} out of range"));
                    }
                }
            }
            Kind::Mulfx => {
                for a in &args[..3] {
                    if !in_mem(*a) {
                        return trap(format!("code[{pc}] {op_name} register {a} out of range"));
                    }
                }
                if !(0..=63).contains(&args[3]) {
                    return trap(format!("code[{pc}] MULFX frac {} must be 0..63", args[3]));
                }
            }
            Kind::Halt => {}
            _ => {
                for a in &args[..arity] {
                    if !in_mem(*a) {
                        return trap(format!("code[{pc}] {op_name} register {a} out of range"));
                    }
                }
            }
        }
        let op_static = OPS.iter().find(|(n, _, _)| *n == op_name).unwrap().0;
        code.push(Ins { op: op_static, args });
    }

    Ok(Program { mem, steps, consts, in_off, in_len, out_off, out_len, code })
}

/// Truncate toward ZERO, like C and unlike Python's `//`.
///
/// Rust's `/` already truncates toward zero, so this exists to name the intent and to
/// keep the division-by-zero refusal in one place. `INT64_MIN / -1` overflows the
/// range and WRAPS to `INT64_MIN` rather than trapping, which is the one genuinely
/// nasty case and is pinned by a test.
fn trunc_div(a: i64, b: i64) -> T<i64> {
    if b == 0 {
        return trap("division by zero");
    }
    Ok(a.wrapping_div(b))
}

/// SHA-256 over the program's canonical JSON.
///
/// `params` carries the program and `params` is inside the claim, so the program
/// cannot be swapped without breaking `receipt_sha256`. Belt and braces on purpose:
/// the digest also gives a stranger a short string to compare with a published one.
pub fn program_sha256(prog: &Value) -> Option<String> {
    canonical_sha256(prog).ok()
}

/// Execute a validated program. Returns the output window and the instruction count.
///
/// The count is verifier-internal -- the cross-implementation contract is
/// (program, inputs) -> output bytes -- and exists so a caller can BOUND its own work
/// when it re-runs a program many times during liveness probing. `step_cap` lowers the
/// budget for this call only; hitting it raises the ordinary step-budget trap.
pub fn run_counted(prog: &Value, inputs: &[i64], step_cap: Option<u64>) -> T<(Vec<i64>, u64)> {
    let p = validate(prog)?;
    run_validated(&p, inputs, step_cap)
}

pub fn run_validated(p: &Program, inputs: &[i64], step_cap: Option<u64>) -> T<(Vec<i64>, u64)> {
    let mut mem = vec![0i64; p.mem];
    let budget = match step_cap {
        Some(c) => p.steps.min(c),
        None => p.steps,
    };

    if inputs.len() != p.in_len {
        return trap(format!(
            "program expects {} input(s), got {}",
            p.in_len,
            inputs.len()
        ));
    }
    for (i, v) in inputs.iter().enumerate() {
        mem[p.in_off + i] = *v;
    }

    let mut pc: i64 = 0;
    let mut steps: u64 = 0;
    let code = &p.code;
    loop {
        // Budget, then count, then the program-counter check -- the same order as the
        // reference, so a program that both exhausts its budget and runs off the end
        // traps for the same reason in every implementation.
        if steps >= budget {
            return trap(format!("step budget exhausted after {budget} steps"));
        }
        steps += 1;
        if pc < 0 || pc >= code.len() as i64 {
            return trap(format!("pc {pc} left the program"));
        }

        let ins = &code[pc as usize];
        let a = ins.args;
        pc += 1;

        match ins.op {
            "HALT" => break,
            "LOADC" => mem[a[0] as usize] = p.consts[a[1] as usize],
            "MOV" => mem[a[0] as usize] = mem[a[1] as usize],
            "NEG" => mem[a[0] as usize] = mem[a[1] as usize].wrapping_neg(),
            "ABS" => mem[a[0] as usize] = mem[a[1] as usize].wrapping_abs(),
            "NOT" => mem[a[0] as usize] = !mem[a[1] as usize],
            "LOAD" => {
                let addr = mem[a[1] as usize];
                if addr < 0 || addr >= mem.len() as i64 {
                    return trap(format!("LOAD address {addr} out of bounds"));
                }
                mem[a[0] as usize] = mem[addr as usize];
            }
            "STORE" => {
                let addr = mem[a[0] as usize];
                if addr < 0 || addr >= mem.len() as i64 {
                    return trap(format!("STORE address {addr} out of bounds"));
                }
                mem[addr as usize] = mem[a[1] as usize];
            }
            "JMP" => pc = a[0],
            "JMPZ" => {
                if mem[a[0] as usize] == 0 {
                    pc = a[1];
                }
            }
            "JMPNZ" => {
                if mem[a[0] as usize] != 0 {
                    pc = a[1];
                }
            }
            "SEL" => {
                mem[a[0] as usize] = if mem[a[1] as usize] != 0 {
                    mem[a[2] as usize]
                } else {
                    mem[a[3] as usize]
                }
            }
            "MULFX" => {
                // EXACT PRODUCT FIRST, THEN TRUNCATE, THEN WRAP. Multiplying in int64
                // and shifting afterwards would lose the high bits the shift exists to
                // discard -- the classic fixed-point porting bug, and the reason i128
                // is here. `as i64` on the i128 quotient is the wrap.
                let x = mem[a[1] as usize] as i128;
                let y = mem[a[2] as usize] as i128;
                let q = (x * y) / (1i128 << a[3]);
                mem[a[0] as usize] = q as i64;
            }
            other => {
                let x = mem[a[1] as usize];
                let y = mem[a[2] as usize];
                let v = match other {
                    "ADD" => x.wrapping_add(y),
                    "SUB" => x.wrapping_sub(y),
                    "MUL" => x.wrapping_mul(y),
                    "DIV" => trunc_div(x, y)?,
                    "MOD" => {
                        if y == 0 {
                            return trap("modulo by zero");
                        }
                        x.wrapping_rem(y)
                    }
                    "MIN" => {
                        if x < y {
                            x
                        } else {
                            y
                        }
                    }
                    "MAX" => {
                        if x > y {
                            x
                        } else {
                            y
                        }
                    }
                    "AND" => x & y,
                    "OR" => x | y,
                    "XOR" => x ^ y,
                    "SHL" | "SHR" => {
                        if !(0..=63).contains(&y) {
                            return trap(format!("{other} shift amount {y} must be 0..63"));
                        }
                        if other == "SHL" {
                            x.wrapping_shl(y as u32)
                        } else {
                            // Arithmetic shift: the sign bit replicates, which is what
                            // Python's `>>` on a negative int does too.
                            x.wrapping_shr(y as u32)
                        }
                    }
                    "EQ" => (x == y) as i64,
                    "NE" => (x != y) as i64,
                    "LT" => (x < y) as i64,
                    "LE" => (x <= y) as i64,
                    "GT" => (x > y) as i64,
                    "GE" => (x >= y) as i64,
                    _ => return trap(format!("unreachable opcode {other}")),
                };
                mem[a[0] as usize] = v;
            }
        }
    }

    Ok((mem[p.out_off..p.out_off + p.out_len].to_vec(), steps))
}

pub fn run(prog: &Value, inputs: &[i64]) -> T<Vec<i64>> {
    Ok(run_counted(prog, inputs, None)?.0)
}

/// Read the receipt's declared `inputs` as int64s.
///
/// A float, a boolean or an integer outside int64 is a REFUSAL, not a coercion: the
/// machine has no float, and `true` is not 1. Kept next to the VM because it is the
/// same rule the constant pool is held to.
pub fn read_inputs(inputs: &Value) -> T<Vec<i64>> {
    let arr = match inputs.as_array() {
        Some(a) => a,
        None => return trap("inputs must be a list"),
    };
    let mut out = Vec::with_capacity(arr.len());
    for (i, v) in arr.iter().enumerate() {
        match v.as_int() {
            None => return trap(format!("input[{i}] is not an integer")),
            Some(n) => match n.as_i64() {
                Some(x) => out.push(x),
                None => return trap(format!("input[{i}] does not fit in int64")),
            },
        }
    }
    Ok(out)
}

/// SHA-256 over the output as little-endian int64.
///
/// One hashing rule covers every kernel; length and dtype ride OUTSIDE this digest,
/// exactly as they do for the array kernel, so they are compared separately rather
/// than trusted.
pub fn output_sha256(values: &[i64]) -> String {
    let mut buf = Vec::with_capacity(values.len() * 8);
    for v in values {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    hex(&sha256(&buf))
}
