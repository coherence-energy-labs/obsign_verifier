# RL — the replay language

RL is a small language that compiles to `obsign/replay/1`, the deterministic int64
machine that travels inside a receipt. It exists so that authoring a provable
computation does not require hand-writing assembly — and it ships in this public
package, standard-library-only, so the author needs no more of a toolchain than the
verifier does.

```
// IFRS 9 expected credit loss, provable end to end
const S = 32;
fn ecl(pd: fx32, lgd: fx32, ead: fx0) { return mulfx(mulfx(pd, lgd, S), ead, S); }
input v[13];
let acc = 0;
for i in 0..v[0] {
  let base = i * 3 + 1;
  acc = acc + ecl(v[base], v[base + 1], v[base + 2]);
}
output acc;
```

```
$ obsign-replayc run cecl.rl -i "4,18038863,1932735283,..."   # compile + execute
$ obsign-replayc build cecl.rl -o prog.json                   # the program a receipt carries
$ obsign-replayc disasm prog.json                             # audit the bytecode
$ obsign-replayc attest cecl.rl --against receipt.json        # prove source == bytecode
```

## The model

Everything is a 64-bit two's-complement integer. Arithmetic **wraps**
(`INT64_MAX + 1` is `INT64_MIN`); division and `%` **truncate toward zero**; there
are **no floats anywhere** — a `1.5` in source is a syntax error, and fixed-point is
written explicitly with `mulfx`. Every partial operation is a **trap** — division by
zero, a shift outside 0..63, an out-of-range array index, an exhausted step budget —
and a trap is a refusal with a reason, never a wrong number.

Scalars read **0 until assigned on the executed path** (the machine's memory starts
zeroed; the language states it rather than leaving it to luck). There is no block
scoping: a `let` is visible from there to the end of the program.

## Declarations

```
#steps 100000            // optional budget pragma -- see "The step budget"
const N = 3;             // compile-time constant; usable in lengths, bounds, fracs
input a, b: fx32;        // scalar inputs, in window order, optionally scale-annotated
input v[13];             // OR the whole input window as one array (not both)
arr m[N]: fx32;          // a zero-initialized array, optionally scale-annotated
fn f(x, y: fx32) { ... return expr; }   // see "Functions"
output expr, expr;       // the output window, in order -- required, last
```

## Statements

```
let x = expr;            let x: fx32 = expr;      // introduce (or re-introduce)
x = expr;                                          // assign an existing scalar
m[i] = expr;                                       // array store (bounds-trapped)
if cond { ... } else { ... }
while cond { ... }
for i in lo..hi { ... }                            // upper-exclusive; bounds eval once
break;  continue;                                  // innermost loop only
```

`for` bounds are evaluated **once**, before the first iteration. The loop variable is
an ordinary scalar the body may assign — the assignment affects iteration, because
the machine increments the variable's cell. `continue` in a `for` lands on the
increment.

## Expressions

Operators, loosest to tightest: `|` `^` `&` — `==` `!=` — `<` `<=` `>` `>=` —
`<<` `>>` — `+` `-` — `*` `/` `%` — unary `-` `~`. Comparisons yield 0 or 1, so
boolean logic is bitwise (`a < b & c < d`); there is no short-circuit operator —
short-circuit is control flow, and control flow is spelled `if`.

Builtins: `min(a,b)` `max(a,b)` `abs(x)` `sel(c,a,b)` (both arms are evaluated; `c`
picks) `mulfx(x,y,F)` (exact 128-bit product, truncate toward zero by 2^F, wrap —
the fixed-point multiply) `len(arr)` (a compile-time constant).

Integer literals: decimal or `0x` hex, with `_` separators. All literals fit int64
or fail to compile.

## Functions

```
fn clamp(x, lo, hi) { return min(max(x, lo), hi); }
```

Functions are **closed**: a body sees only its parameters and its own `let`s — no
globals, no arrays, no inputs. A call is therefore a pure int64 computation, which is
what lets the compiler inline it (the machine has no call stack) and the reference
interpreter execute it natively as an independent check. **Recursion, direct or
mutual, is a compile error** — totality by construction, the same property the
machine itself is built on. The single `return` must be the final statement.

## Fixed-point scales (opt-in)

Annotate values with `: fxN` (N in 0..63; `fx0` means "definitely a plain integer")
and the compiler enforces the units algebra:

| expression                     | result / verdict                                   |
|--------------------------------|----------------------------------------------------|
| `fx32 + fx32`, `-`, `%`, `min/max` | `fx32`                                          |
| `fx32 + fx16`                  | **compile error** — different units                |
| `fx32 * plain-int`             | `fx32` (scaling by a count)                        |
| `fx32 * fx32`                  | **compile error** — the product is fx64; use `mulfx` |
| `fx32 / fx32`                  | `fx0` (a pure ratio)                               |
| `mulfx(fx32, fx32, 32)`        | `fx32` (the compiler checks a+b−F stays in 0..63)  |
| `fx32 << 3`, `fx32 & m`, `~fx32` | **compile error** — bit ops silently change scale |

Unannotated values are polymorphic (compatible with anything, refined by first
concrete use); a program with no annotations skips the checker entirely. This is a
static safety net over a runtime that is already bit-exact — it catches the wrong-unit
bug that re-execution, by design, cannot.

## The step budget

`steps` is a security parameter: it is what stops a hostile receipt from hanging a
verifier. When every loop in a program is statically bounded (`for` with constant
bounds, body not writing its own loop variable, no `while`), the compiler **computes
the exact worst-case instruction count and writes it as the budget** — pinned by tests
that run at the inferred budget and trap at budget−1. An explicit `#steps` always
wins; a program with a `while` must either declare one or accept the hard ceiling
(50,000,000).

## How the compiler earns trust

A wrong compiler would mint receipts that faithfully reproduce the wrong number, so
correctness is established differentially, never asserted. The package carries **two
independent lowerings** of every construct: the compiler (inline → fold → optimize →
emit) and a reference interpreter that tree-walks the checked AST, executing calls
natively — they share only the parse/check front half, which can only *reject*.
The suite proves, per operator, `VM == interpreter == an independently written spec`
over an adversarial int64 edge grid; that traps land in both lowerings at the same
places; that thousands of randomly generated programs agree on the Python VM, the
JavaScript VM and the interpreter; and — the anchor no self-consistency can fake —
that a real, hand-authored production receipt's output hash is regenerated to the
byte from the RL source in `examples/rl/cecl.rl`.

Compilation is deterministic (same source → same bytes), which is what makes
`attest` a proof rather than a heuristic: recompile the source, compare digests, and
a receipt's bytecode is tied to readable source anyone can audit.

## Limits, stated plainly

The machine has 31 opcodes, one flat int64 memory of at most 2^20 cells, at most 2^16
instructions, a hard ceiling of 50,000,000 steps, and no call stack — so no recursion,
no dynamic allocation, no strings, no I/O, and `mulfx` is the only widening operation
(there is no 128-bit divide, hence no `divfx`). These are the *machine's* limits;
changing them is a receipt-format revision across four implementations, not a compiler
feature.

The instruction set itself — every opcode by name, arity and exact semantics — is
`docs/SPEC.md#the-instruction-set`, and the machine-readable table it renders is
`docs/spec/opcodes.json`. The sentence above read "26" for the entire life of a
31-opcode machine, in a section titled *stated plainly*, while `docs/COMPAT.md` said 31
three files away. Prose cannot hold a number still, so the count is now extracted from
this document and from COMPAT.md and compared against the reference table by
`tests/test_spec_constants_match_code.py`: the check fails if either document is wrong,
and it also fails if either stops stating a count at all.
