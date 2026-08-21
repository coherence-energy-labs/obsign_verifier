# SPEC — the normative specification of an Obsign receipt

This is the document a fourth implementation is written from. Everything a conforming
verifier must do is here; nothing here needs `src/`, `js/`, or `rust/` to be read
first.

That is not a style preference. `rust/README.md` records what happened when a third
implementation was attempted from the documents alone: it could not be done, and the
author had to read `src/obsign_verify/*.py` for thirteen separate rules — the opcode
table, the instruction encoding, the receipt schema, the six wire limits, the
duplicate-member refusal, the input-liveness algorithm, `MAX_CODE`, step accounting,
the definition of `program_sha256`, the signature block, the Ed25519 equation and the
out-of-claim key list. Each of those is a place two people reading only `docs/` could
implement differently and both believe they conform. `docs/COMPAT.md` calls exactly
that class of disagreement the one this format cannot absorb, because *a forger hands
the receipt to whichever implementation loads it*.

**Status.** Normative for `obsign/receipt/v1`, `obsign/replay/1` and
`obsign/signature/v2`, as implemented on this branch. Where a rule is stated here and
an implementation disagrees, the implementation is wrong unless it is named in
[Conformance](#conformance) — and every disagreement known at the time of writing is
named there rather than smoothed over. Where the code is genuinely undecided, the
question is in [Open questions](#open-questions) rather than resolved by guessing;
inventing an answer here would be worse than admitting the gap, because a reimplementer
would then conform to something no shipped verifier does.

**The numbers are not in the prose.** Every numeric constant this document states lives
in [`docs/spec/limits.json`](spec/limits.json), and every opcode row lives in
[`docs/spec/opcodes.json`](spec/opcodes.json).
`tests/test_spec_constants_match_code.py` holds both files to the Python reference by
import and to the JavaScript and Rust ports by reading their source. `docs/RL.md`
understated the opcode count by five for the entire life of this machine, in a section
titled *Limits, stated plainly*, while `docs/COMPAT.md` had it right three files away;
prose cannot hold a number still, so it is no longer asked to. The same test extracts
the count from this document too.

---

## The five contracts

A verifier is five independent contracts stacked. Each has its own version string, and
each can be conformed to without the ones above it.

| # | Contract | Question | Version | Broken by |
|---|---|---|---|---|
| 1 | [WIRE](#1-wire--what-a-receipt-is) | What bytes are a receipt at all? | canonical JSON, frozen | a document that loads in one implementation and not another |
| 2 | [CLAIM](#2-claim--what-the-hash-covers) | What did this file assert, and is it intact? | `obsign/receipt/v1` | a claim boundary that moves |
| 3 | [EXECUTION](#3-execution--re-deriving-the-number) | Does the number re-derive here? | `obsign/replay/1`, `tau_field_fixed` | one bit of arithmetic difference |
| 4 | [ATTRIBUTION](#4-attribution--who-signed-it) | Who signed it, and what did the signature cover? | `obsign/signature/v2` | a name attributed that the signature did not cover |
| 5 | [AUTHORITY](#5-authority--out-of-scope) | *Should* you trust that key? | — | **out of scope, deliberately** |

Contracts 1–4 are all cryptographic or arithmetic questions with one right answer on
every machine. Contract 5 is a social question, and a verifier that answered it from a
bundled list would be asserting a social fact as a cryptographic one.

### Conformance language

**MUST** / **MUST NOT** are refusals: a conforming verifier that meets the condition
does not report `verified`. **REFUSE** means the same and names the direction — the
refusal is a verdict, never an exception that escapes to the caller. **UNSUPPORTED** is
a third answer, distinct from both: *I do not know what these bytes mean*, which is
never spelled *invalid*. Collapsing UNSUPPORTED into either pass or fail is how a
verifier starts lying, and `docs/COMPAT.md` freezes the distinction.

A verifier **MUST NOT raise** on any input. A crash on hostile input has failed open in
the eyes of whoever handed you the file.

---

## 1. WIRE — what a receipt IS

The wire format is not "valid JSON". Valid JSON is not one thing across languages, and
every place two parsers disagree about what *loads* is a place one implementation
verifies a document another cannot read. This section closes that, limit by limit.

Everything in this section is enforced **before any semantic verification**, on the raw
text.

### Encoding

A receipt is a **UTF-8** encoded JSON document, per RFC 8259 with the restrictions
below. There is no BOM allowance; there is no other encoding.

**Decoding MUST be strict. A byte sequence that is not valid UTF-8 is REFUSED, never
repaired.** This is a wire rule and not a convenience: Node's
`readFileSync(f, "utf8")` and the browser's `FileReader` substitute U+FFFD for every
invalid byte instead of failing, so the three distinct files `{"a":"\xff"}`,
`{"a":"\x80"}` and `{"a":"\xc3"}` arrived as **one string, one canonical form, one
`receipt_sha256`** — which destroys the defining property of a canonical form one layer
*above* every limit either parser checks. A conforming reader takes **bytes** and decodes
fatally (`TextDecoder({fatal: true})`, Python's default strict `decode`), or it takes
text a fatal decoder produced.

### The six wire limits

Every one is a hard refusal, and all six are part of the format — changing one is a
spec decision, not an implementation's private opinion. Values are normative in
[`limits.json`](spec/limits.json).

| Limit | Value | Applies to |
|---|---|---|
| `MAX_RECEIPT_BYTES` | 4 194 304 (`4 * 1024 * 1024`) | the whole document, in UTF-8 bytes, checked **before parsing** |
| `MAX_DEPTH` | 32 | containers entered — see below |
| `MAX_MEMBERS_PER_OBJECT` | 1 024 | members of any one object |
| `MAX_ARRAY_LENGTH` | 1 048 576 (`1 << 20`) | elements of any one array |
| `MAX_STRING_BYTES` | 65 536 | any string value **and any object key**, in UTF-8 bytes |
| `MAX_INT_DIGITS` | 4 300 | decimal digits of an integer literal, sign excluded |

The size check comes first because everything after it walks the document: the cheapest
refusal must come before any parsing work is done on an unbounded input.

`MAX_INT_DIGITS` is exactly CPython's default int-string conversion limit
(`sys.set_int_max_str_digits`). It is 4 300 for that reason and no other: a 5 000-digit
literal once loaded in JavaScript and was refused in Python, and matching CPython's
number is what makes the two agree. The sign is not a digit — `-` followed by 4 300
digits loads.

All six are roughly 100× the largest shipped receipt (depth 5, 11 members, 35-element
arrays, 128-byte strings, 10-digit integers, 3 KB), so they bound hostile input without
coming near an honest document.

*Source: `MAX_*` in `src/obsign_verify/canonical.py`, `js/src/canonical.js`,
`rust/src/json.rs`.*

### Depth counts containers entered

`MAX_DEPTH` bounds **the number of containers entered**, not the depth a value sits at.
The top-level object is container 1.

The witness that separates the two readings, and the reason this is stated rather than
left to a parser's habit:

```json
{"a":{"a": … 30 more … {}}}
```

A document of **32 nested containers loads. A document of 33 is REFUSED** — whatever
sits at the bottom, and *especially* when the innermost container is empty. Under the
old value-depth reading a 33-container document whose innermost container held nothing
carried 33 containers in one implementation and a maximum value depth of 32 in another:
one document, two answers about whether it exists. Which number is a spec choice; that
the three implementations disagreed was the defect.

A verifier whose own parser hits a recursion limit before reaching this check MUST turn
that into an ordinary refusal, not a crash. The Python reference catches `RecursionError`
out of `json.loads` and re-raises it as a wire-format error for exactly this reason.

*Source: `_check_shape` and `load_receipt` in `src/obsign_verify/canonical.py`.*

### Duplicate members and object-model keys

**Duplicate object members are REFUSED outright, not resolved.** Last-value-wins is a
parser convention, not a guarantee: downstream JSON readers — security appliances, log
pipelines, other languages — do not all share it, so a document containing `"a"` twice
is a document two readers disagree about the contents of. `{"a":1,"a":2}` is not a
receipt.

**An object member named `__proto__`, `constructor` or `prototype` is REFUSED**, at any
depth, anywhere in the document. Python has no object-model problem, which is precisely
why this rule must live in the Python reference too: assigning such a name in JavaScript
reparents or shadows the receiving object rather than storing data, and a JavaScript
verifier once reported `VERIFIED` on a receipt whose `params.program` was carried
entirely on a prototype — a document with no own `spec`, `mem`, `steps` or `code`
members at all — while the reference could not read it. The refusal is at the parser,
and the replay validator refuses the same three names again on the already-parsed
structure, because a program can reach it through a caller with its own loader.

*Source: `_OBJECT_MODEL_KEYS` and `_no_duplicate_members` in
`src/obsign_verify/canonical.py`; the second layer is `validate` in
`src/obsign_verify/replay.py`.*

### Lone surrogates

**A string containing an unpaired surrogate is REFUSED**, whether it appears as a value
or as an object key. An unpaired surrogate has no UTF-8 encoding at all, so
implementations disagree about whether the document exists.

A surrogate is *paired* when a high surrogate (U+D800–U+DBFF) is immediately followed by
a low surrogate (U+DC00–U+DFFF). A high not followed by a low, a low not preceded by a
high, and a high at the end of the string are all lone.

This is stated because it used to be inherited. CPython refused these **by accident**,
via a `UnicodeEncodeError` escaping the string-length check — so the refusal moved
whenever that check did and carried no explanation, and both JavaScript parsers accepted
them. A rule this load-bearing is stated, not inherited from an exception.

*Source: `_has_lone_surrogate` in `src/obsign_verify/canonical.py`.*

### Non-finite numbers and integer literals

`NaN`, `Infinity` and `-Infinity` as **bare tokens** are REFUSED. RFC 8259 forbids them;
CPython's `json` accepts them by default, and without an explicit refusal a receipt
carrying `"env": {"x": NaN}` verified in Python while two JavaScript verifiers could not
parse it.

A **float literal that evaluates to a non-finite double** — `1e400` is the canonical
example — is REFUSED at parse. It does not go through the bare-token path: a permissive
parser reads it straight to `inf`, which has no canonical form.

These refusals apply **everywhere in the document, including fields outside the claim**.
`env` does not change the receipt hash; the point is that all implementations must agree
on what LOADS.

An integer literal is refused if it carries more than `MAX_INT_DIGITS` digits.

### The top level must be an object

The top level of a receipt MUST be a JSON object. An array, string, number, boolean or
`null` at the top level is not a receipt.

### The canonical form

The canonical form is **exactly** CPython's

```python
json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
           allow_nan=False).encode("utf-8")
```

Spelled out, so it can be reimplemented rather than imported:

- **Keys sorted by Unicode code point.** Not by UTF-16 code unit. The two differ: an
  astral key's lead surrogate (U+D800–U+DBFF) sorts *below* a BMP key in U+E000–U+FFFF
  by code unit and *above* it by code point. All three implementations sort by code
  point deliberately.
- **No whitespace at all** — `,` and `:` as separators, nothing around them.
- **`ensure_ascii`**: every character above U+007F is escaped as `\uXXXX`, lowercase hex.
  A character outside the BMP is escaped as a **surrogate pair** — U+1F600 becomes the
  six-plus-six sequence `😀`, never a single `\U0001f600`.
- **`allow_nan=False`** is load-bearing rather than tidiness: NaN and Infinity have no
  JSON representation, so permitting them would let two different receipts share one
  canonical form.
- **Strings** otherwise follow CPython's escaping: `\"`, `\\`, `\b`, `\f`, `\n`, `\r`,
  `\t` for those characters, `\u00XX` for other control characters, and the raw
  character for everything else in ASCII.
- **`true`, `false`, `null`** are spelled as JSON spells them.

### The integer versus float rule

**`1` and `1.0` are different values, canonicalise to different bytes, and therefore
hash differently.** This is the single trap the format spends most of its budget on.

- An **integer** is written in decimal with no decimal point and no exponent, `-` for
  negative, no leading zeros, no `+`. Python's `int` is unbounded; the wire bounds it at
  `MAX_INT_DIGITS`.
- A **float** is written as CPython's `repr` of the double. That is the **correctly
  rounded shortest decimal that round-trips** — not merely *a* shortest one, which is
  the distinction that broke the Rust port's first float formatter
  (`2211529743968985.3` where CPython and JavaScript both produce `…85.2`; both strings
  read back as the same double, and only one of them is CPython's answer).
  - Exponential notation is used below `1e-4` and at or above `1e16`, and not between.
  - The exponent carries an explicit sign and is padded to **two digits**: `1e+16`,
    `1e-05`.
  - A whole-valued float keeps its `.0`: `1.0`, not `1`.
  - `-0.0` is preserved as `-0.0`.

A reader that erases the distinction — notably JavaScript's `JSON.parse`, where every
number is a double — will canonicalise `gamma: 0.0` as `0` and report an honest receipt
as tampered, confidently, for a reason its author would never think to look for. A
conforming parser must therefore **remember, per literal, whether it was written as an
integer or a float**, because that information exists nowhere else once the value is a
double.

The same rule forbids repairing a value the other way. `1.0` inside a program hashes as
`1.0`; re-typing whole-valued floats as integers before canonicalising changes the
program's identity and makes an honest receipt report a digest mismatch.

*Source: `canonical_bytes` in `src/obsign_verify/canonical.py`;
`docs/COMPAT.md` freezes it.*

---

## 2. CLAIM — what the hash covers

### The receipt schema

A receipt is a JSON object. These are the keys the format defines. **Unknown top-level
keys are legal and land inside the claim by default**, which is the safe direction —
they are covered, not ignorable.

| Key | Type | In claim | Read by the verifier |
|---|---|---|---|
| `spec` | string | yes | **yes** — must be `"obsign/receipt/v1"`; see [RECEIPT-SPEC](#receipt-spec) |
| `kernel` | string | yes | **yes** — selects the execution path |
| `params` | object | yes | **yes** — the computation's inputs; shape depends on `kernel` |
| `output` | object | yes | **yes** — the claimed result |
| `input` | object | yes | tau path only, and only `input.sha256` |
| `receipt_sha256` | string | **no** | **yes** — the hash itself |
| `signature` | object | **no** | **yes** — see [ATTRIBUTION](#4-attribution--who-signed-it) |
| `case` | object | **no** | as an out-of-claim fact; see [Out-of-claim facts](#out-of-claim-facts) |
| `env` | object | **no** | no — informational only |
| `producer` | object | yes | no |
| `run` | object | yes | no |
| `_`-prefixed | any | **no** | no |

**`output`** — the claimed result block:

| Key | Type | Checked |
|---|---|---|
| `sha256` | string | **yes**, against the re-derived output digest |
| `length` | integer, or absent | replay path: **yes**, and it MUST be a JSON integer — see below |
| `shape` | array of integers | tau path: **yes**, against the re-executed array's shape |
| `dtype` | string | tau path: **yes**, against the re-executed array's dtype |
| `units` | string | no — informational, and inside the claim |

`output.length` MUST be a **JSON integer** when present. Not a boolean, not a float. The
reference once compared it with a membership test (`in (None, len(out))`), and Python
says `True == 1` and `1.0 == 1`, so `"length": true` VERIFIED over a one-element output
in Python while the JavaScript and Rust ports refused the same bytes. A count is an
integer; a boolean is not a count.

**`params` for `kernel: "obsign/replay/1"`**:

| Key | Type | Required | Checked |
|---|---|---|---|
| `program` | object | yes | **yes** — see [EXECUTION](#3-execution--re-deriving-the-number) |
| `inputs` | array of integers | yes | **yes** — the program's declared input window |
| `program_sha256` | string, or absent | no | **yes when present** — see [Program identity](#program-identity) |
| `links` | array of link objects | no | `--chain` only — see `docs/GRAPHS.md` |
| `note` | string | no | no |

**`params` for `kernel: "tau_field_fixed"`**: `grid`, `steps`, `frac_bits` (integer,
default 24), `sources` (array of 4-element `[cx, cy, strength, width]` arrays), `D`,
`gamma`, `dt`. See [The tau_field_fixed envelope](#the-tau_field_fixed-envelope).

**`input`** — `kind`, `ref`, `sha256`. Only `sha256` is read, and only on the tau path;
a `null` there means the input is params-derived and carries no separate fingerprint by
design, because `params` is already inside the claim.

### The claim rule and integrity

**The claim is every top-level key except `receipt_sha256`, `env`, `signature`, `case`,
and every key whose name begins with `_`.**

```
claim(receipt) = { k: v  for k, v in receipt
                   if k not in ("receipt_sha256", "env", "signature", "case")
                   and not k.startswith("_") }
```

**`receipt_sha256` is the SHA-256, in lowercase hex, of the canonical JSON of the
claim.** This rule never changes; `docs/COMPAT.md` freezes it.

**Integrity** is step 1 of the ladder:

1. `receipt_sha256` MUST be present and a non-empty string. Absent, or not a string:
   integrity fails with *no receipt_sha256 to check against*.
2. The claim MUST canonicalise. A claim that cannot (a value with no canonical form)
   fails integrity rather than raising.
3. The recomputed digest MUST equal the stated one, compared as strings.

`env`, `signature` and `case` are excluded because they are informational or post-hoc: a
verifier that hashed them would report a genuine receipt as tampered the moment anyone
recorded a different platform. `_`-prefixed keys are helpers. The consequence is stated
plainly in [Out-of-claim facts](#out-of-claim-facts): everything outside the claim is
attested by nothing unless a signature binds it.

*Source: `NON_CLAIM`, `claim_of`, `integrity` in `src/obsign_verify/canonical.py`.*

### RECEIPT-SPEC

> **A receipt's `spec` MUST equal the exact string `"obsign/receipt/v1"`. Anything else
> — a different version, a non-string, or an absent field — is UNSUPPORTED, which is
> never spelled *invalid*.**

An UNSUPPORTED receipt:

- sets `unsupported: true` in the result and `verified: false`;
- is **not** re-executed under v1 semantics, because nothing here knows what those bytes
  claim, what their `params` schema is or where their claim boundary lies;
- is **not** accused of anything — no note calls it forged, tampered or invalid;
- still has its signature evaluated, because *who signed this file* is answerable
  without knowing what the file means. That can only ever attribute, never verify.

This is the first decision in verification and it comes **before kernel selection**. It
used to not be asked at all: the ladder dispatched on `kernel` alone, so a document
declaring `spec: "obsign/receipt/v99"` was interpreted under today's semantics and could
be reported `VERIFIED`.

*Implemented on this branch by the protocol change of 2026-08-20. Source:
`RECEIPT_SPEC_V1` and `verify` in `src/obsign_verify/verify.py`.*

---

## 3. EXECUTION — re-deriving the number

Two kernels exist. `kernel` selects between them, and an unrecognised kernel is reported
as not re-executable — never quietly treated as a pass.

| `kernel` | What it is | Where the program lives |
|---|---|---|
| `obsign/replay/1` | a deterministic int64 machine | **inside the receipt** |
| `tau_field_fixed` | a fixed-point screened-diffusion field | reimplemented in the verifier |

### Program shape and static validation

A `obsign/replay/1` program is a JSON object with exactly these members required:

| Member | Type | Constraint |
|---|---|---|
| `spec` | string | MUST equal `"obsign/replay/1"`; anything else is a TRAP naming the unknown spec |
| `mem` | integer | `1 <= mem <= MAX_MEM` (1 048 576) |
| `steps` | integer | `1 <= steps <= MAX_STEPS` (50 000 000) |
| `consts` | array | of integers in int64; at most `MAX_MEM` entries |
| `input` | object | `{offset: int, length: int}` |
| `output` | object | `{offset: int, length: int}` |
| `code` | array | non-empty, at most `MAX_CODE` (65 536) instructions |

Unknown members of a `program` object are **legal** — and they are covered by
`program_sha256`, so a stray value inside one changes the program's identity. The three
object-model names are refused here as well as at the parser.

**Structural scalars are JSON integers.** `mem`, `steps`, both window `offset`s and
`length`s, and every instruction operand MUST be written as an integer literal — not a
boolean, not a float. Python reads a JSON `true` as `1` if asked naively (`bool`
subclasses `int` there) and a naive JavaScript port reads `4.0` as `4`; each
implementation loaded programs the other refused, in opposite directions. Both refuse
both now.

Static validation, all of it **before a single instruction executes**:

- both windows: `offset >= 0`, `length >= 0`, `offset + length <= mem`;
- `output.length` MUST be `> 0`. A program that outputs nothing hashes the empty string,
  and every such program would share one output digest — a collision by construction;
- every `consts[i]` is an integer in `[INT64_MIN, INT64_MAX]`, and **not** a boolean;
- every instruction is a non-empty array whose first element is a **string** opcode;
- the opcode is in the table, and the operand count equals its arity **exactly**;
- every operand is an integer (not a boolean), and in range for its kind — see
  `validation_by_kind` in [`opcodes.json`](spec/opcodes.json).

Static rejection is what lets execution be small and total: by the time it starts, every
opcode is known, every register index is in range, every jump target is a real
instruction and every constant is an int64.

*Source: `validate` and `MAX_*` in `src/obsign_verify/replay.py`.*

### Instruction encoding

**An instruction is a JSON array whose first element is the opcode NAME — a string — and
whose remaining elements are JSON integer operands.**

```json
["ADD", 2, 0, 1]
["MULFX", 4, 2, 3, 32]
["HALT"]
```

There is no numeric opcode encoding anywhere in the format. The `number` column in
[`opcodes.json`](spec/opcodes.json) is the row's ordinal in the canonical table and
exists so this document and the reference cannot drift; **it never appears in a
receipt**.

Operand kinds:

| Kind | Meaning | Validated to |
|---|---|---|
| `reg` | a memory cell index | `0 <= r < mem` |
| `const` | an index into `consts` | `0 <= k < len(consts)` |
| `target` | an instruction index | `0 <= t < len(code)` |
| `frac` | a fixed-point shift | `0 <= f <= 63` |

Memory is one flat array of `mem` int64 cells, **zero-initialised**. There are no
registers distinct from memory: a "register operand" is a cell index. Before execution,
`inputs[i]` is written to cell `input.offset + i`; after `HALT`, the output is
`mem[output.offset : output.offset + output.length]`.

The number of supplied `inputs` MUST equal `input.length` exactly — too few or too many
is a TRAP, not a pad or a truncation. Each input MUST be an integer (not a boolean)
inside int64.

### The instruction set

The machine has **31 opcodes**. The normative table, with arity, operand kinds and exact
semantics, is [`docs/spec/opcodes.json`](spec/opcodes.json); it is held equal to the
reference's table, row for row, by `tests/test_spec_constants_match_code.py`. Summarised:

| # | Name | Arity | Operands | Semantics |
|---|---|---|---|---|
| 0 | `LOADC` | 2 | dst, k | `mem[dst] = consts[k]` |
| 1 | `MOV` | 2 | dst, a | `mem[dst] = mem[a]` |
| 2 | `ADD` | 3 | dst, a, b | `wrap(a + b)` |
| 3 | `SUB` | 3 | dst, a, b | `wrap(a - b)` |
| 4 | `MUL` | 3 | dst, a, b | `wrap(a * b)`, product formed exactly first |
| 5 | `DIV` | 3 | dst, a, b | TRAP if `b == 0`; else `wrap(trunc(a / b))`, **toward zero** |
| 6 | `MOD` | 3 | dst, a, b | TRAP if `b == 0`; else `wrap(a - trunc(a / b) * b)` — sign of the **dividend** |
| 7 | `MIN` | 3 | dst, a, b | signed minimum |
| 8 | `MAX` | 3 | dst, a, b | signed maximum |
| 9 | `AND` | 3 | dst, a, b | bitwise `&` on two's complement |
| 10 | `OR` | 3 | dst, a, b | bitwise `\|` |
| 11 | `XOR` | 3 | dst, a, b | bitwise `^` |
| 12 | `SHL` | 3 | dst, a, b | TRAP unless `0 <= b <= 63`; else `wrap(a << b)` |
| 13 | `SHR` | 3 | dst, a, b | TRAP unless `0 <= b <= 63`; else `wrap(a >> b)`, **arithmetic**, floors |
| 14–19 | `EQ` `NE` `LT` `LE` `GT` `GE` | 3 | dst, a, b | `1` or `0`, signed comparison |
| 20 | `MULFX` | 4 | dst, a, b, frac | `wrap(trunc((a * b) / 2**frac))` — **exact, then truncate, then wrap** |
| 21 | `SEL` | 4 | dst, cond, a, b | `mem[a]` if `mem[cond] != 0` else `mem[b]`; both arms read |
| 22 | `NEG` | 2 | dst, a | `wrap(-a)` |
| 23 | `ABS` | 2 | dst, a | `wrap(abs(a))` |
| 24 | `NOT` | 2 | dst, a | `wrap(~a)` |
| 25 | `LOAD` | 2 | dst, addr | TRAP unless `0 <= mem[addr] < mem`; else `mem[dst] = mem[mem[addr]]` |
| 26 | `STORE` | 2 | addr, src | TRAP unless `0 <= mem[addr] < mem`; else `mem[mem[addr]] = mem[src]` |
| 27 | `JMP` | 1 | target | `pc = target` |
| 28 | `JMPZ` | 2 | cond, target | branch if `mem[cond] == 0` |
| 29 | `JMPNZ` | 2 | cond, target | branch if `mem[cond] != 0` |
| 30 | `HALT` | 0 | — | stop; read the output window. **Costs one step.** |

Three of these are where ports go wrong, so they are spelled out:

- **`MULFX` is the fixed-point multiply, and the ORDER is the specification.** Form the
  product **exactly** (128 bits suffice for any int64 pair), **then** truncate toward
  zero by `2**frac`, **then** reduce into int64. Multiplying in int64 and shifting
  afterwards loses exactly the high bits the shift exists to discard — the classic
  fixed-point porting bug, and reintroducing it makes seven cases of the shipped
  differential grid diverge immediately. Truncating with an arithmetic right shift is a
  second, subtler error: the shift *floors*, and for a negative product the two differ
  (`-3 >> 1` is `-2`; truncation gives `-1`). `frac` is validated to 0..63, so `MULFX`
  cannot trap.
- **`SHR` is the one place the machine floors.** It is an arithmetic shift: the sign bit
  propagates. `DIV` exists separately precisely because it truncates.
- **`STORE`'s operand order is `addr, src`** — the address register first.

### Arithmetic

Everything is **wrapping two's-complement int64**, stated rather than assumed:
`INT64_MAX + 1` is `INT64_MIN`. There are **no floating-point values anywhere** — not in
the ops, not in the operands, not in the constant pool — so there is no libm and no
platform-dependent rounding to worry about.

The edges, each measured against the reference:

| Expression | Result |
|---|---|
| `ADD(INT64_MAX, 1)` | `INT64_MIN` |
| `MUL(INT64_MAX, 2)` | `-2` |
| `DIV(INT64_MIN, -1)` | `INT64_MIN` — leaves the range and WRAPS; it does **not** trap |
| `NEG(INT64_MIN)` | `INT64_MIN` |
| `ABS(INT64_MIN)` | `INT64_MIN` — `2**63` has no int64, so it wraps |
| `DIV(-7, 2)` | `-3` — toward zero, not `-4` |
| `MOD(-7, 2)` | `-1`; `MOD(7, -2)` is `+1` — sign follows the dividend |
| `SHR(-3, 1)` | `-2` — floors |
| `SHL(1, 63)` | `INT64_MIN` |

A port to a language with native `i64` must reproduce all of these. `ABS(INT64_MIN)` in
particular is where a native `abs` panics or invokes undefined behaviour rather than
wrapping.

**Determinism is structural, not promised.** There is no clock, no randomness, no
environment, no I/O, no allocation, no indirect call and no host escape — not restricted,
*absent from the instruction set*. Every operation is total: division by zero, an
out-of-range shift, an out-of-bounds address and an exhausted step budget are all traps.

### Step accounting

The execution loop, in the order that decides trap-for-trap equivalence at the boundary:

```
pc = 0 ; steps = 0
loop:
    if steps >= budget:            TRAP "step budget exhausted after {budget} steps"
    steps += 1
    if not (0 <= pc < len(code)):  TRAP "pc {pc} left the program"
    instruction = code[pc] ; pc += 1
    dispatch
```

The three answers this pins down, none of which was written down before:

- **`HALT` costs one step.** A program consisting of exactly one `HALT` retires 1 step,
  and a program declaring `steps: 1` that is one `HALT` **completes**.
- **The budget is checked BEFORE the instruction**, against the count already retired. A
  two-instruction program declaring `steps: 1` traps at the second instruction with 1
  step retired.
- **Running off the end of `code` costs a step.** The counter is incremented before the
  pc range check, so a one-instruction program with no `HALT` traps with **2** steps
  retired, not 1.

The retired-step count travels with a trap. It is verifier-internal — the
cross-implementation contract is `(program, inputs) -> output bytes` — but it is not
free to get wrong: the [liveness probe](#the-input-liveness-probe) charges itself for
refused runs, and charging the step *cap* instead over-bills a refusal that happened on
instruction three by five orders of magnitude. An over-billed budget runs out and reports
`indeterminate`, **which does not refuse**, in place of the `guarded` that does. A trap
raised by static validation, before execution started, carries 0.

*Source: `run_counted` in `src/obsign_verify/replay.py`.*

### Traps

**A trap is a refusal with a reason, never an exception that escapes.** A malformed or
hostile program — an out-of-bounds address, a division by zero, an infinite loop — makes
the receipt `not verified` and says why. It MUST NOT hang the verifier and it MUST NOT
raise past the verification entry point.

The trap kinds, all of them:

| Trap | Raised by |
|---|---|
| unknown program spec / missing member / malformed shape / bad operand | static validation |
| `division by zero`, `modulo by zero` | `DIV`, `MOD` |
| `SHL`/`SHR` shift amount outside 0..63 | `SHL`, `SHR` |
| `LOAD`/`STORE` address out of bounds | `LOAD`, `STORE` |
| `step budget exhausted after N steps` | the budget check |
| `pc N left the program` | falling off the end of `code` |
| wrong number of inputs, non-integer or out-of-range input | input loading |

Trap **kind** is not part of the contract; **whether** a given `(program, inputs)` traps
is. Two implementations must trap on the same inputs — `docs/AUDIT_SCOPE.md` calls this
trap-for-trap equivalence — but need not agree on the message.

### The output digest

**`output.sha256` is the SHA-256 of the output window written as little-endian signed
int64, and only those bytes.**

```
output_sha256(values) = sha256( concat( int64_le(v) for v in values ) ).hex()
```

Length and dtype ride **outside** this hash — they are separate fields of the `output`
block, compared explicitly against the re-executed result. Prefixing them would arguably
be a stronger binding and is not the published format; a verifier implements the spec,
not its opinion of the spec.

The same byte convention covers `tau_field_fixed`, where the digest is taken over the
contiguous bytes of the C-ordered int64 array.

### Program identity

**`program_sha256` is the SHA-256, lowercase hex, of the program object's canonical
JSON** — the same canonical form as [WIRE](#the-canonical-form), over the `program`
object exactly as it appears in the receipt.

When `params.program_sha256` is present it MUST equal that value, or the receipt is
REFUSED. When it is absent, nothing is compared and nothing is refused.

This is belt and braces on purpose. `params` is already inside the claim, so the program
cannot be swapped without breaking `receipt_sha256` — but the digest gives a stranger a
short string to compare against a published one, and it catches an honest producer
shipping a stale digest. Because it is a canonical-JSON hash, the
[integer-versus-float rule](#the-integer-versus-float-rule) applies: a whole-valued float
inside a program is part of that program's identity and MUST NOT be re-typed to an
integer before hashing.

### The tau_field_fixed envelope

The fixed kernel is a screened-diffusion field in pure int64:

```
t <- clip( t + tdiv(DT * (tdiv(D * laplacian(t)) - tdiv(G * t) + S)), lo, hi )
```

with Neumann (edge-replicating) boundaries, `tdiv` truncating **toward zero** by
`SCALE = 2**frac_bits`, `lo = round(0.01 * SCALE)`, `hi = round(10.0 * SCALE)`, and the
field initialised to `SCALE` everywhere. `S` is `round(s * SCALE)` where `s` is the sum
of `strength * exp(-((x - cx)**2 + (y - cy)**2) / width)` over the declared sources on a
grid of `n * n` points spanning `[0, 1]` in each axis.

**This section is deliberately by reference, not by transcription.** The producer's
fixed-point specification (`obsign.fixedpoint`) is normative for the arithmetic, and
`src/obsign_verify/kernel.py` is a re-implementation of it written separately against
that published spec so a bug in one cannot cancel a bug in the other. Two things are
normative *here*:

1. **Every admissibility constant MUST equal the producer's.** A verifier that admits a
   receipt the producer would never mint, or refuses one it would, has already diverged
   — the disagreement just surfaces as "mints here, refused there" instead of as a hash
   mismatch. The values are in [`limits.json`](spec/limits.json): `MIN_GRID`, `MAX_GRID`,
   `MAX_TAU_STEPS`, `MAX_SOURCES`, `MAX_CELL_STEPS`, `MAX_FRAC_BITS`,
   `MAX_SOURCE_COORD`, `MIN_SOURCE_WIDTH`.
2. **The envelope refuses before it computes.** Every bound is checked in
   arbitrary-precision integers before a cell is allocated, so the check itself cannot
   overflow while looking for overflow. The bound is a sound over-approximation: it may
   refuse a receipt that would not in fact have wrapped, and it can never admit one that
   would. The reason is that int64 overflow is not an error in the substrates this kernel
   claims to be identical on — numpy wraps silently, `rustc -O` wraps silently, a debug
   Rust build panics, and C++ signed overflow is undefined behaviour the optimiser may
   assume away. Three of those four are a wrong answer with no diagnostic.

`MAX_FRAC_BITS = 57` is **derived**, not chosen: the laplacian materialises `4 * hi` as
an int64 temporary, and at `frac_bits = 58` that is 1.15e19 > `INT64_MAX`. The margin is
not theoretical — at 60 the three substrates whose agreement is this kernel's entire
claim returned three different values for one receipt.

**Honest residual risk**, stated rather than hidden: the only floating point in the path
builds the initial source term, which is rounded to int64 before any evolution. A source
value sitting exactly on a `.5` rounding boundary could round differently under a
different libm. Not observed across the platforms tested (x86-64 Linux, ARM64 macOS,
Windows, four Python versions); not proven impossible.

The JavaScript and Rust ports do **not** implement this kernel. Such receipts report
`re-derived: not attempted` there and are **never** reported verified.

### The input-liveness probe

This is the rung `rust/README.md` calls the sharpest gap: a **frozen verdict field**
(`docs/COMPAT.md` lists `input_liveness` among the fields whose meaning does not drift,
and `docs/GRAPHS.md` makes it part of the standalone ladder every graph node must pass)
whose value no document let you compute. Two implementations must produce the same value
or their verdicts differ. Here it is.

#### What it is for, and what it cannot do

A receipt proves *re-run this program on these inputs and you get this hash*. That is
empty if the program ignores the inputs: a two-instruction program that loads a constant
and halts re-derives **perfectly**, and establishes nothing about the inputs it names.

**A `live` verdict is EVIDENCE OF DEPENDENCE. It is not, and cannot be, proof that the
program computes the formula its name claims.** An adversary can always write

```
if inputs == this_quarter_exact_inputs:  return the number I want
else:                                    run the real formula
```

which behaves correctly under every perturbation anyone thinks to try. No finite
black-box probe closes that. The semantic boundary is an
[approved program identity](#approved-program-identity-and-strict-liveness), and this
probe is diagnostic evidence beneath it. A conforming verifier MUST report it as
evidence and MUST NOT present it as proof.

#### The perturbation ladder

For a declared input holding value `x`, the probe re-runs the program with `x` replaced,
in this order, **deduplicated** (each candidate is skipped if it equals `x` or a
candidate already emitted) and **clipped to int64** (a candidate outside
`[INT64_MIN, INT64_MAX]` is dropped, not wrapped — an ingest rejection says nothing about
the program's use of the value):

1. **Absolute deltas**, cheapest first: `x + d` for
   `d ∈ (1, -1, 7, -7, 1000, -1000, 1000000, -1000000)`.
2. **Deltas scaled to the input itself**: for `f ∈ (2, 8, 64, 1024)`, let
   `step = |x| // f`; if `step != 0`, emit `x + step` then `x - step`.
3. **Deltas scaled to the machine word**: for `k ∈ (20, 32, 48, 62)`, emit `x + 2**k`
   then `x - 2**k`.
4. **Edges and special values**: `0`, `1`, `-1`, then `INT64_MAX`, then `INT64_MIN` — as
   **replacements**, not deltas.

All four families are required. A fixed absolute ladder can only exercise a program at
the resolution of its largest step, so a computation coarser than 1 000 000 in its
inputs' own units — money held in cents and reported in hundreds of millions, a byte
count reported in gigabytes, anything bucketed or rounded — never moved and was REFUSED
as a hardcoded constant. Relative deltas alone cannot move a program whose input is
zero. That is why both scales and the type's edges are all here.

#### The budget

Work is measured in **cell-equivalents**: units of "zeroing one memory cell", the
cheapest thing a run does.

```
probe_cost(prog, n_inputs, steps) =   steps        * 64      (COST_STEP)
                                    + prog.mem     * 1       (COST_CELL)
                                    + n_inputs     * 16      (COST_INPUT)
                                    + len(code)    * 128     (COST_CODE)
                                    + len(consts)  * 8       (COST_CONST)
```

These are **orders of magnitude measured on the reference implementation, rounded up to
powers of two**, not calibrated constants: re-validating an instruction is around 150×
a cell store, executing one around 60×, loading an input around 16×. Under-charging is
what turns a budget into an amplifier; over-charging only costs a hostile receipt some
probes.

- **Per-run cap**: `min(MAX_STEPS, max(base_steps, 100_000))` instructions, where
  `base_steps` is what the unperturbed run retired. A single probe therefore never runs
  much longer than the base run did, so a program that spins near its declared budget
  cannot make each probe expensive. Hitting the cap raises the ordinary step-budget trap.
- **Total budget**: `max(probe_cost(prog, n, base_steps) * 8, 32_000_000)` — eight times
  the base run's **cost**, with a floor.

The budget is denominated in **cost, not steps**, and this is a security property rather
than an optimisation. Before a program executes its first instruction it allocates `mem`
cells, re-validates every instruction and every constant, and copies and range-checks
every declared input. A program that HALTs immediately pays all of that and retires
*one* step, so a step-denominated budget of four million bought four million full machine
instantiations: at the wire limit (2²⁰ declared inputs over a 2²⁰-cell machine, a 2.1 MB
receipt the wire format accepts) that is over a hundred hours of CPU from one file, spent
**before integrity was ever trusted**. A 1.7 KB receipt measured 8.0 s in Python and
14.0 s in Node against a 3.2 ms base run.

The floor (32 000 000 cell-equivalents, well under a second of real work) exists so a
small constant program with many declared inputs is still swept exhaustively rather than
reported `indeterminate` — which does **not** refuse.

**A refused run is charged too**, at `probe_cost(prog, n, steps_retired_before_the_trap)`.
Charging the cap instead over-bills an early trap enormously, and an over-billed budget
runs out and reports `indeterminate` in place of the `guarded` that refuses.

#### The algorithm

```
n = len(inputs)
if n == 0:
    return "n/a", [], ["indeterminate"] * len(base_output)

per_run_cap  = min(MAX_STEPS, max(base_steps, 100_000))
total_budget = max(probe_cost(prog, n, base_steps) * 8, 32_000_000)
cell_moved   = [false] * len(base_output)
spent = 0 ; ran = false

probe(i, value):
    if spent >= total_budget:  return NONE          # nothing ran
    trial = inputs with trial[i] = value
    run with step_cap = per_run_cap
    on TRAP:  spent += probe_cost(prog, n, steps_retired) ; return "trap"
    spent += probe_cost(prog, n, steps_used) ; ran = true
    if output == base_output:  return "same"
    for c where output[c] != base_output[c]:  cell_moved[c] = true
    return "moved"

# pass 1 -- the per-input verdict. Stops at the first perturbation that MOVES.
for i in 0..n-1:
    if spent >= total_budget:  per_input[i] = "indeterminate" ; continue
    verdict = "dead" ; trapped = false ; exhausted = false
    for value in ladder(inputs[i]):                 # built lazily, per input
        outcome = probe(i, value)
        if outcome is NONE:  exhausted = true ; break
        tried[i] += 1
        if outcome == "trap":   trapped = true      # NOT evidence
        if outcome == "moved":  verdict = "live" ; break
    if verdict != "live":
        verdict = "indeterminate" if exhausted else ("guarded" if trapped else "dead")
    per_input[i] = verdict

# pass 2 -- finish the ladder, for the CELL answer only.
swept = true
for i in 0..n-1:
    if spent >= total_budget:  swept = false ; break
    for value in ladder(inputs[i])[tried[i]:]:
        if probe(i, value) is NONE:  swept = false ; break
    if not swept: break

per_cell[c] = "live"  if cell_moved[c]
              else ("dead" if (ran and swept) else "indeterminate")

verdict = "live"          if any per_input == "live"
     else "indeterminate" if any per_input == "indeterminate"
     else "guarded"       if any per_input == "guarded"
     else "dead"
```

Four details are load-bearing and a port that drops any of them produces different
verdicts:

- **A TRAP IS NOT EVIDENCE OF DEPENDENCE.** This once counted a trap on a perturbed input
  as `live`, reasoning that the value controls whether an output exists at all. The
  attacker controls when the program traps, so that handed the hardcoded-constant attack
  a way straight back through the check:

  ```
  input a, b;  let ok = 0;
  if a == 5 { if b == 7 { ok = 1; } }
  let guard = 1 / ok;        // traps unless the inputs are the receipted ones
  output 424242;             // ... and the output is a CONSTANT
  ```

  Every probe perturbs, hits the guard, traps — and the old probe called that proof the
  constant depended on its inputs. A trap now says only that the program **refused to
  run**, which is not information about the output.
- **The precedence is `live` > `indeterminate` > `guarded` > `dead`.** An exhausted
  budget is the weakest thing that can be said, so it wins over `guarded`; both are
  weaker than a definite `dead`, which requires every perturbation to have actually RUN
  and left the output alone.
- **Pass 2 exists because "the output" is not one number.** The verdict is about the
  output *window*, which is a vector — so a program whose reported figure is a hardcoded
  constant passes pass 1 by appending one decoy cell that echoes an input
  (`output 424242, a + b;`). Every input is live, the receipt verifies, and a
  `docs/GRAPHS.md` link consuming `src_offset 0, length 1` carries the CONSTANT down the
  chain. Pass 1 stops at the first perturbation that moves *anything*, which proves the
  input live but says nothing about a cell it did not disturb, so **a cell may only be
  called `dead` after the ladder has been finished for every input**.
- **The ladder for input `i` is built only when there is budget left to spend on it.**
  Building all of them up front is `n × ~30` integers before a single probe runs, and
  `inputs` is attacker-controlled up to 2²⁰ — the same uncharged work the cost model
  exists to close, reintroduced in the bookkeeping.

#### The verdicts

| `input_liveness` | Meaning | Refuses? |
|---|---|---|
| `live` | some perturbation of some declared input MOVED the output | no |
| `guarded` | no input was shown to reach the output, and every perturbation that did not, TRAPPED | **yes** |
| `dead` | every input was fully exercised and none ever moved the output | **yes** |
| `indeterminate` | the probe budget ran out before proving dependence either way | no (see [strict liveness](#approved-program-identity-and-strict-liveness)) |
| `n/a` | the program declares no inputs, so it makes no claim about any | no |

`per_cell[c]` is `live`, `dead` or `indeterminate` for output cell `c`, on the same
rules.

**Only `dead` and `guarded` refuse, and both are sound NEGATIVES**: in each case the run
produced no evidence that any declared input reaches the output. **`indeterminate` never
refuses by default** — a verifier must not reject an honest receipt merely because it was
expensive to probe. Fail towards not accusing.

`docs/GRAPHS.md` adds one consequence: a chain link whose entire source slice is `dead`
is REFUSED, because the values that link carries are constants however well every node
re-derives.

*Source: `_input_liveness`, `_probe_values`, `_probe_cost` and the `_LIVENESS_*` /
`_COST_*` constants in `src/obsign_verify/verify.py`.*

### Approved program identity and strict liveness

Two controls sit above the probe. Both are **library-level**, not CLI post-processing:
they were CLI-only in three implementations, which meant every service that imports the
package instead of shelling out silently got the weaker question with no field in the
result to say so.

**`expect_program`** (`--expect-program SHA256`) pins the semantic boundary. A validator
reads the program **once** — for the worked example that is 27 readable instructions —
approves it, and records its digest. From then on the question stops being *did this
re-derive?* and becomes *did this re-derive from the program I approved?*, which is the
question an auditor was asking all along.

- The digest compared is **computed** from `params.program`, never read out of
  `params.program_sha256`. The stated field is a convenience a producer can get wrong and
  a forger can simply write; pinning against it would let anyone claim the approved
  program by typing its digest into the file beside a different program.
- The comparison runs on **every path**, including the ones that could not re-execute. A
  receipt whose kernel this verifier cannot run is not thereby an approved program, and
  reporting "no expectation was supplied" there when one was is the one thing the
  tri-state exists to prevent.
- `approved_program` is `null` when no expectation was supplied, `true` or `false` when
  one was. A `false` forces `verified: false`.

**`strict_liveness`** (`--strict-liveness`) demands a positive `live`: in strict mode
`indeterminate` and `n/a` both REFUSE. The default is unchanged and still accepts
`indeterminate`, because a verifier that refused an honest receipt for being costly to
probe would be accusing producers of forgery on a timing measurement — and an auditor of
a regulated program must be able to switch that acceptance off.

*Implemented on this branch by the protocol change of 2026-08-20. Source: `verify`,
`_program_digest` and `_verify_replay` in `src/obsign_verify/verify.py`.*

---

## 4. ATTRIBUTION — who signed it

A signature adds **who**, not **whether**. An unsigned receipt can still be `verified`:
integrity holds and the number re-derived on your machine, and that is the whole point of
the replay rung — you did not have to trust anyone.

**A signature that is PRESENT but does not verify is a refusal. A signature that is
ABSENT is not.**

### The signature block

The `signature` key, when present, MUST be a JSON object. It carries:

| Member | Type | Covered by v2? | Notes |
|---|---|---|---|
| `spec` | string | **yes** | see [SIG-SPEC](#sig-spec) |
| `alg` | string | **yes** | MUST be exactly `"ed25519"` |
| `public_key` | string | **yes** | 32 raw Ed25519 bytes, in hex |
| `signer` | string | **yes** | the attributed name |
| `binds_sha256` | string or null | **yes** | see [Bound metadata](#bound-metadata) |
| `sig` | string | — | the signature itself, 64 raw bytes in hex |
| `binds` | array of strings | **no** | a hint about how to reproduce `binds_sha256` |

`receipt_sha256` is read from the **receipt**, not from the block, and is part of the
covered set.

**`alg` is compared EXACTLY, never normalised.** A receipt carrying `"ED25519"` is
unsupported. Lowercasing before comparing made this verifier accept what the producer and
the browser verifier — which both compare the exact token — called unsupported: one
implementation verifying what another refuses, over a value that is itself inside the
signed attribute set. A protocol identifier has one spelling. Because the block is
attacker-supplied, `alg` may be any JSON type, and comparing without coercing means a
number, object or `null` simply is not the token.

**`public_key` MUST decode to exactly 32 bytes** and **`sig` to exactly 64**. A shorter
or longer value is a refusal, not a truncation.

### SIG-MEMBER

> **The signature is carried in a member named `sig`, and only `sig`. It MUST be a JSON
> string of hexadecimal characters. There is no alternative spelling.**

The dispatch used to read `sig.get("sig") or sig.get("signature")`, and **a synonym
fallback in a security envelope is a forgery primitive**: a non-string `sig` made the
first read fall through to the second, so

```json
{"sig": 5, "signature": "<a valid 128-hex signature>"}
```

VERIFIED in the JavaScript port and was refused by Python and Rust — the same file, two
verdicts, forger's choice of verifier. No receipt produced by anything ever carried
`signature` inside the signature block, so the fallback is **deleted rather than
harmonised**. A `sig` that is absent, or present and not a string, makes the block
malformed.

*Implemented on this branch by the protocol change of 2026-08-20. Source: `check` in
`src/obsign_verify/signature.py` and `js/src/signature.js`.*

### SIG-SPEC

> **`spec` inside the signature block is exactly three cases:**
>
> 1. **`"obsign/signature/v2"`** — the current envelope. Verify the
>    [v2 message](#the-v2-message) and apply the [bound-metadata](#bound-metadata) rule.
> 2. **absent, `null`, or `"obsign/signature/v1"`** — the legacy envelope. Verify over the
>    bare `receipt_sha256`, and attribute **nobody**.
> 3. **anything else** — including a version this verifier has never seen, and including
>    a value that is not a string — is **UNSUPPORTED**. Set `unsupported: true`, report
>    `valid: false` and `attributed_signer: null`, and **return without reading any of
>    the bytes the unknown spec describes**.

Case 3 is the one that was missing, and the shape of the defect is worth keeping: the
dispatch read `if spec == v2 … else legacy v1`, so `obsign/signature/v9` — a spec whose
covered attribute set nobody here can enumerate — was verified under the **weakest
envelope this format has ever had**. v1 signs the bare receipt hash and covers neither
the signer nor the case block. An unknown future version must never inherit that.

**The spec is decided before any of the bytes it describes are read.** `sig`,
`public_key` and `binds_sha256` only mean anything relative to a spec that says what the
signature covers; reading them first and discovering the spec is unknown afterwards is
the same mistake in a different order.

An **absent** spec still means v1, because receipts minted before the field existed are
real and still verify.

*Implemented on this branch by the protocol change of 2026-08-20. This closes row B5 of
`rust/README.md`. Source: `SUPPORTED_SIG_SPECS` and `check` in
`src/obsign_verify/signature.py`.*

### The v2 message

```
covered = { "spec":           signature.spec,
            "alg":            signature.alg,
            "public_key":     signature.public_key,
            "receipt_sha256": receipt.receipt_sha256,
            "signer":         signature.signer,
            "binds_sha256":   signature.binds_sha256 }

message = b"obsign/signature/v2\x00" + ascii( sha256( canonical(covered) ).hex() )
```

The signed bytes are the **20-byte domain tag** — the ASCII `obsign/signature/v2`
followed by one NUL byte — concatenated with the **64 ASCII characters** of the lowercase
hex digest. Not the raw 32 digest bytes: the ASCII hex.

`signer` and `binds_sha256` enter the covered object with whatever value the block
carries, including `null` when absent. Key order is irrelevant — the canonical form sorts.

**The domain tag is not decoration.** Without it the signed bytes are a bare 64-character
hex digest, which is exactly what a v1 signature covers, and a v2 signature could be
replayed as a v1 one. It is also a contract with the producer: the two must sign the
**same bytes**, and for three releases they did not — this verifier signed and checked
the bare hash while the producer signed the tagged one, so every genuine v2 receipt
reported `InvalidSignature` in the tool customers are told to run. Nothing caught it for
the same reason nothing could: the package shipped zero producer-signed receipts, so the
round trip was never once executed.

Two properties follow from the covered set:

- **The attributed signer is inside what the signature covers.** Rewriting `signer`
  invalidates the signature.
- **`binds_sha256` extends coverage to metadata that lives outside the claim hash but is
  still presented as fact.**

### Bound metadata

`binds_sha256` commits to a subset of the receipt's out-of-claim keys:

```
binds_hash(receipt, keys) = sha256( canonical({ k: receipt[k] for k in keys if k in receipt }) ).hex()
                            if that object is non-empty, else null
```

Two details that look cosmetic are not: only keys **actually present** enter the hashed
object (hashing a missing key as `null` would be a second, silently different canonical
form), and an empty selection is **`null`, not the hash of `{}`** — so *this signature
binds nothing* and *the bound block was deleted* stay distinguishable.

> **THE RECOMPUTATION RUNS UNCONDITIONALLY.**

`binds` is **not** covered by the signature; `binds_sha256` **is**. So the signed hash is
the authority and the unsigned list is only a hint about how to reproduce it. A missing,
empty, or lying `binds` cannot *suppress* the comparison — it can only *fail* it.

The rule, in order:

1. `binds` absent or `null` → treat as `[]`, **and check it as such**.
2. `binds` present but not a list of strings → REFUSE. The bound metadata cannot be
   reproduced.
3. Any name in `binds` that the receipt does not contain → REFUSE. Because `binds_hash`
   hashes only present keys, padding the list with names for absent keys leaves the hash
   unchanged and would otherwise let the verifier report `bound_metadata: ["case",
   "examiner"]` for a signature that bound neither. A producer never emits such a list,
   so the only readings are "the bound block was deleted since signing" and "the list was
   padded". Both are refusals; neither is a pass.
4. `binds_hash(receipt, binds)` must equal `binds_sha256`, or REFUSE.

Only after all four does the verifier set `identity_bound: true` and populate
`attributed_signer`.

This is the check that stops an examiner's name being rewritten on a cryptographically
valid receipt. It used to read `binds = sig.get("binds")` / `if binds:` — a security check
gated on a value the attacker supplies. **Deleting one key from the JSON skipped the
check rather than failing it**, and `case` is excluded from `receipt_sha256`, so
`case.examiner` could be rewritten to any name at all on a valid receipt:
`valid: true, identity_bound: true`, attributed to the original examiner. The producer's
verifier refused that file. The public one — the one customers are told to run — did not.

### Ed25519 verification

Signature verification is **Ed25519 as specified in RFC 8032** (PureEdDSA over
edwards25519, SHA-512), over the message defined above.

RFC 8032 permits both a **cofactored** and a **cofactorless** verification equation, and
they disagree on signatures involving low-order points; the `S` range check also varies
between implementations. The reference and the JavaScript port both delegate to their
platform's library — `cryptography` (OpenSSL) and `node:crypto` (OpenSSL) — and therefore
inherit OpenSSL's answers. The Rust crate is hand-written with no dependencies and
**matches OpenSSL deliberately**, and says so in `rust/src/ed25519.rs`.

**This document records that as the current state and does not standardise it.** See
[Open questions](#open-questions): the exact equation is a real interoperability question
that a fourth implementation is entitled to a written answer to, and inventing one here
would be worse than admitting nobody has decided.

Any failure — a malformed key, a wrong-length signature, a library exception — is a
**refusal**, never an escaping error.

### Out-of-claim facts

`OUT_OF_CLAIM_FACT` is the list of keys that live **outside** the claim hash but are
still presented as fact. It is exactly one key:

```
OUT_OF_CLAIM_FACT = ("case",)
```

`case` (case id + examiner) is rendered into a court-facing report, so a signature that
does not bind it leaves the two lines a court reads first attested by nothing. It is
**not** an automatic refusal — the producer's post-hoc case export legitimately emits an
unbound `case` — but it is **never silent** either: a verifier MUST report it.

That constant is a list, and a list is the wrong shape for the general question. The
general rule is **computed, never enumerated**:

```
unattested(receipt, bound) = sorted( k for k in receipt
                                     if k not in claim(receipt)
                                     and k not in ("receipt_sha256", "signature")
                                     and k not in bound )
```

`receipt_sha256` and `signature` are excluded as **structural**: they are the hash and
the signature themselves, so "not covered by the signature" is not a fact about them.

Enumerating only `case` meant that for the whole life of this package, `env` and every
`_`-prefixed key rode outside both the claim hash and the signature with **no mention at
all** — and those are not obscure corners. The producer stores its verdicts in
`_`-prefixed keys precisely because they are outside the claim: `obsign authenticity`
writes `_combined_verdict` ("AUTHENTIC PROVENANCE (certain) …") and `_aigen` there. On a
genuine, valid, identity-bound signed report, the sentence a reader acts on could be
rewritten by anyone with a text editor while the verifier reported nothing.

A v1 signature binds **nothing** outside the claim hash, so on a v1 receipt every
out-of-claim fact in the file is unattested.

### What the signature fields mean

| Field | Meaning |
|---|---|
| `present` | the receipt carries a `signature` object |
| `valid` | the signature was READ and it HOLDS: it verifies over the message its spec defines, and every bound-metadata check passed |
| `identity_bound` | the signature covered the `signer` name — **true only for v2**, and only after the bound-metadata comparison succeeded |
| `attributed_signer` | the name the signature actually covered, or `null`. **Never populated from a v1 signature** |
| `claimed_signer` | whatever the file says, covered or not. Present so a reader can see the difference |
| `unsupported` | the envelope names a spec this verifier does not implement. Distinct from `valid: false`, which means "I read it and it does not hold"; this means "I did not read it, and nothing here is a verdict about it" |
| `bound_metadata` | the sorted key names the signature bound |
| `unbound_metadata` | the `OUT_OF_CLAIM_FACT` keys present in the receipt and NOT bound |
| `unattested_metadata` | the computed set — every present key covered by neither the claim hash nor the signature |
| `detail` | human-readable; not a contract |

`identity_bound` is reported separately from `valid` **on purpose**. A caller that reads
only `valid` still cannot print a signer name, because `attributed_signer` is `null`
unless the signature actually covered it. Legacy v1 signs the ASCII `receipt_sha256`
alone; it covers neither the signer nor the case block, so **the name it carries can be
rewritten by anyone with a text editor and no key**. v1 signatures still verify — old
receipts do not stop working — but reporting them as "valid, signed by Alice" would
launder an unauthenticated name into an attribution. The refusal to collapse those two
cases is the single most security-relevant line in the package.

---

## 5. AUTHORITY — out of scope

**Step 4 of the ladder — *should you trust this key?* — is deliberately not implemented,
in any implementation.**

Deciding that a public key belongs to an organisation you should trust is an identity
question, and a verifier that answered it by consulting a bundled list would be asserting
a social fact as a cryptographic one. `verified` therefore means steps 1–3, and
`attributed_signer` is only ever populated when the signature actually covered the name.

Key roles and root anchoring live **in the producer**, not here, and are specified by its
key-role and root-anchor model: which keys may issue, which may sign receipts, how a root
is anchored and how trust is withdrawn. This verifier deliberately implements none of it.
Two consequences a relying party must hold onto:

- **A valid signature is not an authorised one.** This document's contract 4 answers *who
  holds the private key for this public key*. Whether that key was ever entitled to sign
  is contract 5, and it is answered elsewhere.
- **The known limitation is recorded, not hidden.** `docs/AUDIT_SCOPE.md` lists "one
  pinned issuer key, no rotation protocol" among the accepted limitations: the producer's
  gate pins a single Ed25519 key and its `trust.json` supports removal only. Key custody
  is the operator's problem; the *absence of a rotation story* is known, accepted and on
  the roadmap.

---

## The verdict ladder

```
                    ┌─ spec == "obsign/receipt/v1"? ──── no ──▶  UNSUPPORTED
                    │                                            (signature still
                    │                                             evaluated; never
                    │                                             "invalid")
                    ▼ yes
   1  integrity     receipt_sha256 recomputes from the claim
                    ▼
   2  reproduced    re-running the kernel reproduces output.sha256
                    ├─ obsign/replay/1  ── + program digest, output length,
                    │                        input-liveness
                    └─ tau_field_fixed  ── + input fingerprint, shape, dtype
                    ▼
   3  signature     present ⇒ must verify, and must cover what it claims
                    ▼
   4  issuer trust  OUT OF SCOPE
```

`verified` is the conjunction of the rungs that apply, and nothing else:

**replay path** — `integrity` ∧ `reproduced` ∧ `digest_ok` ∧ `length_ok` ∧ `live_ok` ∧
`signature_gate`, then `approved_program` if an expectation was supplied.

**tau path** — `integrity` ∧ `reproduced` ∧ `input_ok` ∧ `shape_ok` ∧ `dtype_ok` ∧
`signature_gate`, then `approved_program` if an expectation was supplied.

where

- `digest_ok` — `params.program_sha256` is absent, or equals the computed program digest;
- `length_ok` — `output.length` is absent, or is a JSON **integer** equal to the
  re-executed output's length;
- `live_ok` — `input_liveness` is not `dead` and not `guarded`; under `strict_liveness`,
  is exactly `live`;
- `input_ok` — `input.sha256` is absent/`null`, or the rebuilt input hashes to it;
- `signature_gate` — the signature is absent, **or** it is valid. A signature this
  verifier cannot read — an unrecognised `alg`, an unrecognised `spec` — is **not**
  valid, so a receipt carrying one is not `verified`. That is the correct direction: *I
  cannot check this signature* never resolves to a pass. It is still reported as
  `unsupported` rather than as a forgery, and it attributes nobody.

An **unrecognised kernel** is not a failure of re-derivation, it is an absence of one:
the verifier reports that the kernel cannot be re-executed here, runs the signature gate,
and never reports `verified`. *"I cannot check this"* is a third answer, and collapsing it
into pass or fail is how a verifier starts lying.

**A verifier MUST NOT raise.** Any exception escaping the ladder is caught, recorded as a
note, and the verdict stays `false`.

For chains, `docs/GRAPHS.md` is normative. In summary: `graph_verified` requires that
every supplied node passes this whole ladder standalone, every link binds the parent's
input slice to the child's **re-derived** output slice value for value, the stated link
hashes hold, ranges are strict and non-overlapping, no referenced receipt is missing, and
no cycle or digest collision was found.

## The result schema

`verify(receipt, expect_program=None, strict_liveness=False)` returns an object with
these fields. `docs/COMPAT.md` guarantees that **verdicts may gain fields; the meaning of
existing fields does not drift**.

| Field | Type | Always present | Meaning |
|---|---|---|---|
| `integrity` | boolean | yes | `receipt_sha256` recomputed from the claim |
| `reproduced` | boolean | yes | the kernel re-ran and reproduced `output.sha256`. See [Open questions](#open-questions) on the two- vs three-valued reading |
| `signature` | object or `null` | yes | the block described in [What the signature fields mean](#what-the-signature-fields-mean). `null` only if the ladder raised before the signature gate ran |
| `verified` | boolean | yes | the conjunction above. **Never** true for an UNSUPPORTED receipt |
| `unsupported` | boolean | yes | the receipt's `spec` is not `obsign/receipt/v1`. *This is about the RECEIPT format; the signature block carries its own `unsupported` for the signature envelope* |
| `approved_program` | boolean or `null` | yes | `null` = no expectation was supplied; `true`/`false` = one was, and the **computed** program digest did or did not match |
| `notes` | array of strings | yes | human-readable; not a contract, and never the only place a refusal appears |
| `input_liveness` | string | replay path only | `live` / `dead` / `guarded` / `indeterminate` / `n/a` |
| `input_liveness_by_input` | array of strings | replay path only | one verdict per declared input, same vocabulary |
| `output_liveness_by_cell` | array of strings | replay path only | `live` / `dead` / `indeterminate` per output cell |

`unsupported` and `approved_program` were **implemented on this branch by the protocol
change of 2026-08-20**.

`verify_graph(receipts)` returns `graph_verified`, `complete`, `missing`, `roots`,
`order`, `notes`, and `nodes` — a map from recomputed claim digest to
`{verified, links_ok, envelopes, notes}`, where `links_ok` is `true`, `false`,
`"incomplete"` or `null` (the node declares no links).

---

## Conformance

Three implementations ship in this repository. They are held to identical verdicts by
`tests/test_cross_language_differential.py`, and every divergence found so far is frozen
as a named vector in `rust/harness/corpus.py` rather than described in a paragraph.

| Contract | Python (`src/`) | JavaScript (`js/`) | Rust (`rust/`) |
|---|---|---|---|
| WIRE | full | full | full |
| CLAIM, including RECEIPT-SPEC | full | full | full |
| EXECUTION — `obsign/replay/1` | full | full | full |
| EXECUTION — input liveness | full | full | full |
| EXECUTION — `expect_program`, `strict_liveness` | full | full | full |
| EXECUTION — `tau_field_fixed` | full | **not implemented** — reports *not attempted*, never verified | **not implemented** — same |
| ATTRIBUTION, including SIG-SPEC and SIG-MEMBER | full | full | full |
| AUTHORITY | out of scope everywhere | | |

**`tau_field_fixed` is the one deliberate hole, and it has a consequence worth stating
plainly**: all nine public challenge bundles are `tau_field_fixed`, so the two ports
refuse all of them — and they refuse the two honest ones for the same reason they refuse
the forgeries. Agreement between the ports therefore proves nothing about that kernel.

Three implementations by one author agreeing means the specification was unambiguous
enough to be re-read consistently by that author. **It cannot exclude a misreading all
three share** — which is why the gap list in `rust/README.md` matters more than the
passing tests, and why an independent implementation is still open. It earns
**recognition, not cash**: named on the strangers page, named in the conformance suite,
credited here.

---

## Open questions

Recorded rather than resolved. Each is a place where two conforming implementations could
still differ, and where inventing an answer in this document would be worse than the gap —
a reimplementer would conform to something no shipped verifier does.

**O1 — `reproduced` is two-valued or three-valued.** For a kernel a verifier cannot
execute, the Python reference reports `false` and the JavaScript and Rust ports report
`null`. *"I could not check this"* and *"this failed"* are different facts and the format
insists on that distinction everywhere else, which argues for `null`; the field's declared
type in every existing consumer is boolean, which argues for `false`. This is row B4 of
`rust/README.md` and it is **genuinely open**. Until it closes, a consumer MUST treat any
non-`true` value as *not reproduced* and MUST NOT distinguish the two.

**O2 — the Ed25519 verification equation.** RFC 8032 permits cofactored and cofactorless
checks; they disagree on signatures involving low-order points, and the `S` range check
varies. All three implementations currently match OpenSSL — two by delegating to it, one
deliberately by hand — but no document *requires* that, so a fourth implementation using a
strict library (one that rejects non-canonical point encodings, or applies the cofactored
equation) could refuse a signature these accept. Choosing here would be standardising a
behaviour inherited by accident. It needs a decision, then a conformance vector at the
boundary.

**O3 — hex strictness. CLOSED 2026-08-20, after being found here.** Writing this
document surfaced a live cross-implementation divergence: the reference decoded `sig` and
`public_key` with Python's `bytes.fromhex`, which **skips ASCII whitespace**, while the
JavaScript and Rust ports require every character to be a hex digit. Witness, measured on
all three legs before the fix — a v1-signed receipt whose `sig` is a valid 128-character
hex signature with **one ASCII space inserted**:

```
python  valid=True   signature verifies; legacy obsign/signature/v1 …
node    valid=false  signature is not 64 raw Ed25519 bytes in hex
rust    signature   FAILED          (the same receipt, the same byte)
```

The decoded bytes were identical either way, so no signature verified that would not have
verified anyway — the defect was the disagreement itself, a class-2 divergence by
`docs/AUDIT_SCOPE.md`: one file, two verdicts, from the estate whose whole argument is
that a stranger's verifier reaches the same answer as ours.

**The reference and the producer now enforce the strict rule**, which is the one the ports
already had: decode, then require the re-encoded form to equal the input lowercased. `sig`
is exactly 128 hex characters and `public_key` exactly 64, with no whitespace and no other
character. Measured after the fix: `python valid=False`, `node valid=false` — agreement.
Pinned by `tests/test_hex_has_one_spelling.py`, which runs the JavaScript port in the same
test so a Python-only fix cannot look complete.

**Hex is CASE-INSENSITIVE, in all implementations.** Uppercase `sig` is accepted by all
three (measured, not assumed). Note the asymmetry that follows from the envelope rather
than the encoding: uppercasing `public_key` *does* break a v2 signature, because
`public_key` is one of the covered attributes and its spelling is inside the hashed
message, whereas `sig` is never hashed. Both halves are pinned.

**O4 — `unsupported` is set for an unknown signature `spec` but not for an unknown
`alg`.** Both are refusals of the same kind — *I do not know what these bytes mean* — and
the `alg` branch says exactly that in its detail string (`unsupported algorithm … -
UNVERIFIED, not accepted`) while leaving `unsupported: false`. A consumer switching on the
field therefore sees an unknown algorithm as an ordinary invalid signature. Recorded as an
asymmetry, not resolved, because closing it changes a field's value for an input that
exists.

**O5 — several claim-covered blocks are never read.** `producer`, `run`, `output.units`,
`input.kind` and `input.ref` are inside the claim (so tampering with them breaks
`receipt_sha256`) and no verifier checks their contents against anything. That is coherent
— they are attested, not verified — but no document says whether a future version may
begin enforcing them, and under `docs/COMPAT.md`'s asymmetric guarantee that would be a
*refuse more*, which is permitted. Flagged so a producer does not treat them as free-form.

---

*Apache-2.0, matching the rest of the estate. Changing this document is a format decision
by the maintainers, in the open, with a version string — never a side effect of a patch.*
