# obsign-verify (Rust)

**Re-derive the number yourself. Offline. On your hardware. Zero dependencies, cryptography included.**

A signature tells you a claim is *unmodified*. It never tells you the claim is *true*.
This re-runs the computation and compares bits.

```console
$ cargo run --release -- ../src/obsign_verify/data/conformance/producer_signed_replay.json

  [VERIFIED] .../producer_signed_replay.json
      integrity   ok
      re-derived  ok
      signature   ok, signer BOUND (A. Chen, Coherence Energy Labs)
      - input-liveness is EVIDENCE, not proof: perturbing an input moved the output,
        which shows dependence but cannot show the program computes the formula its
        name claims. Pin an approved program digest (--expect-program) for that.

1/1 receipt(s) verified on THIS machine.
```

That receipt was signed by the **producer**, not by this crate, and the Ed25519 in
`ed25519.rs` is what checked it. Exit `0` if every receipt verified, `1` otherwise.

## Read this before you rely on it

**This is a third implementation by the same author, not an independent third-party
review.** It cannot discharge the independence claim any more than `js/` can — programs
by one author can share one misreading of a spec, and a third one written by the same
hands is a third chance for the same misreading, not an outside opinion. The
independent implementation is still open, and what it earns is **recognition, not
cash**: named on the strangers page, named in the conformance suite, credited in the
spec. The commissioned audit in `docs/AUDIT_SCOPE.md` is also still open, and until one
concludes nothing here should be described as audited.

A fourth implementation now has a document to work from: `docs/SPEC.md`, which exists
because of the list below. Where it and an implementation disagree, the implementation is
wrong unless it is named in `docs/SPEC.md#conformance` — and this crate is named there.

What it *does* establish is narrower, and it is **different from what the JavaScript
port establishes**. That port tested whether the format survives a language whose
native number is a double. This tests something neither of the other two can: both of
them compute in arbitrary-precision integers — Python's `int`, JavaScript's `BigInt` —
and then narrow to int64 with an explicit `wrap` the author had to remember to write. A
mistake in that shared strategy is invisible to a differential between them. Rust
computes in native `i64`, where overflow is the machine's behaviour rather than a step
someone remembered, and this crate builds with `overflow-checks = true` in release so an
unintended overflow is a panic in testing instead of a wrong number in the field.

It measured something more useful than agreement, though. **It could not be written
from `docs/` alone.** The list below is the part of this exercise worth keeping.

## Where the specification ran out

Every entry is a place this implementation had to read `src/obsign_verify/*.py` because
the documents did not say. Each is a latent cross-implementation divergence: two people
reading only `docs/` can implement it differently and both believe they conform. Three
of them turned out to be real divergences between the two SHIPPED implementations, and
those are marked **[live]**.

**Status, 2026-08-20: section A is closed.** `docs/SPEC.md` was written from the code —
every rule below read out of the implementation it lived in and transcribed, with the
numbers moved into `docs/spec/limits.json` and the opcode table into
`docs/spec/opcodes.json` so a test holds the document to the three implementations
instead of a reader holding it to a memory. The rows are kept rather than deleted:
the list is the measurement, and *what was missing* is more useful evidence about how a
format goes wrong than *what is present now*. Each row now names where the rule went.

### A. You cannot write a conforming verifier from the documents

| # | What was missing | Now specified in | Where it lives in code |
|---|---|---|---|
| A1 | **`docs/SPEC.md` does not exist.** `canonical.py` says "Canonical JSON exactly as docs/SPEC.md defines it"; there is no such file in the repository. The nearest thing is the "frozen surfaces" section of `COMPAT.md`, which names the surfaces without specifying them. | **RESOLVED** — `docs/SPEC.md`, five versioned contracts. The dangling pointer in `canonical.py` now resolves, and `tests/test_docs_references_resolve.py` fails if any `docs/*.md` reference in the source, the docs or the READMEs stops resolving. | — |
| A2 | **The 31 opcodes are never named.** `COMPAT.md` freezes "the 31-opcode instruction set" and stops. No names, no arities, no operand kinds, no semantics per opcode. | **RESOLVED** — `docs/SPEC.md#the-instruction-set`, rendered from `docs/spec/opcodes.json`; every row held equal to `replay.OPS` by name, number, arity and kind. | `replay.py` `OPS` |
| A3 | **The instruction encoding is unstated** — that an instruction is a JSON array whose first element is the opcode string and whose remainder are integer operands. | **RESOLVED** — `docs/SPEC.md#instruction-encoding`, including that there is no numeric opcode encoding anywhere in the format. | `replay.py` `validate` |
| A4 | **The receipt schema is unstated.** `kernel`, `params.program`, `params.inputs`, `params.program_sha256`, `output.sha256`, `output.length`, `output.dtype`: no document lists them. `GRAPHS.md` shows a `params` block by example, which is the closest the estate comes to a schema. | **RESOLVED** — `docs/SPEC.md#the-receipt-schema`, key by key, with which keys are inside the claim and which the verifier actually reads. | `verify.py` |
| A5 | **The wire-format limits are stated nowhere in `docs/`** — `MAX_RECEIPT_BYTES`, `MAX_DEPTH`, `MAX_MEMBERS_PER_OBJECT`, `MAX_ARRAY_LENGTH`, `MAX_STRING_BYTES`, `MAX_INT_DIGITS`. `COMPAT.md` says all implementations must agree on "what LOADS"; these decide it. | **RESOLVED** — `docs/SPEC.md#the-six-wire-limits`; the numbers live in `docs/spec/limits.json` and are compared against all three implementations. | `canonical.py` |
| A6 | **Duplicate object members are refused** — a real rule, with a good reason, in a code comment. | **RESOLVED** — `docs/SPEC.md#duplicate-members-and-object-model-keys`, with the object-model-key refusal beside it. | `canonical.py` |
| A7 | **`input_liveness` is a FROZEN verdict field whose value no document lets you compute.** `COMPAT.md` lists it among the fields whose "meaning does not drift"; `GRAPHS.md` makes it part of the standalone ladder every graph node must pass. Neither states the algorithm — the seven perturbation deltas, the per-run step cap, the total budget, the precedence `live` > `indeterminate` > `guarded` > `dead`, or which verdicts refuse. Two implementations must produce the same value for this field or their verdicts differ, and nothing written down would make them. This is the sharpest gap on the list. | **RESOLVED** — `docs/SPEC.md#the-input-liveness-probe`: all four perturbation families, the cost model in cell-equivalents, both budgets, both passes, the precedence, which verdicts refuse, and the standing statement that a `live` is evidence and not proof. Writing it down is what exposed that **this crate was a version behind** — see *Honest limits*; it now implements the same algorithm, and the constants are pinned across all three. | `verify.py` `_input_liveness` |
| A8 | **`MAX_CODE` (65,536 instructions)** is unstated. `RL.md` states the memory and step ceilings; the code-length one is missing. | **RESOLVED** — `docs/SPEC.md#program-shape-and-static-validation`; `RL.md`'s "Limits, stated plainly" now states it too. | `replay.py` |
| A9 | **Step accounting is unstated**: whether `HALT` consumes a step, whether the budget is checked before or after the instruction, and whether running off the end costs a step. This decides trap-for-trap equivalence at the budget boundary, which `AUDIT_SCOPE.md` calls part of the contract. | **RESOLVED** — `docs/SPEC.md#step-accounting`, as the loop itself. All three answers are yes / before / yes, each measured against the reference. | `replay.py` `run_counted` |
| A10 | **`program_sha256` is the SHA-256 of the program's canonical JSON** — never written down, and it is a field a stranger is invited to compare against a published string. | **RESOLVED** — `docs/SPEC.md#program-identity`, including that the pin compares a **computed** digest, never the stated field. | `replay.py` |
| A11 | **The signature BLOCK is unspecified.** The signed attribute set is specified precisely; the block that carries it is not — that the signature may be spelled `sig` or `signature`, that `public_key` is 32 raw bytes in hex, that `binds` is a list of top-level key names. | **RESOLVED** — `docs/SPEC.md#the-signature-block`, member by member. The "may be spelled `sig` or `signature`" half was not documented because it was a **defect**: SIG-MEMBER deletes the fallback. | `signature.py` |
| A12 | **Which Ed25519 verification equation.** RFC 8032 permits cofactored and cofactorless checks, and they disagree on signatures involving low-order points; the S range check also varies. Both shipped implementations inherit OpenSSL's answers without stating them, which is invisible until someone writes the third implementation without OpenSSL. This crate matches OpenSSL deliberately and says so in `ed25519.rs`. | **DOCUMENTED, NOT CLOSED** — `docs/SPEC.md#ed25519-verification` states RFC 8032 and records that all three currently match OpenSSL; the choice itself is `docs/SPEC.md#open-questions` **O2**, because standardising a behaviour inherited by accident is worse than naming the gap. | OpenSSL, transitively |
| A13 | **`OUT_OF_CLAIM_FACT`** — the list of out-of-claim keys a verifier must warn about (`case`) is a constant, not a rule. | **RESOLVED** — `docs/SPEC.md#out-of-claim-facts` gives the constant *and* the computed rule that supersedes it. | `signature.py` |

### B. Two readings are both defensible

| # | The ambiguity | Status |
|---|---|---|
| B1 | **What `MAX_DEPTH` counts.** CPython caps the depth a *value* sits at; the JS parser caps how many *containers* were opened. They differ by exactly one document shape: 33 containers whose innermost is empty. | **CLOSED by `d52376c`.** All three count **containers entered**, and the rule plus the 32-accept / 33-refuse witness is `docs/SPEC.md#depth-counts-containers-entered`. |
| B2 | **Lone surrogates.** `AUDIT_SCOPE.md` names them as a target for exactly this reason and no document says whether they load. CPython refuses them *by accident* — `len(s.encode("utf-8"))` raises — and the JS parser accepts them. | **CLOSED by `d52376c`.** All three refuse them, on purpose, through an explicit pairing scan rather than an escaping exception: `docs/SPEC.md#lone-surrogates`. |
| B3 | **Whether `MAX_STRING_BYTES` exists at all.** It is declared in `js/src/canonical.js` and never used. | **CLOSED by `d52376c`.** npm now reads the limit it declared; all six wire limits are enforced in all three and pinned in `docs/spec/limits.json`. |
| B4 | **`reproduced` is two-valued or three-valued.** For a kernel a verifier cannot execute, Python reports `false` and JavaScript reports `null`. "I could not check this" and "this failed" are different facts, and `js/README.md` argues that case well — but nothing states it, so the two ports disagree in the field. This crate follows the three-valued reading. | **STILL OPEN**, and recorded as such: `docs/SPEC.md#open-questions` **O1**. Until it closes, a consumer must treat any non-`true` value as *not reproduced* and must not distinguish the two. Python: `false`. JavaScript/Rust: `null`. |
| B5 | **An unknown signature `spec` string.** `COMPAT.md` says a verifier meeting an unknown *replay* spec reports *unsupported*, "which is never spelled *invalid*". Nothing says what an unknown *signature* spec does; both implementations silently fall through to the v1 path and verify it against the bare receipt hash. This crate matches them rather than inventing a third answer, and flags it here. | **RESOLVED by the SIG-SPEC rule**, `docs/SPEC.md#sig-spec`: exactly three cases — v2, absent-or-v1, and *anything else is UNSUPPORTED, returning before any of the bytes the unknown spec describes are read*. The fall-through was the defect, not the ambiguity: `obsign/signature/v9` was being verified under the weakest envelope the format has ever had. |
| B6 | **Type discipline on out-of-band scalars.** `COMPAT.md` closed this for the program's structural scalars. It did not close it for `output.length`, `binds_sha256`, or `sig`, and each is a live divergence below. | **PARTLY CLOSED.** `output.length` must be a JSON integer (`docs/SPEC.md#the-receipt-schema`) and `sig` must be a string in a member spelled `sig` (`docs/SPEC.md#sig-member`). Hex *strictness* is still a live divergence: `docs/SPEC.md#open-questions` **O3**. |
| B7 | **Whether unknown members in a `program` object are legal.** They are, in all three — and they are covered by `program_sha256`, so a float sitting in one changes the program's identity. | **CLOSED by statement**, `docs/SPEC.md#program-shape-and-static-validation`. |
| B8 | **How CPython's float `repr` actually behaves.** `COMPAT.md` pins the canonical form to `json.dumps`, which transitively pins CPython's `repr` — but a reimplementer must independently discover that it is the *correctly rounded* shortest decimal (not merely *a* shortest one), that the exponential thresholds are `1e-4` and `1e16`, and that the exponent is padded to two digits. This crate got it wrong first: see "What the differential found in Rust". | **CLOSED by statement**, `docs/SPEC.md#the-integer-versus-float-rule` — correctly-rounded shortest, the two thresholds, the two-digit signed exponent, `.0` retention and `-0.0`. |

### C. The documents contradict each other

| # | Contradiction | Status |
|---|---|---|
| C1 | **`docs/RL.md` says "The machine has 26 opcodes"; `docs/COMPAT.md` says "The 31-opcode instruction set".** Both implementations, and this one, have 31. `RL.md` is wrong, in a sentence titled "Limits, stated plainly". | **FIXED.** `RL.md` says 31. The count is no longer held by prose: `tests/test_spec_constants_match_code.py` extracts it from *both* documents and compares it to `replay.OPS`, and fails if either stops stating a count at all. |
| C2 | **`js/README.md` still says a constant program "re-derives perfectly, and this tool reports `VERIFIED` — correctly, because it did."** `js/src/verify.js` now implements input-liveness and refuses that program. The document describes behaviour the code no longer has. | **FIXED.** `js/README.md` describes the refusal, both liveness verdicts that cause it, and points at `docs/SPEC.md#the-input-liveness-probe` for the algorithm. |

## What the differential found

`tests/test_cross_language_differential.py` runs the same inputs through all three
implementations and requires identical verdicts. It found **twenty-one disagreements**,
reducing to eight distinct defects, each surfacing in more than one mode.

**All eight are now closed, and `KNOWN_DIVERGENCES` is `{}`.** That is the goal state,
not a broken harness: an entry was frozen and asserted to *still* diverge so that the day
it was fixed the test would call the entry stale, and every entry has since been fixed
and deleted. The table is kept because **the finding is the corpus, not a paragraph about
it** — and a defect list that quietly turns into a testimonials page once the defects are
fixed is worth less than one that says what was wrong and where it went.

Class numbers are `docs/AUDIT_SCOPE.md`'s: **2 = divergence**, "latent soundness:
whichever side is wrong can be farmed".

| # | Defect | Which side the spec supports | Class | Closed by |
|---|---|---|---|---|
| D1 | `js/src/canonical.js` declares `MAX_STRING_BYTES` and never uses it, so a receipt with a 65 537-byte string or key loads in JavaScript and is refused in Python and Rust. | Python. The limit exists in `canonical.py`, which is the only place any limit exists, and `COMPAT.md` requires agreement on what loads. | 2 | `d52376c` — npm reads the limit it declared. `docs/SPEC.md#the-six-wire-limits` |
| D2 | A 33-container document whose innermost container is empty loads in Python and Rust and is refused in JavaScript (B1). | Adjudicated in favour of **containers entered**, which is npm's and Rust's rule; the Python reference moved. | 2 | `d52376c`. `docs/SPEC.md#depth-counts-containers-entered` |
| D3 | A lone surrogate escape loads in JavaScript and is refused in Python and Rust (B2). | Adjudicated: **refused everywhere**, and no longer by accident — an explicit pairing scan, not an escaping `UnicodeEncodeError`. | 2 | `d52376c`. `docs/SPEC.md#lone-surrogates` |
| D4 | **`output.length: true` VERIFIES in Python** and is refused by JavaScript and Rust. `True == 1` in Python, and the check is a membership test (`in (None, len(out))`), not a type check. `output.length: 1.0` does the same thing for the same reason. | JavaScript and Rust. `COMPAT.md`'s own "structural scalars are JSON integers" refusal exists to close exactly this, and stopped at the program's scalars. | 2 | `type(declared_len) is int` in `verify.py`. `docs/SPEC.md#the-receipt-schema` |
| D5 | **A program containing a whole-valued float hashes differently in JavaScript.** `js/src/replay.js` `programSha256` re-types any `Number.isInteger` value as an integer before canonicalising, so `1.0` inside a program hashes as `1`. JavaScript reports a digest mismatch on an honest receipt. | Python and Rust. `COMPAT.md`: "`1` and `1.0` distinct". | 2 | `wrapPlain` keeps floats floats. `docs/SPEC.md#program-identity` |
| D6 | **`js/src/verify.js` builds plain objects with `o[k] = v`, so a member named `__proto__` sets the PROTOTYPE.** A receipt whose `params.program` is `{"__proto__": {...a real program...}}` has no own `spec`, `mem`, `steps` or `code` members at all — and **JavaScript reports it `VERIFIED`** while Python and Rust refuse it. The same mechanism gives a program carrying a `__proto__` member a *different program digest* in JavaScript, because `Object.keys` never lists it. | Python and Rust. The JSON document does not contain a conforming program. | 2 | Object-model member names refused at the parser **and** at the replay validator, in all three. `docs/SPEC.md#duplicate-members-and-object-model-keys` |
| D7 | **A non-string `binds_sha256` is read as absent in JavaScript**, so an empty `binds` list "reproduces" it and the receipt comes back `valid`, `identity_bound`, with a signer attributed — while Python and Rust refuse. The comparison that `signature.js`'s own comment says "runs unconditionally, and that is the entire point" is the one being skipped, by a value the attacker supplies. | Python and Rust. A number is not a digest. | 2 | A non-string `binds_sha256` is REFUSED, never normalised to absent. `docs/SPEC.md#bound-metadata` |
| D8 | **A `sig` member of the wrong type falls through to the `signature` member in JavaScript.** `{"sig": 5, "signature": "<valid hex>"}` verifies there and is a malformed block in Python and Rust. | Python and Rust. | 2 | The **SIG-MEMBER** rule: the fallback is deleted in all three rather than harmonised. `docs/SPEC.md#sig-member` |

D6 and D7 were the two worth acting on first: both made the JavaScript verifier print
`VERIFIED` — and D7 made it attribute a named signer — on receipts the reference refused.

### What the differential found in Rust

Recorded with the same prominence, because a findings list that only indicts other
people's code is a testimonials page.

- **The float formatter was wrong, and only a three-way differential caught it.**
  `format!("{}", x)` produced `2211529743968985.3` where CPython and JavaScript both
  produce `...85.2`. Both strings read back as the same double, so both are "the
  shortest that round-trips" — Rust's formatter does not promise to pick the *correctly
  rounded* one, and CPython's `repr` does. Any receipt carrying such a value would have
  been reported as tampered by this crate alone. Fixed by asking for increasing
  precision from `{:.*e}` (which *is* correctly rounded) until the value round-trips.
  This is precisely the failure mode a third implementation exists to expose, and it
  showed up in Rust rather than in the format.
- **Two byte-slice panics.** A 64-*byte* digest check passes for 32 two-byte characters,
  and slicing `&s[..16]` on one would have panicked while composing a refusal message. A
  verifier that dies explaining a refusal has failed open. Fixed to truncate by
  characters.

## What was run

```console
$ cargo test --release            # 38 tests: crypto vectors, spec conformance, hostile input
$ python -m pytest tests/test_cross_language_differential.py
7 passed
```

The differential runs **2,489 cases** through Python, JavaScript and Rust, plus **18,288
operand pairs** batched inside the arithmetic grid:

- **loadability** — the shipped corpus, the wire-format edges, and receipts built to
  probe one suspicion each. The three must agree on what a receipt *is*, not merely on
  what one hashes to.
- **canonical bytes** — 629 documents including random float bit patterns, subnormals,
  the `1e16` and `1e-4` boundaries, astral and private-use keys. Byte for byte.
- **the bare machine** — every binary operator over every pair of 25 int64 edge values,
  `MULFX` at eight fractional scales, every partial operation, plus 900 seeded random
  programs. Value for value and **trap for trap**: 340 of the 900 random programs run to
  completion and 560 trap, across seven distinct trap kinds.
- **the ladder** — 364 replay receipts; 115 verify and 249 are refused, with all four
  liveness verdicts (`live`, `dead`, `guarded`, `indeterminate`) exercised, and 20
  signed receipts among them of which 8 carry a signature that verifies.
- **graphs** — the frozen four-node chain, shuffled, re-enveloped, truncated to
  incomplete, and corrupted nine ways at the link level.

**The harness was checked against a deliberate bug**, because a differential that
cannot fail is worthless. Reintroducing the classic fixed-point porting error in
`MULFX` — multiply in int64, shift afterwards, instead of multiplying exactly at 128
bits first — makes seven grid cases diverge immediately. The real float-formatting bug
above was found the same way, unprompted.

Every divergence in the table is frozen as a **named, deterministically generated
vector** in `harness/corpus.py` and asserted in `KNOWN_DIVERGENCES`, so the corpus is
the finding rather than a paragraph about it.

The shipped fixtures verify in all three, which is the part agreement on a refusal
cannot fake: the four-node conformance chain is `GRAPH VERIFIED`, and
`producer_signed_replay.json` — signed by the **producer**, not by this crate — comes
back verified with `A. Chen, Coherence Energy Labs` bound by the signature.

## Honest limits

- **Same author. Not an independent review.** Stated first because it is the thing most
  likely to be quoted out of context.
- **Its input-liveness probe was a version behind, and the corpus could not see it.**
  Until 2026-08-20 `src/verify.rs` carried the pre-2026-08 algorithm: seven fixed
  absolute deltas, no perturbations scaled to the input or to the machine word, no type
  edges, a **step-denominated** budget that charged a trapped run the full per-run cap,
  and no second pass — so it returned no `output_liveness_by_cell` at all. It would have
  reported `dead` where the specification requires `live` for any computation coarser
  than 1 000 000 in its inputs' own units, and could not supply the per-cell answer
  `docs/GRAPHS.md` rule 2 needs to refuse a link carrying a constant. It now implements
  `docs/SPEC.md#the-input-liveness-probe` in full, identically to the other two down to
  the cost table, and the constants are held equal across all three by
  `tests/test_spec_constants_match_code.py`. **The lesson survives the fix**: the
  three-way differential was green throughout, because agreement on a corpus that never
  reaches the difference is not agreement, and it was writing the specification — not
  running the tests — that made the gap visible.
- **It does not implement `tau_field_fixed`**, exactly as the JavaScript port does not.
  Such receipts report `re-derived: not attempted` and are never reported verified.
  This has a consequence worth stating plainly: **all nine public challenge bundles are
  `tau_field_fixed`**, so this crate refuses all of them, and it refuses the two honest
  ones for the same reason it refuses the forgeries. Its integrity check independently
  catches six of the seven forgeries; the seventh, `resealed_tampered_claim`, is
  designed to pass integrity and fail only on re-derivation, and this crate cannot
  re-derive it. **Agreement here proves nothing about the tau kernel.**
- **The Ed25519 is hand-written**, and hand-written curve arithmetic is where
  cryptographic implementations go wrong. It is checked against the RFC 8032 vectors,
  against all 512 single-bit corruptions of a valid signature, against a recomputation
  of every hardcoded curve constant, and against the producer's real signatures — but
  the edge cases nobody enumerated (non-canonical point encodings, small-order keys, the
  cofactored/cofactorless boundary of A12) are checked only insofar as the corpus
  reaches them, and the corpus is not exhaustive there. If you need a hardened
  implementation, use one; if you need an auditable one, read `ed25519.rs`.
- **Agreement is evidence about the spec's clarity, not proof of correctness.** Three
  implementations by one person agreeing means the spec was unambiguous enough to be
  re-read consistently by that person. It cannot exclude a misreading all three share —
  which is why the spec-gap list above matters more than the passing tests.
- **The randomised corpus is seeded, not exhaustive.** Every failure reproduces; no
  absence of failure is a proof.

## Layout

```
src/json.rs        the wire format: what loads, and the canonical bytes it loads to
src/sha2.rs        SHA-256 and SHA-512
src/ed25519.rs     signature verification, no dependencies
src/replay.rs      the obsign/replay/1 machine
src/signature.rs   obsign/signature/v2, and what v1 refuses to attribute
src/verify.rs      the trust ladder, and the input-liveness probe
src/graph.rs       docs/GRAPHS.md, the chain rule
harness/           the corpus and the JavaScript leg of the three-way differential
```

Apache-2.0, matching the rest of the estate.
