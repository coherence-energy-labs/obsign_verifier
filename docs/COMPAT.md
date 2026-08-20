# Compatibility — what is frozen, and what "frozen" means

A receipt is worthless if next year's verifier reads it differently than this
year's. So before strangers hold receipts in volume, the surfaces their receipts
stand on are named here and frozen, and the freeze itself is enforceable: every
frozen surface is pinned by committed conformance data that any change would break
loudly, in CI, in two languages.

## The frozen surfaces

**`obsign/receipt/v1` — the claim rule.** The claim is every top-level key except
`receipt_sha256`, `env`, `signature`, `case`, and `_`-prefixed helpers;
`receipt_sha256` is SHA-256 over the claim's canonical JSON. This rule never
changes. New top-level keys may be added — they land inside the claim by default,
which is the safe direction (they are covered, not ignorable).

**Canonical JSON.** Exactly CPython's
`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
allow_nan=False)`, UTF-8 encoded: keys sorted by Unicode code point, non-ASCII
escaped, `1` and `1.0` distinct, NaN/Infinity unrepresentable — refused at load,
even in non-claim fields, so all implementations agree on what LOADS. Byte-for-byte
agreement across the four implementations (producer Python, this package, npm,
browser) is pinned by an adversarial corpus. No change, ever; a different
canonicalisation is a different receipt format.

**`obsign/replay/1` — the machine.** The 31-opcode instruction set, wrapping int64
arithmetic, truncate-toward-zero division, MULFX's exact-then-truncate-then-wrap
order, total operations (every partial case a Trap), the step budget, the
`{spec, mem, steps, consts, input, output, code}` program shape, and
little-endian-int64 `output_sha256`. Frozen. New opcodes or wider limits are
**`obsign/replay/2`** — a new spec string, a written spec, implementations in both
VMs with differential proof, and new conformance vectors — never a quiet edit to
`/1`. A verifier that meets an unknown spec string reports *unsupported*, which is
never spelled *invalid*.

**`obsign/signature/v2` — the envelope.** Ed25519 over
`"obsign/signature/v2\0" + SHA-256(canonical({spec, alg, public_key,
receipt_sha256, signer, binds_sha256}))`; the domain tag prevents cross-version
replay; `binds`/`binds_sha256` cover named out-of-claim keys. v1 signatures remain
verifiable and remain reported as *not identity-bound*. Frozen.

**Graphs v1 — the chain rule.** The `params.links` block and the verification rule
of `docs/GRAPHS.md`: links bind a parent's input slice to a child's re-derived
output slice, value for value, both ends `obsign/replay/1`. Additive by
construction — a linked receipt verifies standalone under every pre-graph verifier.
Extending links to other kernels is a documented revision of GRAPHS.md, not an
implementation's private opinion.

## The guarantee

**Any receipt that verifies under this package today verifies under every future
version of it.** Verification support is never deprecated, never feature-flagged,
never removed. Verdicts may gain *fields* and *notes*; the meaning of existing
fields (`integrity`, `reproduced`, `verified`, `input_liveness`, `graph_verified`,
`complete`, `links_ok`) does not drift. A future version may **refuse more** —
close a soundness hole, tighten a bound against denial-of-service — because
refusing a forgery an old version wrongly accepted is a fix, not a break; it may
never silently **accept more**.

## Refusals added under the guarantee

Recorded here because the guarantee is asymmetric and this is the direction it
permits. Each entry made this verifier refuse something an earlier version accepted.
None changes a rule, adds a spec string, or touches any receipt that verifies today.

**`obsign/replay/1` structural scalars are JSON integers, in both languages.** `mem`,
`steps`, the `input`/`output` window bounds and every instruction operand must be
written as an integer literal. The Python reference read a JSON `true` as 1 (`bool`
subclasses `int` there) and the JavaScript port read a JSON `4.0` as 4 (once parsed, a
safe-integer Number is indistinguishable from an integer literal unless the parser
kept the shape — canonical.js does, and the structural check was not consulting it).
Each implementation loaded programs the other refused, in opposite directions; both
now refuse both, so the two agree on which programs exist. Programs whose scalars are
ordinary integers — every program the compiler has emitted, every committed
conformance vector — are unaffected.

**Graphs v1: a node's verdict covers every envelope supplied for its claim.**
`signature`, `case`, `env` and `receipt_sha256` are outside the claim, so two
different documents can index to the same node. `verify_graph` ran the standalone
ladder on the first copy to arrive and dropped the rest, which made the verdict depend
on list order; it now runs the ladder on each and takes the conjunction, reporting the
multiplicity as a `DUPLICATE ENVELOPE` note. That is docs/GRAPHS.md rule 1 — *every
node verifies standalone* — applied to every receipt actually handed over. A second
envelope is not itself a fault: two honest attestations of one claim still verify.
Each node verdict gains an `envelopes` count; a new field is what the guarantee
permits, and no existing field changes meaning.

## How the freeze is enforced, not promised

`data/conformance/` — the kernel vectors, the signed producer receipts, the
challenge bundles, the graph chain — is the freeze made executable: those bytes
must verify, byte-identically, forever, in Python and JavaScript both, and CI runs
them on every change. The compiler may improve (its output bytes may change between
versions; `attest` is per-compiler-version by design), but every program it has
ever emitted remains a valid `obsign/replay/1` program that every future verifier
re-executes identically. Changing this document is a format decision by the
maintainers, in the open, with a version string — never a side effect of a patch.
