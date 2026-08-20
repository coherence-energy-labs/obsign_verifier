# Audit scope — the package for a third-party review

Obsign's claim is adversarial by nature: *you do not have to trust us, re-run the
receipt*. A system that says that in public owes reviewers a map of where the
claim could break and every tool we have for breaking it. This document is that
map. It is written for a commissioned security audit, but it is public, because a
scope we would not publish is a scope we do not deserve credit for passing.

## What a break means here

Ordered by what it buys an attacker:

1. **Soundness** — a forged receipt (or forged chain) that a conforming verifier
   accepts. This is the break. Everything else is weather.
2. **Divergence** — the same bytes verify in one implementation and not another.
   Divergence is latent soundness: whichever side is wrong can be farmed.
3. **Completeness** — an honestly produced receipt a verifier refuses. Erodes
   trust, breaks no promise; the guarantee in `COMPAT.md` is deliberately
   asymmetric (we may refuse more, never accept more).
4. **Denial of service** — inputs that make a verifier hang or exhaust memory.
   Bounded by design (`MAX_STEPS`, `MAX_MEM`, size caps); the bounds are budgets,
   not proofs, and probing them is in scope.
5. **Information** — anything that misleads a relying party without flipping a
   verdict (report wording, UI, docs that overclaim).

## In scope, ranked

**1. Canonicalisation, four times.** `canonical.py` here, `canonical.js` (npm),
the browser verifier's inline canon, and the producer's Python. The format is
defined by CPython's `json.dumps(sort_keys=True, separators=(",",":"),
ensure_ascii=True, allow_nan=False)`; the other three re-implement it. Any input
that canonicalises differently in any pair — or *loads* in one and refuses in
another (non-finite numbers, duplicate keys, lone surrogates, numeric edge forms
like `1e400`, `-0.0`, 2^53-adjacent integers) — is a finding of class 2 trending
to 1. This is the highest-value target in the codebase.

**2. The signature envelope.** `obsign/signature/v2`: Ed25519 over a
domain-tagged digest of `{spec, alg, public_key, receipt_sha256, signer,
binds_sha256}`. Look for cross-version and cross-context replay, malleability,
signer/identity confusion between v1 and v2 verdicts, and anything that lets an
unsigned or differently-signed byte influence a *signed* verdict.

**3. The replay VM, twice.** `replay.py` and `replay.js` implement
`obsign/replay/1` (31 opcodes, wrapping int64, truncate-toward-zero division,
MULFX's exact-128-bit-then-truncate-then-wrap, total ops, hard step/memory
ceilings). The contract is bit-identical execution including *which inputs trap*
(trap-for-trap, though not which trap). Differential-fuzz the pair; any
divergence is class 2. A nondeterminism in one VM alone is class 1.

**4. The compiler and its oracle.** `replayc/` compiles the RL language through
an inliner, folder, and optimizing codegen; a tree-walking interpreter is the
independent oracle, and CI differentials compiled output against it and against
both VMs. The interesting failure is a *correlated* one: a semantic
misunderstanding shared by compiler and oracle (they were written by the same
hands) that the VMs faithfully execute. The spec in `docs/RL.md` is the tiebreak;
readings of it that diverge from the implementation are findings.

**5. The graph rule.** `graph.py` / `graph.js` plus `mint.py`. A chain verdict
must mean: every node re-executed, every link's parent input slice equal, value
for value, to the child's re-derived output slice. Attack the identity scheme
(nodes indexed by *recomputed* claim digest), the incomplete-vs-forged split, the
overlap and range checks, and the DAG argument (cycles require a SHA-256 fixed
point; tampering moves a digest and disconnects, never corrupts). The attack
battery in `tests/test_graph.py` is the state of our own adversarial thinking —
start where it stops.

**6. Input-liveness probing.** The heuristic that reports whether inputs could
have influenced the output. It is advisory and reported as such; in scope is any
way to make a *dead*-input receipt read as live, or wording that lets advisory
read as proven.

**7. The producer's site integrity chain** (repository `obsign`): `seal.json`
minting and checking, the pinned issuer key in `coherence-gate.js`, the eight
`web/build/` gates, and the worker's auth (HMAC tokens, PBKDF2, timing-safe
compares, CSP). In scope as the distribution channel for everything above.

## What auditors get

Everything is committed and runs offline. `data/conformance/` holds kernel
vectors, signed producer receipts, challenge bundles, and a frozen four-node
chain — the executable freeze described in `COMPAT.md`. `tests/` holds the
attack batteries (canonical, signature, replay, compiler, graph), three fuzzers
(kernel differential, compiler-vs-oracle-vs-VMs, graph corruption), and the
cross-language runners that hold Python and JavaScript to identical verdict
objects. `pytest` and `npm test` (in `js/`) run all of it; `OBSIGN_REQUIRE=node`
makes the cross-language legs mandatory. Fuzzers are seeded — every failure
prints its reproduction.

## Known, accepted limitations

Billing us for rediscovering these helps nobody; disagreeing with our acceptance
of them is itself a welcome finding.

- **One pinned issuer key, no rotation protocol.** The gate pins a single
  Ed25519 key; `trust.json` supports removal only. Key custody is the operator's
  problem and out of scope; the *absence of a rotation story* is accepted, known,
  and on the roadmap.
- **`env` is outside the claim** by design in v1 — it is diagnostic. A v2
  signature can cover it via `binds`; nothing makes that mandatory.
- **`replay/1` is int64-only.** No floats, no strings, no call stack. That is
  the point (totality, bit-identity), not an oversight.
- **Step/memory ceilings are budgets.** They bound work per receipt; they do not
  bound how many receipts you are handed. Rate limiting is deployment-side.
- **The compiler is not verified.** It is differentially tested against an
  independent oracle and two VMs; `attest` proves *this* compiler produced *that*
  bytecode. A Coq-grade guarantee is explicitly not claimed.
- **No third-party audit has happened yet.** This document is the ask. Until one
  concludes, the README must not say "audited", and it does not.

## Reporting

Disclose per `https://obsign.io/.well-known/security.txt` — contact
`josh@coherenceenergylabs.com`, good faith honored, reasonable window before
publication, credit on request. Findings of class 1 or 2 will ship as
conformance vectors with the fix, named for their finder if they want that:
a break, once fixed, is the strongest test we own.
