# obsign-verify

**Re-derive the number yourself. Offline. On your hardware.**

A signature tells you a claim is *unmodified*. It never tells you the claim is *true*.
This verifier re-runs the computation and compares bits.

```console
$ pip install obsign-verify
$ obsign-verify receipt.json

  [VERIFIED] receipt.json
      integrity   ok
      re-derived  ok
      signature   absent (integrity and re-derivation still hold)

1/1 receipt(s) verified on THIS machine.
```

Exit code `0` if every receipt verified, `1` otherwise. That is the whole interface.

## It imports nothing from the producer

Zero code is shared with the engine that mints these receipts. If it imported the
producer, *"it verifies"* would mean *"the producer agrees with itself"* — which is
not a claim worth making. The kernel here was written separately against the
published spec, so a bug in one cannot cancel a bug in the other.

Dependencies: **numpy**. That is it. Signature checking is an optional extra
(`pip install 'obsign-verify[sig]'`) *by design* — the two steps that make this more
than attestation, integrity and re-derivation, need no cryptography library at all.

## What it checks

| Step | Question | Status |
|---|---|---|
| 1 · integrity | does `receipt_sha256` recompute from the claim? | checked |
| 2 · reproduced | does re-running the kernel reproduce `output.sha256`? | checked |
| 3 · signature | does the signature verify, and cover what it claims to? | checked (optional dep) |
| 4 · issuer trust | *should* you trust this key? | **out of scope, deliberately** |

Step 4 is an identity question. A verifier that answered it from a bundled list
would be asserting a social fact as a cryptographic one. `verified` means steps 1–3.

**`VERIFIED` without a signature is not a weaker result.** It means integrity holds
and the number re-derived on your machine — you did not have to trust anyone. A
signature adds *who*, not *whether*.

## Replay programs — your number, not ours

Until 0.2.0 this verifier could re-execute exactly one computation, ours. Everything
else came back *"kernel cannot be re-executed here"*. Useful as a demonstration,
useless as a product: the number anyone actually wants a receipt for is **theirs**.

A **replay program** travels inside the receipt. `obsign-verify` executes it with
nothing but the standard library — no compiler, no producer toolchain, no network.

**Nondeterminism is not restricted, it is inexpressible.** There are no floats
anywhere: not in the operations, not in the operands, not in the constant pool. There
is no clock, no randomness, no environment, no I/O, no allocation, no host call.
Arithmetic is wrapping `int64`, stated rather than assumed. Every operation is total —
division by zero, an out-of-range shift, a bad address and an exhausted step budget are
all **traps**, and a trap is a refusal with a reason, never an exception that escapes.

The step budget is a security property, not a nicety: a receipt handed to you by an
adversary must not be able to hang your verifier.

### Chains — verify a pipeline, leaf to root

One receipt proves one computation. A **receipt graph** proves a pipeline of them: a
receipt's `params.links` binds slices of its inputs to other receipts' outputs, and

```
obsign-verify --chain desk_*.json firm_root.json
```

re-derives every node and checks every link **value-for-value** against a fresh
re-execution of the child — an auditor holding a firm-level number can unroll it
through every intermediate calculation down to raw inputs, on their own machine.
Links name claim hashes, so the graph is immutable the way git history is: cycles are
unconstructible, and tampering with any receipt doesn't corrupt the chain — it visibly
**disconnects** it. A missing receipt reports the chain *incomplete*, which is never
spelled the same as *forged*, in either direction. The rule, its verdicts, and the
shipped conformance chain (three desk-level ECL receipts feeding a firm-level root)
are specified in `docs/GRAPHS.md` and enforced identically by the Python and
JavaScript implementations.

### A worked example, and what it measures

`examples/ecl_portfolio.py` puts **IFRS 9 / CECL expected credit loss** —
`Σ PD × LGD × EAD` — on the replay path. It is the canonical number a model validator
re-derives by hand and an auditor disputes.

```console
$ python examples/ecl_portfolio.py
  ECL (replay, int) : 38,922,496 cents  = $389,224.96
  instructions      : 27

$ obsign-verify examples/ecl_receipt.json
  [VERIFIED] ecl_receipt.json
```

**Twenty-seven instructions is the whole deterministic core.** The models that produce
`PD` and `LGD` do not move — they stay in whatever stack and whatever floating point
they already use. Only the arithmetic that *combines* them crosses over. That is the
80/20 made concrete: the disputed number is usually not the model, it is the
aggregation, and the aggregation is small.

### The boundary, stated because you will find it anyway

**Replay proves the output follows from the program. It does not prove the program
computes what its name claims.** A two-instruction program returning a hardcoded
constant re-derives perfectly — the re-derivation is honest, and it establishes nothing
about the inputs the receipt names.

This tool now **refuses** that program rather than reporting `VERIFIED`: it perturbs
each declared input and, if nothing ever moves the output, reports `input_liveness:
dead` and fails the verdict. A constant behind an equality guard — one that traps on
anything but its own receipted inputs — is refused the same way, as `guarded`, because
a program that declines to run yields no evidence either.

**Do not mistake that for a proof of honesty.** Probing is evidence of dependence, not
a semantic guarantee, and no finite black-box probe can be more:

```
if inputs == this_quarter_exact_inputs:  return the number I want
else:                                    run the real formula
```

behaves correctly under every perturbation anyone thinks to try. The verdict says so in
its own notes, and reports which inputs were shown to reach the output and which were
not. Liveness catches the lazy forgery; only pinning the program answers the real
question.

The answer is not a weaker verdict, it is to pin the program — which is how model
validation already works. Read the program once (for the example: 27 instructions),
approve it, record its digest:

```console
$ obsign-verify receipt.json --expect-program 3ba4e9302ac39c36...
```

The question stops being *"did this re-derive?"* and becomes *"did this re-derive from
the program my validator approved?"* — which is what the auditor was asking all along.

## Two things it will not do

**It will not name a signer the signature did not cover.** Legacy
`obsign/signature/v1` signs the bare receipt hash, so it covers neither the signer
nor the case block — the name in the file can be rewritten by anyone with a text
editor and no key. Such receipts still verify, and are reported
`identity_bound: false`, `attributed_signer: null`. Only `obsign/signature/v2`
puts the signer inside the signed bytes.

**It will not crash instead of refusing.** A verifier that raises on a hostile
receipt has failed open in the eyes of whoever handed it the file. Malformed input
returns `verified: false`.

## Verify it against us

The package ships the same `conformance_vectors.json` the engine is judged against.

```console
$ pip install 'obsign-verify[dev]' && pytest
```

**The forgeries ship inside the package.** One command, no files of your own, no
login, no request:

```console
$ obsign-verify --self-check

  ok  env_only_change_must_still_verify   VERIFIED (expected VERIFIED)
  ok  forged_input_hash                   REFUSED  (expected REFUSED)
  ok  resealed_tampered_claim             REFUSED  (expected REFUSED)
  ...
9/9 bundles behaved as declared.
  ok  producer_signed_replay              SIGNER BOUND (A. Chen, Coherence Energy Labs)
  ...
  ok  binds stripped, examiner rewritten  REFUSED      (attributed nobody)

3/3 producer-signed receipt(s) accepted with the signer bound; the binds-stripping forgery was refused.
```

Exit `0` means every bundle got the verdict it declares — the two honest receipts
verified and **all seven forgeries refused.** Refusing them is the job, so a clean
run is not "9 verified". It then verifies three receipts **signed by the producer,
not by this package** (`data/conformance/`), and refuses the forgery that strips the
`binds` list and rewrites the examiner. That is the round trip that was never once
executed before 0.3.0 — and the reason 0.1.0–0.2.1 refused every genuine v2
signature while their own tests stayed green.

The one to look at is `resealed_tampered_claim`. Its output was edited, its receipt
re-hashed, its signature re-applied — so it passes the integrity check cleanly and
fails only on re-derivation. That single bundle is the entire argument for step 2.

## Why the number is the same on your machine

Integer fixed-point. Floating point is non-associative and vendor-dependent, so the
same float kernel on two chips can differ in the last bits; int64 arithmetic is
exact and identical on every machine that has it. The only float builds the initial
source term, and it is rounded to int64 before any evolution — so a last-ulp libm
difference is absorbed rather than compounded.

Honest residual risk, stated rather than hidden: a source value sitting exactly on a
`.5` rounding boundary could round differently under a different libm. **Not proven
impossible** — but now genuinely measured rather than assumed.

CI runs the conformance vectors on **x86_64 Linux, ARM64 macOS and Windows**, across
four Python versions, and prints the actual output hashes on every runner. The
architecture split is the load-bearing part: `aarch64` and `x86_64` ship different libm
implementations, and if that risk were going to bite, that is where it would.

When this sentence was first written it said "not observed across the platforms tested"
and exactly one platform had been tested — true, and nearly empty. If the hashes ever
diverge between two runners, the job fails and says so, because that divergence is the
finding, not an inconvenience.

## Status

**Apache-2.0.** Permissive on purpose: this is the artifact we ask strangers to run in
order to check us, and a licence that adds friction to that would defeat its own point.
It matches what the estate's other public "check our work" repos already carry.

`BUILT`. Publication is a single decision away — the package name `obsign-verify` was
verified available on PyPI on 2026-08-01, and everything here installs and passes today.

**A note on the name.** The bare `obsign` name is not available and is not ours: a PyPI
placeholder reading *"Reserved for the Obsign project — cryptographic proof of AI agent
actions"* was uploaded on 2026-07-30, seventeen minutes after the GitHub org it points at
was created. This package is the verifier rather than the engine, so the longer name is
the accurate one in any case.
