# obsign-verify (JavaScript)

**Re-derive the number yourself. Offline. On your hardware. Zero dependencies.**

A signature tells you a claim is *unmodified*. It never tells you the claim is *true*.
This re-runs the computation and compares bits.

```console
$ npm i -g obsign-verify
$ obsign-verify receipt.json

  [VERIFIED] receipt.json
      integrity   ok
      re-derived  ok
      signature   ok, signer BOUND (A. Chen, Coherence Energy Labs)

1/1 receipt(s) verified on THIS machine.
```

Exit `0` if every receipt verified, `1` otherwise. A receipt that carries a signature
which does not verify is **refused** — the exit code, not a note, carries that verdict.

## Read this before you rely on it

**This is a port by the same author, not an independent second implementation.** It
cannot discharge the independence claim — two programs by one author can share one
misreading of a spec — and it is labelled that way in the package, the CLI and the
source. The independent implementation is still open, and earns **recognition, not
cash**: named on the strangers page, named in the conformance suite, credited in the
spec.

What it *does* establish is narrower and worth having. The replay instruction set was
designed to be re-implementable "in an afternoon, in any language with 64-bit
integers". This is that claim tested rather than asserted — in a language whose native
number is a double and whose JSON parser destroys a distinction the spec depends on.
The test suite verifies receipts **produced by the Python implementation** and requires
byte-identical agreement.

## What it checks, and what it refuses to pretend

| | |
|---|---|
| **integrity** — does `receipt_sha256` recompute from the claim? | every receipt |
| **re-derived** — does re-running the program reproduce the output? | `obsign/replay/1` |
| **signature** — does the Ed25519 signature verify, and cover what it claims to? | every signed receipt |
| **issuer trust** | out of scope in every implementation, deliberately |

It does **not** re-execute `tau_field_fixed`; those receipts report `re-derived: not
attempted` with a note and are **never reported as verified** — a valid signature says
*who*, it does not stand in for recomputing *whether*. *"I cannot check this"* is a
third answer, and collapsing it into pass or fail is how a verifier starts lying.

### The signature check, and what it refuses to pretend

Ed25519 comes from `node:crypto` (Node 18+), so this still has zero dependencies.
The check mirrors the Python reference exactly, including the part that matters most:

- **It will not name a signer the signature did not cover.** Legacy
  `obsign/signature/v1` signs the bare receipt hash and attributes *nobody*
  (`identity_bound: false`, `attributed_signer: null`). Only `obsign/signature/v2`,
  which signs the domain-tagged hash of `{spec, alg, public_key, receipt_sha256,
  signer, binds_sha256}`, binds a name.
- **The bound-metadata check runs unconditionally.** `binds` is not covered by the
  signature — it is supplied by whoever hands you the file — so deleting or emptying it
  cannot *skip* the comparison against `binds_sha256`, only *fail* it. The `case`
  block (case id, examiner) lives outside `receipt_sha256`, so this is the check that
  stops an examiner's name being rewritten on a cryptographically valid receipt.
- **An unbound `case` is reported, never assumed harmless.** The producer's post-hoc
  case export legitimately emits one; the verifier says out loud that it is an
  unattested annotation.

Before 0.3.0 this port did **not** check signatures, and said so in a note — while
`verified` was computed without the signature, so a forged one printed `VERIFIED` and
exited `0`. The note was honest and useless: documentation is not a control. Whatever
this implementation declines to check, it now also declines to pass.

The signature fixtures it is tested against were **signed by the producer**, not by
this package (`src/obsign_verify/data/conformance/`). Two implementations that only
ever check their own output agree about their own mistakes; for three releases the
Python verifier and the producer disagreed about the signed bytes and neither suite
could see it.

## The trap this package exists to survive

`JSON.parse` turns every number into a double, so `1` and `1.0` become the same value.
The canonical form writes `1` for an integer and `1.0` for a float, and those hash
differently. **A JavaScript verifier built on `JSON.parse` reports every honest receipt
containing a whole-numbered float as tampered** — confidently, for a reason its author
would never think to look for.

So this does not use `JSON.parse`. It parses the *text* and remembers, per literal,
whether it was written as an integer or a float. That information exists nowhere else
once the value is a double.

Arithmetic is `BigInt` throughout. JavaScript numbers are exact only to 2^53; the
worked example's intermediates reach 4e20, because `MULFX` multiplies **exactly** and
then truncates. Using `Number` would agree with the reference on small inputs and
diverge silently on large ones — the worst failure shape available.

## Pin the program your validator approved

Re-derivation proves the output follows **from the program**. It does not prove the
program computes what its name claims: a two-instruction program returning a hardcoded
constant re-derives perfectly, and this tool reports `VERIFIED` — correctly, because it
did.

The answer is not a weaker verdict. Read the program once, approve it, record its
digest:

```console
$ obsign-verify receipt.json --expect-program 3ba4e9302ac39c36...
```

The question stops being *"did this re-derive?"* and becomes *"did this re-derive from
the program my validator approved?"*

## Links

- Python reference implementation: <https://pypi.org/project/obsign-verify/>
- Source: <https://github.com/coherence-energy-labs/obsign_verifier>
- <https://obsign.io>

Apache-2.0.
