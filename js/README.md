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
      inputs      ok - the output depends on the declared inputs
      signature   ok, signer BOUND (A. Chen, Coherence Energy Labs)
      - input-liveness is EVIDENCE, not proof: perturbing an input moved the
        output, which shows dependence but cannot show the program computes the
        formula its name claims. Pin an approved program digest
        (--expect-program) for that.

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
| **input-liveness** — does perturbing a declared input ever move the output? | `obsign/replay/1` |
| **signature** — does the Ed25519 signature verify, and cover what it claims to? | every signed receipt |
| **issuer trust** | out of scope in every implementation, deliberately |

Every rule this port implements is specified in `docs/SPEC.md` — the wire limits, the
canonical form, the 31-opcode machine, the liveness probe and the signature envelope —
so the two implementations can be compared against a document rather than against each
other.

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
constant re-derives perfectly, and the re-derivation is honest — it just establishes
nothing about the inputs the receipt names.

This port **refuses** that program rather than reporting `VERIFIED`. It perturbs each
declared input, and if nothing ever moves the output it reports `input_liveness: dead`
and fails the verdict; a constant hidden behind an equality guard — one that traps on
anything but its own receipted inputs — is refused the same way, as `guarded`, because a
program that declines to run yields no evidence either. This README said the opposite
until 0.4.0, describing behaviour `js/src/verify.js` no longer had. The exact algorithm,
identical in this port and the Python reference down to the perturbation ladder and the
probe budget, is `docs/SPEC.md#the-input-liveness-probe`.

A `live` verdict is **evidence of dependence, not proof of meaning**, and no finite
black-box probe can be more than that: an adversary can always return the number they
want for one exact set of inputs and run the real formula otherwise. So liveness is the
floor, not the answer. The answer is not a weaker verdict either — read the program once,
approve it, record its digest:

```console
$ obsign-verify receipt.json --expect-program 3ba4e9302ac39c36...
```

The question stops being *"did this re-derive?"* and becomes *"did this re-derive from
the program my validator approved?"*

## Chains

A receipt proves one computation. A **set** of receipts whose `params.links` bind each
parent's input slices to other receipts' re-derived output slices proves a pipeline:

```console
$ obsign-verify --chain desk_*.json firm_root.json
```

Every node is re-executed, and every link is compared **value-for-value** against a
fresh re-derivation of the child it names — nothing is taken from a stated hash that a
recomputation could establish instead. Exit 0 only if the whole chain holds.

Verifying the same files *without* `--chain` is a different and much weaker question:
each receipt is checked on its own, and a link naming a receipt you were never handed
is not looked at. Three verdicts stay distinguishable, because "I could not check this"
and "this is false" are different facts:

| verdict | meaning |
| --- | --- |
| `CHAIN VERIFIED` | every node re-derived, every link binds |
| `CHAIN INCOMPLETE` | a referenced receipt was not supplied, or a link carries values that were never shown to depend on anything — not forged, not established |
| `CHAIN REFUSED` | a node failed, or a link lied about where its inputs came from |

The second row is doing real work. `verify` refuses a receipt whose output ignores every
declared input — "a constant dressed as a computation" — but an output window is a
*vector*, so that check is passed by one decoy cell (`output 424242, a + b;`) and then
linking only cell 0. The same rule applied to **the slice the link actually carries**
closes it: a slice that never moved under any perturbation is `REFUSED`, and a slice the
probe ran out of budget on is `INCOMPLETE` rather than silently accepted. `--chain
--strict-liveness` demands a positive demonstration and refuses both.

## Links

- Python reference implementation: <https://pypi.org/project/obsign-verify/>
- Source: <https://github.com/coherence-energy-labs/obsign_verifier>
- <https://obsign.io>

Apache-2.0.
