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

**The forgeries ship with the package.** Nine bundles — two that must verify and
seven that must be refused — live in `challenge/bundles/`, so you get them in the
same clone as the verifier. Nothing to request, nothing behind a login:

```console
$ obsign-verify challenge/bundles/*/receipt.json
```

Exit `1` is the correct result: seven of the nine are forgeries and refusing them is
the job. `challenge/ATTESTATION.md` says what each one attacks.

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
