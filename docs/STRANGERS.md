# The strangers page

**You are the control group.** We claim these receipts re-derive to identical bytes on
hardware we have never touched. Do not take our word for it — that is the entire point
of the format.

```console
$ pip install obsign-verify
$ obsign-verify stream/*.json
```

Exit `0` means you got our bytes. Exit `1` means you did not, and **we want to hear
about it far more than we want another success.**

---

## What we are asking you to do

1. Run it. Two minutes, numpy only, no network, no GPU, no account.
2. **Publish your unedited log** — including the boring parts, especially the boring parts.
3. Fill in `attestation.json` below and sign it with any key you control, or don't sign
   it at all. An unsigned attestation from a named human is worth more to us than a
   signed one from an anonymous key.
4. Report anything ambiguous. **An ambiguity report is as valuable as an attestation.**
   If the output made you unsure whether you had passed, that is a defect in our tool.

## What we are not asking

We are not asking you to trust us, install anything privileged, run as root, or send us
data. The verifier reads a JSON file and does arithmetic. If it ever asks for more than
that, something is wrong and you should say so loudly.

---

## Attestation format

```jsonc
{
  "spec": "obsign/attestation/v1",
  "verifier_version": "0.1.0",
  "verified_at": "2026-08-01T00:00:00Z",
  "attestor": "your name, handle, or 'anonymous'",
  "platform": {
    "os": "the output of `uname -a` or equivalent",
    "python": "3.12.4",
    "numpy": "2.1.0",
    "cpu": "arch is what matters -- aarch64 and x86_64 are the interesting split"
  },
  "receipts": [
    { "file": "v1_basic.json", "expected": "VERIFIED", "observed": "VERIFIED" }
  ],
  "exit_code": 0,
  "log": "your UNEDITED terminal output",
  "notes": "anything ambiguous, confusing, or surprising -- this field is the point"
}
```

**Platform diversity is the whole value.** A hundred attestations from x86_64 Linux
prove less than three from aarch64 macOS, Windows, and a Raspberry Pi. If you are on
something unusual, you are the most useful reader we have.

---

## The log

*No stranger verifications recorded yet. This section is deliberately empty rather than
absent — an empty log is a fact about where we are, and a page that only appeared once
it had good news would be worthless.*

| Date | Attestor | Platform | Result | Log |
|---|---|---|---|---|
| — | — | — | — | — |

**Negative results are published here too, unedited, with the same prominence.** A
strangers page that only lists successes is a testimonials page, and testimonials are
what this product exists to replace.

---

## If you want to try to break it

Better. The public challenge ships forgeries on purpose — one honest receipt and seven
tampered ones, including a **resealed** forgery whose signature is intact and whose
claim is false. It gets past integrity and is caught only by re-derivation.

The interesting attacks are not on the cryptography:

- **Find a platform where the bytes differ.** The honest residual risk is stated in the
  README: a source value sitting exactly on a `.5` rounding boundary could round
  differently under a different libm. Not observed; not proven impossible. Finding one
  would be a genuine result and we would publish it here as such.
- **Find a forgery the verifier accepts.** That breaks the scheme, not the tool.
- **Find a valid receipt it refuses.** Equally serious in the other direction — a
  verifier that cries wolf is one people stop running.

**There is no cash bounty, and there will not be one.** What an independent
implementation earns is **recognition**: named here, named in the conformance suite it
is judged against, and credited in the spec as the second implementation. That is the
honest offer, and it is stated plainly so nobody spends a weekend expecting otherwise.

It is also the offer that fits the artifact. A second implementation is the protocol's
graduation event because it proves the spec is writable-from, not because it was paid
for — and money would attract people optimising for a payout rather than for finding
the place we are wrong.
