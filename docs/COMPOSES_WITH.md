# How this composes with C2PA, in-toto, SLSA and SCITT

**Short version:** they answer *who did what*. This answers *and here is the number,
recomputed on your machine*. Those are different rungs, and the lower one is load-
bearing — none of this works without signatures, transparency logs and identity.
We are not a replacement for any of them, and the composition is the interesting part.

*Standards facts below were checked 2026-08-01 and carry their sources. Per this
estate's own re-verification rule, re-check them before they appear in external
material; standards move.*

---

## The one distinction

**Attestation:** *"I, holder of this key, assert that this happened."*
Trust is anchored in the key. The reader's question becomes *do I trust the signer?*

**Replay:** *"Re-run this and you will get these exact bytes."*
Trust is anchored in determinism. The reader's question becomes *did I get the same
bytes?* — which they answer themselves, offline, without deciding anything about us.

A signature proves a claim is **unmodified**. It never proves the claim is **true**.
That gap is not a flaw in signing; it is what signing is for. The public challenge
ships a **resealed forgery** to make it concrete: the output is edited, the receipt
re-hashed, the signature re-applied. Integrity passes. Re-derivation fails. One file
demonstrates why the second step exists.

---

## The neighbours, described as they describe themselves

### C2PA — Content Credentials

Cryptographically signed manifests travelling with media, asserting capture device,
edit history and authorship. It is the reason a photo can carry its provenance
through a publishing pipeline.

C2PA records **what was done** and signs it. It does not re-execute the edit and
confirm the result. For photographs that is the right design — a camera sensor's
output is not reproducible by construction, so there is nothing to re-derive.

**Composition:** an Obsign receipt is a natural C2PA assertion for the parts of a
pipeline that *are* deterministic. Obsign already ships a C2PA-native bridge.

### in-toto — supply-chain layouts and link metadata

A layout defines the steps a supply chain must follow; link metadata attests each
step was performed by an authorised functionary. Strong at *the right party did the
right step in the right order*.

Again: attestation of authorship and sequence, not re-derivation of a value.

**Composition:** an Obsign receipt fits cleanly as an in-toto attestation predicate.
The link says the step ran; the receipt lets anyone re-run it.

### SLSA — Supply-chain Levels for Software Artifacts

Build provenance at increasing levels of hardening. This one is worth stating
precisely, because it is the most instructive.

**SLSA does not require reproducible builds.** Reproducible and hermetic builds were
**removed in SLSA 1.0**; verified reproducible builds remain *one option* for meeting
requirements, and the stated reasoning is that reproducibility is hard in practice.
Provenance attestation is what L1–L3 actually require, with L2 and L3 hardening *how*
that attestation is produced ([SLSA FAQ](https://slsa.dev/spec/v1.0/faq),
[Build: Provenance](https://slsa.dev/spec/draft/build-provenance)).

That is not a criticism — it is a correct engineering judgement about whole builds.
Making an entire toolchain bit-reproducible is a multi-year effort with a long tail
of timestamps, paths and parallelism. SLSA hardened the attestation path instead.

**And it is exactly the rung we occupy.** We are not doing the thing SLSA declined to
do; we are doing it for a much smaller object. Not a build — **one computed number**.
That narrowing is what makes it tractable, and it is the honest scope statement: only
the *claimed value* must live in the deterministic core, not your whole pipeline.

**Composition:** SLSA provenance says which builder produced the binary. An Obsign
receipt says what the binary computed and lets a reader confirm it. Stacked, not
substituted.

### SCITT — Supply Chain Integrity, Transparency and Trust (IETF)

A transparency service registers signed statements in an append-only verifiable data
structure. Registration is a notarisation: the service checks policy, records the
statement, and issues a **Receipt** — a signature over verifiable-data-structure
proofs that the statement is registered, verifiable without online access to the
service ([draft-ietf-scitt-architecture-22](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-architecture-22),
[scitt.io](https://scitt.io/)). Active work: the architecture draft is at -22 (Oct 2025),
and a Canonical Payload Binding profile appeared in July 2026
([draft-mih-sokolov-scitt-payload-binding-01](https://datatracker.ietf.org/doc/html/draft-mih-sokolov-scitt-payload-binding-01)).

**A naming collision, stated plainly so nobody has to discover it in a meeting.**
SCITT's *Receipt* and our *receipt* are different objects:

| | SCITT Receipt | Obsign receipt |
|---|---|---|
| Asserts | this statement is **registered** in the log | this value is **re-derivable** from these inputs |
| Verified by | checking an inclusion proof | re-running the computation |
| Answers | has anyone else seen this claim? | is this claim *true*? |

They are complementary, not competing, and the composition is the obvious one: **an
Obsign receipt is exactly the kind of signed statement worth registering with a SCITT
transparency service.** Registration gives it non-equivocation and a public audit
trail; re-derivation gives it truth. Neither supplies the other.

---

## Where this sits

```
  Gate      a transition that cannot produce a conformant receipt does not execute
  Replay    any stranger re-derives the value bit-for-bit          <-- this rung
  Attest    the issuer signed that this happened                   <-- C2PA, in-toto,
                                                                       SLSA, SCITT
```

**Attest before Gate.** Leading with enforcement demands maximum trust on day one and
is a cold-start killer. Replay is adoptable because it asks nothing of you: you do not
have to trust the issuer, adopt a policy, or change your build. You run one command.

---

## What would falsify this positioning

Stated so it can be checked rather than argued:

- **If a model or build provider shipped per-customer re-derivation** — not attestation
  of *their* pipeline, but re-derivation of *your* computation on *your* data — the
  distinction above would collapse and this rung would be commodity.
- **If determinism proved unnecessary** — if a statistical re-check were accepted as
  equivalent by the auditors who actually sign off — then bit-identity would be
  over-engineering.
- **If the scope narrowing failed in practice** — if real customers could not shrink
  their claim to the handful of disputed numbers, the porting cost would block
  adoption regardless of the cryptography.

The third is the live one, and it is a sales-qualification test, not a technical
question: *if you cannot shrink scope to the disputed numbers on the first call, that
customer is not ready.*

---

## Sources

- [SLSA — Frequently asked questions](https://slsa.dev/spec/v1.0/faq)
- [SLSA — Build: Provenance](https://slsa.dev/spec/draft/build-provenance)
- [draft-ietf-scitt-architecture-22 (IETF)](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-architecture-22)
- [SCITT — What is SCITT](https://scitt.io/)
- [draft-mih-sokolov-scitt-payload-binding-01](https://datatracker.ietf.org/doc/html/draft-mih-sokolov-scitt-payload-binding-01)
