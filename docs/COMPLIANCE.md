# What a replay receipt is evidence of

**For the people whose job is to say no.**

This maps one capability — *the claimed number can be re-derived, bit-for-bit, by
someone who does not trust us* — to the controls an auditor already has to satisfy.

**It is technical-evidence mapping to support an audit. It is not a legal compliance
certification, and it is not advice.** The tables below are generated from
`tools/compliance_map.py`; a gate fails the build if this document and that module
disagree. The hand-written version of this artifact in a sibling repo had already
gone stale against its own code, which is why it is derived here rather than typed.

---

## The change in evidence class

Most controls in this space are satisfied *procedurally*: you assert that validation
happened, and the auditor assesses your process for asserting it. The reviewer's
question is **do I believe this organisation's process?**

A replay receipt changes what is handed over. The artifact is not a statement that
the number was checked — it is the number, plus a program that regenerates it. The
reviewer's question becomes **did I get the same bytes?**, which they answer
themselves, offline, in one command.

That converts a procedural control into a technical one. It is the only claim in this
document, and everything below is a consequence of it.

**A signature does not do this.** Signing proves a claim is *unmodified*; it never
proves the claim is *true*. The public challenge ships a **resealed forgery** — output
edited, receipt re-hashed, signature re-applied — precisely so the distinction is
demonstrable rather than argued. It passes the integrity check and fails re-derivation.

---

## Frameworks cited

<!-- BEGIN GENERATED: frameworks -- edit tools/compliance_map.py, not this block -->
| Framework | Edition cited |
|---|---|
| **EU AI Act** | Reg. (EU) 2024/1689, as amended by the 2026 Digital Omnibus |
| **ISO/IEC 42001** | 2023 |
| **NIST AI RMF** | 1.0 |
| **SOC 2** | AICPA Trust Services Criteria |
| **SR 11-7** | Fed/OCC supervisory guidance on model risk management |
<!-- END GENERATED: frameworks -->

Control identifiers are **edition-sensitive**. Article numbers, Annex A controls and
Trust Services Criteria references are cited as of the editions above; an auditor
working from a different edition must re-check the numbering. The stable part is the
capability-to-requirement argument. The identifier is a pointer, and pointers rot.

## Controls a receipt provides technical evidence for

<!-- BEGIN GENERATED: controls-evidenced -- edit tools/compliance_map.py, not this block -->
| Capability | Framework | Control | Requirement |
|---|---|---|---|
| declared accuracy that can be checked | EU AI Act | `Art. 15(1)` | Declared level of accuracy, with the metric stated |
| declared accuracy that can be checked | NIST AI RMF | `MEASURE 2.5` | Uncertainty and performance quantified per claim |
| declared accuracy that can be checked | SR 11-7 | `Outcomes Analysis` | Decisions carry a quantified, checkable claim |
| exact identification of what produced the value | EU AI Act | `Annex IV(1)` | Identification of the AI system and its exact version |
| exact identification of what produced the value | SOC 2 | `PI1.3` | Processing is authorised and attributable to a defined version |
| exact identification of what produced the value | SR 11-7 | `Model Development` | Model versioning bound to each result |
| independent re-derivation of the claimed value | EU AI Act | `Annex IV(2)` | Technical documentation of the system's development and validation |
| independent re-derivation of the claimed value | ISO/IEC 42001 | `A.6.2.4` | AI system verification and validation of intended behaviour |
| independent re-derivation of the claimed value | NIST AI RMF | `MEASURE 2.5` | Validity and reliability demonstrated and documented |
| independent re-derivation of the claimed value | SOC 2 | `PI1.4` | Output is complete and accurate -- evidenced by re-derivation rather than by attestation |
| independent re-derivation of the claimed value | SR 11-7 | `Model Validation` | Results are replicable by a party independent of the model's developer |
| resilience of the record against alteration | EU AI Act | `Art. 15(5)` | Cybersecurity; resilience against data or model manipulation |
| resilience of the record against alteration | NIST AI RMF | `MEASURE 2.7` | Robustness and security of the system evaluated |
| resilience of the record against alteration | SOC 2 | `PI1.5` | Stored output is protected from unauthorised change |
| tamper-evident record of the operation | EU AI Act | `Art. 12` | Automatic recording of events over the system's lifetime |
| tamper-evident record of the operation | EU AI Act | `Art. 26(6)` | Deployer retains automatically generated logs |
| tamper-evident record of the operation | ISO/IEC 42001 | `A.6.2.8` | Recording of event logs for AI system operation |
| tamper-evident record of the operation | NIST AI RMF | `GOVERN 1.5` | Traceability and accountability for system decisions |
| tamper-evident record of the operation | SOC 2 | `CC7.2` | System operation is monitored and anomalies detected |
| tamper-evident record of the operation | SR 11-7 | `Documentation` | Audit trail sufficient for independent review |
<!-- END GENERATED: controls-evidenced -->

The strongest row is **SOC 2 `PI1.4`**. Processing Integrity asks whether output is
complete and accurate. Every other technology in this space answers it by
*attestation* — someone with a key says so. A receipt answers it by *demonstration*.
That is the difference between showing and saying, and it is the entire product
argument in one control reference.

## Controls a receipt does NOT address

<!-- BEGIN GENERATED: controls-not-covered -- edit tools/compliance_map.py, not this block -->
| Framework | Control | Why a receipt does not address it |
|---|---|---|
| EU AI Act | `Art. 10` | Data and data governance; training-data quality and representativeness |
| EU AI Act | `Art. 14` | Human oversight design (a computed-claim receipt evidences no oversight step) |
| EU AI Act | `Art. 9` | Risk-management system across the lifecycle (process) |
| ISO/IEC 42001 | `A.5.2` | AI system impact assessment (process-level) |
| ISO/IEC 42001 | `A.7.2` | Data governance for AI systems |
| NIST AI RMF | `MEASURE 2.11` | Fairness and harmful-bias evaluation (needs a bias audit) |
| SOC 2 | `A1.x` | Availability commitments and capacity management (organisational) |
| SOC 2 | `CC6.x` | Logical access controls over the issuing system (organisational) |
| SOC 2 | `CC8.1` | Change management for the model and its deployment (process) |
| SR 11-7 | `Conceptual Soundness` | Justification of model design and assumptions |
<!-- END GENERATED: controls-not-covered -->

This list is why the previous one is credible. Every entry is process-level or
organisational, and a mapping that quietly omitted them would be the kind of overreach
that costs an auditor's trust in the rows that *are* evidenced. The self-test enforces
it structurally: **no framework may appear in the evidenced table without also
appearing here.** A framework claimed without its limits stated fails the build.

---

## Scope, stated before you ask

**Only the claimed number must live in the deterministic core — not your pipeline.**
This is the objection that decides adoption, so it is answered first rather than
defended later. You do not port your training stack. You identify the handful of
numbers that are actually in dispute — the ones a validator currently re-implements by
hand — and put those on the replay path.

If that scope cannot be shrunk to a short list on the first conversation, this is not
the right time for that organisation, and saying so early is cheaper for both sides.

**Cryptography stops at the sensor**, and for computed claims it stops at the input.
A receipt proves the stated inputs produce the stated output. It cannot prove the
inputs describe reality. Anyone who tells you otherwise is selling.

**Key custody is a separate question.** An unsigned receipt whose number re-derives is
still fully verified in the sense that matters here: integrity holds and you recomputed
the value. A signature adds *who*, not *whether* — and this verifier will not name a
signer the signature did not cryptographically cover.

---

## What to hand an examiner

1. The receipt.
2. `pip install` and one command.
3. This mapping, with the not-covered table intact.

The third item is the one that makes the first two land. An examiner who has been
handed only cryptography has been handed homework.
