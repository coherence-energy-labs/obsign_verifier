# Receipt graphs — supply chains of computation

A single receipt proves one computation: *re-run this program on these inputs and you
get this hash*. A receipt **graph** proves a pipeline of them: this quarter's number
was computed from three desks' numbers, each of which was computed from its own raw
inputs — and a stranger can re-derive the whole chain, leaf to root, with the same
`pip install obsign-verify` that checks one receipt. Verification of an entire
computation supply chain, transparent all the way down.

The design constraint that governs everything here: **a linked receipt is still an
ordinary `obsign/receipt/v1` receipt.** Links ride in an additive field; a verifier
that has never heard of graphs still verifies every node standalone, byte for byte.
Nothing about single-receipt semantics changes — the graph rule only ever *adds*
constraints, so it can refuse more, never accept more.

## The link block

A replay receipt declares that a slice of its inputs is the output of another
receipt by carrying `links` inside `params` (and therefore inside the claim — links
are covered by `receipt_sha256` and by any signature, so they cannot be edited after
the fact):

```json
"params": {
  "program": { ... },
  "program_sha256": "...",
  "inputs": [3, 17500, 20125, 4088, ...],
  "links": [
    {
      "receipt_sha256": "9f2c…",   // the child receipt's claim hash (64 hex)
      "output_sha256":  "eb3f…",   // the child's output hash — explicit, belt and braces
      "src_offset": 0,             // where the slice starts in the child's output
      "length": 1,                 // how many int64 values carry over
      "dst_offset": 1              // where the slice lands in THIS receipt's inputs
    }
  ]
}
```

The parent still carries the actual input **values** — that is what makes it
verifiable standalone. A link adds the claim that those values are not merely
asserted but **produced**: by the named receipt, at the named place in its output.

## The chain rule

`verify_graph(receipts)` takes any set of receipts and enforces, for every node and
every link:

1. **Every node verifies standalone.** The full single-receipt ladder — integrity,
   re-execution, input-liveness, the signature gate — exactly as `verify()` runs it.
   A graph of unverified nodes proves nothing, whatever its links say.
2. **Every link binds values, not just hashes.** The child is re-executed and its
   re-derived output slice `[src_offset, src_offset+length)` must equal the parent's
   declared input slice `[dst_offset, dst_offset+length)` **value for value**. The
   parent consumed exactly what the child produced — established by re-derivation on
   both sides, never by trusting a stated hash.
3. **The stated hashes must also hold**: `link.receipt_sha256` must be the child's
   recomputed claim hash, and `link.output_sha256` the child's re-derived output
   hash. Redundant against rule 2 for a tamperer — and exactly the redundancy this
   estate ships everywhere, because it catches honest mistakes loudly and gives a
   stranger short strings to compare against published ones.
4. **Ranges are strict.** A link's destination range must lie inside the parent's
   inputs, its source range inside the child's output, and no two links on one
   parent may overlap destinations. Malformed ranges refuse; they do not clamp.
5. **The graph is a DAG by construction — and the verifier guards anyway.** A link
   names the child's *claim hash*, and a cycle would require a receipt whose hash is
   computed over a link that already contains a hash computed over that receipt —
   a fixed point SHA-256 does not offer. Cycles and self-links are therefore
   cryptographically impossible to mint, exactly as a git commit cannot contain its
   own descendant; the conformance suite demonstrates the impossibility, and the
   verifier still carries a cycle check as defense in depth for a broken-hash world.
   The same mechanism makes history immutable: *editing any leaf changes its digest,
   which orphans every link that pointed at it* — tampering does not corrupt a chain,
   it visibly disconnects it. A referenced receipt that was not supplied makes the
   graph **incomplete** — reported with the missing digest, distinct from *forged*:
   "I could not check this" is never spelled the same as "this is false", in either
   direction.
6. **One digest, one receipt.** If two supplied receipts claim the same
   `receipt_sha256` with different canonical bytes and both pass integrity, that is
   a SHA-256 collision and the graph refuses outright.

The verdict keeps split results honest: a node can be `verified` (it is internally
true) while its `links_ok` is false (it lied about where its inputs came from) — and
the graph is only `graph_verified` when every node verifies, every link binds, and
nothing is missing.

## Scope, version 1

Both ends of a link must be `obsign/replay/1` receipts — their outputs are flat
int64 vectors, so "the parent's input slice equals the child's output slice" is
exact and unambiguous. A link on or to any other kernel is reported as unsupported
(`links_ok: false` with a reason), never silently skipped. Extending links to array
kernels (`tau_field_fixed`) requires pinning a flattening order and belongs to a
later revision of this document, not to an implementation's private opinion.

## Compatibility

`links` is additive. Receipts without it are unaffected. Receipts with it verify
standalone under pre-graph verifiers (unknown `params` content does not change the
single-receipt ladder) and verify transitively under `verify_graph`. There is no
`obsign/receipt/v2`; this document plus the conformance chain under
`data/conformance/chain/` **is** the graph contract, and the Python and JavaScript
implementations are both held to it by shared fixtures and differential tests.
