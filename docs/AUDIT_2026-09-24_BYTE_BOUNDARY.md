# Byte-boundary hardening, 2026-09-24

Status: draft, scoped hardening; NOT a release or independent certification.
Baseline: `5d14d112e40231aee59b10e09f86beaf6afda047` (`master`).
Original `js/src/canonical.js` blob: `36e144fccf6315b90aadc77a0247bd2d59979389`.
Python comparison blob: `60cbe09ef95c9be22b6a080075574fb90660d482`.

## Confirmed findings

1. A leading UTF-8 BOM was silently removed by TextDecoder when the caller supplied
   bytes. The same document was refused when supplied as text and by the Python
   text reader. This is a parser/encoding agreement defect, not a demonstrated
   signature forgery or an accepted false computation.
2. The 4 MiB size check happened after byte decoding. An oversized Uint8Array
   could make the decoder allocate a text representation before refusal.

## Fix

Check byteLength before constructing the decoder. Set ignoreBOM:true so a leading
U+FEFF is retained for the JSON parser to refuse, matching the string/Python
boundary. An embedded U+FEFF inside a JSON string remains ordinary data. Keep
fatal UTF-8 decoding and the existing post-decode string-byte limit.

The pre-decode check bounds this API's decoding allocation. It does not bound a
caller's earlier file read or certify overall service resource consumption.

## Executed evidence

Node 22.16.0 and Python 3.13.5, Linux x86-64. Complete canonical modules were
executed, after matching original file copies to their Git blob hashes.

- New node:test regression file: 8 passed patched; 2 failed and 6 passed on the
  original. Includes valid receipts, Unicode, tampering, invalid UTF-8 and a
  decoder spy proving oversized bytes never invoke decoding.
- 20,041 seeded generated/adversarial documents: 12,284 accepted and 7,757
  refused by both implementations, zero acceptance/hash disagreements and zero
  unexpected JavaScript exceptions.
- 152,098 binary64 serialization cases: zero Python repr / JavaScript
  pyFloatRepr disagreements on both original and patched complete modules.
- Removing BOM preservation or the pre-decode limit independently made the
  corresponding regression fail.

```sh
cd js
node --test test/wire_byte_boundary.test.js
npm test
```

The existing npm test glob includes this new file. Only the new focused file and
custom differential harness were run locally, not the complete npm suite.

## Boundaries

No claim is made that this tests replay graphs, approved-program semantics,
cryptographic forgery resistance, Rust, actual browsers, or production deployment.
No live service was attacked. The byte parser patch changes no arithmetic,
canonical serialization, signing, trust policy, publication credentials or site
seal. Existing CI, cross-runtime conformance and release review remain required.
