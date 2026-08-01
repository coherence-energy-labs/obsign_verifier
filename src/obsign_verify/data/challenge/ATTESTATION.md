# Attestation — I ran the Receipt Challenge

Fill in, publish anywhere, link it back if you're willing. A failure to break it
is as useful as a break; a break is more useful.

## Who
- Name / handle:
- Affiliation (optional):
- Date (UTC):

## Platform
- OS + version:
- CPU (and whether ARM / x86):
- Python version:
- numpy version:
- Anything unusual (musl, emulation, BSD, big-endian, PyPy, WASM):

## What I ran
```
python verify_challenge.py
```
Paste the full output:

```

```

## SHA256SUMS I observed
Confirm the bundle you ran matches what was published:
```
sha256sum -c SHA256SUMS      # or: python -c "..."
```
Result:

## Verdict
- [ ] Every valid receipt re-derived on my machine
- [ ] Every forgery was refused
- [ ] I found a forgery that VERIFIED  ← the interesting one
- [ ] The valid receipt did NOT reproduce on my hardware  ← also interesting

## Notes / anything you broke or tried to break

<!-- Attacks attempted, near-misses, ambiguity in the spec, anything the
     verifier fails to check. Negative findings welcome and wanted. -->

## Independence
- [ ] I confirmed `verify_challenge.py` imports nothing from the producing project
- [ ] I read the verifier before running it
