'use strict';
/**
 * Signature checking, in JavaScript. A port of `obsign_verify/signature.py`, and it
 * must agree with it on every receipt -- including the ones designed to be refused.
 *
 * WHY THIS FILE EXISTS AT ALL
 *
 * It did not, and the omission was disclosed honestly in a comment: "does not check
 * signatures ... reported null with a note". The comment was true. The EXIT CODE was
 * not. `verified` was `integrity && reproduced && digestOk && lenOk` -- the signature
 * was not a term in that conjunction -- so a receipt carrying a signature forged by
 * nobody's key printed VERIFIED and exited 0. A note in stdout is documentation; the
 * exit status is the interface, and it is what a CI pipeline actually reads.
 *
 * Two ways out: refuse every signed receipt, or check the signature. Refusing would
 * make the JavaScript verifier useless on exactly the receipts that carry an
 * attribution. So it checks. Ed25519 is in `node:crypto` (Node 18+), so this costs
 * the package nothing -- it still has zero dependencies.
 *
 * If a runtime cannot do Ed25519, this reports the signature INVALID with a reason
 * and the receipt is refused. "I cannot check this" must never resolve to a pass in
 * the field that gates the exit code.
 */

const crypto = require('node:crypto');
const { canonicalSha256, claimOf, integrity, isObj } = require('./canonical.js');

/** Only Ed25519 today. An unknown algorithm is UNVERIFIED, never "fine". */
const SUPPORTED_ALGS = new Set(['ed25519']);

/**
 * The v2 message is the domain tag followed by the canonical hash of the covered
 * attribute set. THE TAG IS A CROSS-IMPLEMENTATION CONTRACT: the producer, the
 * Python verifier and this file must produce byte-identical messages. They did not
 * for three releases -- the producer prefixed the tag, the verifier signed the bare
 * hash -- and every genuine v2 receipt failed in the tool customers were told to run.
 */
// Built from an explicit byte rather than a string escape: the trailing octet is NUL,
// and a NUL that silently became a space would look right in every diff while making
// this implementation reject every genuine receipt. A raw NUL in a source file is also
// exactly the kind of byte an editor, a linter or a copy-paste quietly eats.
const SIG_DOMAIN_V2 = Buffer.concat([
  Buffer.from('obsign/signature/v2', 'ascii'), Buffer.from([0]),
]);

/** Keys outside the claim hash that are still presented as fact. Must match Python. */
const OUT_OF_CLAIM_FACT = ['case'];

/** Structural keys: the hash and the signature themselves, never "metadata". */
const STRUCTURAL = new Set(['receipt_sha256', 'signature']);

/**
 * Every key PRESENT in the receipt that the claim hash does not cover and the
 * signature does not bind. COMPUTED, never enumerated -- the port of Python's
 * `unattested_keys`.
 *
 * `OUT_OF_CLAIM_FACT` names `case` and nothing else, so `env` and every
 * `_`-prefixed key rode outside both the claim hash and the signature with no
 * mention at all. The producer stores its printed VERDICT in a `_`-prefixed key
 * (`_combined_verdict`) precisely because it is outside the claim, so on a
 * genuine, valid, identity-bound report the sentence a reader acts on could be
 * rewritten by anyone with a text editor while this verifier said nothing.
 */
function unattestedKeys(receipt, bound) {
  const claim = claimOf(receipt).__obj;
  const isBound = new Set(bound || []);
  const out = [];
  for (const k of receipt.__obj.keys()) {
    if (claim.has(k) || STRUCTURAL.has(k) || isBound.has(k)) continue;
    out.push(k);
  }
  return out.sort();
}

/** Raw Ed25519 public key -> SPKI DER, which is what `createPublicKey` accepts. */
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function ed25519Ok(publicKeyHex, signatureHex, message) {
  let pub;
  let sig;
  try {
    const raw = Buffer.from(publicKeyHex, 'hex');
    if (raw.length !== 32 || raw.toString('hex') !== publicKeyHex.toLowerCase()) {
      return [false, 'public key is not 32 raw Ed25519 bytes in hex'];
    }
    sig = Buffer.from(signatureHex, 'hex');
    if (sig.length !== 64 || sig.toString('hex') !== signatureHex.toLowerCase()) {
      return [false, 'signature is not 64 raw Ed25519 bytes in hex'];
    }
    pub = crypto.createPublicKey({
      key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: 'der', type: 'spki',
    });
  } catch (e) {
    // Includes a runtime with no Ed25519 support. Refusal, not a pass.
    return [false, `cannot use this key for Ed25519 (${e.message})`];
  }
  try {
    return crypto.verify(null, message, pub, sig)
      ? [true, 'signature verifies']
      : [false, 'signature does NOT verify (InvalidSignature)'];
  } catch (e) {
    return [false, `signature does NOT verify (${e.message})`];
  }
}

/**
 * Recompute the hash a signature's `binds_sha256` commits to. Mirrors the producer:
 * only keys PRESENT in the receipt enter the hashed object, and an empty selection
 * is null rather than the hash of `{}`.
 */
function bindsHash(receipt, keys) {
  const bound = new Map();
  for (const k of keys) if (receipt.__obj.has(k)) bound.set(k, receipt.__obj.get(k));
  return bound.size ? canonicalSha256({ __obj: bound }) : null;
}

/** Read a scalar (string / null) out of a tagged object, without unwrapping numbers. */
function str(map, key) {
  const v = map.get(key);
  return typeof v === 'string' ? v : null;
}

/** Step 3 of the ladder. Returns a plain object; never throws. */
function check(receipt) {
  const out = {
    present: false, valid: false, identity_bound: false,
    attributed_signer: null, claimed_signer: null, detail: '',
    bound_metadata: [], unbound_metadata: [],
    // the COMPUTED set (see unattestedKeys); `unbound_metadata` stays the
    // `case`-shaped answer the wire format and the other ports already carry
    unattested_metadata: [],
  };

  const sigv = receipt.__obj.get('signature');
  if (!isObj(sigv)) {
    out.detail = 'no signature (integrity and re-derivation still apply)';
    return out;
  }
  const sig = sigv.__obj;
  out.present = true;
  out.claimed_signer = str(sig, 'signer');

  // A signature attributes a NAME to a CLAIM. If the claim no longer hashes to
  // `receipt_sha256` there is no claim left to attribute.
  const [okIntegrity, integrityDetail] = integrity(receipt);
  if (!okIntegrity) {
    out.detail = `signature NOT evaluated - ${integrityDetail}`;
    return out;
  }

  // THE ALGORITHM TOKEN IS EXACT, NOT NORMALIZED. This lower-cased before
  // comparing, so "ED25519" was accepted here and called unsupported by the
  // producer and the browser verifier, which both compare the exact token. The
  // value is inside the SIGNED attribute set, so this is not display formatting:
  // it is one implementation verifying a receipt another refuses. `sig` is
  // attacker-supplied, so reading it without coercion also means a number,
  // object, or null simply is not the token rather than throwing past a caller
  // this function promises never to throw to.
  const alg = sig.get('alg');
  if (typeof alg !== 'string' || !SUPPORTED_ALGS.has(alg)) {
    out.detail = `unsupported algorithm '${alg}' - UNVERIFIED, not accepted`;
    return out;
  }

  const sigHex = str(sig, 'sig') || str(sig, 'signature');
  const pubHex = str(sig, 'public_key');
  const receiptHash = str(receipt.__obj, 'receipt_sha256');
  if (!sigHex || !pubHex || !receiptHash) {
    out.detail = 'signature block is missing sig/public_key/receipt_sha256';
    return out;
  }

  const spec = str(sig, 'spec');
  if (spec === 'obsign/signature/v2') {
    const covered = new Map([
      ['spec', spec], ['alg', sig.get('alg')], ['public_key', pubHex],
      ['receipt_sha256', receiptHash], ['signer', sig.get('signer') ?? null],
      ['binds_sha256', sig.get('binds_sha256') ?? null],
    ]);
    const message = Buffer.concat([
      SIG_DOMAIN_V2, Buffer.from(canonicalSha256({ __obj: covered }), 'ascii'),
    ]);
    const [ok, detail] = ed25519Ok(pubHex, sigHex, message);
    out.valid = ok;
    out.detail = detail;
    if (!ok) return out;

    // THE COMPARISON BELOW RUNS UNCONDITIONALLY. `binds` is supplied by whoever hands
    // you the file and is NOT covered by the signature; `binds_sha256` IS. So the
    // signed hash is the authority, and a missing, empty or lying `binds` can only
    // FAIL the comparison, never skip it. Skipping it is how `case.examiner` -- which
    // is excluded from the receipt hash and printed at the top of a court report --
    // became a free-text field on a cryptographically valid receipt.
    let binds = sig.get('binds');
    if (binds === undefined || binds === null) binds = [];
    if (!Array.isArray(binds) || !binds.every((k) => typeof k === 'string')) {
      out.valid = false;
      out.detail = 'signature `binds` is not a list of key names - REFUSED '
        + '(the bound metadata cannot be reproduced)';
      return out;
    }

    // A NAME THAT IS NOT IN THE FILE IS NOT A BOUND KEY. `bindsHash` hashes only the
    // keys actually PRESENT, and `binds` is outside the signature, so padding the
    // list with names for absent keys leaves the hash unchanged: the comparison
    // below passes and `bound_metadata` then reports keys this signature never
    // bound and this receipt does not even contain. A producer never emits such a
    // list; the only readings are "the bound block was deleted" and "the list was
    // padded", and both are refusals.
    const missing = binds.filter((k) => !receipt.__obj.has(k));
    if (missing.length) {
      out.valid = false;
      out.detail = `signature \`binds\` names [${[...missing].sort().join(', ')}], which this `
        + 'receipt does not contain - the bound block was removed since signing, or the '
        + 'list was padded with keys no signature ever covered. REFUSED';
      return out;
    }

    const recomputed = bindsHash(receipt, binds);
    const declared = sig.get('binds_sha256') ?? null;
    if (declared !== null && typeof declared !== 'string') {
      // Coercing a non-string to null let an attacker-supplied value be read as
      // "absent", which an empty `binds` then reproduced -- turning a malformed
      // field into a passing identity binding. Malformed is refused, never
      // normalised: whoever handed you the file chose this value.
      out.valid = false;
      out.detail = `signature binds_sha256 is ${typeof declared}, not a string or absent `
        + '- REFUSED (the bound metadata cannot be reproduced)';
      return out;
    }
    if (recomputed !== declared) {
      out.valid = false;
      out.detail = `signature verifies but its bound metadata [${[...binds].sort().join(', ')}] `
        + 'does NOT reproduce binds_sha256 - the bound block has been changed, removed, '
        + 'or the `binds` list was stripped since signing';
      return out;
    }

    out.identity_bound = true;
    out.attributed_signer = str(sig, 'signer');
    out.bound_metadata = [...binds].sort();
    out.unbound_metadata = OUT_OF_CLAIM_FACT.filter(
      (k) => receipt.__obj.has(k) && !binds.includes(k));
    out.unattested_metadata = unattestedKeys(receipt, binds);
    if (out.unattested_metadata.length) {
      const n = out.unattested_metadata.length;
      out.detail += `; WARNING: ${out.unattested_metadata.join(', ')} `
        + `${n === 1 ? 'is' : 'are'} present but NOT covered by this signature - `
        + `unattested annotation${n === 1 ? '' : 's'}, which must not be printed as if `
        + `the signature vouched for ${n === 1 ? 'it' : 'them'}`;
    }
    return out;
  }

  // Legacy v1: signs the bare receipt hash. Verifies, attributes NOBODY.
  const [ok, detail] = ed25519Ok(pubHex, sigHex, Buffer.from(receiptHash, 'ascii'));
  out.valid = ok;
  out.identity_bound = false;
  out.attributed_signer = null;
  out.bound_metadata = [];
  out.unbound_metadata = OUT_OF_CLAIM_FACT.filter((k) => receipt.__obj.has(k));
  out.unattested_metadata = unattestedKeys(receipt, []);
  out.detail = ok
    ? `${detail}; legacy obsign/signature/v1 covers NEITHER the signer NOR the case `
      + 'block - the name in this file can be rewritten by anyone with a text editor '
      + 'and no key'
    : detail;
  return out;
}

module.exports = { check, bindsHash, unattestedKeys, SUPPORTED_ALGS, SIG_DOMAIN_V2, OUT_OF_CLAIM_FACT };
