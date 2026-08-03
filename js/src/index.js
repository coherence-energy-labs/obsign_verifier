'use strict';
/**
 * obsign-verify — re-derive an Obsign receipt's claim, in JavaScript.
 *
 * This is a PORT BY THE SAME AUTHOR of the Python reference implementation, and it is
 * labelled that way everywhere it appears. It is NOT the independent second
 * implementation the spec's recognition offer is about, and it cannot discharge the
 * independence claim: two programs by one author can share one misreading of the spec.
 *
 * What it does establish is narrower and still worth having. The replay instruction
 * set was designed to be re-implementable "in an afternoon, in any language with
 * 64-bit integers". This is that claim being tested rather than asserted -- in a
 * language whose native number type is a double and whose JSON parser destroys the
 * int/float distinction the spec depends on. If the two implementations disagree on
 * any receipt, one is wrong and the spec is ambiguous.
 */

const canonical = require('./canonical.js');
const replay = require('./replay.js');
const { verify } = require('./verify.js');

module.exports = {
  verify,
  loadReceipt: canonical.loadReceipt,
  claimOf: canonical.claimOf,
  canonicalString: canonical.canonicalString,
  canonicalSha256: canonical.canonicalSha256,
  integrity: canonical.integrity,
  replay,
  VERSION: '0.2.1',
};
