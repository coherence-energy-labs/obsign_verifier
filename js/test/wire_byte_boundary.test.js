'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const c = require(process.env.OBSIGN_CANONICAL_UNDER_TEST || '../src/canonical.js');

function sealed(text) {
  const parsed = c.loadReceipt(text);
  return text.slice(0, -1) + ',"receipt_sha256":"' + c.canonicalSha256(c.claimOf(parsed)) + '"}';
}
const valid = sealed('{"spec":"obsign/receipt/v1","test":1}');

test('valid receipt has the same canonical hash through text and bytes', () => {
  for (const source of [valid, Buffer.from(valid)]) {
    assert.equal(c.integrity(c.loadReceipt(source))[0], true);
  }
});

test('leading BOM cannot be erased to admit bytes rejected as text', () => {
  for (const source of ['\ufeff' + valid, Buffer.from('\ufeff' + valid)]) {
    assert.throws(() => c.loadReceipt(source), c.JsonError);
  }
});

test('embedded BOM remains ordinary string data', () => {
  const text = sealed('{"label":"inside\ufeffdata"}');
  assert.equal(c.canonicalString(c.loadReceipt(text)),
               c.canonicalString(c.loadReceipt(Buffer.from(text))));
  assert.equal(c.integrity(c.loadReceipt(Buffer.from(text)))[0], true);
});

test('oversized bytes are refused before any decoder invocation', () => {
  const Original = globalThis.TextDecoder;
  let calls = 0;
  globalThis.TextDecoder = class {
    constructor() { calls++; }
    decode() { throw new Error('decoder must not be reached'); }
  };
  try {
    assert.throws(() => c.loadReceipt(Buffer.alloc(4 * 1024 * 1024 + 1)), c.JsonError);
    assert.equal(calls, 0);
  } finally {
    globalThis.TextDecoder = Original;
  }
});

test('invalid UTF-8 is refused rather than replaced', () => {
  for (const byte of [0x80, 0xc0, 0xff]) {
    const bytes = Buffer.concat([Buffer.from('{"x":"'), Buffer.from([byte]), Buffer.from('"}')]);
    assert.throws(() => c.loadReceipt(bytes), c.JsonError);
  }
});

test('Unicode and astral keys canonicalize identically', () => {
  const text = '{"\ue000":1,"😀":2.0,"z":"é"}';
  assert.equal(c.canonicalString(c.loadReceipt(text)),
               c.canonicalString(c.loadReceipt(Buffer.from(text))));
});

test('altered claims cannot keep the original claim hash', () => {
  const tampered = valid.replace('"test":1', '"test":2');
  assert.equal(c.integrity(c.loadReceipt(Buffer.from(tampered)))[0], false);
});

test('int and float identity remains distinct', () => {
  assert.notEqual(c.canonicalSha256(c.loadReceipt('{"x":1}')),
                  c.canonicalSha256(c.loadReceipt('{"x":1.0}')));
});
