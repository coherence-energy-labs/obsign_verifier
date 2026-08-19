'use strict';
/**
 * The version lives in two files here (package.json and src/index.js) and in two more
 * in the Python package. The Python suite holds its pair together; nothing held this
 * pair together, and nothing held the two pairs to each other. A stale `--version`
 * prints confidently and is wrong, which is the exact failure shape this package is
 * about. The release workflow additionally checks all four against the git tag.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { VERSION } = require('../src/index.js');

const HERE = path.resolve(__dirname, '..');
const REPO = path.resolve(HERE, '..');

test('package.json and src/index.js agree on the version', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(HERE, 'package.json'), 'utf8'));
  assert.strictEqual(pkg.version, VERSION, 'package.json vs src/index.js VERSION');
});

test('the JavaScript port carries the SAME version as the Python package', () => {
  // The two packages ship together, from the same tag, and are described to
  // strangers as one tool in two languages. A version skew between them is a lie
  // about which spec behaviour each one implements.
  const pyproject = fs.readFileSync(path.join(REPO, 'pyproject.toml'), 'utf8');
  const m = /^version\s*=\s*"([^"]+)"/m.exec(pyproject);
  assert.ok(m, 'no version = "..." in pyproject.toml -- this test would be vacuous');
  assert.strictEqual(m[1], VERSION, 'pyproject.toml vs js VERSION');
});
