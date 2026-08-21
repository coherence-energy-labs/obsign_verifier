// Report, per case, whether the JavaScript parser LOADS the receipt text.
// Compared field-for-field against Python in test_wire_format_limits.py: the two
// implementations must agree on what is a receipt, not merely on what it hashes to.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { loadReceipt } = require('../js/src/canonical.js');

const cases = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const out = {};
for (const [name, text] of cases) {
  try { loadReceipt(text); out[name] = true; } catch (e) { out[name] = false; }
}
console.log(JSON.stringify(out));
