#!/usr/bin/env node
'use strict';
/**
 * CLI. Exit 0 if every receipt verified, 1 otherwise. That is the whole interface.
 */

const fs = require('node:fs');
const { loadReceipt } = require('../src/canonical.js');
const { verify } = require('../src/verify.js');
const { VERSION } = require('../src/index.js');

const USAGE = `obsign-verify ${VERSION}  --  re-derive a receipt's claim, offline

  obsign-verify RECEIPT [RECEIPT...]
  obsign-verify --expect-program SHA256 RECEIPT

  --expect-program SHA256   require the replay program to be the one your validator
                            approved. Re-derivation proves the output follows FROM THE
                            PROGRAM; it cannot prove the program computes what its name
                            claims. Pinning the digest asks the auditor's real question.
  --json                    machine-readable
  --version

This is a PORT of the Python reference implementation by the same author, not an
independent second implementation. It re-derives obsign/replay/1 programs and checks
integrity for every receipt; it does NOT re-execute tau_field_fixed and does NOT check
signatures -- both are reported explicitly rather than silently skipped.`;

function main(argv) {
  const args = argv.slice(2);
  if (args.includes('--version')) { console.log(`obsign-verify ${VERSION}`); return 0; }
  if (!args.length || args.includes('-h') || args.includes('--help')) { console.log(USAGE); return args.length ? 0 : 1; }

  const asJson = args.includes('--json');
  let expectProgram = null;
  const files = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--json') continue;
    if (args[i] === '--expect-program') { expectProgram = args[++i]; continue; }
    files.push(args[i]);
  }
  if (!files.length) { console.error('no receipt given'); return 1; }

  const report = [];
  let failures = 0;

  for (const file of files) {
    let res;
    try {
      res = verify(loadReceipt(fs.readFileSync(file, 'utf8')));
    } catch (e) {
      res = { integrity: false, reproduced: null, verified: false, notes: [`unreadable: ${e.message}`] };
    }

    if (expectProgram) {
      // Same pin as the Python CLI, for the same reason.
      let actual = null;
      try {
        const r = loadReceipt(fs.readFileSync(file, 'utf8'));
        const params = r.__obj.get('params');
        actual = params && params.__obj ? params.__obj.get('program_sha256') : null;
      } catch { /* already reported above */ }
      if (actual !== expectProgram) {
        res = { ...res, verified: false,
          notes: [...res.notes, `program is not the approved one: expected ${expectProgram.slice(0, 16)}.., receipt carries ${String(actual).slice(0, 16)}..`] };
      }
    }

    failures += res.verified ? 0 : 1;
    report.push({ file, ...res });

    if (!asJson) {
      console.log(`  [${res.verified ? 'VERIFIED' : 'REFUSED '}] ${file}`);
      console.log(`      integrity   ${res.integrity ? 'ok' : 'FAILED'}`);
      console.log(`      re-derived  ${res.reproduced === null ? 'not attempted' : (res.reproduced ? 'ok' : 'FAILED')}`);
      for (const n of res.notes) console.log(`      - ${n}`);
    }
  }

  if (asJson) console.log(JSON.stringify(report, null, 2));
  else console.log(`\n${report.length - failures}/${report.length} receipt(s) verified on THIS machine.`);
  return failures ? 1 : 0;
}

process.exit(main(process.argv));
