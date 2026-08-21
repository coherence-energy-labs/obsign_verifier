#!/usr/bin/env node
'use strict';
/**
 * CLI. Exit 0 if every receipt verified, 1 otherwise. That is the whole interface.
 */

const fs = require('node:fs');
const { loadReceipt } = require('../src/canonical.js');
const { verify } = require('../src/verify.js');
const { verifyGraph } = require('../src/graph.js');
const { VERSION } = require('../src/index.js');

const USAGE = `obsign-verify ${VERSION}  --  re-derive a receipt's claim, offline

  obsign-verify RECEIPT [RECEIPT...]
  obsign-verify --expect-program SHA256 RECEIPT
  obsign-verify --chain RECEIPT [RECEIPT...]
  obsign-verify --chain-list FILE

  --chain                   verify the receipts as a GRAPH (docs/GRAPHS.md): every node
                            re-derived, and every params.links slice compared
                            value-for-value against a fresh re-derivation of the child
                            it names. Exit 0 only if the whole chain holds. Without
                            this the receipts are checked one at a time and a link that
                            names a receipt you were never given is not looked at.

  --expect-program SHA256   require the replay program to be the one your validator
                            approved. Re-derivation proves the output follows FROM THE
                            PROGRAM; it cannot prove the program computes what its name
                            claims. Pinning the digest asks the auditor's real question.
  --strict-liveness         refuse a receipt whose input-liveness probe ended
                            'indeterminate'. The default accepts it -- a verifier must
                            not accuse an honest receipt of forgery for being expensive
                            to probe -- but an audited program should not rest on a
                            probe that ran out of budget.
  --chain-list FILE         read receipt paths from FILE, one per line. A chain of
                            thousands of nodes is past the command-line length limit on
                            Windows, which is a refusal to RUN rather than a verdict.
  --json                    machine-readable
  --version

This is a PORT of the Python reference implementation by the same author, not an
independent second implementation. It re-derives obsign/replay/1 programs, checks
integrity for every receipt, and verifies Ed25519 signatures over what they actually
cover. It does NOT re-execute tau_field_fixed -- that is reported explicitly rather
than silently skipped, and such a receipt is never reported as verified.`;

/**
 * `--chain`: verify FILES as a graph and report node-by-node, then the chain verdict.
 *
 * Mirrors src/obsign_verify/cli.py `_chain` line for line, including the three
 * distinguishable outcomes -- VERIFIED, INCOMPLETE (supply the missing receipts) and
 * REFUSED -- because "I could not check this" and "this is false" are different facts
 * and a chain that collapses them tells an auditor the wrong one.
 */
function chainMain(files, asJson, strictLiveness) {
  const receipts = [];
  const unreadable = [];
  for (const file of files) {
    try {
      receipts.push(loadReceipt(fs.readFileSync(file)));
    } catch (e) {
      unreadable.push(`${file}: ${e.message}`);
    }
  }
  const g = verifyGraph(receipts, strictLiveness);
  const ok = g.graph_verified && unreadable.length === 0;

  if (asJson) {
    console.log(JSON.stringify({ ...g, unreadable }, null, 2));
    return ok ? 0 : 1;
  }
  const order = (g.order && g.order.length) ? g.order : Object.keys(g.nodes);
  for (const digest of order) {
    const n = g.nodes[digest];
    if (!n) continue;
    const mark = n.verified ? 'VERIFIED' : ' REFUSED';
    const link = n.links_ok === null || n.links_ok === undefined ? ''
      : n.links_ok === true ? '  links OK'
        : n.links_ok === 'incomplete' ? '  links INCOMPLETE'
          : '  links REFUSED';
    console.log(`  [${mark}] ${digest.slice(0, 16)}..${link}`);
    for (const note of n.notes || []) console.log(`             - ${note}`);
  }
  for (const u of unreadable) console.log(`  [ REFUSED ] ${u}`);
  for (const note of g.notes || []) console.log(`  ! ${note}`);
  for (const m of g.missing || []) {
    console.log(`  ? missing: ${m.slice(0, 16)}.. (referenced but not supplied)`);
  }
  const verdict = ok
    ? 'CHAIN VERIFIED - every node re-derived, every link binds'
    : (!g.complete ? 'CHAIN INCOMPLETE - supply the missing receipts' : 'CHAIN REFUSED');
  const nNodes = Object.keys(g.nodes).length;
  console.log(`\n${verdict} (${nNodes} node(s), ${(g.roots || []).length} root(s))`);
  return ok ? 0 : 1;
}

function main(argv) {
  const args = argv.slice(2);
  if (args.includes('--version')) { console.log(`obsign-verify ${VERSION}`); return 0; }
  if (!args.length || args.includes('-h') || args.includes('--help')) { console.log(USAGE); return args.length ? 0 : 1; }

  const asJson = args.includes('--json');
  const strictLiveness = args.includes('--strict-liveness');
  let expectProgram = null;
  const files = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--json' || args[i] === '--strict-liveness' || args[i] === '--chain') continue;
    if (args[i] === '--expect-program') {
      // A flag with no value must not silently mean "no pin". `args[++i]` yielded
      // undefined at the end of argv, and `expectProgram ?? null` then disabled the
      // pin while the run still printed VERIFIED. It also swallowed the NEXT flag
      // (`--expect-program --json r.json` consumed `--json` as the digest). The
      // reference CLI refuses both; this one does now too.
      const v = args[++i];
      if (v === undefined || v.startsWith('--')) {
        console.error('--expect-program needs a program digest; none was given. '
          + 'Refusing to run WITHOUT the pin rather than silently verifying without it.');
        process.exit(2);
      }
      expectProgram = v;
      continue;
    }
    if (args[i] === '--chain-list') {
      // THE SAME ARGUMENT LIST, DELIVERED THROUGH A CHANNEL WITH NO LIMIT. A chain of
      // thousands of nodes cannot be named in argv on Windows (8191 characters), and a
      // refusal to RUN is not a verdict -- while the deep-chain property is exactly
      // the one that needs thousands of nodes to exercise.
      const listFile = args[++i];
      let listed;
      try {
        listed = fs.readFileSync(listFile, 'utf8').split(/\r?\n/);
      } catch (e) {
        console.error(`cannot read --chain-list ${listFile}: ${e.message}`);
        return 1;
      }
      for (const line of listed) {
        const t = line.trim();
        if (t && !t.startsWith('#')) files.push(t);
      }
      continue;
    }
    // AN UNKNOWN SWITCH IS AN ERROR, NOT A FILENAME.
    //
    // This pushed everything here, so `--strict-livenes` (one letter short) became a
    // path, failed to open, and was reported as `[REFUSED] --strict-livenes` with exit
    // 1. It fails closed, which is the only reason this is a defect and not a breach --
    // but the diagnosis is wrong in the direction that matters: the strictness the
    // operator asked for WAS NEVER APPLIED, and the run reports "a file failed", which
    // in a multi-receipt run reads as one bad receipt among many. Same class as the
    // `--expect-program` fail-open above. The reference CLI (argparse) has always
    // exited 2 with "unrecognized arguments".
    //
    // A bare "-" is left alone: a conventional stdin sentinel, not a switch.
    if (args[i].startsWith('-') && args[i] !== '-') {
      console.error(`unrecognized argument '${args[i]}'. Refusing to run rather than `
        + 'treat a switch as a filename -- a mistyped flag must not silently mean the '
        + 'flag was never given.');
      return 2;
    }
    files.push(args[i]);
  }
  if (!files.length) { console.error('no receipt given'); return 1; }

  // A CHAIN IS A DIFFERENT QUESTION FROM A PILE OF RECEIPTS, and this CLI could not
  // ask it. `verifyGraph` shipped in the package all along; only the binary could not
  // reach it, so `npm i -g @obsign/verify` gave a user everything except the rung a
  // supply chain exists to establish -- and verifying the same files one at a time
  // reports VERIFIED for each, because a link naming a receipt you were never handed
  // is not examined by the standalone ladder. The reference's words and exit codes
  // are reproduced deliberately: two verifiers that disagree about how to SAY a
  // verdict are read as disagreeing about the verdict.
  if (args.includes('--chain')) return chainMain(files, asJson, strictLiveness);

  const report = [];
  let failures = 0;

  for (const file of files) {
    let res;
    try {
      // PROGRAM PINNING AND STRICT LIVENESS ARE LIBRARY ARGUMENTS, not CLI
      // post-processing. Living in three CLIs meant every caller that imports the
      // package instead of shelling out silently got the weaker question, with no
      // field in the result to say so. This CLI now calls THROUGH the library rule.
      res = verify(loadReceipt(fs.readFileSync(file)), expectProgram ?? null, strictLiveness);
    } catch (e) {
      res = { integrity: false, reproduced: null, verified: false, unsupported: false,
        approved_program: null, notes: [`unreadable: ${e.message}`] };
      if (expectProgram) {
        // A file that cannot be read is not the approved program either. Reporting
        // null here would say "no expectation was supplied" to a caller who gave one.
        res.approved_program = false;
      }
    }

    failures += res.verified ? 0 : 1;
    report.push({ file, ...res });

    if (!asJson) {
      // A HEADLINE THAT HIDES AN UNPROVEN RUNG IS THE DEFECT, NOT THE VERDICT.
      // `verified` deliberately still accepts an `indeterminate` probe; the reader who
      // scans one line and stops must not come away believing the inputs were shown to
      // reach the output when the probe ran out of budget before proving anything.
      const tag = (res.verified && res.input_liveness === 'indeterminate')
        ? '  (inputs unproven)'
        : (res.unsupported ? '  (unsupported format - NOT verified)' : '');
      console.log(`  [${res.verified ? 'VERIFIED' : 'REFUSED '}] ${file}${tag}`);
      console.log(`      integrity   ${res.integrity ? 'ok' : 'FAILED'}`);
      console.log(`      re-derived  ${res.reproduced === null ? 'not attempted' : (res.reproduced ? 'ok' : 'FAILED')}`);
      if (res.input_liveness && res.input_liveness !== 'n/a') {
        const shown = {
          live: 'ok - the output depends on the declared inputs',
          dead: 'FAIL - the output ignores every declared input',
          guarded: 'FAIL - the program trapped on every perturbation, so nothing was '
            + 'shown to reach the output',
          indeterminate: 'UNPROVEN (probe budget reached) - semantic validity not '
            + 'established',
        }[res.input_liveness] || res.input_liveness;
        console.log(`      inputs      ${shown}`);
      }
      if (res.approved_program !== null && res.approved_program !== undefined) {
        console.log(`      program     ${res.approved_program ? 'ok - matches the approved digest' : 'FAIL - not the approved program'}`);
      }
      // A signature the tool checked must SAY so, and one it refused must say that
      // louder. Reporting only integrity and re-derivation is how an unchecked
      // signature stayed invisible behind a green exit code.
      const s = res.signature;
      console.log(`      signature   ${!s || !s.present ? 'absent'
        : (s.unsupported ? 'UNSUPPORTED spec - nothing was checked'
          : (s.valid ? (s.identity_bound ? `ok, signer BOUND (${s.attributed_signer})`
            : 'ok, but signer NOT bound (legacy v1)') : 'REFUSED'))}`);
      for (const n of res.notes) console.log(`      - ${n}`);
    }
  }

  if (asJson) console.log(JSON.stringify(report, null, 2));
  else console.log(`\n${report.length - failures}/${report.length} receipt(s) verified on THIS machine.`);
  return failures ? 1 : 0;
}

process.exit(main(process.argv));
