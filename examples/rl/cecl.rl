// IFRS 9 / CECL expected credit loss -- the computation behind the shipped
// conformance receipt (producer_signed_replay.json). ECL = sum(PD * LGD * EAD)
// over the portfolio. PD and LGD are fx32 fractions; EAD and the result are
// plain cents, and the units are pinned at the function boundary so a scale
// mix-up is a compile error, not a wrong receipt.
//
// input layout: v[0] = exposure count n, then n triples of (pd, lgd, ead).
const S = 32;
fn ecl(pd: fx32, lgd: fx32, ead: fx0) { return mulfx(mulfx(pd, lgd, S), ead, S); }
input v[13];
let acc = 0;
for i in 0..v[0] {
  let base = i * 3 + 1;
  acc = acc + ecl(v[base], v[base + 1], v[base + 2]);
}
output acc;
