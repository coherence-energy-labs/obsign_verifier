// Portfolio statistics without a single float: weighted mean and a population
// variance over fx32 returns, weights in plain units. Multiplying two fx32
// values yields fx64, so every product is renormalized through mulfx -- and the
// scale checker refuses the version of this file that forgets.
const S = 32;
input r[8]: fx32;      // eight returns, fx32
arr w[8];              // weights, plain integers
w[0]=10; w[1]=20; w[2]=5; w[3]=15; w[4]=10; w[5]=10; w[6]=20; w[7]=10;

let wsum = 0;
let wret: fx32 = 0;
for i in 0..len(r) {
  wsum = wsum + w[i];
  wret = wret + r[i] * w[i];
}
let mean: fx32 = wret / wsum;

let var2: fx32 = 0;
for i in 0..len(r) {
  let d: fx32 = r[i] - mean;
  var2 = var2 + mulfx(d, d, S) * w[i];
}
output mean, var2 / wsum;
