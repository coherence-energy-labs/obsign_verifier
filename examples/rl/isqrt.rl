// Integer square root by Newton's method -- and a worked lesson in wrapping
// arithmetic. The naive seed x = n overflows at x + n/x for n near INT64_MAX
// and converges, deterministically, to garbage. The fix is knowledge, not
// luck: 3037000500 > isqrt(INT64_MAX), so min(n, 3037000500) is always a safe
// upper seed and every intermediate stays around 6e9.
fn isqrt(n) {
  let x = 0;
  if n > 0 {
    x = min(n, 3037000500);
    let y = (x + n / x) / 2;
    while y < x { x = y; y = (x + n / x) / 2; }
  }
  return x;
}
input a;
output isqrt(a);
