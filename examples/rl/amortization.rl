// Fixed-rate loan amortization: after n monthly payments, what principal is
// left, and how much interest was paid in total? Everything in integer cents;
// the monthly rate is an fx32 fraction. Balances round toward zero exactly the
// way the machine divides -- stated, deterministic, and re-runnable by anyone.
//
// inputs: principal (cents), monthly_rate (fx32), payment (cents), months
input principal, monthly_rate: fx32, payment, months;
let balance = principal;
let interest_total = 0;
let m = 0;
while m < months {
  let interest = mulfx(balance, monthly_rate, 32);
  interest_total = interest_total + interest;
  balance = balance + interest - payment;
  if balance < 0 { balance = 0; }
  m = m + 1;
}
output balance, interest_total;
