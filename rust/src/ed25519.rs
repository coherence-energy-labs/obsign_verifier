//! Ed25519 signature VERIFICATION (RFC 8032), with no dependencies.
//!
//! WHY THIS IS HERE RATHER THAN A CRATE, and the honest cost of that choice.
//!
//! The crate's argument is that one person can read all of it in an afternoon and owe
//! nothing to a supply chain. A signature check pulled from a dependency reintroduces
//! exactly the trust a receipt exists to remove -- and the two shipped implementations
//! already take their Ed25519 from the same place (Python's `cryptography` and Node's
//! `node:crypto` are both OpenSSL), so a third one built on that same code would not
//! be a third opinion about anything.
//!
//! The cost is real and is not hidden: hand-written curve arithmetic is where
//! cryptographic implementations go wrong, and a WRONG verifier here produces false
//! refusals or, far worse, false acceptances. So it is never asserted, only measured:
//! the differential harness runs every signature this repository ships plus thousands
//! of randomly generated valid and corrupted ones through all three implementations
//! and requires the same accept/reject, and `tests/` pins the RFC 8032 vectors.
//!
//! WHICH VERIFICATION EQUATION. RFC 8032 permits two checks, and they disagree on
//! signatures involving low-order points. This implements the COFACTORLESS one --
//! recompute `R' = [s]B - [h]A` and compare its ENCODING with `R` byte for byte --
//! because that is what OpenSSL does, and OpenSSL is what the other two
//! implementations are. Matching the deployed behaviour is the point; a lone
//! cofactored verifier would report divergences that are really its own.
//! The S range check is likewise OpenSSL's (`sig[63] & 224`), not a full `S < L`.

use crate::sha2::sha512;

const P: [u64; 4] = [0xffff_ffff_ffff_ffed, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0x7fff_ffff_ffff_ffff];

/// d = -121665/121666 (mod p). Verified against a recomputation in `tests/`.
const D: [u64; 4] = [0x75eb_4dca_1359_78a3, 0x0070_0a4d_4141_d8ab, 0x8cc7_4079_7779_e898, 0x5203_6cee_2b6f_fe73];

/// sqrt(-1) (mod p), needed to recover x from y during point decompression.
const SQRT_M1: [u64; 4] = [0xc4ee_1b27_4a0e_a0b0, 0x2f43_1806_ad2f_e478, 0x2b4d_0099_3dfb_d7a7, 0x2b83_2480_4fc1_df0b];

/// The group order L = 2^252 + 27742317777372353535851937790883648493.
const L: [u64; 4] = [0x5812_631a_5cf5_d3ed, 0x14de_f9de_a2f7_9cd6, 0x0000_0000_0000_0000, 0x1000_0000_0000_0000];

/// The base point B.
const BX: [u64; 4] = [0xc956_2d60_8f25_d51a, 0x692c_c760_9525_a7b2, 0xc0a4_e231_fdd6_dc5c, 0x2169_36d3_cd6e_53fe];
const BY: [u64; 4] = [0x6666_6666_6666_6658, 0x6666_6666_6666_6666, 0x6666_6666_6666_6666, 0x6666_6666_6666_6666];

type Fe = [u64; 4];

const ZERO: Fe = [0, 0, 0, 0];
const ONE: Fe = [1, 0, 0, 0];

// ------------------------------------------------------------------ field mod 2^255-19
//
// Field elements are kept FULLY REDUCED after every operation. Lazy reduction is how
// these implementations get fast and how they get subtly wrong: the sign test used in
// point decompression reads the low bit of the CANONICAL encoding, so a value that is
// merely congruent gives the wrong answer.

fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = (a as u128) + (b as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}

fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let t = (a as i128) - (b as i128) - (borrow as i128);
    (t as u64, if t < 0 { 1 } else { 0 })
}

fn ge_p(x: &Fe) -> bool {
    for i in (0..4).rev() {
        if x[i] > P[i] {
            return true;
        }
        if x[i] < P[i] {
            return false;
        }
    }
    true
}

fn sub_p(x: &mut Fe) {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (v, b) = sbb(x[i], P[i], borrow);
        x[i] = v;
        borrow = b;
    }
}

/// Bring a value below p. Three conditional subtractions cover every input this module
/// produces (each operation leaves at most 2p + a small carry).
fn freeze(x: &mut Fe) {
    for _ in 0..3 {
        if ge_p(x) {
            sub_p(x);
        }
    }
}

fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut out = ZERO;
    let mut carry = 0u64;
    for i in 0..4 {
        let (v, c) = adc(a[i], b[i], carry);
        out[i] = v;
        carry = c;
    }
    // A carry out of 256 bits is 2^256 = 38 (mod p).
    if carry != 0 {
        let mut c2 = 38u64;
        for limb in out.iter_mut() {
            let (v, c) = adc(*limb, c2, 0);
            *limb = v;
            c2 = c;
        }
    }
    freeze(&mut out);
    out
}

fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    // a + 2p - b never goes negative, and 2p fits in 256 bits.
    let mut out = ZERO;
    let mut borrow = 0u64;
    for i in 0..4 {
        let (v, br) = sbb(a[i], b[i], borrow);
        out[i] = v;
        borrow = br;
    }
    if borrow != 0 {
        // Add 2p back (2p = 2^256 - 38), i.e. subtract 38.
        let mut b2 = 38u64;
        for limb in out.iter_mut() {
            let (v, br) = sbb(*limb, b2, 0);
            *limb = v;
            b2 = br;
        }
    }
    freeze(&mut out);
    out
}

fn fe_neg(a: &Fe) -> Fe {
    fe_sub(&ZERO, a)
}

/// Fold a 512-bit product down mod 2^255-19, using 2^256 = 38 (mod p).
fn reduce_wide(w: &[u64; 8]) -> Fe {
    // acc = lo + 38 * hi, accumulated over five limbs (38*hi needs 262 bits).
    let mut acc = [0u128; 5];
    for i in 0..4 {
        acc[i] += w[i] as u128;
    }
    for i in 0..4 {
        acc[i] += 38u128 * (w[4 + i] as u128);
    }
    let mut limbs = [0u64; 5];
    let mut carry = 0u128;
    for i in 0..5 {
        let t = acc[i] + carry;
        limbs[i] = t as u64;
        carry = t >> 64;
    }
    debug_assert!(carry == 0);

    // Fold the fifth limb (at most 2^7) back in the same way.
    let mut out: Fe = [limbs[0], limbs[1], limbs[2], limbs[3]];
    let extra = (limbs[4] as u128) * 38;
    let mut c = extra;
    for limb in out.iter_mut() {
        let t = (*limb as u128) + (c & 0xffff_ffff_ffff_ffff);
        *limb = t as u64;
        c = (c >> 64) + (t >> 64);
    }
    if c != 0 {
        let mut c2 = (c as u64).wrapping_mul(38);
        for limb in out.iter_mut() {
            let (v, cc) = adc(*limb, c2, 0);
            *limb = v;
            c2 = cc;
        }
    }
    freeze(&mut out);
    out
}

fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let mut w = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let t = (a[i] as u128) * (b[j] as u128) + (w[i + j] as u128) + carry;
            w[i + j] = t as u64;
            carry = t >> 64;
        }
        let mut k = i + 4;
        while carry != 0 {
            let t = (w[k] as u128) + carry;
            w[k] = t as u64;
            carry = t >> 64;
            k += 1;
        }
    }
    reduce_wide(&w)
}

fn fe_sq(a: &Fe) -> Fe {
    fe_mul(a, a)
}

/// a^(p-2) = a^-1, by square-and-multiply over the exponent's bits.
///
/// p-2 = 2^255 - 21 is public and fixed, so a variable-time ladder is fine: nothing
/// secret passes through this module, which only ever verifies.
fn fe_inv(a: &Fe) -> Fe {
    // p - 2 = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb
    let exp: Fe = [0xffff_ffff_ffff_ffeb, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0x7fff_ffff_ffff_ffff];
    fe_pow(a, &exp)
}

fn fe_pow(a: &Fe, exp: &Fe) -> Fe {
    let mut result = ONE;
    for i in (0..256).rev() {
        result = fe_sq(&result);
        if (exp[i / 64] >> (i % 64)) & 1 == 1 {
            result = fe_mul(&result, a);
        }
    }
    result
}

fn fe_is_zero(a: &Fe) -> bool {
    let mut x = *a;
    freeze(&mut x);
    x == ZERO
}

fn fe_eq(a: &Fe, b: &Fe) -> bool {
    fe_is_zero(&fe_sub(a, b))
}

/// The sign convention: a field element is "negative" when the low bit of its
/// canonical little-endian encoding is 1.
fn fe_is_negative(a: &Fe) -> bool {
    let mut x = *a;
    freeze(&mut x);
    x[0] & 1 == 1
}

fn fe_from_bytes(b: &[u8; 32]) -> Fe {
    let mut out = ZERO;
    for i in 0..4 {
        let mut c = [0u8; 8];
        c.copy_from_slice(&b[8 * i..8 * i + 8]);
        out[i] = u64::from_le_bytes(c);
    }
    // The top bit is the x sign, not part of y.
    out[3] &= 0x7fff_ffff_ffff_ffff;
    out
}

fn fe_to_bytes(a: &Fe) -> [u8; 32] {
    let mut x = *a;
    freeze(&mut x);
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[8 * i..8 * i + 8].copy_from_slice(&x[i].to_le_bytes());
    }
    out
}

// ------------------------------------------------------------------------ the group
//
// Extended coordinates (X:Y:Z:T) with x = X/Z, y = Y/Z, T = XY/Z, on the twisted
// Edwards curve -x^2 + y^2 = 1 + d*x^2*y^2.

#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

const IDENTITY: Point = Point { x: ZERO, y: ONE, z: ONE, t: ZERO };

/// add-2008-hwcd-3 for a = -1.
fn point_add(p1: &Point, p2: &Point) -> Point {
    let a = fe_mul(&fe_sub(&p1.y, &p1.x), &fe_sub(&p2.y, &p2.x));
    let b = fe_mul(&fe_add(&p1.y, &p1.x), &fe_add(&p2.y, &p2.x));
    let c = fe_mul(&fe_mul(&p1.t, &p2.t), &fe_add(&D, &D));
    let d = fe_mul(&fe_mul(&p1.z, &p2.z), &fe_add(&ONE, &ONE));
    let e = fe_sub(&b, &a);
    let f = fe_sub(&d, &c);
    let g = fe_add(&d, &c);
    let h = fe_add(&b, &a);
    Point { x: fe_mul(&e, &f), y: fe_mul(&g, &h), t: fe_mul(&e, &h), z: fe_mul(&f, &g) }
}

/// dbl-2008-hwcd for a = -1. Written out rather than reusing the addition law, so
/// nothing depends on that law being unified.
fn point_double(p: &Point) -> Point {
    let a = fe_sq(&p.x);
    let b = fe_sq(&p.y);
    let c = fe_add(&fe_sq(&p.z), &fe_sq(&p.z));
    let d = fe_neg(&a);
    let e = fe_sub(&fe_sub(&fe_sq(&fe_add(&p.x, &p.y)), &a), &b);
    let g = fe_add(&d, &b);
    let f = fe_sub(&g, &c);
    let h = fe_sub(&d, &b);
    Point { x: fe_mul(&e, &f), y: fe_mul(&g, &h), t: fe_mul(&e, &h), z: fe_mul(&f, &g) }
}

/// [k]P by double-and-add over the scalar's 256 bits, most significant first.
///
/// Variable time on purpose and safely: every input to this module is public.
fn scalar_mul(k: &[u8; 32], p: &Point) -> Point {
    let mut acc = IDENTITY;
    for i in (0..256).rev() {
        acc = point_double(&acc);
        if (k[i / 8] >> (i % 8)) & 1 == 1 {
            acc = point_add(&acc, p);
        }
    }
    acc
}

fn point_encode(p: &Point) -> [u8; 32] {
    let zinv = fe_inv(&p.z);
    let x = fe_mul(&p.x, &zinv);
    let y = fe_mul(&p.y, &zinv);
    let mut out = fe_to_bytes(&y);
    if fe_is_negative(&x) {
        out[31] |= 0x80;
    }
    out
}

/// Decompress a 32-byte encoding into a curve point, or `None` if it is not one.
///
/// Follows ref10's `ge_frombytes_negate_vartime` rules, which is what OpenSSL uses:
/// the y coordinate is taken modulo p without a canonicality check, and x = 0 with the
/// sign bit set is NOT rejected. Both choices are visible to an attacker and both are
/// matched deliberately -- diverging from the deployed implementations here would show
/// up as a "finding" that was really this file's own opinion.
fn point_decode(b: &[u8; 32]) -> Option<Point> {
    let y = fe_from_bytes(b);
    let y2 = fe_sq(&y);
    let u = fe_sub(&y2, &ONE);
    let v = fe_add(&fe_mul(&D, &y2), &ONE);

    // x = sqrt(u/v) = u*v^3 * (u*v^7)^((p-5)/8), then corrected by sqrt(-1).
    let v3 = fe_mul(&fe_sq(&v), &v);
    let v7 = fe_mul(&fe_sq(&v3), &v);
    let uv7 = fe_mul(&u, &v7);
    // (p-5)/8 = 0x0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd
    let exp: Fe = [0xffff_ffff_ffff_fffd, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0x0fff_ffff_ffff_ffff];
    let pow = fe_pow(&uv7, &exp);
    let mut x = fe_mul(&fe_mul(&u, &v3), &pow);

    let check = fe_sub(&fe_mul(&v, &fe_sq(&x)), &u);
    if !fe_is_zero(&check) {
        let check2 = fe_add(&fe_mul(&v, &fe_sq(&x)), &u);
        if !fe_is_zero(&check2) {
            return None; // u/v is not a square: this y is not on the curve
        }
        x = fe_mul(&x, &SQRT_M1);
    }

    if fe_is_negative(&x) != (b[31] >> 7 == 1) {
        x = fe_neg(&x);
    }
    let t = fe_mul(&x, &y);
    Some(Point { x, y, z: ONE, t })
}

// ------------------------------------------------------------------------- scalars

/// Reduce a 64-byte little-endian integer modulo L, by binary long division.
///
/// Slow and obviously correct, which is the right trade for something run a handful of
/// times per receipt. A Barrett constant would be faster and would be one more number
/// a reader has to take on faith.
fn scalar_reduce_wide(h: &[u8; 64]) -> [u8; 32] {
    let mut rem = [0u64; 5]; // < L < 2^253, so five limbs is ample
    for byte_i in (0..64).rev() {
        for bit in (0..8).rev() {
            // rem = rem*2 + bit
            let mut carry = ((h[byte_i] >> bit) & 1) as u64;
            for limb in rem.iter_mut() {
                let new = (*limb << 1) | carry;
                carry = *limb >> 63;
                *limb = new;
            }
            if ge_l(&rem) {
                sub_l(&mut rem);
            }
        }
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[8 * i..8 * i + 8].copy_from_slice(&rem[i].to_le_bytes());
    }
    out
}

fn ge_l(r: &[u64; 5]) -> bool {
    if r[4] != 0 {
        return true;
    }
    for i in (0..4).rev() {
        if r[i] > L[i] {
            return true;
        }
        if r[i] < L[i] {
            return false;
        }
    }
    true
}

fn sub_l(r: &mut [u64; 5]) {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (v, b) = sbb(r[i], L[i], borrow);
        r[i] = v;
        borrow = b;
    }
    let (v, _) = sbb(r[4], 0, borrow);
    r[4] = v;
}

// ---------------------------------------------------------------------- verification

/// Verify an Ed25519 signature. `public_key` is 32 raw bytes, `signature` is 64.
///
/// Returns false for every failure -- a bad key, a bad encoding, a bad signature. "I
/// could not check this" must never resolve to a pass in the field that gates a
/// verdict, and the caller cannot tell the failures apart because it must not act
/// differently on them.
pub fn verify(public_key: &[u8], signature: &[u8], message: &[u8]) -> bool {
    if public_key.len() != 32 || signature.len() != 64 {
        return false;
    }
    // OpenSSL's range check on S. Anything with these bits set is far above L, so it
    // is rejected before any curve arithmetic happens.
    if signature[63] & 224 != 0 {
        return false;
    }
    let mut a_bytes = [0u8; 32];
    a_bytes.copy_from_slice(public_key);
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);

    let a = match point_decode(&a_bytes) {
        Some(p) => p,
        None => return false,
    };
    // -A, so the check becomes R' = [s]B + [h](-A) with one addition.
    let neg_a = Point { x: fe_neg(&a.x), y: a.y, z: a.z, t: fe_neg(&a.t) };

    let mut to_hash = Vec::with_capacity(64 + message.len());
    to_hash.extend_from_slice(&r_bytes);
    to_hash.extend_from_slice(&a_bytes);
    to_hash.extend_from_slice(message);
    let h = scalar_reduce_wide(&sha512(&to_hash));

    let base = Point { x: BX, y: BY, z: ONE, t: fe_mul(&BX, &BY) };
    let sb = scalar_mul(&s_bytes, &base);
    let ha = scalar_mul(&h, &neg_a);
    let r_check = point_add(&sb, &ha);

    point_encode(&r_check) == r_bytes
}

/// Exposed only so `tests/` can prove the hardcoded curve constants are the real ones
/// rather than a plausible-looking typo.
pub mod internals {
    use super::*;
    pub fn d_bytes() -> [u8; 32] {
        fe_to_bytes(&D)
    }
    pub fn sqrt_m1_bytes() -> [u8; 32] {
        fe_to_bytes(&SQRT_M1)
    }
    pub fn base_bytes() -> [u8; 32] {
        point_encode(&Point { x: BX, y: BY, z: ONE, t: fe_mul(&BX, &BY) })
    }
    /// sqrt(-1)^2 must be -1, and d must satisfy 121666*d + 121665 == 0.
    pub fn constants_are_consistent() -> bool {
        let m1 = fe_sub(&ZERO, &ONE);
        if !fe_eq(&fe_sq(&SQRT_M1), &m1) {
            return false;
        }
        let n121666: Fe = [121666, 0, 0, 0];
        let n121665: Fe = [121665, 0, 0, 0];
        if !fe_is_zero(&fe_add(&fe_mul(&n121666, &D), &n121665)) {
            return false;
        }
        // The base point must be on the curve: -x^2 + y^2 = 1 + d x^2 y^2.
        let x2 = fe_sq(&BX);
        let y2 = fe_sq(&BY);
        let lhs = fe_sub(&y2, &x2);
        let rhs = fe_add(&ONE, &fe_mul(&D, &fe_mul(&x2, &y2)));
        fe_eq(&lhs, &rhs)
    }
    /// [L]B must be the identity.
    pub fn base_has_order_l() -> bool {
        let mut lb = [0u8; 32];
        for i in 0..4 {
            lb[8 * i..8 * i + 8].copy_from_slice(&L[i].to_le_bytes());
        }
        let base = Point { x: BX, y: BY, z: ONE, t: fe_mul(&BX, &BY) };
        let r = scalar_mul(&lb, &base);
        point_encode(&r) == point_encode(&IDENTITY)
    }
}
