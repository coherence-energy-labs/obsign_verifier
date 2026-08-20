//! The receipt wire format: what LOADS, and what bytes a loaded document canonicalises to.
//!
//! THE INT/FLOAT DISTINCTION IS THE WHOLE PROBLEM, and it is why this file exists
//! rather than a serde dependency. Canonical JSON writes `1` for an integer and `1.0`
//! for a float, and the two hash differently. Any reader that decides a number's type
//! from its VALUE rather than from how the literal was WRITTEN destroys that
//! distinction, and then reports honest receipts as tampered. So the parser records
//! the literal's shape and nothing infers it later.
//!
//! Rust does not have JavaScript's problem (it has i64 and f64 as separate types) but
//! it has its own, in the same place: `String` cannot hold a lone surrogate, and
//! Python's `str` can. A receipt carrying `"\ud800"` is a document the other two
//! implementations disagree about (Python refuses it, JavaScript loads it), so a
//! representation that could not even hold the value could not be honest about which
//! side it was on. Strings are therefore UTF-16 code units -- exactly Python's model
//! of a code-point sequence, and exactly what `ensure_ascii` escaping consumes.
//!
//! WHERE THESE RULES COME FROM, stated because it matters for who is right in a
//! disagreement. Canonical JSON is specified in docs/COMPAT.md as CPython's
//! `json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True,
//! allow_nan=False)`. The WIRE LIMITS below are specified nowhere in docs/ -- they
//! exist only as constants and comments in `src/obsign_verify/canonical.py`, which is
//! therefore the normative source for them and is treated as such here. See
//! rust/README.md, "Where the specification ran out".

use crate::sha2::sha256_hex;
use std::fmt::Write as _;

// WIRE-FORMAT LIMITS -- the same table as src/obsign_verify/canonical.py and
// js/src/canonical.js. Every place two parsers disagree about what LOADS is a place
// one implementation verifies a document the other cannot read, which lets a forger
// hand the receipt to whichever implementation accepts it.
pub const MAX_RECEIPT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_DEPTH: usize = 32;
pub const MAX_MEMBERS_PER_OBJECT: usize = 1024;
pub const MAX_ARRAY_LENGTH: usize = 1 << 20;
pub const MAX_STRING_BYTES: usize = 65536;
pub const MAX_INT_DIGITS: usize = 4300; // exactly CPython's default, so all sides agree

/// A parse depth far above anything the shape check accepts, so recursion is bounded
/// before the stack is. CPython bounds this accidentally, by catching its own
/// `RecursionError` and re-reporting it as a refusal; a stack overflow in Rust is not
/// catchable and would abort the process -- a verifier that dies on a hostile receipt
/// has failed open in the eyes of whoever handed it the file.
const MAX_PARSE_DEPTH: usize = 400;

/// The bytes are outside the receipt wire format. Refused BEFORE any verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError(pub String);

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for JsonError {}

type R<T> = Result<T, JsonError>;

fn err<T>(msg: impl Into<String>) -> R<T> {
    Err(JsonError(msg.into()))
}

/// A JSON string as UTF-16 code units. See the module header for why not `String`.
pub type JStr = Vec<u16>;

/// A JSON integer, kept as its canonical decimal text.
///
/// Integer literals run to 4300 digits, so the value does not always fit any machine
/// type -- but its canonical form is just the literal, so the text IS the answer for
/// hashing, and `i64` is only needed where the format says int64 (consts, inputs,
/// operands). Keeping both means an out-of-range integer is a REFUSAL with a reason
/// rather than a silently truncated value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Int {
    text: String,
    fits: Option<i64>,
}

impl Int {
    pub fn from_text(text: &str) -> Int {
        // JSON forbids leading zeros, so a literal is already canonical -- except
        // `-0`, which CPython's `int()` and JavaScript's `BigInt()` both flatten to 0.
        let text = if text == "-0" { "0".to_string() } else { text.to_string() };
        let fits = text.parse::<i64>().ok();
        Int { text, fits }
    }
    pub fn from_i64(v: i64) -> Int {
        Int { text: v.to_string(), fits: Some(v) }
    }
    pub fn as_i64(&self) -> Option<i64> {
        self.fits
    }
    pub fn text(&self) -> &str {
        &self.text
    }
    pub fn digits(&self) -> usize {
        self.text.trim_start_matches('-').len()
    }
}

/// A parsed JSON value. Object members keep insertion order; duplicates never arrive
/// (the parser refuses them), so order is only about reproducing the input, never
/// about meaning -- the canonical form sorts.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(Int),
    Float(f64),
    Str(JStr),
    Array(Vec<Value>),
    Object(Vec<(JStr, Value)>),
}

impl Value {
    pub fn str_of(s: &str) -> Value {
        Value::Str(s.encode_utf16().collect())
    }

    /// The member named `key`, or `None`. Linear over at most 1024 members.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(m) => {
                let k: JStr = key.encode_utf16().collect();
                m.iter().find(|(mk, _)| *mk == k).map(|(_, v)| v)
            }
            _ => None,
        }
    }
    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }
    pub fn as_object(&self) -> Option<&Vec<(JStr, Value)>> {
        match self {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    /// The value as a Rust string, or `None` if it is not a string or holds a lone
    /// surrogate. Callers comparing protocol tokens (`alg`, digests, spec strings)
    /// want exactly this: a value that cannot be a token is not the token.
    pub fn as_str(&self) -> Option<String> {
        match self {
            Value::Str(u) => String::from_utf16(u).ok(),
            _ => None,
        }
    }
    pub fn is_str(&self) -> bool {
        matches!(self, Value::Str(_))
    }
    /// A JSON integer, and nothing else. `true` is not 1 and `4.0` is not 4: both
    /// reads have split the two shipped implementations before (docs/COMPAT.md,
    /// "structural scalars are JSON integers, in both languages").
    pub fn as_int(&self) -> Option<&Int> {
        match self {
            Value::Int(i) => Some(i),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        self.as_int().and_then(|i| i.as_i64())
    }
}

// --------------------------------------------------------------------------- parse

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        // Exactly RFC 8259's four: space, tab, LF, CR. CPython's json and the
        // hand-written JS parser both stop here, so a document separated by any other
        // byte must not load in one implementation and fail in another.
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn parse_value(&mut self) -> R<Value> {
        self.skip_ws();
        match self.peek() {
            None => err("unexpected end of input"),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Value::Str(self.parse_string()?)),
            Some(b't') => {
                self.lit("true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.lit("false")?;
                Ok(Value::Bool(false))
            }
            Some(b'n') => {
                self.lit("null")?;
                Ok(Value::Null)
            }
            // NaN / Infinity / -Infinity are not JSON. CPython's parser accepts them
            // unless told otherwise -- `load_receipt` tells it otherwise -- because a
            // non-finite number has no canonical form, so two different receipts could
            // otherwise share one.
            _ => self.parse_number(),
        }
    }

    fn lit(&mut self, word: &str) -> R<()> {
        if self.s[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(())
        } else {
            err(format!("invalid literal at offset {}", self.i))
        }
    }

    fn enter(&mut self) -> R<()> {
        self.depth += 1;
        if self.depth > MAX_PARSE_DEPTH {
            return err("receipt nesting is too deep to parse");
        }
        Ok(())
    }

    fn parse_object(&mut self) -> R<Value> {
        self.enter()?;
        self.i += 1;
        let mut out: Vec<(JStr, Value)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            self.depth -= 1;
            return Ok(Value::Object(out));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return err(format!("expected a string key at offset {}", self.i));
            }
            let k = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return err(format!("expected : at offset {}", self.i));
            }
            self.i += 1;
            // OBJECT-MODEL KEYS ARE REFUSED. Rust has no prototype chain, so nothing
            // here is at risk -- which is exactly why the rule belongs here too. The
            // npm verifier once built plain objects with o[k] = v, where assigning
            // "__proto__" reparents the object instead of adding a member; a program
            // carried entirely on a prototype was executed and REPRODUCED there while
            // Python could not read it. A load rule that only the endangered
            // implementation enforces is a divergence, not a fix.
            // JStr is UTF-16 code units, so compare unit-by-unit against ASCII
            // rather than reaching for a byte literal.
            let named = |n: &str| {
                k.len() == n.len() && k.iter().zip(n.bytes()).all(|(a, b)| *a == u16::from(b))
            };
            if named("__proto__") || named("constructor") || named("prototype") {
                return err("object member names a JavaScript object-model slot, \
                            not a data field");
            }
            // DUPLICATE MEMBERS ARE REFUSED, NOT RESOLVED. Last-value-wins is a parser
            // convention, not a guarantee; a document whose meaning depends on which
            // reader opens it has no business being called canonical.
            if out.iter().any(|(mk, _)| *mk == k) {
                return err("duplicate object member: last-value-wins is a parser \
                            convention, not a guarantee, and two readers may disagree \
                            about which value this document contains");
            }
            if out.len() >= MAX_MEMBERS_PER_OBJECT {
                return err(format!("object has more than {MAX_MEMBERS_PER_OBJECT} members"));
            }
            let v = self.parse_value()?;
            out.push((k, v));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b'}') => {
                    self.i += 1;
                    self.depth -= 1;
                    return Ok(Value::Object(out));
                }
                _ => return err(format!("expected , or }} at offset {}", self.i)),
            }
        }
    }

    fn parse_array(&mut self) -> R<Value> {
        self.enter()?;
        self.i += 1;
        let mut out = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            self.depth -= 1;
            return Ok(Value::Array(out));
        }
        loop {
            if out.len() >= MAX_ARRAY_LENGTH {
                return err(format!("array longer than {MAX_ARRAY_LENGTH}"));
            }
            out.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b']') => {
                    self.i += 1;
                    self.depth -= 1;
                    return Ok(Value::Array(out));
                }
                _ => return err(format!("expected , or ] at offset {}", self.i)),
            }
        }
    }

    fn parse_string(&mut self) -> R<JStr> {
        self.i += 1; // opening quote
        let mut out: JStr = Vec::new();
        loop {
            let c = match self.peek() {
                None => return err("unterminated string"),
                Some(c) => c,
            };
            if c == b'"' {
                self.i += 1;
                return Ok(out);
            }
            // RFC 8259 forbids a raw control character inside a string; it must be
            // escaped. CPython's json refuses it in strict mode (the default), so
            // accepting it here would make a receipt only this implementation loads.
            if c < 0x20 {
                return err("unescaped control character in string");
            }
            if c != b'\\' {
                // A raw non-ASCII character: decode one UTF-8 sequence and re-encode
                // it as UTF-16, so the in-memory form is the same code-point sequence
                // Python's `str` holds.
                let start = self.i;
                let len = utf8_seq_len(c);
                if len == 0 || start + len > self.s.len() {
                    return err("invalid UTF-8 in string");
                }
                let chunk = &self.s[start..start + len];
                let text = std::str::from_utf8(chunk)
                    .map_err(|_| JsonError("invalid UTF-8 in string".into()))?;
                for u in text.encode_utf16() {
                    out.push(u);
                }
                self.i += len;
                continue;
            }
            self.i += 1;
            let e = match self.peek() {
                None => return err("unterminated escape"),
                Some(e) => e,
            };
            self.i += 1;
            let simple = match e {
                b'"' => Some(0x22),
                b'\\' => Some(0x5c),
                b'/' => Some(0x2f),
                b'b' => Some(0x08),
                b'f' => Some(0x0c),
                b'n' => Some(0x0a),
                b'r' => Some(0x0d),
                b't' => Some(0x09),
                _ => None,
            };
            if let Some(u) = simple {
                out.push(u);
                continue;
            }
            if e != b'u' {
                return err("bad escape");
            }
            if self.i + 4 > self.s.len() {
                return err("bad \\u escape");
            }
            let hexs = std::str::from_utf8(&self.s[self.i..self.i + 4])
                .map_err(|_| JsonError("bad \\u escape".into()))?;
            let unit = u16::from_str_radix(hexs, 16)
                .map_err(|_| JsonError("bad \\u escape".into()))?;
            if !hexs.bytes().all(|b| b.is_ascii_hexdigit()) {
                return err("bad \\u escape");
            }
            self.i += 4;
            // A surrogate is stored as written. CPython's decoder pairs a high
            // surrogate with a following low one into a single code point and leaves a
            // lone one lone; storing UTF-16 units reproduces both behaviours for free,
            // because pairing is what UTF-16 already means.
            out.push(unit);
        }
    }

    fn parse_number(&mut self) -> R<Value> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.i += 1;
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.i += 1;
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            is_float = true;
            self.i += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.i += 1;
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.i += 1;
            }
        }
        let lit = std::str::from_utf8(&self.s[start..self.i])
            .map_err(|_| JsonError("bad number".into()))?;
        if !valid_number(lit) {
            return err(format!("bad number {lit}"));
        }
        if is_float {
            // THE LITERAL'S SHAPE DECIDES THE TYPE, NOT ITS VALUE. `1.0` is a float
            // and canonicalises to `1.0`; `1` is an integer and canonicalises to `1`.
            let f: f64 = lit.parse().map_err(|_| JsonError(format!("bad number {lit}")))?;
            // `1e400` parses to infinity, which has no JSON form. CPython refuses it
            // here, at load, and so must every other implementation or the four
            // disagree about which documents exist.
            if !f.is_finite() {
                return err(format!("non-finite float literal {lit}"));
            }
            return Ok(Value::Float(f));
        }
        // A literal CPython refuses to convert must not become a value here, or the
        // same bytes load in one implementation and are refused in another.
        if lit.trim_start_matches('-').len() > MAX_INT_DIGITS {
            return err(format!("integer with more than {MAX_INT_DIGITS} digits"));
        }
        Ok(Value::Int(Int::from_text(lit)))
    }
}

fn utf8_seq_len(b: u8) -> usize {
    match b {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => 0,
    }
}

/// The JSON number grammar: `-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?`. No leading zeros,
/// no bare `.5`, no trailing `1.`, no `+1` -- the same shape CPython's scanner and the
/// JavaScript parser's regex accept.
fn valid_number(lit: &str) -> bool {
    let b = lit.as_bytes();
    let mut i = 0;
    if i < b.len() && b[i] == b'-' {
        i += 1;
    }
    if i >= b.len() {
        return false;
    }
    if b[i] == b'0' {
        i += 1;
    } else if b[i].is_ascii_digit() {
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
    } else {
        return false;
    }
    if i < b.len() && b[i] == b'.' {
        i += 1;
        if i >= b.len() || !b[i].is_ascii_digit() {
            return false;
        }
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
    }
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        i += 1;
        if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
            i += 1;
        }
        if i >= b.len() || !b[i].is_ascii_digit() {
            return false;
        }
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
    }
    i == b.len()
}

/// The UTF-8 byte length CPython would measure, or `None` for a lone surrogate.
///
/// CPython measures this with `len(s.encode("utf-8"))`, which RAISES on a lone
/// surrogate -- so a receipt carrying `"\ud800"` is refused there, by accident rather
/// than by design, while the JavaScript parser loads it. Reproducing the refusal keeps
/// this implementation on the reference's side of a split the spec never adjudicated;
/// rust/README.md records that it is a spec gap and not a decision this file made.
fn utf8_len(units: &[u16]) -> Option<usize> {
    let mut n = 0usize;
    let mut i = 0usize;
    while i < units.len() {
        let u = units[i] as u32;
        if (0xd800..0xdc00).contains(&u) {
            let lo = units.get(i + 1).copied().unwrap_or(0) as u32;
            if !(0xdc00..0xe000).contains(&lo) {
                return None; // unpaired high surrogate
            }
            n += 4;
            i += 2;
            continue;
        }
        if (0xdc00..0xe000).contains(&u) {
            return None; // unpaired low surrogate
        }
        n += if u < 0x80 {
            1
        } else if u < 0x800 {
            2
        } else {
            3
        };
        i += 1;
    }
    Some(n)
}

/// Walk the parsed document and enforce the structural limits.
///
/// The depth rule is CPython's, exactly: the top-level value is depth 0 and a
/// The cap is on CONTAINERS ENTERED, matching canonical.py and js/src/canonical.js.
/// Bounding the deepest VALUE is a different rule -- an empty container has no member
/// to check -- and the three implementations answering differently was a real
/// loadability split, now closed.
fn check_shape(v: &Value, depth: usize) -> R<()> {
    // COUNT CONTAINERS ENTERED, which is what js/src/canonical.js counts and what
    // canonical.py now counts. Bounding the deepest VALUE instead admitted 33
    // containers whenever the innermost was empty, so one document loaded here and
    // was refused there. Which number is a spec choice; three answers was the bug.
    let depth = match v {
        Value::Object(_) | Value::Array(_) => depth + 1,
        _ => depth,
    };
    if depth > MAX_DEPTH {
        return err(format!("nesting deeper than {MAX_DEPTH}"));
    }
    match v {
        Value::Object(m) => {
            for (k, val) in m {
                match utf8_len(k) {
                    None => return err("object key is not encodable (lone surrogate)"),
                    Some(n) if n > MAX_STRING_BYTES => {
                        return err(format!("object key longer than {MAX_STRING_BYTES} bytes"))
                    }
                    _ => {}
                }
                check_shape(val, depth)?;
            }
        }
        Value::Array(a) => {
            if a.len() > MAX_ARRAY_LENGTH {
                return err(format!("array of {} exceeds {MAX_ARRAY_LENGTH}", a.len()));
            }
            for val in a {
                check_shape(val, depth)?;
            }
        }
        Value::Str(u) => match utf8_len(u) {
            None => return err("string is not encodable (lone surrogate)"),
            Some(n) if n > MAX_STRING_BYTES => {
                return err(format!("string longer than {MAX_STRING_BYTES} bytes"))
            }
            _ => {}
        },
        Value::Int(i) => {
            if i.digits() > MAX_INT_DIGITS {
                return err(format!("integer with more than {MAX_INT_DIGITS} digits"));
            }
        }
        _ => {}
    }
    Ok(())
}

/// Parse JSON text WITHOUT the receipt wire limits.
///
/// The limits are a rule about what a RECEIPT is, not about what JSON is, and the two
/// must not be confused: this exists for internal plumbing that reads ordinary JSON
/// this crate produced itself (the differential harness's job files, which legitimately
/// carry a 65537-byte string as the TEXT OF A CASE). It must never be used to load a
/// document that arrived from outside -- `load_receipt` is the only entry point for
/// that, and the limits are exactly what stops a hostile document from being expensive.
pub fn parse_permissive(text: &str) -> R<Value> {
    let mut p = Parser { s: text.as_bytes(), i: 0, depth: 0 };
    let v = p.parse_value()?;
    p.skip_ws();
    if p.i != p.s.len() {
        return err("trailing data after JSON value");
    }
    Ok(v)
}

/// Parse receipt TEXT, preserving the int/float distinction.
///
/// Takes text rather than a path so the caller owns I/O, and so the one place the trap
/// can bite is one function.
pub fn load_receipt(text: &str) -> R<Value> {
    // Size first: everything below walks the document, so the cheapest refusal comes
    // before any parsing work is done on an unbounded input.
    if text.len() > MAX_RECEIPT_BYTES {
        return err(format!("receipt larger than {MAX_RECEIPT_BYTES} bytes"));
    }
    let mut p = Parser { s: text.as_bytes(), i: 0, depth: 0 };
    let v = p.parse_value()?;
    p.skip_ws();
    if p.i != p.s.len() {
        return err("trailing data after JSON value");
    }
    if !matches!(v, Value::Object(_)) {
        return err("a receipt must be a JSON object");
    }
    check_shape(&v, 0)?;
    Ok(v)
}

// ----------------------------------------------------------------------- serialize

/// CPython's `repr` of a float, which is what `json.dumps` emits.
///
/// "SHORTEST DECIMAL THAT ROUND-TRIPS" IS NOT ONE ANSWER, and that is the trap here.
/// For some doubles two different 17-digit strings both read back exactly -- e.g.
/// 2211529743968985.2 and ...85.3 are the same double -- and the implementations pick
/// different ones. `format!("{}", x)` chose `.3` where CPython and JavaScript both
/// choose `.2`, so a receipt carrying that value would have hashed differently here
/// than in the other two implementations: an honest receipt reported as tampered, for
/// a reason its author would never think to look for.
///
/// CPython's rule is the shortest digit count whose CORRECTLY ROUNDED decimal reads
/// back as the same double, so that is what this asks for directly -- increasing
/// precision until the value round-trips. `{:.*e}` is correctly rounded, which is the
/// property `{}` does not promise.
fn shortest_digits(x: f64) -> (String, i32) {
    for prec in 0..=16 {
        let s = format!("{:.*e}", prec, x);
        if s.parse::<f64>() == Ok(x) {
            return split_exp(&s);
        }
    }
    split_exp(&format!("{:.*e}", 17, x))
}

/// "-1.2345e-7" -> ("12345", -7): the significant digits, and the power of ten the
/// FIRST of them carries. The sign is handled by the caller.
fn split_exp(s: &str) -> (String, i32) {
    let s = s.strip_prefix('-').unwrap_or(s);
    let (mant, exp) = s.split_once('e').expect("LowerExp always emits an exponent");
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    (digits, exp.parse::<i32>().expect("exponent is an integer"))
}

/// CPython's `repr` of a float, in the two shapes it uses.
///
/// Rust and Python both print a shortest round-tripping decimal, and they disagree on
/// PRESENTATION in three ways that change bytes and therefore hashes:
///   whole-numbered float: Python `1.0`, Rust `1`
///   exponent threshold:   Python switches at 1e16 and 1e-4, Rust never
///   exponent padding:     Python `1e-07`, Rust `1e-7`
fn py_float_repr(x: f64) -> R<String> {
    if !x.is_finite() {
        // NaN and Infinity have no JSON representation, so permitting them would let
        // two different receipts share one canonical form.
        return err("NaN and Infinity have no JSON form (allow_nan=False)");
    }
    if x == 0.0 {
        return Ok(if x.is_sign_negative() { "-0.0".into() } else { "0.0".into() });
    }
    let sign = if x < 0.0 { "-" } else { "" };
    let (digits, exp) = shortest_digits(x);
    let n = digits.len() as i32;
    let a = x.abs();

    if a >= 1e16 || a < 1e-4 {
        // NO `.0` PADDING ON THE MANTISSA: Python writes `1e-06`, never `1.0e-06`.
        let mant = if n == 1 {
            digits.clone()
        } else {
            format!("{}.{}", &digits[..1], &digits[1..])
        };
        let (esign, edigits) = if exp < 0 {
            ('-', (-exp).to_string())
        } else {
            ('+', exp.to_string())
        };
        let padded = if edigits.len() < 2 { format!("0{edigits}") } else { edigits };
        return Ok(format!("{sign}{mant}e{esign}{padded}"));
    }

    // Positional, with the `.0` Python keeps on a whole-numbered float.
    let body = if exp >= n - 1 {
        format!("{}{}.0", digits, "0".repeat((exp - n + 1) as usize))
    } else if exp >= 0 {
        let split = (exp + 1) as usize;
        format!("{}.{}", &digits[..split], &digits[split..])
    } else {
        format!("0.{}{}", "0".repeat((-exp - 1) as usize), digits)
    };
    Ok(format!("{sign}{body}"))
}

/// Escape a string the way CPython's json with `ensure_ascii=True` does: everything
/// outside printable ASCII becomes `\uXXXX`, and a non-BMP code point becomes an
/// escaped SURROGATE PAIR rather than one escape. Holding UTF-16 units makes the
/// second rule automatic -- the pair is already what is stored.
fn py_string_repr(units: &[u16], out: &mut String) {
    out.push('"');
    for &u in units {
        match u {
            0x22 => out.push_str("\\\""),
            0x5c => out.push_str("\\\\"),
            0x0a => out.push_str("\\n"),
            0x0d => out.push_str("\\r"),
            0x09 => out.push_str("\\t"),
            0x08 => out.push_str("\\b"),
            0x0c => out.push_str("\\f"),
            0x20..=0x7e => out.push(u as u8 as char),
            _ => {
                let _ = write!(out, "\\u{u:04x}");
            }
        }
    }
    out.push('"');
}

/// Key order is by Unicode CODE POINT, which is what Python's `sorted()` gives.
/// Sorting UTF-16 code UNITS is a different order: an astral key's lead surrogate
/// (U+D800..U+DBFF) sorts below a BMP key in U+E000..U+FFFF by unit and above it by
/// code point. js/src/canonical.js carries the same correction for the same reason.
fn code_points(units: &[u16]) -> Vec<u32> {
    let mut out = Vec::with_capacity(units.len());
    let mut i = 0;
    while i < units.len() {
        let u = units[i] as u32;
        if (0xd800..0xdc00).contains(&u) {
            if let Some(&lo) = units.get(i + 1) {
                if (0xdc00..0xe000).contains(&(lo as u32)) {
                    out.push(0x10000 + ((u - 0xd800) << 10) + (lo as u32 - 0xdc00));
                    i += 2;
                    continue;
                }
            }
        }
        out.push(u);
        i += 1;
    }
    out
}

fn write_canonical(v: &Value, out: &mut String) -> R<()> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(i) => out.push_str(i.text()),
        Value::Float(f) => out.push_str(&py_float_repr(*f)?),
        Value::Str(s) => py_string_repr(s, out),
        Value::Array(a) => {
            out.push('[');
            for (n, item) in a.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keyed: Vec<(Vec<u32>, &JStr, &Value)> =
                m.iter().map(|(k, val)| (code_points(k), k, val)).collect();
            keyed.sort_by(|a, b| a.0.cmp(&b.0));
            out.push('{');
            for (n, (_, k, val)) in keyed.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                py_string_repr(k, out);
                out.push(':');
                write_canonical(val, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Canonical JSON, exactly as docs/COMPAT.md defines it: keys sorted by code point, no
/// separators' whitespace, non-ASCII escaped, `1` and `1.0` distinct, NaN and Infinity
/// unrepresentable.
pub fn canonical_string(v: &Value) -> R<String> {
    let mut s = String::new();
    write_canonical(v, &mut s)?;
    Ok(s)
}

pub fn canonical_bytes(v: &Value) -> R<Vec<u8>> {
    Ok(canonical_string(v)?.into_bytes())
}

pub fn canonical_sha256(v: &Value) -> R<String> {
    Ok(sha256_hex(canonical_string(v)?.as_bytes()))
}

/// Fields the spec excludes from the claim (docs/COMPAT.md, "the claim rule"). `env`
/// is informational, `signature` and `case` are post-hoc, `receipt_sha256` is the hash
/// itself, `_`-prefixed keys are helpers.
pub const NON_CLAIM: [&str; 4] = ["receipt_sha256", "env", "signature", "case"];

/// The subset of a receipt that its `receipt_sha256` covers.
pub fn claim_of(receipt: &Value) -> Value {
    let members = match receipt.as_object() {
        Some(m) => m,
        None => return Value::Object(Vec::new()),
    };
    let out = members
        .iter()
        .filter(|(k, _)| {
            let name = String::from_utf16_lossy(k);
            !NON_CLAIM.contains(&name.as_str()) && !name.starts_with('_')
        })
        .cloned()
        .collect();
    Value::Object(out)
}

/// Step 1 of the trust ladder: does `receipt_sha256` recompute from the claim?
///
/// Returns (ok, detail) and never fails on a hostile receipt -- a verifier that
/// crashes on malformed input has failed open in the eyes of whoever supplied it.
pub fn integrity(receipt: &Value) -> (bool, String) {
    let stated = match receipt.get("receipt_sha256").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s,
        _ => return (false, "no receipt_sha256 to check against".into()),
    };
    let recomputed = match canonical_sha256(&claim_of(receipt)) {
        Ok(h) => h,
        Err(e) => return (false, format!("claim is not canonicalisable ({e})")),
    };
    if recomputed != stated {
        // `stated` is whatever the file says, so it may be any UTF-8 at all. Slicing it
        // by BYTES could land mid-character and panic -- and a verifier that panics
        // while explaining a refusal has turned a verdict into a crash.
        let head: String = stated.chars().take(16).collect();
        return (false, format!("INTEGRITY FAIL - states {head}.., recomputes {}..", &recomputed[..16]));
    }
    (true, "integrity OK".into())
}
