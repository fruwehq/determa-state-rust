//! A focused interpreter for the CEL subset harel uses (SPEC §6).
//!
//! Guards and action values are CEL. We implement literals (int/float/string/bool/
//! null/list), identifiers, member/index access, arithmetic, comparison, logical,
//! and `in`. Runtime failures (division by zero, type mismatches) surface as
//! [`CelError`], which the runtime treats as an action fault (SPEC §5.10).

use crate::value::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CelError {
    DivByZero,
    Type(String),
    /// A runtime structural failure (e.g. indexing a non-collection).
    Other(String),
}

impl std::fmt::Display for CelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CelError::DivByZero => write!(f, "division by zero"),
            CelError::Type(m) => write!(f, "type error: {m}"),
            CelError::Other(m) => write!(f, "{m}"),
        }
    }
}
impl std::error::Error for CelError {}

type Res = Result<Value, CelError>;

// ---------------------------------------------------------------------------
// Tokenizer

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(f64, bool), // (value, is_int)
    Str(String),
    Ident(String),
    Dot,
    LBrack,
    RBrack,
    LParen,
    RParen,
    Comma,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    EqEq,
    NotEq,
    Lt,
    Le,
    Gt,
    Ge,
    AndAnd,
    OrOr,
    Bang,
    In,
}

fn tokenize(src: &str) -> Result<Vec<Tok>, CelError> {
    let chars: Vec<char> = src.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' | '\n' | '\r' => i += 1,
            '.' => {
                out.push(Tok::Dot);
                i += 1;
            }
            '[' => {
                out.push(Tok::LBrack);
                i += 1;
            }
            ']' => {
                out.push(Tok::RBrack);
                i += 1;
            }
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            ',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            '+' => {
                out.push(Tok::Plus);
                i += 1;
            }
            '-' => {
                out.push(Tok::Minus);
                i += 1;
            }
            '*' => {
                out.push(Tok::Star);
                i += 1;
            }
            '/' => {
                out.push(Tok::Slash);
                i += 1;
            }
            '%' => {
                out.push(Tok::Percent);
                i += 1;
            }
            '=' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    out.push(Tok::EqEq);
                    i += 2;
                } else {
                    return Err(CelError::Other("unexpected '='".into()));
                }
            }
            '!' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    out.push(Tok::NotEq);
                    i += 2;
                } else {
                    out.push(Tok::Bang);
                    i += 1;
                }
            }
            '<' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    out.push(Tok::Le);
                    i += 2;
                } else {
                    out.push(Tok::Lt);
                    i += 1;
                }
            }
            '>' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    out.push(Tok::Ge);
                    i += 2;
                } else {
                    out.push(Tok::Gt);
                    i += 1;
                }
            }
            '&' => {
                if i + 1 < chars.len() && chars[i + 1] == '&' {
                    out.push(Tok::AndAnd);
                    i += 2;
                } else {
                    return Err(CelError::Other("unexpected '&'".into()));
                }
            }
            '|' => {
                if i + 1 < chars.len() && chars[i + 1] == '|' {
                    out.push(Tok::OrOr);
                    i += 2;
                } else {
                    return Err(CelError::Other("unexpected '|'".into()));
                }
            }
            '\'' | '"' => {
                let quote = c;
                i += 1;
                let mut s = String::new();
                while i < chars.len() && chars[i] != quote {
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        let e = chars[i + 1];
                        let esc = match e {
                            'n' => '\n',
                            't' => '\t',
                            'r' => '\r',
                            '\\' => '\\',
                            '\'' => '\'',
                            '"' => '"',
                            '0' => '\0',
                            other => other,
                        };
                        s.push(esc);
                        i += 2;
                    } else {
                        s.push(chars[i]);
                        i += 1;
                    }
                }
                if i >= chars.len() {
                    return Err(CelError::Other("unterminated string".into()));
                }
                i += 1; // closing quote
                out.push(Tok::Str(s));
            }
            _ if c.is_ascii_digit() => {
                let start = i;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                let mut is_float = false;
                if i < chars.len() && chars[i] == '.' && i + 1 < chars.len()
                    && chars[i + 1].is_ascii_digit()
                {
                    is_float = true;
                    i += 1;
                    while i < chars.len() && chars[i].is_ascii_digit() {
                        i += 1;
                    }
                }
                // exponent
                if i < chars.len() && (chars[i] == 'e' || chars[i] == 'E') {
                    is_float = true;
                    i += 1;
                    if i < chars.len() && (chars[i] == '+' || chars[i] == '-') {
                        i += 1;
                    }
                    while i < chars.len() && chars[i].is_ascii_digit() {
                        i += 1;
                    }
                }
                let text: String = chars[start..i].iter().collect();
                let val: f64 = text.parse().map_err(|_| CelError::Other("bad number".into()))?;
                out.push(Tok::Num(val, !is_float));
            }
            _ if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len()
                    && (chars[i].is_ascii_alphanumeric() || chars[i] == '_')
                {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                if word == "in" {
                    out.push(Tok::In);
                } else {
                    out.push(Tok::Ident(word));
                }
            }
            _ => return Err(CelError::Other(format!("unexpected char {c:?}"))),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Parser -> AST (we parse-and-evaluate in one pass for compactness)

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn bump(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn eat(&mut self, t: &Tok) -> bool {
        if self.toks.get(self.pos) == Some(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn parse(&mut self, env: &Env) -> Res {
        let v = self.parse_or(env)?;
        if self.pos != self.toks.len() {
            return Err(CelError::Other(format!(
                "trailing tokens at {}",
                self.pos
            )));
        }
        Ok(v)
    }

    fn parse_or(&mut self, env: &Env) -> Res {
        let mut a = self.parse_and(env)?;
        while self.eat(&Tok::OrOr) {
            let b = self.parse_and(env)?;
            a = Value::Bool(a.truthy() || b.truthy());
        }
        Ok(a)
    }

    fn parse_and(&mut self, env: &Env) -> Res {
        let mut a = self.parse_rel(env)?;
        while self.eat(&Tok::AndAnd) {
            let b = self.parse_rel(env)?;
            a = Value::Bool(a.truthy() && b.truthy());
        }
        Ok(a)
    }

    fn parse_rel(&mut self, env: &Env) -> Res {
        let mut a = self.parse_add(env)?;
        loop {
            let op = match self.peek() {
                Some(Tok::EqEq) => "==",
                Some(Tok::NotEq) => "!=",
                Some(Tok::Lt) => "<",
                Some(Tok::Le) => "<=",
                Some(Tok::Gt) => ">",
                Some(Tok::Ge) => ">=",
                Some(Tok::In) => "in",
                _ => break,
            };
            self.pos += 1;
            let b = self.parse_add(env)?;
            a = if op == "in" {
                Value::Bool(in_op(&a, &b)?)
            } else {
                compare(op, &a, &b)?
            };
        }
        Ok(a)
    }

    fn parse_add(&mut self, env: &Env) -> Res {
        let mut a = self.parse_mul(env)?;
        loop {
            let op = match self.peek() {
                Some(Tok::Plus) => '+',
                Some(Tok::Minus) => '-',
                _ => break,
            };
            self.pos += 1;
            let b = self.parse_mul(env)?;
            a = arith(op, &a, &b)?;
        }
        Ok(a)
    }

    fn parse_mul(&mut self, env: &Env) -> Res {
        let mut a = self.parse_unary(env)?;
        loop {
            let op = match self.peek() {
                Some(Tok::Star) => '*',
                Some(Tok::Slash) => '/',
                Some(Tok::Percent) => '%',
                _ => break,
            };
            self.pos += 1;
            let b = self.parse_unary(env)?;
            a = arith(op, &a, &b)?;
        }
        Ok(a)
    }

    fn parse_unary(&mut self, env: &Env) -> Res {
        match self.peek() {
            Some(Tok::Minus) => {
                self.pos += 1;
                let v = self.parse_unary(env)?;
                match v {
                    Value::Int(i) => Ok(Value::Int(-i)),
                    Value::Float(f) => Ok(Value::Float(-f)),
                    other => Err(CelError::Type(format!("cannot negate {}", other.type_name()))),
                }
            }
            Some(Tok::Bang) => {
                self.pos += 1;
                let v = self.parse_unary(env)?;
                Ok(Value::Bool(!v.truthy()))
            }
            _ => self.parse_postfix(env),
        }
    }

    fn parse_postfix(&mut self, env: &Env) -> Res {
        let mut v = self.parse_primary(env)?;
        loop {
            match self.peek() {
                Some(Tok::Dot) => {
                    self.pos += 1;
                    let field = match self.bump() {
                        Some(Tok::Ident(s)) => s,
                        _ => return Err(CelError::Other("expected field after '.'".into())),
                    };
                    v = select(&v, &field)?;
                }
                Some(Tok::LBrack) => {
                    self.pos += 1;
                    let idx = self.parse_or(env)?;
                    if !self.eat(&Tok::RBrack) {
                        return Err(CelError::Other("expected ']'".into()));
                    }
                    v = index(&v, &idx)?;
                }
                _ => break,
            }
        }
        Ok(v)
    }

    fn parse_primary(&mut self, env: &Env) -> Res {
        match self.bump() {
            Some(Tok::Num(n, is_int)) => {
                if is_int {
                    Ok(Value::Int(n as i64))
                } else {
                    Ok(Value::Float(n))
                }
            }
            Some(Tok::Str(s)) => Ok(Value::Str(s)),
            Some(Tok::Ident(name)) => {
                if name == "true" {
                    Ok(Value::Bool(true))
                } else if name == "false" {
                    Ok(Value::Bool(false))
                } else if name == "null" {
                    Ok(Value::Null)
                } else {
                    env.get(&name)
                        .cloned()
                        .ok_or_else(|| CelError::Other(format!("undefined name '{name}'")))
                }
            }
            Some(Tok::LParen) => {
                let v = self.parse_or(env)?;
                if !self.eat(&Tok::RParen) {
                    return Err(CelError::Other("expected ')'".into()));
                }
                Ok(v)
            }
            Some(Tok::LBrack) => {
                let mut items = Vec::new();
                if !self.eat(&Tok::RBrack) {
                    loop {
                        let e = self.parse_or(env)?;
                        items.push(e);
                        if self.eat(&Tok::Comma) {
                            continue;
                        }
                        break;
                    }
                    if !self.eat(&Tok::RBrack) {
                        return Err(CelError::Other("expected ']'".into()));
                    }
                }
                Ok(Value::List(items))
            }
            other => Err(CelError::Other(format!("unexpected token {other:?}"))),
        }
    }
}

fn select(v: &Value, field: &str) -> Res {
    match v {
        Value::Map(m) => Ok(m.get(field).cloned().unwrap_or(Value::Null)),
        _ => Err(CelError::Type(format!(
            "cannot select '.{field}' on {}",
            v.type_name()
        ))),
    }
}

fn index(v: &Value, idx: &Value) -> Res {
    match (v, idx) {
        (Value::List(l), Value::Int(i)) => {
            let n = *i as isize;
            if n < 0 || n as usize >= l.len() {
                Ok(Value::Null)
            } else {
                Ok(l[n as usize].clone())
            }
        }
        (Value::Map(m), Value::Str(k)) => Ok(m.get(k).cloned().unwrap_or(Value::Null)),
        _ => Err(CelError::Type(format!(
            "cannot index {} with {}",
            v.type_name(),
            idx.type_name()
        ))),
    }
}

fn in_op(a: &Value, b: &Value) -> Result<bool, CelError> {
    match b {
        Value::List(l) => Ok(l.contains(a)),
        Value::Map(m) => match a {
            Value::Str(k) => Ok(m.contains_key(k)),
            _ => Ok(false),
        },
        _ => Err(CelError::Type(format!(
            "'in' expects list/map, got {}",
            b.type_name()
        ))),
    }
}

fn as_f64(v: &Value) -> Result<f64, CelError> {
    match v {
        Value::Int(i) => Ok(*i as f64),
        Value::Float(f) => Ok(*f),
        _ => Err(CelError::Type(format!("expected number, got {}", v.type_name()))),
    }
}

fn arith(op: char, a: &Value, b: &Value) -> Res {
    match (a, b) {
        // list concatenation
        (Value::List(l1), Value::List(l2)) if op == '+' => {
            Ok(Value::List(l1.iter().chain(l2.iter()).cloned().collect()))
        }
        // string concatenation
        (Value::Str(s1), Value::Str(s2)) if op == '+' => {
            Ok(Value::Str(format!("{s1}{s2}")))
        }
        // int/int arithmetic (keep ints integral when possible)
        (Value::Int(x), Value::Int(y)) => match op {
            '+' => Ok(Value::Int(x.wrapping_add(*y))),
            '-' => Ok(Value::Int(x.wrapping_sub(*y))),
            '*' => Ok(Value::Int(x.wrapping_mul(*y))),
            '/' => {
                if *y == 0 {
                    Err(CelError::DivByZero)
                } else {
                    Ok(Value::Int(x.wrapping_div(*y)))
                }
            }
            '%' => {
                if *y == 0 {
                    Err(CelError::DivByZero)
                } else {
                    Ok(Value::Int(x.wrapping_rem(*y)))
                }
            }
            _ => Err(CelError::Type(format!("bad int op {op}"))),
        },
        // float involved
        _ => {
            let x = as_f64(a)?;
            let y = as_f64(b)?;
            let r = match op {
                '+' => x + y,
                '-' => x - y,
                '*' => x * y,
                '/' => {
                    if y == 0.0 {
                        return Err(CelError::DivByZero);
                    }
                    x / y
                }
                '%' => {
                    if y == 0.0 {
                        return Err(CelError::DivByZero);
                    }
                    x % y
                }
                _ => return Err(CelError::Type(format!("bad float op {op}"))),
            };
            // preserve int if both int-coercible and result is integral
            if matches!(a, Value::Int(_)) && matches!(b, Value::Int(_)) {
                Ok(Value::Float(r))
            } else {
                Ok(Value::Float(r))
            }
        }
    }
}

fn compare(op: &str, a: &Value, b: &Value) -> Res {
    let eq = a == b;
    let r = match op {
        "==" => eq,
        "!=" => !eq,
        "<" | "<=" | ">" | ">=" => {
            let c = match (a, b) {
                (Value::Int(x), Value::Int(y)) => x.cmp(y),
                _ => {
                    let x = as_f64(a)?;
                    let y = as_f64(b)?;
                    x.partial_cmp(&y).ok_or_else(|| {
                        CelError::Type("unordered comparison".into())
                    })?
                }
            };
            // also allow string comparison
            let c = match (a, b) {
                (Value::Str(x), Value::Str(y)) => x.cmp(y),
                _ => c,
            };
            match op {
                "<" => c.is_lt(),
                "<=" => c.is_le(),
                ">" => c.is_gt(),
                ">=" => c.is_ge(),
                _ => unreachable!(),
            }
        }
        _ => unreachable!(),
    };
    Ok(Value::Bool(r))
}

// ---------------------------------------------------------------------------
// Public API

/// A CEL environment: bindings visible to a guard / action value.
#[derive(Debug, Clone, Default)]
pub struct Env {
    pub bindings: BTreeMap<String, Value>,
}

impl Env {
    pub fn new() -> Self {
        Self {
            bindings: BTreeMap::new(),
        }
    }
    pub fn with(mut self, k: impl Into<String>, v: Value) -> Self {
        self.bindings.insert(k.into(), v);
        self
    }
    pub fn get(&self, k: &str) -> Option<&Value> {
        self.bindings.get(k)
    }
}

/// Evaluate a CEL expression, returning its value.
pub fn eval(src: &str, env: &Env) -> Res {
    let toks = tokenize(src)?;
    let mut p = Parser { toks, pos: 0 };
    p.parse(env)
}

/// Evaluate a CEL expression as a boolean guard.
pub fn eval_bool(src: &str, env: &Env) -> Result<bool, CelError> {
    match eval(src, env)? {
        Value::Bool(b) => Ok(b),
        other => Ok(other.truthy()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Env {
        Env::new()
            .with("x", Value::Int(10))
            .with(
                "event",
                Value::Map(
                    [( "payload".to_string(), Value::Map(
                        [("n".to_string(), Value::Int(5))].into_iter().collect(),
                    ))]
                        .into_iter()
                        .collect(),
                ),
            )
            .with("s", Value::Str("hi".into()))
    }

    #[test]
    fn basics() {
        assert_eq!(eval("1 + 2", &Env::new()).unwrap(), Value::Int(3));
        assert_eq!(eval("x + 5", &env()).unwrap(), Value::Int(15));
        assert_eq!(eval("event.payload.n > 3", &env()).unwrap(), Value::Bool(true));
        assert_eq!(eval("event.payload.n > 10", &env()).unwrap(), Value::Bool(false));
        assert_eq!(eval("s + '!' == \"hi!\"", &env()).unwrap(), Value::Bool(true));
        assert_eq!(eval("'a' in ['a','b']", &Env::new()).unwrap(), Value::Bool(true));
        assert_eq!(eval("3 in ['a','b']", &Env::new()).unwrap(), Value::Bool(false));
    }

    #[test]
    fn div_zero() {
        assert!(matches!(eval("10 / 0", &Env::new()), Err(CelError::DivByZero)));
        assert!(matches!(eval("10 / 0.0", &Env::new()), Err(CelError::DivByZero)));
    }

    #[test]
    fn list_concat() {
        assert_eq!(
            eval("[1,2] + ['c']", &Env::new()).unwrap(),
            Value::List(vec![Value::Int(1), Value::Int(2), Value::Str("c".into())])
        );
        // int + list is a type error (concat requires both lists)
        assert!(eval("x + ['c']", &env()).is_err());
    }
}
