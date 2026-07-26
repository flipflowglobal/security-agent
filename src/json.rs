//! Minimal, dependency-free JSON reader shared by the wire-format envelope
//! (`crate::compat`) and tool-output ingestion (`crate::ingest`).
//!
//! This is not a general-purpose JSON library: it is just enough to read
//! this crate's fixed envelope shape and to walk arbitrary tool-emitted
//! JSON (semgrep, SARIF, ...) as a generic value tree, so callers can pull
//! out only the handful of fields they need without a second, divergent
//! parser. Writing JSON stays local to `crate::compat`, the only producer.

use std::collections::BTreeMap;
use std::iter::Peekable;
use std::str::Chars;

/// A generic JSON value. Used only for reading third-party or wire-format
/// input — this crate never serializes through this type.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl JsonValue {
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }

    /// Looks up `key` when `self` is an object; `None` for any other shape
    /// or a missing key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(fields) => fields.get(key),
            _ => None,
        }
    }

    /// The value as a non-negative whole number, when it can be represented
    /// exactly as one (used for line numbers in tool-emitted JSON).
    // The guard checks non-negativity, upper bound, and whole-number-ness
    // before the cast, so it cannot truncate or lose sign; the u64::MAX
    // comparison is inherently approximate at the top of f64 range,
    // which is acceptable for this bounds check.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(value)
                if *value >= 0.0 && *value <= u64::MAX as f64 && value.fract() == 0.0 =>
            {
                Some(*value as u64)
            }
            _ => None,
        }
    }

    /// Returns `true` when the value is `JsonValue::Bool(true)`.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Returns `true` when the value is `JsonValue::Null`.
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Returns an iterator over the key-value pairs of an object value.
    /// Yields nothing for any other variant.
    #[must_use]
    pub fn iter_object(&self) -> JsonObjectIter<'_> {
        match self {
            Self::Object(fields) => JsonObjectIter::Some(fields.iter()),
            _ => JsonObjectIter::Empty,
        }
    }
}

/// Iterator over JSON object key-value pairs.
pub enum JsonObjectIter<'a> {
    Some(std::collections::btree_map::Iter<'a, String, JsonValue>),
    Empty,
}

impl<'a> Iterator for JsonObjectIter<'a> {
    type Item = (&'a str, &'a JsonValue);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Some(iter) => iter.next().map(|(k, v)| (k.as_str(), v)),
            Self::Empty => None,
        }
    }
}

/// Parses a complete JSON document from `text`. Returns `None` for
/// anything that isn't well-formed JSON, including trailing content after
/// the value (a whole line/file is expected, not a prefix of one).
#[must_use]
pub fn parse(text: &str) -> Option<JsonValue> {
    let mut chars = text.trim().chars().peekable();
    let value = parse_value(&mut chars)?;
    skip_whitespace(&mut chars);
    if chars.next().is_some() {
        return None;
    }
    Some(value)
}

fn parse_value(chars: &mut Peekable<Chars<'_>>) -> Option<JsonValue> {
    skip_whitespace(chars);
    match *chars.peek()? {
        '"' => Some(JsonValue::String(parse_json_string(chars)?)),
        '{' => parse_object(chars),
        '[' => parse_array(chars),
        't' => parse_literal(chars, "true", JsonValue::Bool(true)),
        'f' => parse_literal(chars, "false", JsonValue::Bool(false)),
        'n' => parse_literal(chars, "null", JsonValue::Null),
        '-' | '0'..='9' => parse_number(chars),
        _ => None,
    }
}

fn parse_literal(
    chars: &mut Peekable<Chars<'_>>,
    literal: &str,
    value: JsonValue,
) -> Option<JsonValue> {
    for expected in literal.chars() {
        if chars.next()? != expected {
            return None;
        }
    }
    Some(value)
}

fn parse_number(chars: &mut Peekable<Chars<'_>>) -> Option<JsonValue> {
    let mut text = String::new();
    if peek_char(chars, '-') {
        text.push(chars.next()?);
    }
    consume_digits(chars, &mut text)?;
    if peek_char(chars, '.') {
        text.push(chars.next()?);
        consume_digits(chars, &mut text)?;
    }
    if matches!(chars.peek(), Some('e' | 'E')) {
        text.push(chars.next()?);
        if matches!(chars.peek(), Some('+' | '-')) {
            text.push(chars.next()?);
        }
        consume_digits(chars, &mut text)?;
    }
    text.parse::<f64>().ok().map(JsonValue::Number)
}

fn consume_digits(chars: &mut Peekable<Chars<'_>>, out: &mut String) -> Option<()> {
    let mut consumed_any = false;
    while let Some(&ch) = chars.peek() {
        if ch.is_ascii_digit() {
            out.push(ch);
            chars.next();
            consumed_any = true;
        } else {
            break;
        }
    }
    consumed_any.then_some(())
}

fn parse_object(chars: &mut Peekable<Chars<'_>>) -> Option<JsonValue> {
    expect_char(chars, '{')?;
    let mut fields = BTreeMap::new();
    skip_whitespace(chars);
    if peek_char(chars, '}') {
        chars.next();
        return Some(JsonValue::Object(fields));
    }
    loop {
        skip_whitespace(chars);
        let key = parse_json_string(chars)?;
        skip_whitespace(chars);
        expect_char(chars, ':')?;
        let value = parse_value(chars)?;
        fields.insert(key, value);
        skip_whitespace(chars);
        match chars.next()? {
            ',' => {}
            '}' => return Some(JsonValue::Object(fields)),
            _ => return None,
        }
    }
}

fn parse_array(chars: &mut Peekable<Chars<'_>>) -> Option<JsonValue> {
    expect_char(chars, '[')?;
    let mut values = Vec::new();
    skip_whitespace(chars);
    if peek_char(chars, ']') {
        chars.next();
        return Some(JsonValue::Array(values));
    }
    loop {
        values.push(parse_value(chars)?);
        skip_whitespace(chars);
        match chars.next()? {
            ',' => {}
            ']' => return Some(JsonValue::Array(values)),
            _ => return None,
        }
    }
}

// --- Shared low-level primitives (also used by crate::compat's fixed,
// flat envelope parser) ---

pub fn skip_whitespace(chars: &mut Peekable<Chars<'_>>) {
    while chars.next_if(|ch| ch.is_whitespace()).is_some() {}
}

pub fn peek_char(chars: &mut Peekable<Chars<'_>>, expected: char) -> bool {
    chars.peek() == Some(&expected)
}

pub fn expect_char(chars: &mut Peekable<Chars<'_>>, expected: char) -> Option<()> {
    skip_whitespace(chars);
    if chars.next() == Some(expected) {
        Some(())
    } else {
        None
    }
}

pub fn parse_json_string(chars: &mut Peekable<Chars<'_>>) -> Option<String> {
    skip_whitespace(chars);
    expect_char(chars, '"')?;
    let mut value = String::new();
    loop {
        match chars.next()? {
            '"' => return Some(value),
            '\\' => match chars.next()? {
                '"' => value.push('"'),
                '\\' => value.push('\\'),
                '/' => value.push('/'),
                'n' => value.push('\n'),
                'r' => value.push('\r'),
                't' => value.push('\t'),
                'u' => {
                    let code_point = parse_hex4(chars)?;
                    value.push(char::from_u32(code_point)?);
                }
                _ => return None,
            },
            ch => value.push(ch),
        }
    }
}

fn parse_hex4(chars: &mut Peekable<Chars<'_>>) -> Option<u32> {
    let mut code_point = 0_u32;
    for _ in 0..4 {
        let digit = chars.next()?.to_digit(16)?;
        code_point = code_point * 16 + digit;
    }
    Some(code_point)
}

/// Parses a JSON object whose values are all strings — the crate's fixed
/// wire-format envelope shape (see `crate::compat::CompatibilityEnvelope`).
pub fn parse_json_string_object(
    chars: &mut Peekable<Chars<'_>>,
) -> Option<BTreeMap<String, String>> {
    expect_char(chars, '{')?;
    let mut map = BTreeMap::new();
    loop {
        skip_whitespace(chars);
        if peek_char(chars, '}') {
            chars.next();
            return Some(map);
        }
        let key = parse_json_string(chars)?;
        skip_whitespace(chars);
        expect_char(chars, ':')?;
        let value = parse_json_string(chars)?;
        map.insert(key, value);
        skip_whitespace(chars);
        match chars.next()? {
            ',' => {}
            '}' => return Some(map),
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flat_object_of_strings() {
        let value = parse(r#"{"a":"1","b":"2"}"#).expect("should parse");
        assert_eq!(value.get("a").and_then(JsonValue::as_str), Some("1"));
        assert_eq!(value.get("b").and_then(JsonValue::as_str), Some("2"));
    }

    #[test]
    fn parses_nested_objects_and_arrays() {
        let value = parse(r#"{"results":[{"severity":"ERROR"},{"severity":"WARNING"}]}"#)
            .expect("should parse");
        let results = value
            .get("results")
            .and_then(JsonValue::as_array)
            .expect("array");
        assert_eq!(results.len(), 2);
        assert_eq!(
            results[0].get("severity").and_then(JsonValue::as_str),
            Some("ERROR")
        );
    }

    #[test]
    fn parses_booleans_null_and_numbers() {
        let value = parse(r#"{"a":true,"b":false,"c":null,"d":42,"e":-3.5,"f":1e2}"#)
            .expect("should parse");
        assert_eq!(value.get("a"), Some(&JsonValue::Bool(true)));
        assert_eq!(value.get("b"), Some(&JsonValue::Bool(false)));
        assert_eq!(value.get("c"), Some(&JsonValue::Null));
        assert_eq!(value.get("d").and_then(JsonValue::as_u64), Some(42));
        assert_eq!(value.get("e"), Some(&JsonValue::Number(-3.5)));
        assert_eq!(value.get("f"), Some(&JsonValue::Number(100.0)));
    }

    #[test]
    fn as_u64_rejects_negative_and_fractional_values() {
        assert_eq!(JsonValue::Number(-1.0).as_u64(), None);
        assert_eq!(JsonValue::Number(1.5).as_u64(), None);
        assert_eq!(JsonValue::Number(5.0).as_u64(), Some(5));
    }

    #[test]
    fn empty_object_and_array_parse() {
        assert_eq!(parse("{}"), Some(JsonValue::Object(BTreeMap::new())));
        assert_eq!(parse("[]"), Some(JsonValue::Array(Vec::new())));
    }

    #[test]
    fn rejects_malformed_or_trailing_content() {
        assert!(parse("not json").is_none());
        assert!(parse("{\"a\":1").is_none());
        assert!(parse("{}{}").is_none());
        assert!(parse("").is_none());
    }

    #[test]
    fn get_and_as_array_return_none_for_the_wrong_shape() {
        let value = JsonValue::String("x".to_string());
        assert!(value.get("a").is_none());
        assert!(value.as_array().is_none());
        assert!(value.as_str().is_some());
    }
}
