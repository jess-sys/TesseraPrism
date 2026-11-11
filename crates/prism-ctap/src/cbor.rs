//! Minimal pure-Rust CBOR (RFC 8949 subset needed by CTAP2): definite lengths only,
//! no floats/tags. Encoding is CTAP2-canonical (map keys sorted by encoded length, then bytewise).

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CborError {
    Truncated,
    Unsupported,
    TooDeep,
    TrailingData,
    InvalidUtf8,
}

impl Value {
    pub fn text(s: &str) -> Value {
        Value::Text(s.to_string())
    }
    pub fn bytes(b: &[u8]) -> Value {
        Value::Bytes(b.to_vec())
    }
    /// Look up an integer key in a map.
    pub fn get(&self, key: i64) -> Option<&Value> {
        match self {
            Value::Map(m) => m.iter().find(|(k, _)| *k == Value::Int(key)).map(|(_, v)| v),
            _ => None,
        }
    }
    /// Look up a text key in a map.
    pub fn get_text(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(m) => m
                .iter()
                .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        if let Value::Int(i) = self { Some(*i) } else { None }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        if let Value::Bytes(b) = self { Some(b) } else { None }
    }
    pub fn as_text(&self) -> Option<&str> {
        if let Value::Text(t) = self { Some(t) } else { None }
    }
    pub fn as_array(&self) -> Option<&[Value]> {
        if let Value::Array(a) = self { Some(a) } else { None }
    }
    pub fn as_bool(&self) -> Option<bool> {
        if let Value::Bool(b) = self { Some(*b) } else { None }
    }
    pub fn is_map(&self) -> bool {
        matches!(self, Value::Map(_))
    }
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.push(m | 24);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

pub fn encode_into(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Int(i) => {
            if *i >= 0 {
                head(out, 0, *i as u64)
            } else {
                head(out, 1, (-1 - *i) as u64)
            }
        }
        Value::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            head(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(a) => {
            head(out, 4, a.len() as u64);
            for x in a {
                encode_into(x, out);
            }
        }
        Value::Map(m) => {
            let mut items: Vec<(Vec<u8>, Vec<u8>)> =
                m.iter().map(|(k, v)| (encode(k), encode(v))).collect();
            items.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
            head(out, 5, items.len() as u64);
            for (k, v) in items {
                out.extend_from_slice(&k);
                out.extend_from_slice(&v);
            }
        }
        Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Value::Null => out.push(0xf6),
    }
}

struct Reader<'a> {
    d: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        if self.d.len() - self.pos < n {
            return Err(CborError::Truncated);
        }
        let s = &self.d[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn arg(&mut self, info: u8) -> Result<u64, CborError> {
        Ok(match info {
            0..=23 => info as u64,
            24 => self.take(1)?[0] as u64,
            25 => u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64,
            26 => u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64,
            27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
            _ => return Err(CborError::Unsupported),
        })
    }
    fn value(&mut self, depth: u8) -> Result<Value, CborError> {
        if depth > 16 {
            return Err(CborError::TooDeep);
        }
        let b = self.take(1)?[0];
        let (major, info) = (b >> 5, b & 31);
        match major {
            0 => {
                let n = self.arg(info)?;
                i64::try_from(n).map(Value::Int).map_err(|_| CborError::Unsupported)
            }
            1 => {
                let n = self.arg(info)?;
                i64::try_from(n)
                    .map(|n| Value::Int(-1 - n))
                    .map_err(|_| CborError::Unsupported)
            }
            2 | 3 => {
                let n = self.arg(info)? as usize;
                let s = self.take(n)?;
                if major == 2 {
                    Ok(Value::Bytes(s.to_vec()))
                } else {
                    core::str::from_utf8(s)
                        .map(|t| Value::Text(t.to_string()))
                        .map_err(|_| CborError::InvalidUtf8)
                }
            }
            4 => {
                let n = self.arg(info)? as usize;
                if n > self.d.len() - self.pos {
                    return Err(CborError::Truncated);
                }
                let mut a = Vec::with_capacity(n);
                for _ in 0..n {
                    a.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(a))
            }
            5 => {
                let n = self.arg(info)? as usize;
                if n > self.d.len() - self.pos {
                    return Err(CborError::Truncated);
                }
                let mut m = Vec::with_capacity(n);
                for _ in 0..n {
                    let k = self.value(depth + 1)?;
                    let v = self.value(depth + 1)?;
                    m.push((k, v));
                }
                Ok(Value::Map(m))
            }
            7 => match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 | 23 => Ok(Value::Null),
                _ => Err(CborError::Unsupported),
            },
            _ => Err(CborError::Unsupported),
        }
    }
}

/// Decode exactly one item; trailing bytes are an error.
pub fn decode(d: &[u8]) -> Result<Value, CborError> {
    let mut r = Reader { d, pos: 0 };
    let v = r.value(0)?;
    if r.pos != d.len() {
        return Err(CborError::TrailingData);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8949_examples() {
        assert_eq!(encode(&Value::Int(0)), [0x00]);
        assert_eq!(encode(&Value::Int(1000)), [0x19, 0x03, 0xe8]);
        assert_eq!(encode(&Value::Int(-100)), [0x38, 0x63]);
        assert_eq!(encode(&Value::text("IETF")), [0x64, 0x49, 0x45, 0x54, 0x46]);
        let m = Value::Map(vec![
            (Value::Int(-2), Value::Int(1)),
            (Value::Int(3), Value::Int(1)),
            (Value::Int(1), Value::Int(1)),
            (Value::Int(-1), Value::Int(1)),
        ]);
        let e = encode(&m);
        assert_eq!(e, [0xa4, 0x01, 0x01, 0x03, 0x01, 0x20, 0x01, 0x21, 0x01]);
        assert_eq!(decode(&e).unwrap().get(-2), Some(&Value::Int(1)));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(decode(&[0x18]), Err(CborError::Truncated));
        assert_eq!(decode(&[0x00, 0x00]), Err(CborError::TrailingData));
        assert_eq!(decode(&[0xf9, 0, 0]), Err(CborError::Unsupported));
    }
}
