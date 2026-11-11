//! RFC 4226 / 6238 TOTP, base32 and otpauth:// URIs.

use crate::model::{Totp, TotpAlgorithm};
use crate::{Error, Result};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Case-insensitive, ignores spaces/dashes/padding.
pub fn base32_decode(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.chars() {
        if c == ' ' || c == '-' || c == '=' {
            continue;
        }
        let c = c.to_ascii_uppercase();
        let v = B32.iter().position(|&b| b as char == c).ok_or(Error::Base32)? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

/// Unpadded uppercase base32.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
        buf &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn mac(algo: TotpAlgorithm, key: &[u8], msg: &[u8]) -> Zeroizing<Vec<u8>> {
    macro_rules! go {
        ($h:ty) => {{
            let mut m = <Hmac<$h> as Mac>::new_from_slice(key).expect("hmac any key len");
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }};
    }
    Zeroizing::new(match algo {
        TotpAlgorithm::Sha1 => go!(Sha1),
        TotpAlgorithm::Sha256 => go!(Sha256),
        TotpAlgorithm::Sha512 => go!(Sha512),
    })
}

/// RFC 4226 HOTP.
pub fn hotp(secret: &[u8], counter: u64, algo: TotpAlgorithm, digits: u8) -> String {
    let h = mac(algo, secret, &counter.to_be_bytes());
    let o = (h[h.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]]);
    let digits = digits.clamp(1, 10) as u32;
    let v = (bin as u64) % 10u64.pow(digits);
    format!("{:0width$}", v, width = digits as usize)
}

/// Current code for `unix` seconds.
pub fn code(t: &Totp, unix: u64) -> String {
    let period = t.period.max(1) as u64;
    hotp(&t.secret, unix / period, t.algorithm, t.digits)
}

/// Unix time at which the code valid at `unix` expires.
pub fn valid_until(t: &Totp, unix: u64) -> u64 {
    let period = t.period.max(1) as u64;
    (unix / period + 1) * period
}

fn pct_decode(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let h = s.get(i + 1..i + 3).ok_or_else(|| Error::Otpauth("bad escape".into()))?;
                out.push(u8::from_str_radix(h, 16).map_err(|_| Error::Otpauth("bad escape".into()))?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| Error::Otpauth("not utf-8".into()))
}

fn pct_encode(s: &str) -> String {
    let mut o = String::new();
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// Parse `otpauth://totp/Issuer:account?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30`.
pub fn parse_otpauth(uri: &str) -> Result<Totp> {
    let bad = |m: &str| Error::Otpauth(m.to_string());
    let rest = uri.trim().strip_prefix("otpauth://").ok_or_else(|| bad("missing scheme"))?;
    let rest = rest.strip_prefix("totp/").ok_or_else(|| bad("only totp supported"))?;
    let (label, query) = rest.split_once('?').ok_or_else(|| bad("missing query"))?;
    let label = pct_decode(label)?;
    let (mut label_issuer, account) = match label.split_once(':') {
        Some((i, a)) => (i.trim().to_string(), a.trim().to_string()),
        None => (String::new(), label.trim().to_string()),
    };
    let (mut secret, mut algorithm, mut digits, mut period) = (None, TotpAlgorithm::Sha1, 6u8, 30u32);
    for kv in query.split('&') {
        let Some((k, v)) = kv.split_once('=') else { continue };
        let v = pct_decode(v)?;
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(base32_decode(&v)?),
            "issuer" => label_issuer = v,
            "algorithm" => {
                algorithm = match v.to_ascii_uppercase().as_str() {
                    "SHA1" => TotpAlgorithm::Sha1,
                    "SHA256" => TotpAlgorithm::Sha256,
                    "SHA512" => TotpAlgorithm::Sha512,
                    _ => return Err(bad("unknown algorithm")),
                }
            }
            "digits" => digits = v.parse().map_err(|_| bad("bad digits"))?,
            "period" => period = v.parse().map_err(|_| bad("bad period"))?,
            _ => {}
        }
    }
    let secret = secret.ok_or_else(|| bad("missing secret"))?;
    if secret.is_empty() {
        return Err(bad("empty secret"));
    }
    if !(6..=8).contains(&digits) {
        return Err(bad("digits must be 6-8"));
    }
    if period == 0 {
        return Err(bad("period must be > 0"));
    }
    Ok(Totp { issuer: label_issuer, account, secret, algorithm, digits, period })
}

/// Build an otpauth URI (contains the secret!).
pub fn build_otpauth(t: &Totp) -> String {
    let label = if t.issuer.is_empty() {
        pct_encode(&t.account)
    } else {
        format!("{}:{}", pct_encode(&t.issuer), pct_encode(&t.account))
    };
    let algo = match t.algorithm {
        TotpAlgorithm::Sha1 => "SHA1",
        TotpAlgorithm::Sha256 => "SHA256",
        TotpAlgorithm::Sha512 => "SHA512",
    };
    let mut u = format!(
        "otpauth://totp/{label}?secret={}&algorithm={algo}&digits={}&period={}",
        base32_encode(&t.secret),
        t.digits,
        t.period
    );
    if !t.issuer.is_empty() {
        u.push_str(&format!("&issuer={}", pct_encode(&t.issuer)));
    }
    u
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secret: &[u8], algorithm: TotpAlgorithm) -> Totp {
        Totp { issuer: String::new(), account: String::new(), secret: secret.to_vec(), algorithm, digits: 8, period: 30 }
    }

    #[test]
    fn rfc6238_appendix_b() {
        let s1 = b"12345678901234567890".to_vec();
        let s256 = b"12345678901234567890123456789012".to_vec();
        let s512 = b"1234567890123456789012345678901234567890123456789012345678901234".to_vec();
        let cases: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (ts, a, b, c) in cases {
            assert_eq!(code(&t(&s1, TotpAlgorithm::Sha1), ts), a);
            assert_eq!(code(&t(&s256, TotpAlgorithm::Sha256), ts), b);
            assert_eq!(code(&t(&s512, TotpAlgorithm::Sha512), ts), c);
        }
    }

    #[test]
    fn rfc4226_hotp() {
        let exp = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
        for (i, e) in exp.iter().enumerate() {
            assert_eq!(hotp(b"12345678901234567890", i as u64, TotpAlgorithm::Sha1, 6), *e);
        }
    }

    #[test]
    fn base32_roundtrip() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("mzxw 6ytb oi======").unwrap(), b"foobar");
        assert!(base32_decode("1!").is_err());
        for n in 0..20u8 {
            let d: Vec<u8> = (0..n).collect();
            assert_eq!(base32_decode(&base32_encode(&d)).unwrap(), d);
        }
    }

    #[test]
    fn otpauth_roundtrip() {
        let u = "otpauth://totp/ACME%20Co:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60";
        let t = parse_otpauth(u).unwrap();
        assert_eq!(t.issuer, "ACME Co");
        assert_eq!(t.account, "john@example.com");
        assert_eq!((t.digits, t.period, t.algorithm), (8, 60, TotpAlgorithm::Sha256));
        assert_eq!(parse_otpauth(&build_otpauth(&t)).unwrap(), t);
        assert_eq!(valid_until(&t, 61), 120);
        assert!(parse_otpauth("otpauth://hotp/x?secret=AA").is_err());
        assert!(parse_otpauth("otpauth://totp/x").is_err());
    }
}
