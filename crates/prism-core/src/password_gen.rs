//! Password and passphrase generators.

use crate::bip39::wordlist;
use crate::{Error, Result};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/";
const AMBIGUOUS: &str = "O0oIl1|`'\"";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordOptions {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self { length: 20, lower: true, upper: true, digits: true, symbols: true, exclude_ambiguous: false }
    }
}

/// Uniform in 0..n via rejection sampling.
fn below(rng: &mut dyn CryptoRngCore, n: usize) -> usize {
    assert!(n > 0 && n <= u32::MAX as usize);
    let n = n as u32;
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let v = rng.next_u32();
        if v < zone {
            return (v % n) as usize;
        }
    }
}

/// Generates a password containing at least one char of each enabled class.
pub fn generate_password(opts: &PasswordOptions, rng: &mut dyn CryptoRngCore) -> Result<Zeroizing<String>> {
    let mut sets: Vec<Vec<char>> = Vec::new();
    for (on, s) in [(opts.lower, LOWER), (opts.upper, UPPER), (opts.digits, DIGITS), (opts.symbols, SYMBOLS)] {
        if on {
            let v: Vec<char> =
                s.chars().filter(|c| !(opts.exclude_ambiguous && AMBIGUOUS.contains(*c))).collect();
            if !v.is_empty() {
                sets.push(v);
            }
        }
    }
    if sets.is_empty() {
        return Err(Error::Invalid("no character set selected"));
    }
    if opts.length < sets.len() || opts.length > 1024 {
        return Err(Error::Invalid("bad password length"));
    }
    let all: Vec<char> = sets.iter().flatten().copied().collect();
    let mut chars: Vec<char> = sets.iter().map(|s| s[below(rng, s.len())]).collect();
    while chars.len() < opts.length {
        chars.push(all[below(rng, all.len())]);
    }
    // Fisher-Yates
    for i in (1..chars.len()).rev() {
        chars.swap(i, below(rng, i + 1));
    }
    let out: String = chars.iter().collect();
    chars.iter_mut().for_each(|c| *c = '\0');
    Ok(Zeroizing::new(out))
}

/// Diceware-like passphrase from the BIP39 English list (11 bits per word).
pub fn generate_passphrase(words: usize, separator: &str, rng: &mut dyn CryptoRngCore) -> Result<Zeroizing<String>> {
    if !(1..=32).contains(&words) {
        return Err(Error::Invalid("word count must be 1-32"));
    }
    let wl = wordlist();
    let picked: Vec<&str> = (0..words).map(|_| wl[below(rng, wl.len())]).collect();
    Ok(Zeroizing::new(picked.join(separator)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn password_classes_and_length() {
        for _ in 0..50 {
            let p = generate_password(&PasswordOptions { length: 8, exclude_ambiguous: true, ..Default::default() }, &mut OsRng).unwrap();
            assert_eq!(p.chars().count(), 8);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
            assert!(!p.chars().any(|c| AMBIGUOUS.contains(c)));
        }
        let o = PasswordOptions { lower: false, upper: false, digits: false, symbols: false, ..Default::default() };
        assert!(generate_password(&o, &mut OsRng).is_err());
        let d = PasswordOptions { length: 30, lower: false, upper: false, symbols: false, ..Default::default() };
        assert!(generate_password(&d, &mut OsRng).unwrap().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn passphrase() {
        let p = generate_passphrase(6, "-", &mut OsRng).unwrap();
        assert_eq!(p.split('-').count(), 6);
        assert!(p.split('-').all(|w| wordlist().contains(&w)));
        assert!(generate_passphrase(0, "-", &mut OsRng).is_err());
    }
}
