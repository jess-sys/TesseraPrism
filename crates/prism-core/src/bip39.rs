//! BIP39 24-word mnemonics <-> 32-byte master seed (entropy).

use crate::{Error, Result};
use zeroize::Zeroizing;

/// A 24-word English mnemonic. Zeroized on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct Mnemonic(Zeroizing<String>);

impl core::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Mnemonic(<redacted>)")
    }
}

impl Mnemonic {
    pub fn from_entropy(entropy: &[u8; 32]) -> Self {
        let m = ::bip39::Mnemonic::from_entropy(entropy).expect("32 bytes is valid entropy");
        Mnemonic(Zeroizing::new(m.to_string()))
    }

    /// Parse (whitespace/case tolerant) and validate checksum. Must be 24 words.
    pub fn parse(phrase: &str) -> Result<Self> {
        let m = ::bip39::Mnemonic::parse_in_normalized(::bip39::Language::English, phrase.trim())
            .map_err(|e| Error::Mnemonic(e.to_string()))?;
        if m.word_count() != 24 {
            return Err(Error::Mnemonic("expected 24 words".into()));
        }
        Ok(Mnemonic(Zeroizing::new(m.to_string())))
    }

    pub fn entropy(&self) -> Zeroizing<[u8; 32]> {
        let m = ::bip39::Mnemonic::parse_in_normalized(::bip39::Language::English, &self.0)
            .expect("validated");
        let (buf, len) = m.to_entropy_array();
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&buf[..len]);
        out
    }

    pub fn phrase(&self) -> &str {
        &self.0
    }

    pub fn words(&self) -> Vec<&str> {
        self.0.split(' ').collect()
    }
}

/// The 2048-word English list.
pub fn wordlist() -> &'static [&'static str; 2048] {
    ::bip39::Language::English.word_list()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vectors() {
        // Trezor reference vectors (24 words).
        let cases = [
            ("0000000000000000000000000000000000000000000000000000000000000000",
             "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"),
            ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
             "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
             "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"),
        ];
        for (h, p) in cases {
            let mut e = [0u8; 32];
            e.copy_from_slice(&hex::decode(h).unwrap());
            let m = Mnemonic::from_entropy(&e);
            assert_eq!(m.phrase(), p);
            assert_eq!(*Mnemonic::parse(p).unwrap().entropy(), e);
        }
    }

    #[test]
    fn rejects_bad() {
        assert!(Mnemonic::parse("abandon abandon").is_err());
        let bad = "abandon ".repeat(24);
        assert!(Mnemonic::parse(bad.trim()).is_err()); // bad checksum
        assert_eq!(wordlist().len(), 2048);
    }
}
