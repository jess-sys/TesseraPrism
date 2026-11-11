//! USB CDC framing: COBS-encoded frames terminated by a single `0x00`.

use crate::{Error, Result};

/// Max encoded size we accept (65535 + COBS overhead) before declaring an overlong frame.
const MAX_ENCODED: usize = 65535 + 65535 / 254 + 2;

/// COBS-encode `frame` and append the `0x00` delimiter.
pub fn encode(frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(frame.len() + frame.len() / 254 + 2);
    let mut code_idx = 0;
    out.push(0);
    let mut code = 1u8;
    for &b in frame {
        if b == 0 {
            out[code_idx] = code;
            code_idx = out.len();
            out.push(0);
            code = 1;
        } else {
            out.push(b);
            code += 1;
            if code == 0xff {
                out[code_idx] = code;
                code_idx = out.len();
                out.push(0);
                code = 1;
            }
        }
    }
    out[code_idx] = code;
    out.push(0);
    out
}

fn cobs_decode(src: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(src.len());
    let mut i = 0;
    while i < src.len() {
        let code = src[i] as usize;
        if code == 0 {
            return Err(Error::Cobs);
        }
        let end = i + code;
        if end > src.len() {
            return Err(Error::Cobs);
        }
        out.extend_from_slice(&src[i + 1..end]);
        i = end;
        if code != 0xff && i < src.len() {
            out.push(0);
        }
    }
    Ok(out)
}

/// Streaming decoder: feed arbitrary byte slices, get completed frames.
/// Empty frames (back-to-back delimiters) are ignored; malformed ones yield `Err`.
#[derive(Default, Debug)]
pub struct Decoder {
    buf: Vec<u8>,
    overflow: bool,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) -> Vec<Result<Vec<u8>>> {
        let mut out = Vec::new();
        for &b in bytes {
            if b == 0 {
                if self.overflow {
                    out.push(Err(Error::FrameTooLarge));
                } else if !self.buf.is_empty() {
                    out.push(cobs_decode(&self.buf));
                }
                self.buf.clear();
                self.overflow = false;
            } else if !self.overflow {
                if self.buf.len() >= MAX_ENCODED {
                    self.overflow = true;
                    self.buf.clear();
                } else {
                    self.buf.push(b);
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn known_vectors() {
        assert_eq!(encode(&[]), vec![1, 0]);
        assert_eq!(encode(&[0]), vec![1, 1, 0]);
        assert_eq!(encode(&[0, 0]), vec![1, 1, 1, 0]);
        assert_eq!(
            encode(&[0x11, 0x22, 0x00, 0x33]),
            vec![3, 0x11, 0x22, 2, 0x33, 0]
        );
        let ff: Vec<u8> = (1..=254).collect();
        let e = encode(&ff);
        assert_eq!(e[0], 0xff);
        assert_eq!(e.len(), 257);
    }

    proptest! {
        #[test]
        fn roundtrip_split(data in proptest::collection::vec(any::<u8>(), 1..2000),
                           splits in proptest::collection::vec(any::<usize>(), 0..8)) {
            let mut stream = encode(&data);
            stream.extend(encode(&[0, 1, 0]));
            let mut cuts: Vec<usize> = splits.iter().map(|s| s % (stream.len() + 1)).collect();
            cuts.sort();
            let mut d = Decoder::new();
            let mut frames = Vec::new();
            let mut prev = 0;
            for c in cuts.into_iter().chain([stream.len()]) {
                frames.extend(d.push(&stream[prev..c]));
                prev = c;
            }
            let frames: Vec<Vec<u8>> = frames.into_iter().map(|f| f.unwrap()).collect();
            prop_assert_eq!(frames, vec![data, vec![0, 1, 0]]);
        }

        #[test]
        fn no_zero_inside(data in proptest::collection::vec(any::<u8>(), 0..600)) {
            let e = encode(&data);
            prop_assert!(!e[..e.len()-1].contains(&0));
            prop_assert_eq!(*e.last().unwrap(), 0);
        }
    }

    #[test]
    fn long_runs_roundtrip() {
        for n in [253usize, 254, 255, 508, 1000, 65535] {
            let data = vec![7u8; n];
            let mut d = Decoder::new();
            let r = d.push(&encode(&data));
            assert_eq!(r.len(), 1);
            assert_eq!(r[0].as_ref().unwrap(), &data);
        }
    }
}
