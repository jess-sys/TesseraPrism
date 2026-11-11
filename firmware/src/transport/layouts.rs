//! Pure (hardware independent) keyboard layout tables: character -> HID (modifier, keycode).
//!
//! HID keycodes are *positions* on a US keyboard; the host maps them through its own layout, so
//! the tables below describe which position (and modifier) yields a character on the given
//! layout. Unit tests: see the `tests` module.

use prism_core::model::KeyboardLayout;

pub const MOD_LSHIFT: u8 = 0x02;
/// Right Alt, a.k.a. AltGr.
pub const MOD_RALT: u8 = 0x40;

pub const KEY_ENTER: u8 = 0x28;
pub const KEY_TAB: u8 = 0x2b;
pub const KEY_SPACE: u8 = 0x2c;

/// One key press needed to produce a character.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stroke {
    pub modifier: u8,
    pub keycode: u8,
    /// Dead key: the host waits for another key; a Space press must follow to emit the accent itself.
    pub dead: bool,
}

const fn k(modifier: u8, keycode: u8) -> Option<Stroke> {
    Some(Stroke { modifier, keycode, dead: false })
}

const fn dead(modifier: u8, keycode: u8) -> Option<Stroke> {
    Some(Stroke { modifier, keycode, dead: true })
}

pub fn lookup(layout: KeyboardLayout, c: char) -> Option<Stroke> {
    match c {
        '\n' | '\r' => return k(0, KEY_ENTER),
        '\t' => return k(0, KEY_TAB),
        ' ' => return k(0, KEY_SPACE),
        _ => {}
    }
    match layout {
        KeyboardLayout::Us => us(c),
        KeyboardLayout::FrAzerty => fr_azerty(c),
    }
}

/// Position of a letter on the US layout (`a` = 0x04 ... `z` = 0x1d).
fn us_letter(c: char) -> u8 {
    0x04 + (c.to_ascii_lowercase() as u8 - b'a')
}

fn us(c: char) -> Option<Stroke> {
    let s = MOD_LSHIFT;
    match c {
        'a'..='z' => k(0, us_letter(c)),
        'A'..='Z' => k(s, us_letter(c)),
        '1'..='9' => k(0, 0x1e + (c as u8 - b'1')),
        '0' => k(0, 0x27),
        '!' => k(s, 0x1e),
        '@' => k(s, 0x1f),
        '#' => k(s, 0x20),
        '$' => k(s, 0x21),
        '%' => k(s, 0x22),
        '^' => k(s, 0x23),
        '&' => k(s, 0x24),
        '*' => k(s, 0x25),
        '(' => k(s, 0x26),
        ')' => k(s, 0x27),
        '-' => k(0, 0x2d),
        '_' => k(s, 0x2d),
        '=' => k(0, 0x2e),
        '+' => k(s, 0x2e),
        '[' => k(0, 0x2f),
        '{' => k(s, 0x2f),
        ']' => k(0, 0x30),
        '}' => k(s, 0x30),
        '\\' => k(0, 0x31),
        '|' => k(s, 0x31),
        ';' => k(0, 0x33),
        ':' => k(s, 0x33),
        '\'' => k(0, 0x34),
        '"' => k(s, 0x34),
        '`' => k(0, 0x35),
        '~' => k(s, 0x35),
        ',' => k(0, 0x36),
        '<' => k(s, 0x36),
        '.' => k(0, 0x37),
        '>' => k(s, 0x37),
        '/' => k(0, 0x38),
        '?' => k(s, 0x38),
        _ => None,
    }
}

/// French (France) AZERTY, ISO keyboard.
fn fr_azerty(c: char) -> Option<Stroke> {
    let s = MOD_LSHIFT;
    let g = MOD_RALT;
    match c {
        // Letters: A/Q, Z/W and M are swapped relative to QWERTY.
        'a' => k(0, 0x14),
        'A' => k(s, 0x14),
        'q' => k(0, 0x04),
        'Q' => k(s, 0x04),
        'z' => k(0, 0x1a),
        'Z' => k(s, 0x1a),
        'w' => k(0, 0x1d),
        'W' => k(s, 0x1d),
        'm' => k(0, 0x33),
        'M' => k(s, 0x33),
        'a'..='z' => k(0, us_letter(c)),
        'A'..='Z' => k(s, us_letter(c)),
        // Number row: digits need Shift.
        '1'..='9' => k(s, 0x1e + (c as u8 - b'1')),
        '0' => k(s, 0x27),
        '&' => k(0, 0x1e),
        'é' => k(0, 0x1f),
        '"' => k(0, 0x20),
        '\'' => k(0, 0x21),
        '(' => k(0, 0x22),
        '-' => k(0, 0x23),
        'è' => k(0, 0x24),
        '_' => k(0, 0x25),
        'ç' => k(0, 0x26),
        'à' => k(0, 0x27),
        // AltGr on the number row.
        '~' => dead(g, 0x1f),
        '#' => k(g, 0x20),
        '{' => k(g, 0x21),
        '[' => k(g, 0x22),
        '|' => k(g, 0x23),
        '`' => dead(g, 0x24),
        '\\' => k(g, 0x25),
        '@' => k(g, 0x27),
        // Right of the number row.
        ')' => k(0, 0x2d),
        '°' => k(s, 0x2d),
        ']' => k(g, 0x2d),
        '=' => k(0, 0x2e),
        '+' => k(s, 0x2e),
        '}' => k(g, 0x2e),
        '^' => dead(0, 0x2f),
        '$' => k(0, 0x30),
        '£' => k(s, 0x30),
        '¤' => k(g, 0x30),
        '*' => k(0, 0x32),
        'µ' => k(s, 0x32),
        'ù' => k(0, 0x34),
        '%' => k(s, 0x34),
        '²' => k(0, 0x35),
        ',' => k(0, 0x10),
        '?' => k(s, 0x10),
        ';' => k(0, 0x36),
        '.' => k(s, 0x36),
        ':' => k(0, 0x37),
        '/' => k(s, 0x37),
        '!' => k(0, 0x38),
        '§' => k(s, 0x38),
        '<' => k(0, 0x64),
        '>' => k(s, 0x64),
        '€' => k(g, 0x08),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use KeyboardLayout::{FrAzerty, Us};

    #[test]
    fn us_basics() {
        assert_eq!(lookup(Us, 'a'), k(0, 0x04));
        assert_eq!(lookup(Us, 'Z'), k(MOD_LSHIFT, 0x1d));
        assert_eq!(lookup(Us, '0'), k(0, 0x27));
        assert_eq!(lookup(Us, '@'), k(MOD_LSHIFT, 0x1f));
        assert_eq!(lookup(Us, '~'), k(MOD_LSHIFT, 0x35));
        assert_eq!(lookup(Us, '\n'), k(0, KEY_ENTER));
        assert_eq!(lookup(Us, 'é'), None);
    }

    #[test]
    fn us_all_printable_ascii_mapped() {
        for c in (0x20u8..0x7f).map(|b| b as char) {
            assert!(lookup(Us, c).is_some(), "US missing {c:?}");
        }
    }

    #[test]
    fn azerty_all_printable_ascii_mapped() {
        for c in (0x20u8..0x7f).map(|b| b as char) {
            assert!(lookup(FrAzerty, c).is_some(), "AZERTY missing {c:?}");
        }
    }

    #[test]
    fn azerty_altgr_symbols() {
        for (c, key) in [('@', 0x27), ('#', 0x20), ('{', 0x21), ('[', 0x22), ('|', 0x23), ('\\', 0x25), (']', 0x2d), ('}', 0x2e), ('€', 0x08)] {
            let s = lookup(FrAzerty, c).unwrap();
            assert_eq!((s.modifier, s.keycode, s.dead), (MOD_RALT, key, false), "{c:?}");
        }
        let t = lookup(FrAzerty, '~').unwrap();
        assert!(t.dead && t.modifier == MOD_RALT && t.keycode == 0x1f);
    }

    #[test]
    fn azerty_swaps_and_digits() {
        assert_eq!(lookup(FrAzerty, 'a'), k(0, 0x14));
        assert_eq!(lookup(FrAzerty, 'q'), k(0, 0x04));
        assert_eq!(lookup(FrAzerty, 'm'), k(0, 0x33));
        assert_eq!(lookup(FrAzerty, '1'), k(MOD_LSHIFT, 0x1e));
        assert_eq!(lookup(FrAzerty, '.'), k(MOD_LSHIFT, 0x36));
    }

    #[test]
    fn azerty_letters_are_a_bijection() {
        let mut seen = std::collections::HashSet::new();
        for c in 'a'..='z' {
            let s = lookup(FrAzerty, c).unwrap();
            assert!(seen.insert(s.keycode), "duplicate position for {c}");
        }
    }
}
