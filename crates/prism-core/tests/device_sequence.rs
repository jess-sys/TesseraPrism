//! Reproduces the on-device order: create (unhardened) -> unlock -> change_pin with a hardware
//! hardener -> seal -> set_recovery_passphrase -> seal -> verify passphrase against the sealed bytes.
use prism_core::slots::KdfParams;
use prism_core::{KekHardener, NoHardening, UnlockedVault};
use rand_core::OsRng;

struct Hw;
impl KekHardener for Hw {
    fn harden(&self, k: [u8; 32]) -> [u8; 32] {
        let mut o = k;
        for b in o.iter_mut() {
            *b ^= 0xA5;
        }
        o
    }
}

#[test]
fn recovery_passphrase_after_pin_hardening() {
    let (mut uv, _m) =
        UnlockedVault::create_with_params("123456", &NoHardening, KdfParams::TEST, KdfParams::TEST, &mut OsRng).unwrap();
    let bytes = uv.seal(&mut OsRng).unwrap();
    let mut uv = UnlockedVault::unlock_with_pin(&bytes, "123456", &NoHardening).unwrap();
    uv.change_pin("123456", &Hw, &mut OsRng).unwrap();
    let _bytes2 = uv.seal(&mut OsRng).unwrap();
    uv.set_recovery_passphrase("correct horse battery", &mut OsRng).unwrap();
    let bytes3 = uv.seal(&mut OsRng).unwrap();
    UnlockedVault::unlock_with_pin(&bytes3, "123456", &Hw).expect("PIN with hardener");
    UnlockedVault::unlock_with_passphrase(&bytes3, "correct horse battery").expect("recovery passphrase");
}

#[test]
fn verified_kdf_is_deterministic() {
    prism_core::slots::set_kdf_verify(true);
    let a = prism_core::slots::argon2_derive(b"pw", &[1u8; 16], &KdfParams::TEST).unwrap();
    let b = prism_core::slots::argon2_derive(b"pw", &[1u8; 16], &KdfParams::TEST).unwrap();
    prism_core::slots::set_kdf_verify(false);
    assert_eq!(*a, *b);
}
