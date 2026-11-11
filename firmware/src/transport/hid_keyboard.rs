//! USB HID boot-keyboard typing ("type password into the host").

use std::{sync::mpsc, thread, time::Duration};

use prism_core::model::KeyboardLayout;
use zeroize::{Zeroize, Zeroizing};

use super::{
    layouts::{self, KEY_SPACE},
    usb,
};

/// Delay after every report (key down and key up are separate reports): conservative for hosts
/// that poll slowly or drop fast keystrokes.
const REPORT_DELAY: Duration = Duration::from_millis(8);

pub struct TypeJob {
    pub text: Zeroizing<String>,
    pub layout: KeyboardLayout,
}

/// Spawn the typing thread.
pub fn spawn() -> anyhow::Result<mpsc::Sender<TypeJob>> {
    let (tx, rx) = mpsc::channel::<TypeJob>();
    thread::Builder::new().name("hid-kbd".into()).stack_size(6144).spawn(move || {
        while let Ok(job) = rx.recv() {
            type_text(&job.text, job.layout);
        }
    })?;
    Ok(tx)
}

fn press(modifier: u8, keycode: u8) -> bool {
    let mut report = [0u8; 8];
    report[0] = modifier;
    report[2] = keycode;
    let ok = usb::kbd_report(&report);
    thread::sleep(REPORT_DELAY);
    let ok = ok && usb::kbd_report(&[0u8; 8]);
    thread::sleep(REPORT_DELAY);
    report.zeroize();
    ok
}

fn type_text(text: &str, layout: KeyboardLayout) {
    if !usb::mounted() {
        log::warn!("hid: no USB host, TypeText dropped");
        return;
    }
    let mut skipped = 0usize;
    for c in text.chars() {
        match layouts::lookup(layout, c) {
            Some(s) => {
                if !press(s.modifier, s.keycode) {
                    log::warn!("hid: report send failed, aborting TypeText");
                    return;
                }
                if s.dead && !press(0, KEY_SPACE) {
                    return;
                }
            }
            None => skipped += 1,
        }
    }
    if skipped > 0 {
        // Never log the characters themselves: this is secret material.
        log::warn!("hid: {skipped} character(s) have no mapping in {layout:?} and were skipped");
    }
    let _ = usb::kbd_report(&[0u8; 8]);
}
