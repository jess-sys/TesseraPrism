mod common;
use common::rig;
use prism_core::model::*;

#[tokio::test]
async fn full_cli_flow() {
    let r = rig("hunter2-pass");
    // Not paired + not in pairing mode -> fails; first, pair.
    let out = r.prism(&["pair"]).await.unwrap();
    assert!(out.contains("Verification code:"), "{out}");
    assert!(out.contains("Paired as"), "{out}");
    let cfg = r.env.paths.load_config().unwrap();
    assert_eq!(cfg.pinned_device(), Some(r.dev.device_pubkey()));
    assert_eq!(r.dev.paired_hosts().len(), 1);

    // every command syncs time
    r.prism(&["info"]).await.unwrap();
    assert!(r.dev.time().is_some());
    let info = r.prism(&["--json", "info"]).await.unwrap();
    assert_eq!(serde_json::from_str::<serde_json::Value>(&info).unwrap()["battery_pct"], 87);

    // passwords
    r.prism(&["add", "password", "GitHub", "--username", "alice", "--generate", "--length", "30"]).await.unwrap();
    r.prism(&["add", "password", "Bank", "--username", "bob"]).await.unwrap(); // prompted: "hunter2-pass"
    let pw = r.prism(&["show", "bank"]).await.unwrap();
    assert_eq!(pw.trim(), "hunter2-pass");
    let gh = r.prism(&["show", "GitHub", "--field", "password"]).await.unwrap();
    assert_eq!(gh.trim().len(), 30);
    let user = r.prism(&["--json", "show", "bank", "--field", "username"]).await.unwrap();
    assert_eq!(serde_json::from_str::<serde_json::Value>(&user).unwrap()["value"], "bob");

    // totp
    r.prism(&["add", "totp", "otpauth://totp/Ex:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Ex"]).await.unwrap();
    r.prism(&["add", "totp", "--secret", "JBSWY3DPEHPK3PXP", "--title", "Plain"]).await.unwrap();
    let code = r.prism(&["--json", "totp", "plain"]).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&code).unwrap();
    assert_eq!(v["code"].as_str().unwrap().len(), 6);

    // recovery
    let f = r._dir.path().join("codes.txt");
    std::fs::write(&f, "# codes\nAAAA-1111\n\nBBBB-2222\n").unwrap();
    r.prism(&["add", "recovery", "Google", "--file", f.to_str().unwrap()]).await.unwrap();
    let codes = r.prism(&["show", "google"]).await.unwrap();
    assert_eq!(codes.trim(), "AAAA-1111\nBBBB-2222");

    // ls
    let ls = r.prism(&["--json", "ls"]).await.unwrap();
    let arr: Vec<serde_json::Value> = serde_json::from_str(&ls).unwrap();
    assert_eq!(arr.len(), 5);
    let ls = r.prism(&["ls", "--kind", "totp"]).await.unwrap();
    assert!(ls.contains("Plain") && !ls.contains("Bank"), "{ls}");

    // ssh
    let pk = r.prism(&["ssh-gen", "laptop", "--comment", "me@laptop"]).await.unwrap();
    assert!(pk.starts_with("ssh-ed25519 "), "{pk}");
    let again = r.prism(&["ssh-pubkey", "laptop"]).await.unwrap();
    assert_eq!(pk.trim(), again.trim());

    // export / import / rm (fixed prompter doubles as the recovery passphrase)
    assert!(r.prism(&["export", "/nonexistent-dir/x"]).await.is_err()); // wrong passphrase on device
    r.prism(&["recovery-passphrase", "set"]).await.unwrap();
    let ex = r._dir.path().join("backup.prism");
    r.prism(&["export", ex.to_str().unwrap()]).await.unwrap();
    assert!(std::fs::read(&ex).unwrap().starts_with(b"PRSMEXP1"));
    r.prism(&["rm", "bank"]).await.unwrap();
    assert!(r.prism(&["show", "bank"]).await.is_err());
    assert_eq!(r.dev.entries().len(), 5);
    r.prism(&["import", ex.to_str().unwrap(), "--merge"]).await.unwrap();
    assert_eq!(r.dev.entries().len(), 6);
    let j = r.prism(&["--json", "show", "google"]).await.unwrap();
    assert_eq!(serde_json::from_str::<serde_json::Value>(&j).unwrap()["codes"][1]["used"], false);

    // settings
    r.prism(&["settings", "set", "auto-lock-secs", "90"]).await.unwrap();
    assert_eq!(r.dev.settings().auto_lock_secs, 90);
    r.prism(&["settings", "set", "keyboard-layout", "fr-azerty"]).await.unwrap();
    assert_eq!(r.dev.settings().keyboard_layout, KeyboardLayout::FrAzerty);
    assert!(r.prism(&["settings", "set", "bogus", "1"]).await.is_err());
    let s = r.prism(&["--json", "settings", "get"]).await.unwrap();
    assert_eq!(serde_json::from_str::<serde_json::Value>(&s).unwrap()["auto-lock-secs"], 90);

    // hosts
    let h = r.prism(&["hosts", "ls"]).await.unwrap();
    assert!(h.contains("fake-host"));
    r.prism(&["hosts", "rm", "0"]).await.unwrap();
    assert!(r.dev.paired_hosts().is_empty());
    assert!(r.prism(&["info"]).await.is_err()); // no longer paired
}

#[tokio::test]
async fn import_with_right_passphrase_and_pin_mismatch() {
    let r = rig(prism_client::fake::FAKE_PASSPHRASE);
    r.prism(&["pair"]).await.unwrap();
    r.prism(&["add", "password", "A", "--generate"]).await.unwrap();
    let ex = r._dir.path().join("b.prism");
    r.prism(&["export", ex.to_str().unwrap()]).await.unwrap();
    r.prism(&["rm", "A"]).await.unwrap();
    assert_eq!(r.dev.entries().len(), 0);
    r.prism(&["import", ex.to_str().unwrap(), "--merge"]).await.unwrap();
    assert_eq!(r.dev.entries().len(), 1);

    // a different device (pinned key mismatch) must be refused
    let other = rig("x");
    let mut cfg = r.env.paths.load_config().unwrap();
    cfg.pin_device(&[1; 32]);
    r.env.paths.save_config(&cfg).unwrap();
    let e = r.prism(&["info"]).await.unwrap_err();
    assert!(format!("{e:#}").contains("pinned"), "{e:#}");
    drop(other);
}

#[tokio::test]
async fn ssh_import_plain_and_encrypted() {
    if std::process::Command::new("ssh-keygen").arg("-?").output().is_err() {
        eprintln!("ssh-keygen not available; skipping");
        return;
    }
    let r = rig("sekrit-pass");
    r.prism(&["pair"]).await.unwrap();
    for (name, pass) in [("plain", ""), ("enc", "sekrit-pass")] {
        let path = r._dir.path().join(name);
        let st = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-C", "test@host", "-N", pass, "-f", path.to_str().unwrap()])
            .status()
            .unwrap();
        assert!(st.success());
        r.prism(&["add", "ssh-import", path.to_str().unwrap()]).await.unwrap();
        let want = std::fs::read_to_string(format!("{}.pub", path.display())).unwrap();
        let got = r.prism(&["ssh-pubkey", name]).await.unwrap();
        let w: Vec<&str> = want.split_whitespace().collect();
        let g: Vec<&str> = got.split_whitespace().collect();
        assert_eq!(w[1], g[1], "public key must match for {name}");
        assert_eq!(g[2], "test@host");
    }
    // RSA is rejected
    let path = r._dir.path().join("rsa");
    let st = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ecdsa", "-N", "", "-f", path.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(st.success());
    let e = r.prism(&["add", "ssh-import", path.to_str().unwrap()]).await.unwrap_err();
    assert!(format!("{e}").contains("Ed25519"), "{e}");
    assert!(matches!(r.dev.entries().iter().find(|e| e.title == "enc").unwrap().data, EntryData::SshKey(_)));
}
