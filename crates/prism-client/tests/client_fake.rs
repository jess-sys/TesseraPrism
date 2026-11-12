use prism_client::fake::{FakeDevice, FAKE_PASSPHRASE};
use prism_client::{Client, ClientOptions, EstablishOutcome, Error, Paths};
use prism_core::model::*;
use prism_core::totp;
use prism_proto::generate_static_keypair;

fn pw_entry(title: &str) -> Entry {
    Entry {
        id: EntryId([title.len() as u8; 16]),
        title: title.into(),
        tags: vec![],
        created: 1,
        modified: 1,
        policy: ApprovalPolicy::Always,
        data: EntryData::Password(Password {
            username: "alice".into(),
            password: "s3cret".into(),
            url: None,
            notes: "n".into(),
            totp: None,
        }),
    }
}

async fn paired(dev: &FakeDevice) -> (Client, [u8; 32]) {
    let (hk, hp) = generate_static_keypair();
    let mut c = Client::connect(Box::new(dev.connect()), ClientOptions::new(hk)).await.unwrap();
    let mut sas = None;
    let out = c.establish(Some(&mut |s: &str| sas = Some(s.to_string()))).await.unwrap();
    assert!(matches!(out, EstablishOutcome::Paired { .. }));
    assert_eq!(sas.as_deref(), Some(c.sas()));
    assert_eq!(dev.sas_log(), vec![c.sas().to_string()]);
    (c, hp)
}

#[tokio::test]
async fn pair_then_reconnect_and_unknown_host_rejected() {
    let dev = FakeDevice::new();
    let (hk, hp) = generate_static_keypair();
    let mut c = Client::connect(Box::new(dev.connect()), ClientOptions::new(hk)).await.unwrap();
    assert_eq!(c.device_pubkey(), dev.device_pubkey());
    c.establish(None).await.unwrap();
    assert_eq!(dev.paired_hosts()[0].public_key, hp);
    drop(c);
    // reconnect: now "Ready"
    let mut c = Client::connect(Box::new(dev.connect()), ClientOptions::new(hk).pinned(Some(dev.device_pubkey()))).await.unwrap();
    assert!(matches!(c.establish(None).await.unwrap(), EstablishOutcome::Ready(_)));
    // different host, device not in pairing mode
    let (hk2, _) = generate_static_keypair();
    let mut c2 = Client::connect(Box::new(dev.connect()), ClientOptions::new(hk2)).await.unwrap();
    assert!(matches!(c2.establish(None).await, Err(Error::NotPaired)));
}

#[tokio::test]
async fn pinned_key_mismatch_rejected() {
    let dev = FakeDevice::new();
    let (hk, _) = generate_static_keypair();
    let err = Client::connect(Box::new(dev.connect()), ClientOptions::new(hk).pinned(Some([7; 32]))).await.err().unwrap();
    assert!(matches!(err, Error::DeviceKeyMismatch { .. }));
}

#[tokio::test]
async fn crud_secret_totp_ssh() {
    let dev = FakeDevice::new();
    let (mut c, _) = paired(&dev).await;
    c.sync_time().await.unwrap();
    assert!(dev.time().is_some());
    assert!(c.info().await.unwrap().time_valid);

    let id = c.add_entry(pw_entry("github")).await.unwrap();
    let list = c.list(None).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].title, "github");
    assert_eq!(c.list(Some(EntryKind::Totp)).await.unwrap().len(), 0);
    assert_eq!(c.get_secret(id, SecretField::Password, None).await.unwrap(), SecretValue::Text("s3cret".into()));

    // totp
    let t = totp::parse_otpauth("otpauth://totp/Ex:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Ex").unwrap();
    let tid = c
        .add_entry(Entry {
            id: EntryId([0xaa; 16]),
            title: "ex".into(),
            tags: vec![],
            created: 1,
            modified: 1,
            policy: ApprovalPolicy::Always,
            data: EntryData::Totp(t.clone()),
        })
        .await
        .unwrap();
    c.set_time(59).await.unwrap();
    let (code, until) = c.get_totp(tid).await.unwrap();
    assert_eq!(code, totp::code(&t, 59));
    assert_eq!(until, 60);

    // ssh
    let k = c.generate_ssh_key("laptop", "me@host", ApprovalPolicy::Never).await.unwrap();
    assert_eq!(c.ssh_list_keys().await.unwrap(), vec![k.clone()]);
    let sig = c.ssh_sign(&k.blob, b"hello", 0, Some("github.com".into())).await.unwrap();
    assert!(!sig.is_empty());
    assert_eq!(dev.sign_hints(), vec![Some("github.com".to_string())]);

    // delete, errors
    c.delete_entry(id).await.unwrap();
    assert!(matches!(c.delete_entry(id).await, Err(Error::Device(prism_proto::ErrorCode::NotFound))));
    dev.set_deny(true);
    assert!(matches!(c.get_secret(tid, SecretField::TotpSecret, None).await, Err(Error::Device(prism_proto::ErrorCode::Denied))));
    dev.set_deny(false);

    // lock / unlock
    c.lock().await.unwrap();
    assert!(matches!(c.list(None).await, Err(Error::Device(prism_proto::ErrorCode::Locked))));
    assert!(matches!(c.unlock("wrong").await, Err(Error::Device(prism_proto::ErrorCode::BadPassphrase))));
    c.unlock(FAKE_PASSPHRASE).await.unwrap();

    // settings, hosts
    let mut s = c.get_settings().await.unwrap();
    s.auto_lock_secs = 60;
    c.set_settings(s).await.unwrap();
    assert_eq!(dev.settings().auto_lock_secs, 60);
    let hosts = c.list_paired_hosts().await.unwrap();
    assert_eq!(hosts.len(), 1);
    c.rename_paired_host(hosts[0].public_key, "  Work laptop ").await.unwrap();
    assert_eq!(c.list_paired_hosts().await.unwrap()[0].label, "Work laptop");
    assert!(matches!(c.rename_paired_host(hosts[0].public_key, " ").await, Err(Error::Device(prism_proto::ErrorCode::InvalidRequest))));
    assert!(matches!(c.rename_paired_host([1; 32], "x").await, Err(Error::Device(prism_proto::ErrorCode::NotFound))));
}

#[tokio::test]
async fn export_import_roundtrip() {
    let dev = FakeDevice::new();
    let (mut c, _) = paired(&dev).await;
    for i in 0..60 {
        let mut e = pw_entry(&format!("entry-number-{i}"));
        e.id = EntryId([i as u8 + 1; 16]);
        if let EntryData::Password(p) = &mut e.data { p.notes = "x".repeat(300); }
        c.add_entry(e).await.unwrap();
    }
    let blob = c.export(FAKE_PASSPHRASE).await.unwrap();
    assert!(blob.len() > 8192, "export must span multiple chunks, was {}", blob.len());
    assert!(blob.starts_with(b"PRSMEXP1"));
    assert!(matches!(c.export("nope nope").await, Err(Error::Device(prism_proto::ErrorCode::BadPassphrase))));
    let full = c.get_entry(EntryId([1; 16])).await.unwrap();
    assert_eq!(full.title, "entry-number-0");
    c.set_recovery_passphrase("a new passphrase").await.unwrap();
    assert!(c.export(FAKE_PASSPHRASE).await.is_err());
    let blob2 = c.export("a new passphrase").await.unwrap();
    assert!(blob2.starts_with(b"PRSMEXP1"));
    c.set_recovery_passphrase(FAKE_PASSPHRASE).await.unwrap();

    // wipe two entries, then merge back
    c.delete_entry(EntryId([1; 16])).await.unwrap();
    c.delete_entry(EntryId([2; 16])).await.unwrap();
    assert_eq!(c.list(None).await.unwrap().len(), 58);
    assert!(matches!(
        c.import(&blob, "wrong", ImportMode::Merge).await,
        Err(Error::Device(prism_proto::ErrorCode::BadPassphrase))
    ));
    c.import(&blob, FAKE_PASSPHRASE, ImportMode::Merge).await.unwrap();
    assert_eq!(c.list(None).await.unwrap().len(), 60);
    c.import(&blob, FAKE_PASSPHRASE, ImportMode::Replace).await.unwrap();
    assert_eq!(dev.entries().len(), 60);
}

#[test]
fn host_key_and_config_persist() {
    let d = tempfile::tempdir().unwrap();
    let p = Paths::at(d.path().join("prism"));
    let k1 = p.load_or_create_host_key().unwrap();
    let k2 = p.load_or_create_host_key().unwrap();
    assert_eq!(k1, k2);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(p.host_key_file()).unwrap().permissions().mode();
        assert_eq!(m & 0o777, 0o600);
    }
    let mut cfg = p.load_config().unwrap();
    assert!(cfg.pinned_device().is_none());
    cfg.pin_device(&[9; 32]);
    cfg.last_ble_id = Some("abc".into());
    p.save_config(&cfg).unwrap();
    let cfg2 = p.load_config().unwrap();
    assert_eq!(cfg2.pinned_device(), Some([9; 32]));
    assert_eq!(cfg2.last_ble_id.as_deref(), Some("abc"));
}

#[tokio::test]
async fn list_passkeys_returns_public_identifiers_only() {
    let dev = FakeDevice::new();
    let (mut c, _) = paired(&dev).await;
    c.add_entry(pw_entry("github")).await.unwrap();
    c.add_entry(Entry {
        id: EntryId([0x5c; 16]),
        title: "example.org".into(),
        tags: vec![],
        created: 1,
        modified: 1,
        policy: ApprovalPolicy::Always,
        data: EntryData::Passkey(Passkey {
            rp_id: "example.org".into(),
            rp_name: "Example".into(),
            user_handle: vec![1, 2, 3],
            user_name: "alice@example.org".into(),
            user_display_name: "Alice".into(),
            credential_id: vec![9; 16],
            alg: CoseAlg::Es256,
            key_nonce: [7; 16],
            created: 1,
        }),
    })
    .await
    .unwrap();
    let pk = c.list_passkeys().await.unwrap();
    assert_eq!(
        pk,
        vec![PasskeyIdentity {
            id: EntryId([0x5c; 16]),
            rp_id: "example.org".into(),
            user_name: "alice@example.org".into(),
            user_handle: vec![1, 2, 3],
            credential_id: vec![9; 16],
        }]
    );
    c.lock().await.unwrap();
    assert!(matches!(c.list_passkeys().await, Err(Error::Device(prism_proto::ErrorCode::Locked))));
}

#[tokio::test]
async fn password_snapshot_and_entry_policy() {
    let dev = FakeDevice::new();
    let (mut c, _) = paired(&dev).await;
    c.sync_time().await.unwrap();
    let id = c.add_entry(pw_entry("github")).await.unwrap();
    c.add_entry(Entry { id: EntryId([0xaa; 16]), data: EntryData::Totp(totp::parse_otpauth("otpauth://totp/Ex:bob?secret=GEZDGNBVGY3TQOJQ&issuer=Ex").unwrap()), ..pw_entry("totp") })
        .await
        .unwrap();
    // Caching is off by default.
    assert!(matches!(c.password_snapshot().await, Err(Error::Device(prism_proto::ErrorCode::Unsupported))));
    let mut s = c.get_settings().await.unwrap();
    s.password_cache_secs = 3600;
    s.approvals.password = ApprovalPolicy::Session;
    c.set_settings(s).await.unwrap();
    let snap = c.password_snapshot().await.unwrap();
    assert_eq!(snap.entries.len(), 1, "passwords only");
    assert_eq!(snap.entries[0].password, "s3cret");
    assert_eq!(snap.expires_at - snap.generated_at, 3600);

    c.set_entry_policy(id, ApprovalPolicy::Default).await.unwrap();
    let e = c.list(None).await.unwrap().into_iter().find(|e| e.id == id).unwrap();
    assert_eq!(e.policy, ApprovalPolicy::Default);
    assert!(matches!(c.set_entry_policy(EntryId([3; 16]), ApprovalPolicy::Never).await, Err(Error::Device(prism_proto::ErrorCode::NotFound))));
}
