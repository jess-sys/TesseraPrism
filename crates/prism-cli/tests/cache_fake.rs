mod common;
use common::rig;
use prism_cli::cache::MemoryKeyStore;
use std::sync::Arc;

async fn rig_with_keys(secret: &str) -> common::Rig {
    let mut r = rig(secret);
    Arc::get_mut(&mut r.env).unwrap().keys = Box::new(MemoryKeyStore::default());
    r.prism(&["pair"]).await.unwrap();
    r
}

#[tokio::test]
async fn approvals_and_policy() {
    let r = rig_with_keys("pw1").await;
    r.prism(&["add", "password", "Bank", "--username", "bob"]).await.unwrap();
    let ls = r.prism(&["ls"]).await.unwrap();
    assert!(ls.contains("default (always)"), "{ls}");
    let t = r.prism(&["approvals"]).await.unwrap();
    assert!(t.contains("password") && t.contains("always"), "{t}");
    r.prism(&["approvals", "set", "password", "session"]).await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&r.prism(&["--json", "approvals"]).await.unwrap()).unwrap();
    assert_eq!(v["password"], "session");
    assert!(r.prism(&["approvals", "set", "passkey", "never"]).await.is_err());
    let ls = r.prism(&["ls"]).await.unwrap();
    assert!(ls.contains("default (session)"), "{ls}");
    r.prism(&["policy", "bank", "never"]).await.unwrap();
    let v: Vec<serde_json::Value> = serde_json::from_str(&r.prism(&["--json", "ls"]).await.unwrap()).unwrap();
    assert_eq!(v[0]["policy"], "Never");
    r.prism(&["policy", "bank", "default"]).await.unwrap();
    let v: Vec<serde_json::Value> = serde_json::from_str(&r.prism(&["--json", "ls"]).await.unwrap()).unwrap();
    assert_eq!(v[0]["effective_policy"], "session");
}

#[tokio::test]
async fn cache_sync_status_offline_clear() {
    let r = rig_with_keys("pw1").await;
    r.prism(&["add", "password", "Bank", "--username", "bob"]).await.unwrap();
    // Caching off on the device by default.
    let e = r.prism(&["cache", "sync"]).await.unwrap_err().to_string();
    assert!(e.contains("Password caching is off"), "{e}");
    assert!(r.prism(&["cache", "ttl", "bogus"]).await.is_err());
    r.prism(&["cache", "ttl", "1d"]).await.unwrap();
    assert_eq!(r.dev.settings().password_cache_secs, 86400);
    let out = r.prism(&["cache", "sync"]).await.unwrap();
    assert!(out.contains("Cached 1 passwords"), "{out}");
    let st: serde_json::Value = serde_json::from_str(&r.prism(&["--json", "cache", "status"]).await.unwrap()).unwrap();
    assert_eq!(st["count"], 1);
    assert_eq!(st["cached"], true);

    assert_eq!(r.prism(&["show", "bank", "--offline"]).await.unwrap().trim(), "pw1");
    assert_eq!(r.prism(&["show", "bank", "--offline", "--field", "username"]).await.unwrap().trim(), "bob");
    assert!(r.prism(&["show", "bank", "--offline", "--field", "notes"]).await.is_err());

    r.prism(&["cache", "clear"]).await.unwrap();
    let e = r.prism(&["show", "bank", "--offline"]).await.unwrap_err().to_string();
    assert!(e.contains("no local password cache"), "{e}");
}

struct Down;
#[async_trait::async_trait]
impl prism_cli::Connector for Down {
    async fn open(&self, _c: &mut prism_client::Config) -> prism_client::Result<Box<dyn prism_client::Transport>> {
        Err(prism_client::Error::NoDevice("unplugged".into()))
    }
}

#[tokio::test]
async fn show_falls_back_to_cache_when_device_down() {
    let mut r = rig_with_keys("pw1").await;
    r.prism(&["add", "password", "Bank", "--username", "bob"]).await.unwrap();
    r.prism(&["add", "totp", "--secret", "JBSWY3DPEHPK3PXP", "--title", "Plain"]).await.unwrap();
    // No cache yet: the original connection error surfaces.
    {
        Arc::get_mut(&mut r.env).unwrap().connector = Box::new(Down);
        assert!(r.prism(&["show", "bank"]).await.is_err());
    }
    Arc::get_mut(&mut r.env).unwrap().connector = Box::new(common::FakeConnector(r.dev.clone()));
    r.prism(&["cache", "ttl", "1h"]).await.unwrap();
    r.prism(&["cache", "sync"]).await.unwrap();
    Arc::get_mut(&mut r.env).unwrap().connector = Box::new(Down);
    assert_eq!(r.prism(&["show", "bank"]).await.unwrap().trim(), "pw1");
    // TOTP is never served from the cache.
    assert!(r.prism(&["show", "plain"]).await.is_err());
    assert!(r.prism(&["totp", "plain"]).await.is_err());
}

#[tokio::test]
async fn ttl_off_deletes_cache() {
    let r = rig_with_keys("pw1").await;
    r.prism(&["add", "password", "Bank", "--username", "bob"]).await.unwrap();
    r.prism(&["cache", "ttl", "1h"]).await.unwrap();
    r.prism(&["cache", "sync"]).await.unwrap();
    assert!(r.env.paths.dir.join("password-cache.bin").exists());
    r.prism(&["cache", "ttl", "off"]).await.unwrap();
    assert!(!r.env.paths.dir.join("password-cache.bin").exists());
}
