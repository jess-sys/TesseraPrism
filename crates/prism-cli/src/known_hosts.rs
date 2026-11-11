//! `~/.ssh/known_hosts` lookup: map a server host key blob to a host name (for approval prompts).
//!
//! Plain entries (`host1,host2 ssh-ed25519 AAAA…`) are matched by key and the first literal
//! host name is returned. Hashed entries (`|1|salt|HMAC-SHA1(salt, host)`) cannot be reversed from
//! the key alone, so they are only resolved for *candidate* host names (names from `~/.ssh/config`
//! plus a few well-known forges).

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::path::Path;

pub const DEFAULT_CANDIDATES: &[&str] = &["github.com", "gitlab.com", "bitbucket.org", "ssh.dev.azure.com", "git.sr.ht", "codeberg.org"];

/// Does the hashed pattern `|1|salt|hash` match `host`?
pub fn hashed_matches(pattern: &str, host: &str) -> bool {
    let Some(rest) = pattern.strip_prefix("|1|") else { return false };
    let Some((salt, hash)) = rest.split_once('|') else { return false };
    let (Ok(salt), Ok(hash)) = (B64.decode(salt), B64.decode(hash)) else { return false };
    let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(&salt) else { return false };
    mac.update(host.as_bytes());
    mac.verify_slice(&hash).is_ok()
}

fn clean_host(p: &str) -> String {
    // `[host]:port` -> host
    if let Some(r) = p.strip_prefix('[') {
        if let Some((h, _)) = r.split_once("]:") {
            return h.to_string();
        }
    }
    p.to_string()
}

/// Find the host name for `hostkey_blob` in `known_hosts` text.
pub fn lookup(known_hosts: &str, hostkey_blob: &[u8], candidates: &[String]) -> Option<String> {
    let mut hashed_hit = false;
    let mut hashed_patterns: Vec<&str> = vec![];
    for line in known_hosts.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
            continue; // markers (@cert-authority, @revoked) are not host-key identity
        }
        let mut it = line.split_whitespace();
        let (Some(hosts), Some(_ty), Some(b64)) = (it.next(), it.next(), it.next()) else { continue };
        let Ok(blob) = B64.decode(b64) else { continue };
        if blob != hostkey_blob {
            continue;
        }
        if hosts.starts_with("|1|") {
            hashed_hit = true;
            hashed_patterns.push(hosts);
            continue;
        }
        for p in hosts.split(',') {
            if p.is_empty() || p.starts_with('!') || p.contains('*') || p.contains('?') {
                continue;
            }
            return Some(clean_host(p));
        }
    }
    if hashed_hit {
        for c in candidates {
            if hashed_patterns.iter().any(|p| hashed_matches(p, c) || hashed_matches(p, &format!("[{c}]:22"))) {
                return Some(c.clone());
            }
        }
    }
    None
}

/// Literal host names / HostName values from an ssh_config.
pub fn config_candidates(ssh_config: &str) -> Vec<String> {
    let mut out = vec![];
    for line in ssh_config.lines() {
        let line = line.trim();
        let mut it = line.splitn(2, |c: char| c.is_whitespace() || c == '=');
        let (Some(k), Some(v)) = (it.next(), it.next()) else { continue };
        if k.eq_ignore_ascii_case("host") || k.eq_ignore_ascii_case("hostname") {
            for h in v.trim().trim_start_matches('=').split_whitespace() {
                if !h.contains(['*', '?', '!']) && !out.iter().any(|x| x == h) {
                    out.push(h.to_string());
                }
            }
        }
    }
    out
}

/// Resolve using the user's real files (`~/.ssh/known_hosts`, `~/.ssh/config`).
pub fn lookup_in_home(hostkey_blob: &[u8]) -> Option<String> {
    let ssh = dirs::home_dir()?.join(".ssh");
    resolve_with(&ssh, hostkey_blob)
}

pub fn resolve_with(ssh_dir: &Path, hostkey_blob: &[u8]) -> Option<String> {
    let kh = std::fs::read_to_string(ssh_dir.join("known_hosts")).ok()?;
    let mut cands = std::fs::read_to_string(ssh_dir.join("config")).map(|c| config_candidates(&c)).unwrap_or_default();
    cands.extend(DEFAULT_CANDIDATES.iter().map(|s| s.to_string()));
    lookup(&kh, hostkey_blob, &cands)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hashed(salt: &[u8], host: &str) -> String {
        let mut mac = Hmac::<Sha1>::new_from_slice(salt).unwrap();
        mac.update(host.as_bytes());
        format!("|1|{}|{}", B64.encode(salt), B64.encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn hashed_and_plain() {
        let key = b"\0\0\0\x0bssh-ed25519\0\0\0\x20AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let other = b"other-key";
        let b64 = B64.encode(key);
        let kh = format!(
            "# comment\n\
             @cert-authority *.corp ssh-ed25519 {b64}\n\
             {h} ssh-ed25519 {b64} user@x\n\
             [git.example.org]:2222,10.0.0.1 ssh-ed25519 {b64}\n\
             {o} ssh-ed25519 {ob}\n",
            h = hashed(b"0123456789abcdefghij", "github.com"),
            o = hashed(b"salt-salt-salt-salt-", "secret.example"),
            ob = B64.encode(other),
        );
        let cands = vec!["gitlab.com".to_string(), "github.com".to_string()];
        // Hashed line comes first but plain match is preferred only if encountered first; here the
        // hashed one is first in the file yet plain is found by the same scan.
        assert_eq!(lookup(&kh, key, &cands), Some("git.example.org".into()));
        // Only hashed entry present
        let only: String = kh.lines().filter(|l| !l.contains("git.example.org")).collect::<Vec<_>>().join("\n");
        assert_eq!(lookup(&only, key, &cands), Some("github.com".into()));
        assert_eq!(lookup(&only, key, &["nope.com".to_string()]), None);
        assert_eq!(lookup(&kh, b"unknown", &cands), None);
        assert_eq!(lookup(&only, other, &["secret.example".to_string()]), Some("secret.example".into()));
    }

    #[test]
    fn hashed_matches_direct() {
        let p = hashed(b"saltsaltsaltsaltsalt", "example.com");
        assert!(hashed_matches(&p, "example.com"));
        assert!(!hashed_matches(&p, "example.org"));
        assert!(!hashed_matches("plain", "example.org"));
    }

    #[test]
    fn config_hosts() {
        let c = "Host *\n  User x\nHost foo bar.example *.wild\n  HostName 1.2.3.4\nHostName=baz.io\n";
        assert_eq!(config_candidates(c), vec!["foo", "bar.example", "1.2.3.4", "baz.io"]);
    }
}
