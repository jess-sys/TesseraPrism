mod common;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use common::rig;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use prism_cli::agent::{self, Agent};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

async fn xfer(s: &mut UnixStream, msg: &[u8]) -> Vec<u8> {
    s.write_all(&(msg.len() as u32).to_be_bytes()).await.unwrap();
    s.write_all(msg).await.unwrap();
    let mut l = [0u8; 4];
    s.read_exact(&mut l).await.unwrap();
    let mut b = vec![0u8; u32::from_be_bytes(l) as usize];
    s.read_exact(&mut b).await.unwrap();
    b
}
fn string(out: &mut Vec<u8>, d: &[u8]) {
    out.extend_from_slice(&(d.len() as u32).to_be_bytes());
    out.extend_from_slice(d);
}
fn take_string<'a>(b: &mut &'a [u8]) -> &'a [u8] {
    let n = u32::from_be_bytes(b[..4].try_into().unwrap()) as usize;
    let s = &b[4..4 + n];
    *b = &b[4 + n..];
    s
}

#[tokio::test]
async fn agent_identities_sign_and_session_bind() {
    let r = rig("x");
    r.prism(&["pair"]).await.unwrap();
    let pk = r.prism(&["ssh-gen", "laptop", "--comment", "me@laptop"]).await.unwrap();
    let blob = B64.decode(pk.split_whitespace().nth(1).unwrap()).unwrap();

    // ssh dir with a known_hosts containing the "server" key under a plain name
    let ssh = r._dir.path().join("ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    let hostkey = b"fake-server-host-key-blob";
    std::fs::write(ssh.join("known_hosts"), format!("git.example.org ssh-ed25519 {}\n", B64.encode(hostkey))).unwrap();

    let sock = r._dir.path().join("agent.sock");
    let listener = agent::bind(&sock).unwrap();
    let ag = Agent::with_ssh_dir(r.env.clone(), ssh);
    let h = tokio::spawn(ag.serve(listener));

    let mut s = UnixStream::connect(&sock).await.unwrap();
    // identities
    let resp = xfer(&mut s, &[agent::REQUEST_IDENTITIES]).await;
    assert_eq!(resp[0], agent::IDENTITIES_ANSWER);
    assert_eq!(u32::from_be_bytes(resp[1..5].try_into().unwrap()), 1);
    let mut rest = &resp[5..];
    assert_eq!(take_string(&mut rest), blob.as_slice());
    assert_eq!(take_string(&mut rest), b"me@laptop");

    // session-bind
    let mut ext = vec![agent::EXTENSION];
    string(&mut ext, b"session-bind@openssh.com");
    string(&mut ext, hostkey);
    string(&mut ext, b"session-id");
    string(&mut ext, b"signature");
    ext.push(0);
    assert_eq!(xfer(&mut s, &ext).await, vec![agent::SUCCESS]);
    let mut unk = vec![agent::EXTENSION];
    string(&mut unk, b"query");
    assert_eq!(xfer(&mut s, &unk).await, vec![agent::FAILURE]);

    // sign (with rsa flags set: ignored)
    let data = b"data to be signed";
    let mut req = vec![agent::SIGN_REQUEST];
    string(&mut req, &blob);
    string(&mut req, data);
    req.extend_from_slice(&2u32.to_be_bytes());
    let resp = xfer(&mut s, &req).await;
    assert_eq!(resp[0], agent::SIGN_RESPONSE);
    let mut b = &resp[1..];
    let mut sigblob = take_string(&mut b);
    assert_eq!(take_string(&mut sigblob), b"ssh-ed25519");
    let sig = take_string(&mut sigblob);
    let mut pkb = &blob[..];
    take_string(&mut pkb);
    let vk = VerifyingKey::from_bytes(take_string(&mut pkb).try_into().unwrap()).unwrap();
    vk.verify(data, &Signature::from_slice(sig).unwrap()).unwrap();
    assert_eq!(r.dev.sign_hints(), vec![Some("git.example.org".to_string())]);

    // unknown key -> failure; garbage -> failure
    let mut bad = vec![agent::SIGN_REQUEST];
    string(&mut bad, b"nope");
    string(&mut bad, data);
    bad.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(xfer(&mut s, &bad).await, vec![agent::FAILURE]);
    assert_eq!(xfer(&mut s, &[99]).await, vec![agent::FAILURE]);

    // a second connection has no session-bind state
    let mut s2 = UnixStream::connect(&sock).await.unwrap();
    let mut req = vec![agent::SIGN_REQUEST];
    string(&mut req, &blob);
    string(&mut req, data);
    req.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(xfer(&mut s2, &req).await[0], agent::SIGN_RESPONSE);
    assert_eq!(r.dev.sign_hints().last().unwrap(), &None);
    h.abort();
}

#[tokio::test]
async fn agent_with_ssh_keygen() {
    if std::process::Command::new("ssh-keygen").arg("-?").output().is_err() {
        return;
    }
    let r = rig("x");
    r.prism(&["pair"]).await.unwrap();
    let pk = r.prism(&["ssh-gen", "laptop", "--comment", "me@laptop"]).await.unwrap();
    let pubfile = r._dir.path().join("id.pub");
    std::fs::write(&pubfile, &pk).unwrap();
    let sock = r._dir.path().join("a.sock");
    let listener = agent::bind(&sock).unwrap();
    let ag = Agent::with_ssh_dir(r.env.clone(), r._dir.path().join("none"));
    let h = tokio::spawn(ag.serve(listener));

    let msg = r._dir.path().join("msg.txt");
    std::fs::write(&msg, "hello prism").unwrap();
    let st = tokio::process::Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", "file", "-U", "-f"])
        .arg(&pubfile)
        .arg(&msg)
        .env("SSH_AUTH_SOCK", &sock)
        .output()
        .await
        .unwrap();
    assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stderr));
    let sigpem = std::fs::read_to_string(r._dir.path().join("msg.txt.sig")).unwrap();
    let sig = ssh_key::SshSig::from_pem(&sigpem).unwrap();
    let pubkey = ssh_key::PublicKey::from_openssh(&pk).unwrap();
    pubkey.verify("file", b"hello prism", &sig).unwrap();
    h.abort();
}
