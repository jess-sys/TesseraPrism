#![allow(dead_code)]
use async_trait::async_trait;
use clap::Parser;
use prism_cli::{run, Cli, Connector, Env, Prompter};
use prism_client::fake::FakeDevice;
use prism_client::{Config, Paths, Transport};
use std::io::Write;
use std::sync::{Arc, Mutex};

pub struct FakeConnector(pub FakeDevice);
#[async_trait]
impl Connector for FakeConnector {
    async fn open(&self, _cfg: &mut Config) -> prism_client::Result<Box<dyn Transport>> {
        Ok(Box::new(self.0.connect()))
    }
}

pub struct Fixed(pub String);
impl Prompter for Fixed {
    fn secret(&self, _p: &str, _k: &str) -> anyhow::Result<String> {
        Ok(self.0.clone())
    }
}

#[derive(Clone, Default)]
pub struct Buf(pub Arc<Mutex<Vec<u8>>>);
impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Buf {
    pub fn take(&self) -> String {
        String::from_utf8(std::mem::take(&mut *self.0.lock().unwrap())).unwrap()
    }
}

pub struct Rig {
    pub dev: FakeDevice,
    pub env: Arc<Env>,
    pub out: Buf,
    pub _dir: tempfile::TempDir,
}

pub fn rig(secret: &str) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let dev = FakeDevice::new();
    let out = Buf::default();
    let mut env = Env::new(Box::new(FakeConnector(dev.clone())), Paths::at(dir.path().join("cfg")));
    env.prompter = Box::new(Fixed(secret.into()));
    env.out = Mutex::new(Box::new(out.clone()));
    Rig { dev, env: Arc::new(env), out, _dir: dir }
}

impl Rig {
    pub async fn prism(&self, args: &[&str]) -> anyhow::Result<String> {
        let mut v = vec!["prism"];
        v.extend_from_slice(args);
        run(Cli::try_parse_from(v)?, &self.env).await?;
        Ok(self.out.take())
    }
}
