use clap::Parser;
use prism_cli::{run, Cli, Env, RealConnector, TransportArg};
use prism_client::{Paths, TransportChoice, TransportPref};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let paths = Paths::default_dir();
    let cfg = paths.load_config().unwrap_or_default();
    let pref = match cli.transport {
        Some(TransportArg::Auto) => TransportPref::Auto,
        Some(TransportArg::Usb) => TransportPref::Usb,
        Some(TransportArg::Ble) => TransportPref::Ble,
        None => cfg.transport,
    };
    let choice = match pref {
        TransportPref::Auto if cli.port.is_none() => TransportChoice::Auto,
        TransportPref::Auto | TransportPref::Usb => TransportChoice::Usb(cli.port.clone()),
        TransportPref::Ble => TransportChoice::Ble,
    };
    let mut env = Env::new(Box::new(RealConnector(choice)), paths);
    env.time_sync = !cli.no_time_sync;
    if let Err(e) = run(cli, &Arc::new(env)).await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
