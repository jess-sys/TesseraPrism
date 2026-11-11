//! `prism agent install/uninstall`: launchd (macOS) / systemd --user (Linux) service files.

use std::path::{Path, PathBuf};

pub const LAUNCHD_LABEL: &str = "dev.prism.agent";

pub fn launchd_plist(exe: &Path, socket: &Path, log: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
    <string>agent</string>
    <string>--socket</string>
    <string>{socket}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>{log}</string>
  <key>StandardOutPath</key><string>{log}</string>
</dict>
</plist>
"#,
        exe = xml(&exe.display().to_string()),
        socket = xml(&socket.display().to_string()),
        log = xml(&log.display().to_string()),
    )
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

pub fn systemd_unit(exe: &Path, socket: &Path) -> String {
    format!(
        "[Unit]\nDescription=Prism SSH agent\n\n[Service]\nType=simple\nExecStart={} agent --socket {}\nRestart=on-failure\nRestartSec=2\n\n[Install]\nWantedBy=default.target\n",
        exe.display(),
        socket.display()
    )
}

pub fn plist_path() -> Option<PathBuf> {
    Some(dirs::home_dir()?.join("Library/LaunchAgents").join(format!("{LAUNCHD_LABEL}.plist")))
}

pub fn unit_path() -> Option<PathBuf> {
    Some(dirs::config_dir()?.join("systemd/user/prism-agent.service"))
}

fn run(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
    let st = std::process::Command::new(cmd).args(args).status()?;
    anyhow::ensure!(st.success(), "`{cmd} {}` failed", args.join(" "));
    Ok(())
}

pub fn install(socket: &Path, load: bool) -> anyhow::Result<String> {
    let exe = std::env::current_exe()?;
    let mut msg = String::new();
    if cfg!(target_os = "macos") {
        let p = plist_path().ok_or_else(|| anyhow::anyhow!("no home directory"))?;
        std::fs::create_dir_all(p.parent().unwrap())?;
        let log = dirs::home_dir().unwrap().join("Library/Logs/prism-agent.log");
        std::fs::write(&p, launchd_plist(&exe, socket, &log))?;
        msg += &format!("Wrote {}\n", p.display());
        if load {
            run("launchctl", &["load", "-w", &p.display().to_string()])?;
            msg += "Loaded with launchctl.\n";
        } else {
            msg += &format!("Load it with: launchctl load -w {}\n", p.display());
        }
        msg += &format!(
            "Point ssh at the agent: add to ~/.ssh/config\n  Host *\n    IdentityAgent {0}\nor export SSH_AUTH_SOCK={0}\n(For GUI apps: launchctl setenv SSH_AUTH_SOCK {0})\n",
            socket.display()
        );
    } else {
        let p = unit_path().ok_or_else(|| anyhow::anyhow!("no config directory"))?;
        std::fs::create_dir_all(p.parent().unwrap())?;
        std::fs::write(&p, systemd_unit(&exe, socket))?;
        msg += &format!("Wrote {}\n", p.display());
        if load {
            run("systemctl", &["--user", "daemon-reload"])?;
            run("systemctl", &["--user", "enable", "--now", "prism-agent.service"])?;
            msg += "Enabled and started with systemctl --user.\n";
        } else {
            msg += "Enable it with: systemctl --user daemon-reload && systemctl --user enable --now prism-agent.service\n";
        }
        msg += &format!("Then: export SSH_AUTH_SOCK={}\n", socket.display());
    }
    Ok(msg)
}

pub fn uninstall(load: bool) -> anyhow::Result<String> {
    let mut msg = String::new();
    let (p, unload): (Option<PathBuf>, Box<dyn Fn(&Path) -> anyhow::Result<()>>) = if cfg!(target_os = "macos") {
        (plist_path(), Box::new(|p: &Path| run("launchctl", &["unload", "-w", &p.display().to_string()])))
    } else {
        (
            unit_path(),
            Box::new(|_: &Path| run("systemctl", &["--user", "disable", "--now", "prism-agent.service"])),
        )
    };
    let p = p.ok_or_else(|| anyhow::anyhow!("cannot determine service path"))?;
    if load {
        if let Err(e) = unload(&p) {
            msg += &format!("warning: unload failed: {e}\n");
        }
    }
    if p.exists() {
        std::fs::remove_file(&p)?;
        msg += &format!("Removed {}\n", p.display());
    } else {
        msg += &format!("{} not present\n", p.display());
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_render() {
        let p = launchd_plist(Path::new("/usr/local/bin/prism"), Path::new("/tmp/a&b.sock"), Path::new("/tmp/l.log"));
        assert!(p.contains("<string>dev.prism.agent</string>"));
        assert!(p.contains("/usr/local/bin/prism</string>"));
        assert!(p.contains("a&amp;b.sock"));
        let u = systemd_unit(Path::new("/usr/bin/prism"), Path::new("/run/user/1000/prism-agent.sock"));
        assert!(u.contains("ExecStart=/usr/bin/prism agent --socket /run/user/1000/prism-agent.sock"));
    }
}
