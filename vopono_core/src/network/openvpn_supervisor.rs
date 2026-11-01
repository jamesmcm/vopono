//! A namespace-local helper keeps a stable PID across OpenVPN child restarts.
//! Its immutable launch plan is written by the daemon beside frozen TLS inputs.
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

#[derive(Serialize, Deserialize)]
struct Plan {
    argv: Vec<String>,
    device: String,
}

pub(crate) fn prepare(argv: &[&str], runtime: &Path) -> anyhow::Result<Vec<String>> {
    let plan = runtime.join("supervisor.json");
    let config = argv
        .windows(2)
        .find(|args| args[0] == "--config")
        .context("Missing frozen OpenVPN configuration")?[1];
    let mut device = "tun0".to_owned();
    for line in fs::read_to_string(config)?.lines() {
        if let Ok(fields) = shell_words::split(line)
            && fields.first().is_some_and(|field| field == "dev")
            && let Some(value) = fields.get(1)
        {
            if value != "tun" {
                device = value.clone();
            }
            break;
        }
    }
    ensure!(
        device.starts_with("tun") && device[3..].bytes().all(|b| b.is_ascii_digit()),
        "Invalid frozen TUN device"
    );
    let mut command: Vec<String> = argv.iter().map(|s| (*s).to_owned()).collect();
    command.extend([
        "--dev".into(),
        device.clone(),
        "--dev-type".into(),
        "tun".into(),
    ]);
    fs::write(
        &plan,
        serde_json::to_vec(&Plan {
            argv: command,
            device,
        })?,
    )?;
    fs::set_permissions(&plan, fs::Permissions::from_mode(0o600))?;
    Ok(vec![
        std::env::current_exe()?
            .to_str()
            .context("Invalid helper path")?
            .to_owned(),
        "__openvpn-supervisor".into(),
        plan.to_str().context("Invalid runtime path")?.to_owned(),
    ])
}

fn spawn(plan: &Plan, runtime: &Path) -> anyhow::Result<Child> {
    let _ = fs::remove_file(runtime.join("child-exited"));
    // A killed DCO process can leave its kernel interface and routes behind.
    // Remove only this supervisor's fixed device, retaining the kill switch.
    let exists = Command::new("ip")
        .args(["link", "show", "dev", &plan.device])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if exists.success() {
        ensure!(
            Command::new("ip")
                .args(["link", "delete", "dev", &plan.device])
                .status()?
                .success(),
            "Could not remove obsolete OpenVPN device"
        );
    }
    let child = Command::new(&plan.argv[0])
        .args(&plan.argv[1..])
        .current_dir(runtime)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    fs::write(runtime.join("child.pid"), child.id().to_string())?;
    Ok(child)
}

fn terminate(child: &mut Child) {
    let group = nix::unistd::Pid::from_raw(-(child.id() as i32));
    let _ = nix::sys::signal::kill(group, nix::sys::signal::Signal::SIGTERM);
    for _ in 0..20 {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = nix::sys::signal::kill(group, nix::sys::signal::Signal::SIGKILL);
    let _ = child.wait();
}

/// Only invoked by the daemon's root helper inside the target namespace.
pub fn run(path: &Path) -> anyhow::Result<()> {
    ensure!(
        nix::unistd::geteuid().is_root(),
        "OpenVPN supervisor requires root"
    );
    let runtime = path
        .parent()
        .context("Missing runtime directory")?
        .canonicalize()?;
    let directory = fs::symlink_metadata(&runtime)?;
    let file = fs::symlink_metadata(path)?;
    ensure!(
        runtime.parent() == Some(Path::new("/run"))
            && runtime
                .file_name()
                .is_some_and(|s| s.as_encoded_bytes().starts_with(b"vopono-openvpn-"))
            && directory.uid() == 0
            && directory.mode() & 0o077 == 0
            && file.uid() == 0
            && file.is_file()
            && file.mode() & 0o022 == 0
            && file.len() <= 65536,
        "Invalid root-owned OpenVPN launch plan"
    );
    let plan: Plan = serde_json::from_slice(&fs::read(path)?)?;
    ensure!(
        plan.argv.first().is_some_and(|s| s == "openvpn"),
        "Invalid OpenVPN executable"
    );
    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGUSR1,
    ])?;
    let mut child = Some(spawn(&plan, &runtime)?);
    loop {
        for signal in signals.pending() {
            if signal == signal_hook::consts::SIGUSR1 {
                if let Some(child) = &mut child {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(child.id() as i32),
                        nix::sys::signal::Signal::SIGUSR1,
                    );
                } else {
                    child = Some(spawn(&plan, &runtime)?);
                }
            } else {
                if let Some(child) = &mut child {
                    terminate(child);
                }
                return Ok(());
            }
        }
        if let Some(running) = &mut child
            && running.try_wait()?.is_some()
        {
            child = None;
            fs::write(runtime.join("child-exited"), b"OpenVPN child exited")?;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub(crate) fn matches(pid: u32, runtime: &Path) -> bool {
    fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .is_some_and(|bytes| {
            bytes.split(|byte| *byte == 0).any(|arg| {
                arg == runtime
                    .join("supervisor.json")
                    .as_os_str()
                    .as_encoded_bytes()
            })
        })
}
