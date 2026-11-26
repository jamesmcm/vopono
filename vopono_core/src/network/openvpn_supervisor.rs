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
    let mut inline_block: Option<String> = None;
    for raw_line in fs::read_to_string(config)?.lines() {
        let trimmed = raw_line.trim();
        if let Some(tag) = &inline_block {
            if trimmed == format!("</{tag}>") {
                inline_block = None;
            }
            continue;
        }
        if let Some(tag) = trimmed
            .strip_prefix('<')
            .and_then(|rest| rest.strip_suffix('>'))
            && !tag.is_empty()
            && !tag.starts_with('/')
            && tag
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            inline_block = Some(tag.to_owned());
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Ok(fields) = shell_words::split(trimmed)
            && fields
                .first()
                .is_some_and(|field| field.strip_prefix("--").unwrap_or(field) == "dev")
            && let Some(value) = fields.get(1)
        {
            device = if value == "tun" {
                "tun0".to_owned()
            } else {
                value.clone()
            };
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
        crate::util::current_vopono_exe()?
            .to_str()
            .context("Invalid helper path")?
            .to_owned(),
        "__openvpn-supervisor".into(),
        "--".into(),
        plan.to_str().context("Invalid runtime path")?.to_owned(),
    ])
}

pub(super) const RECOVERY_PROFILE: &str = "recovery.ovpn";

fn spawn(plan: &Plan, runtime: &Path, recovery: bool) -> anyhow::Result<Child> {
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
    let mut args = plan.argv[1..].to_vec();
    if recovery {
        let config = args
            .iter()
            .position(|arg| arg == "--config")
            .context("Missing OpenVPN config argument")?;
        let path = runtime.join(RECOVERY_PROFILE);
        args[config + 1] = path
            .to_str()
            .context("Invalid OpenVPN recovery config path")?
            .to_owned();
    }
    let mut command = Command::new(&plan.argv[0]);
    command
        .args(args)
        .current_dir(runtime)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let parent = nix::unistd::getpid();
    // Let the kernel stop this child if the supervisor is killed. Checking
    // getppid after arming the signal also covers death before pre_exec ran.
    unsafe {
        command.pre_exec(move || {
            nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL)?;
            if nix::unistd::getppid() != parent {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    if let Err(error) = fs::write(runtime.join("child.pid"), child.id().to_string()) {
        terminate(&mut child);
        return Err(error.into());
    }
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
    let mut child = Some(spawn(&plan, &runtime, false)?);
    loop {
        // Reap any already-exited child BEFORE draining signals so a SIGUSR1
        // restart request immediately spawns a fresh OpenVPN child instead of
        // signaling a zombie and dropping the recovery request.
        if let Some(running) = &mut child
            && let Some(status) = running.try_wait()?
        {
            child = None;
            let _ = fs::remove_file(runtime.join("child.pid"));
            fs::write(runtime.join("child-exited"), status.to_string())?;
        }
        for signal in signals.pending() {
            if signal == signal_hook::consts::SIGUSR1 {
                let recovery = runtime.join(RECOVERY_PROFILE).is_file();
                // Always respawn cleanly on recovery so wedged children or
                // fixed-local-port/persist-local-ip sessions reset completely
                // instead of hitting `--connect-retry-max 1`.
                if let Some(mut child) = child.take() {
                    terminate(&mut child);
                }
                match spawn(&plan, &runtime, recovery) {
                    Ok(spawned) => child = Some(spawned),
                    Err(error) => {
                        log::warn!("OpenVPN supervisor could not restart child: {error:#}");
                    }
                }
            } else {
                if let Some(child) = &mut child {
                    terminate(child);
                }
                let _ = fs::remove_file(runtime.join("child.pid"));
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub(crate) fn matches(pid: u32, runtime: &Path) -> bool {
    let Ok(meta) = fs::metadata(format!("/proc/{pid}")) else {
        return false;
    };
    if meta.uid() != 0 {
        return false;
    }
    fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .is_some_and(|bytes| {
            let args: Vec<&[u8]> = bytes
                .split(|byte| *byte == 0)
                .filter(|arg| !arg.is_empty())
                .collect();
            let expected_plan = runtime.join("supervisor.json");
            args.get(1) == Some(&b"__openvpn-supervisor".as_slice())
                && args
                    .iter()
                    .any(|arg| *arg == expected_plan.as_os_str().as_encoded_bytes())
        })
}
