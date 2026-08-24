pub mod country_map;
pub mod env_vars;
pub mod open_hosts;
pub mod open_ports;
pub mod owner_write;
pub mod pulseaudio;
pub mod unix;
pub mod wireguard;

pub use owner_write::{
    ensure_dir_as_config_owner, perform_owner_write, run_owner_write_from_stdin,
    set_helper_exe_override, validated_user_owned_dir, write_file_as_config_owner,
};

extern crate shell_words as shellwords;
use crate::config::vpn::Protocol;
use crate::network::firewall::Firewall;
use crate::status::{self, LockNamespaces};
use anyhow::{Context, anyhow};
use directories_next::BaseDirs;
use ipnet::Ipv4Net;
use log::{debug, info, warn};
use nix::unistd::{Gid, Group, Uid, User};
pub(crate) use open_hosts::nft_interface_name;
pub use open_hosts::{open_hosts, open_hosts_on_interface};
pub use open_ports::open_ports;
use rand::prelude::IndexedRandom;
use regex::Regex;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use sysinfo::{ProcessRefreshKind, RefreshKind, System};
use uzers::{get_current_uid, get_user_by_uid};
use walkdir::WalkDir;
use which::which;

thread_local! {
    static CONFIG_DIR_OVERRIDE: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    static CONFIG_OWNER_OVERRIDE: std::cell::RefCell<Option<(Uid, Gid)>> =
        const {std::cell::RefCell::new(None) };
}

static DAEMON_MODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_daemon_mode(v: bool) {
    DAEMON_MODE.store(v, std::sync::atomic::Ordering::Relaxed);
}

pub fn is_daemon_mode() -> bool {
    DAEMON_MODE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Set a thread-local override for the base config directory (i.e., the parent of `vopono/`).
/// When set, `config_dir()` will return this path instead of detecting from env/XDG.
/// Use `None` to clear. This is safe for the daemon where each client runs on its own thread.
pub fn set_config_dir_override(path: Option<PathBuf>) {
    CONFIG_DIR_OVERRIDE.with(|ov| *ov.borrow_mut() = path);
}

pub fn set_config_owner_override(owner: Option<(Uid, Gid)>) {
    CONFIG_OWNER_OVERRIDE.with(|ov| *ov.borrow_mut() = owner);
}

/// The per-thread config owner override, if any (daemon client threads).
pub fn config_owner_override() -> Option<(Uid, Gid)> {
    CONFIG_OWNER_OVERRIDE.with(|ov| *ov.borrow())
}

pub fn config_dir() -> anyhow::Result<PathBuf> {
    // Respect thread-local override first (used by daemon to select the connecting user's config).
    if let Some(override_path) = CONFIG_DIR_OVERRIDE.with(|ov| ov.borrow().clone()) {
        debug!(
            "Using config dir from override: {}",
            override_path.to_string_lossy()
        );
        return Ok(override_path);
    }

    let path: Option<PathBuf> = None
        .or_else(|| {
            if let Ok(home) = std::env::var("HOME") {
                let confpath = format!("{home}/.config");
                let path = Path::new(&confpath);
                debug!(
                    "Using config dir from $HOME config: {}",
                    path.to_string_lossy()
                );
                if path.exists() {
                    // Work-around for case when root $HOME is set but user's is not
                    // It seems we cannot distinguish these cases
                    if path.to_string_lossy().contains("/root") {
                        None
                    } else {
                        Some(path.into())
                    }
                } else {
                    None
                }
            } else {
                None
            }
        })
        .or_else(|| {
            if let Ok(user) = std::env::var("SUDO_USER") {
                // TODO: DRY
                let confpath = format!("/home/{user}/.config");
                let path = Path::new(&confpath);
                debug!(
                    "Using config dir from $SUDO_USER config: {}",
                    path.to_string_lossy()
                );
                if path.exists() {
                    Some(path.into())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .or_else(|| {
            if let Some(base_dirs) = BaseDirs::new() {
                debug!(
                    "Using config dir from XDG dirs: {}",
                    base_dirs.config_dir().to_string_lossy()
                );
                Some(base_dirs.config_dir().into())
            } else {
                None
            }
        })
        .or_else(|| {
            if let Some(user) = get_user_by_uid(get_current_uid()) {
                // Handles case when run as root directly
                let confpath = if get_current_uid() == 0 {
                    "/root/.config".to_string()
                } else {
                    format!("/home/{}/.config", user.name().to_str().unwrap())
                };
                let path = Path::new(&confpath);
                debug!(
                    "Using config dir from current user config: {}",
                    path.to_string_lossy()
                );
                if path.exists() {
                    Some(path.into())
                } else {
                    None
                }
            } else {
                None
            }
        });

    path.ok_or_else(|| anyhow!("Could not find valid config directory!"))
}

pub fn vopono_dir() -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join("vopono"))
}

// TODO: DRY with above
pub fn get_username() -> anyhow::Result<String> {
    if let Ok(user) = std::env::var("SUDO_USER") {
        Ok(user)
    } else if let Some(user) = get_user_by_uid(get_current_uid()) {
        Ok(String::from(
            user.name().to_str().expect("Invalid username"),
        ))
    } else {
        Err(anyhow!("No valid username!"))
    }
}

pub fn get_group(username: &str) -> anyhow::Result<String> {
    let user = User::from_name(username)?;

    match user {
        Some(x) => Ok(Group::from_gid(x.gid)?
            .expect("Failed to use group id")
            .name),
        None => Ok(username.to_string()),
    }
}

/// Resolve the (uid, gid) that files under the vopono config tree belong to:
/// the daemon client override when set, otherwise derived from the invoking
/// user (SUDO_USER / current uid).
pub fn resolve_config_owner() -> anyhow::Result<(Option<Uid>, Option<Gid>)> {
    CONFIG_OWNER_OVERRIDE.with(|ov| *ov.borrow()).map_or_else(
        || -> anyhow::Result<(Option<Uid>, Option<Gid>)> {
            let username = get_username()?;
            let group_name = get_group(&username)?;
            let user = User::from_name(&username)?
                .map(|x| x.uid)
                .ok_or_else(|| anyhow!("Failed to resolve uid for user '{username}'"))?;
            let group = Group::from_name(&group_name)?
                .map(|x| x.gid)
                .ok_or_else(|| anyhow!("Failed to resolve gid for group '{group_name}'"))?;
            Ok((Some(user), Some(group)))
        },
        |(uid, gid)| Ok((Some(uid), Some(gid))),
    )
}

pub fn set_config_permissions() -> anyhow::Result<()> {
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;

    let check_dir = vopono_dir()?;
    let (user, group) = resolve_config_owner()?;

    debug!(
        "Setting config permissions in {} to user: {:?}, group: {:?}",
        check_dir.display(),
        user,
        group
    );

    // Provider trees contain plaintext passwords, API tokens, and WireGuard
    // private keys. They are consumed by the owning user and root only; no
    // group access is required.
    let file_permissions = Permissions::from_mode(0o600);
    let dir_permissions = Permissions::from_mode(0o700);

    for entry in WalkDir::new(check_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        nix::unistd::chown(path, user, group)?;
        if path.is_file() {
            std::fs::set_permissions(path, file_permissions.clone())?;
        } else {
            std::fs::set_permissions(path, dir_permissions.clone())?;
        }
    }
    Ok(())
}

/// Create or truncate a secret-bearing configuration file with owner-only
/// permissions from the instant the inode is created.
pub fn create_private_file(path: &Path) -> anyhow::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?)
}

/// Assign a freshly written file back to the config owner.
///
/// Used on the legacy (sudo/CLI) path where root writes into the invoking
/// user's config tree: an atomic rename replaces the inode, so ownership
/// must be reapplied after the replacement - not just once at directory
/// setup time.
pub fn chown_to_config_owner(path: &Path) -> anyhow::Result<()> {
    let (user, group) = resolve_config_owner()?;
    debug!(
        "Setting ownership of {} to user: {:?}, group: {:?}",
        path.display(),
        user,
        group
    );
    nix::unistd::chown(path, user, group)?;
    Ok(())
}

pub fn get_allocated_ip_addresses() -> anyhow::Result<Vec<Ipv4Net>> {
    let output = Command::new("ip")
        .args(["addr", "show", "type", "veth"])
        .output()?
        .stdout;
    let output = std::str::from_utf8(&output)?;
    debug!("Existing interfaces: {output}");

    let re = Regex::new(r"inet\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})").unwrap();
    let mut ips = Vec::new();
    for caps in re.captures_iter(output) {
        ips.push(Ipv4Net::from_str(&caps["ip"])?);
    }
    debug!("Assigned IPs: {:?}", ips);
    Ok(ips)
}

pub fn get_existing_namespaces() -> anyhow::Result<Vec<String>> {
    let output = Command::new("ip").args(["netns", "list"]).output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "ip netns list failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let output = std::str::from_utf8(&output.stdout)?
        .split('\n')
        .map(|x| x.split_whitespace().next())
        .filter(|x| x.is_some())
        .map(|x| String::from(x.unwrap()))
        .collect();
    debug!("Existing namespaces: {output:?}");

    Ok(output)
}

pub fn get_pids_in_namespace(ns_name: &str) -> anyhow::Result<Vec<i32>> {
    let output = Command::new("ip")
        .args(["netns", "pids", ns_name])
        .output()?
        .stdout;
    let output = std::str::from_utf8(&output)?
        .split('\n')
        .filter_map(|x| x.split_whitespace().next())
        .filter_map(|x| x.parse::<i32>().ok())
        .collect();
    debug!("PIDs active in {}: {:?}", ns_name, output);

    Ok(output)
}

pub fn check_process_running(pid: u32) -> bool {
    let s = System::new_with_specifics(
        RefreshKind::everything().with_processes(ProcessRefreshKind::everything()),
    );
    s.process(sysinfo::Pid::from_u32(pid)).is_some()
}

/// Return the PIDs of processes whose comm name matches `process_name`.
///
/// This intentionally uses the kernel-visible process name rather than the
/// command line.  It is suitable for detecting common single-instance
/// applications before launch, but callers should treat it as a warning
/// signal rather than as an identity guarantee.
pub fn get_running_process_pids(process_name: &str) -> Vec<u32> {
    let s = System::new_with_specifics(
        RefreshKind::everything().with_processes(ProcessRefreshKind::everything()),
    );
    s.processes()
        .iter()
        .filter(|(_, process)| process.name().to_string_lossy() == process_name)
        .map(|(pid, _)| pid.as_u32())
        .collect()
}

/// Check whether a process is currently attached to a named network namespace.
///
/// Namespace identity is compared via the `(device, inode)` pair of the
/// namespace files: every namespace gets a unique inode on its nsfs
/// superblock. Reading the symlink targets is not reliable here because
/// `readlink(2)` on `/run/netns/<name>` bind mounts returns `EINVAL` on
/// several kernels.
pub fn process_is_in_network_namespace(pid: u32, ns_name: &str) -> anyhow::Result<bool> {
    let process_namespace = fs::metadata(format!("/proc/{pid}/ns/net"))
        .with_context(|| format!("Could not inspect network namespace for PID {pid}"))?;
    let target_namespace = fs::metadata(format!("/var/run/netns/{ns_name}"))
        .with_context(|| format!("Could not inspect network namespace '{ns_name}'"))?;

    use std::os::unix::fs::MetadataExt;
    Ok(process_namespace.ino() == target_namespace.ino()
        && process_namespace.dev() == target_namespace.dev())
}

pub fn get_all_running_pids() -> Vec<u32> {
    let s = System::new_with_specifics(
        RefreshKind::everything().with_processes(ProcessRefreshKind::everything()),
    );
    s.processes().keys().map(|x| x.as_u32()).collect()
}

pub fn get_all_running_process_names() -> Vec<String> {
    let s = System::new_with_specifics(
        RefreshKind::everything().with_processes(ProcessRefreshKind::everything()),
    );
    s.processes()
        .values()
        .map(|x| x.name().to_string_lossy().to_string())
        .collect()
}

pub fn get_target_subnet() -> anyhow::Result<u8> {
    // TODO: Fix hard limit of <254 vopono instances
    let assigned_ips = get_allocated_ip_addresses()?;
    let mut target_ip = 1;
    while target_ip <= 254 {
        let ip = Ipv4Net::new(Ipv4Addr::new(10, 200, target_ip, 1), 24)?;
        if assigned_ips.contains(&ip) {
            target_ip += 1;
        } else {
            return Ok(target_ip);
        }
    }
    Err(anyhow!(
        "Could not find free subnet of form: 10.200.xxx.1/24"
    ))
}

/// Run a command that requires elevated privileges.
/// Note: This function doesn't invoke sudo itself; it expects to be called
/// from a context that already has root privileges (e.g., the vopono daemon
/// or when vopono is run with sudo).
pub fn sudo_command(command: &[&str]) -> anyhow::Result<()> {
    debug!("{}", command.join(" "));

    let (start_command, args) = command
        .split_first()
        .expect("Could not split command slice");

    let exit_status = Command::new(start_command)
        .args(args)
        .status()
        .with_context(|| format!("Failed to run command: {}", command.join(" ")))?;

    if exit_status.success() {
        Ok(())
    } else {
        Err(anyhow!("Command failed: {}", command.join(" ")))
    }
}

// TODO: Clean this up (can we combine maps and filters?)
pub fn clean_dead_locks() -> anyhow::Result<()> {
    let running_processes = get_all_running_pids();
    let mut lockfile_path = config_dir()?;
    lockfile_path.push("vopono/locks");

    if lockfile_path.exists() && lockfile_path.read_dir()?.next().is_some() {
        debug!("Cleaning dead lock files...");
        // Delete primary lock files if their PIDs are no longer running (numeric file names)
        std::fs::create_dir_all(&lockfile_path)?;
        WalkDir::new(&lockfile_path)
            .into_iter()
            .filter_map(|x| x.ok())
            .filter(|x| x.path().is_file())
            .map(|x| {
                (
                    x.clone(),
                    x.file_name()
                        .to_str()
                        .expect("Failed to parse file name")
                        .parse::<u32>()
                        .ok(),
                )
            })
            .filter(|x| x.1.is_some())
            .map(|x| (x.0, running_processes.contains(&x.1.unwrap())))
            .filter(|x| !x.1)
            .try_for_each(|x| {
                debug!("Removing lockfile: {}", x.0.path().display());
                std::fs::remove_file(x.0.path())
            })?;

        // Delete auxiliary client-* lock files if their PIDs are no longer running
        WalkDir::new(&lockfile_path)
            .into_iter()
            .filter_map(|x| x.ok())
            .filter(|x| x.path().is_file())
            .filter_map(|x| {
                let fname = x.file_name().to_str().unwrap_or("").to_string();
                if let Some(rest) = fname.strip_prefix("client-")
                    && let Ok(pid) = rest.parse::<u32>()
                {
                    return Some((x, pid));
                }
                None
            })
            .filter(|(_, pid)| !running_processes.contains(pid))
            .try_for_each(|(entry, _)| {
                debug!("Removing client lockfile: {}", entry.path().display());
                std::fs::remove_file(entry.path())
            })?;

        // Delete subdirectories if they contain no locks (ignore errors)
        WalkDir::new(&lockfile_path)
            .into_iter()
            .filter_map(|x| x.ok())
            .filter(|x| x.path().is_dir())
            .try_for_each(|x| std::fs::remove_dir(x.path()))
            .ok();
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Ok(())
}

/// Remove every lockfile for a single namespace, then the directory itself.
///
/// Owns the `vopono/locks` layout so callers (e.g. the lifecycle control
/// commands) do not need to know where lockfiles live on disk.
pub fn remove_lock_files(namespace: &str) -> anyhow::Result<()> {
    let mut lock_dir = config_dir()?;
    lock_dir.push(format!("vopono/locks/{namespace}"));
    if !lock_dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(&lock_dir)? {
        let entry = entry?;
        if entry.path().is_file() {
            debug!("Removing lockfile: {}", entry.path().display());
            std::fs::remove_file(entry.path())?;
        }
    }
    // Best-effort: only succeeds when the directory is now empty.
    std::fs::remove_dir(&lock_dir).ok();
    Ok(())
}

pub fn clean_dead_namespaces() -> anyhow::Result<()> {
    let lock_namespaces = get_lock_namespaces()?;
    let existing_namespaces = get_existing_namespaces()?;

    existing_namespaces
        .into_iter()
        .filter(|x| {
            !lock_namespaces.contains_key(x) && get_pids_in_namespace(x).unwrap().is_empty()
        })
        .try_for_each(|x| {
            debug!("Removing dead namespace: {x}");
            let path = format!("/etc/netns/{x}");
            std::fs::remove_dir_all(path).ok();

            sudo_command(&["ip", "netns", "delete", x.as_str()])
        })?;

    Ok(())
}

pub fn elevate_privileges(askpass: bool) -> anyhow::Result<()> {
    use signal_hook::{consts::SIGINT, flag};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    // Check if already running as root
    if nix::unistd::getuid().as_raw() != 0 {
        info!("Calling sudo for elevated privileges, current user will be used as default user");
        let args: Vec<String> = std::env::args().collect();

        let terminated = Arc::new(AtomicBool::new(false));
        flag::register(SIGINT, Arc::clone(&terminated))?;

        let sudo_flags = if askpass { "-AE" } else { "-E" };
        // TODO: This isn't passing RUST_LOG ?

        debug!("Args: {:?}", args);
        // status blocks until the process has ended
        let status = Command::new("sudo")
            .arg(sudo_flags)
            .args(args.clone())
            .status()
            .context(format!("Executing sudo {} {:?}", sudo_flags, args))?;

        // TODO: Could handle executing with non-sudo firejail here

        if terminated.load(Ordering::SeqCst) {
            // we received a sigint,
            // so we want to pass it on by terminating with a sigint
            nix::sys::signal::kill(nix::unistd::getpid(), nix::sys::signal::Signal::SIGINT)
                .expect("failed to send SIGINT");
        }

        std::process::exit(status.code().unwrap_or(1));
    } else if std::env::var("SUDO_USER").is_err() {
        warn!("Running vopono as root user directly!");
    }
    Ok(())
}

pub fn delete_all_files_in_dir(dir: &Path) -> anyhow::Result<()> {
    dir.read_dir()?
        .flatten()
        .map(|x| std::fs::remove_file(x.path()))
        .collect::<Result<Vec<()>, std::io::Error>>()?;
    Ok(())
}

pub fn get_configs_from_alias(list_path: &Path, alias: &str) -> Vec<PathBuf> {
    let alias = alias.trim().to_ascii_lowercase();
    let code_to_country = country_map::code_to_country_map();
    let country_to_code = country_map::country_to_code_map();
    let mut country_matches = Vec::new();
    let mut other_matches = Vec::new();

    for entry in WalkDir::new(list_path).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if !path.is_file()
            || !path
                .extension()
                .is_some_and(|ext| ext == "conf" || ext == "ovpn")
        {
            continue;
        }

        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(stem) = path.file_stem().and_then(|name| name.to_str()) else {
            continue;
        };
        let components = stem
            .split('-')
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>();
        if components.is_empty() {
            continue;
        }

        let component_match = alias.is_empty()
            || components
                .iter()
                .any(|component| component.starts_with(&alias))
            || file_name.to_ascii_lowercase().starts_with(&alias);
        if !component_match {
            continue;
        }

        let country_match = !alias.is_empty()
            && (components[0].starts_with(&alias)
                || code_to_country
                    .get(components[0].as_str())
                    .is_some_and(|country| country.starts_with(&alias))
                || country_to_code
                    .get(components[0].as_str())
                    .is_some_and(|code| code.starts_with(&alias)));

        if country_match {
            country_matches.push(path.to_path_buf());
        } else {
            other_matches.push(path.to_path_buf());
        }
    }

    if country_matches.is_empty() {
        other_matches
    } else {
        country_matches
    }
}

pub fn get_config_from_alias(list_path: &Path, alias: &str) -> anyhow::Result<PathBuf> {
    let paths = get_configs_from_alias(list_path, alias);
    if paths.is_empty() {
        Err(anyhow!("Could not find config file for alias {}", alias))
    } else {
        let config = paths
            .choose(&mut rand::rng())
            .expect("Could not find config");

        info!("Chosen config: {}", config.display());
        Ok(config.clone())
    }
}

pub fn get_config_file_protocol(config_file: &Path) -> anyhow::Result<Protocol> {
    let content = fs::read_to_string(config_file).map_err(|e| {
        anyhow!(
            "Failed to read VPN config file: {}, err: {}",
            config_file.to_string_lossy(),
            e
        )
    })?;

    detect_config_protocol(&content).with_context(|| {
        format!(
            "Could not detect VPN protocol for {}",
            config_file.display()
        )
    })
}

fn detect_config_protocol(content: &str) -> anyhow::Result<Protocol> {
    if content.contains("[Interface]") {
        if content.contains("Jc =")
            || content.contains("Jmin =")
            || content.contains("Jmax =")
            || content.contains("S1 =")
            || content.contains("S2 =")
            || content.contains("H1 =")
            || content.contains("H2 =")
            || content.contains("H3 =")
            || content.contains("H4 =")
        {
            return Ok(Protocol::AmneziaWG);
        }

        Ok(Protocol::Wireguard)
    } else if content.lines().any(|line| {
        let line = line.trim_start();
        line == "client"
            || line.starts_with("remote ")
            || line.starts_with("dev ")
            || line.starts_with("proto ")
            || line.starts_with("<ca>")
    }) {
        Ok(Protocol::OpenVpn)
    } else {
        Err(anyhow!(
            "Config is neither a Wireguard/AmneziaWG config nor a recognizable OpenVPN config"
        ))
    }
}

pub fn get_firewall() -> anyhow::Result<Firewall> {
    if which("iptables").is_ok() {
        Ok(Firewall::IpTables)
    } else if which("nft").is_ok() {
        Ok(Firewall::NfTables)
    } else {
        Err(anyhow!("Neither nftables nor iptables is installed!"))
    }
}

pub fn get_lock_namespaces() -> anyhow::Result<LockNamespaces> {
    status::strict_namespaces(status::read_lock_namespaces()?)
}

pub fn parse_command_str(command_str: &str) -> anyhow::Result<Vec<String>> {
    shellwords::split(command_str).map_err(|e| {
        anyhow::anyhow!(
            "Failed to parse command string: {}, error: {:?}",
            command_str,
            e
        )
    })
}

pub fn hostname_to_ip(hostname: &str) -> anyhow::Result<Vec<IpAddr>> {
    let socket_addrs = format!("{hostname}:80").to_socket_addrs()?;
    let ip_addrs = socket_addrs.map(|addr| addr.ip()).collect();

    Ok(ip_addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_supported_custom_config_protocols() {
        assert_eq!(
            detect_config_protocol("[Interface]\nPrivateKey = secret").unwrap(),
            Protocol::Wireguard
        );
        assert_eq!(
            detect_config_protocol("[Interface]\nJc = 4").unwrap(),
            Protocol::AmneziaWG
        );
        assert_eq!(
            detect_config_protocol("client\nremote vpn.example.com 1194").unwrap(),
            Protocol::OpenVpn
        );
    }

    #[test]
    fn rejects_unknown_custom_config_format() {
        assert!(detect_config_protocol("this is not a VPN config").is_err());
    }

    #[test]
    fn private_files_are_owner_only_at_creation() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("secret");
        create_private_file(&path).unwrap();
        let mode = std::fs::metadata(path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn country_aliases_are_prioritized_over_server_prefixes() {
        let directory = tempfile::tempdir().unwrap();
        for filename in [
            "romania-ro-canes.conf",
            "canada-ca-ross.conf",
            "ro-legacy.conf",
            "ca-ross.conf",
        ] {
            std::fs::File::create(directory.path().join(filename)).unwrap();
        }

        let mut romania = get_configs_from_alias(directory.path(), "ro")
            .into_iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        romania.sort();
        assert_eq!(romania, ["ro-legacy.conf", "romania-ro-canes.conf"]);

        let mut ross = get_configs_from_alias(directory.path(), "ross")
            .into_iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        ross.sort();
        assert_eq!(ross, ["ca-ross.conf", "canada-ca-ross.conf"]);
    }
}
