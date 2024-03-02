pub mod country_map;
pub mod open_hosts;
pub mod open_ports;
pub mod pulseaudio;
pub mod wireguard;

use crate::config::vpn::Protocol;
use crate::network::firewall::Firewall;
use crate::network::netns::Lockfile;
use anyhow::{anyhow, Context};
use directories_next::BaseDirs;
use ipnet::Ipv4Net;
use log::{debug, info, warn};
use nix::unistd::{Group, User};
pub use open_hosts::open_hosts;
pub use open_ports::open_ports;
use rand::seq::SliceRandom;
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use sysinfo::{ProcessRefreshKind, RefreshKind, System};
use users::{get_current_uid, get_user_by_uid};
use walkdir::WalkDir;
use which::which;

pub fn config_dir() -> anyhow::Result<PathBuf> {
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

pub fn set_config_permissions() -> anyhow::Result<()> {
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;

    let check_dir = vopono_dir()?;
    let username = get_username()?;
    let group = get_group(&username)?;

    let file_permissions = Permissions::from_mode(0o640);
    let dir_permissions = Permissions::from_mode(0o750);

    let group = nix::unistd::Group::from_name(&group)?.map(|x| x.gid);
    let user = nix::unistd::User::from_name(&username)?.map(|x| x.uid);
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

pub fn get_allocated_ip_addresses() -> anyhow::Result<Vec<Ipv4Net>> {
    let output = Command::new("ip")
        .args(["addr", "show", "type", "veth"])
        .output()?
        .stdout;
    let output = std::str::from_utf8(&output)?;
    debug!("Existing interfaces: {}", output);

    let re = Regex::new(r"inet\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})").unwrap();
    let mut ips = Vec::new();
    for caps in re.captures_iter(output) {
        ips.push(Ipv4Net::from_str(&caps["ip"])?);
    }
    debug!("Assigned IPs: {:?}", &ips);
    Ok(ips)
}

pub fn get_existing_namespaces() -> anyhow::Result<Vec<String>> {
    let output = Command::new("ip").args(["netns", "list"]).output()?.stdout;
    let output = std::str::from_utf8(&output)?
        .split('\n')
        .map(|x| x.split_whitespace().next())
        .filter(|x| x.is_some())
        .map(|x| String::from(x.unwrap()))
        .collect();
    debug!("Existing namespaces: {:?}", output);

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
    debug!("PIDs active in {}: {:?}", &ns_name, output);

    Ok(output)
}

pub fn check_process_running(pid: u32) -> bool {
    let s =
        System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new()));
    s.process(sysinfo::Pid::from_u32(pid)).is_some()
}

pub fn get_all_running_pids() -> Vec<u32> {
    let s =
        System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new()));
    s.processes().keys().map(|x| x.as_u32()).collect()
}

pub fn get_all_running_process_names() -> Vec<String> {
    let s =
        System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new()));
    s.processes()
        .values()
        .map(|x| x.name().to_string())
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

// TODO: Fix deprecated name
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
        // Delete files if their PIDs are no longer running
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

pub fn clean_dead_namespaces() -> anyhow::Result<()> {
    let lock_namespaces = get_lock_namespaces()?;
    let existing_namespaces = get_existing_namespaces()?;

    existing_namespaces
        .into_iter()
        .filter(|x| {
            !lock_namespaces.contains_key(x) && get_pids_in_namespace(x).unwrap().is_empty()
        })
        .try_for_each(|x| {
            debug!("Removing dead namespace: {}", x);
            let path = format!("/etc/netns/{x}");
            std::fs::remove_dir_all(path).ok();

            sudo_command(&["ip", "netns", "delete", x.as_str()])
        })?;

    // TODO - deserialize to struct without Drop instead
    std::mem::forget(lock_namespaces);
    Ok(())
}

pub fn elevate_privileges(askpass: bool) -> anyhow::Result<()> {
    use signal_hook::{consts::SIGINT, flag};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // Check if already running as root
    if nix::unistd::getuid().as_raw() != 0 {
        info!("Calling sudo for elevated privileges, current user will be used as default user");
        let args: Vec<String> = std::env::args().collect();

        let terminated = Arc::new(AtomicBool::new(false));
        flag::register(SIGINT, Arc::clone(&terminated))?;

        let sudo_flags = if askpass { "-AE" } else { "-E" };

        debug!("Args: {:?}", &args);
        // status blocks until the process has ended
        let _status = Command::new("sudo")
            .arg(sudo_flags)
            .args(args.clone())
            .status()
            .context(format!("Executing sudo {} {:?}", sudo_flags, &args))?;

        // TODO: Could handle executing with non-sudo firejail here

        if terminated.load(Ordering::SeqCst) {
            // we received a sigint,
            // so we want to pass it on by terminating with a sigint
            nix::sys::signal::kill(nix::unistd::getpid(), nix::sys::signal::Signal::SIGINT)
                .expect("failed to send SIGINT");
        }

        std::process::exit(0);
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
    WalkDir::new(list_path)
        .into_iter()
        .filter_map(|x| x.ok())
        .filter(|x| {
            x.path().is_file()
                && x.path().extension().is_some()
                && (x.path().extension().expect("No file extension") == "conf"
                    || x.path().extension().expect("No file extension") == "ovpn")
        })
        .map(|x| {
            (
                x.clone(),
                x.file_name()
                    .to_str()
                    .expect("No filename")
                    .split('-')
                    .next()
                    .expect("No - in filename")
                    .to_string(),
                x.file_name()
                    .to_str()
                    .expect("No filename")
                    .split('-')
                    .nth(1)
                    .unwrap_or("")
                    .to_string(),
            )
        })
        .filter(|x| {
            x.2.starts_with(alias)
                || (x.1.starts_with(alias))
                || x.0
                    .file_name()
                    .to_str()
                    .expect("No filename")
                    .starts_with(alias)
        })
        .map(|x| PathBuf::from(x.0.path()))
        .collect::<Vec<PathBuf>>()
}

pub fn get_config_from_alias(list_path: &Path, alias: &str) -> anyhow::Result<PathBuf> {
    let paths = get_configs_from_alias(list_path, alias);
    if paths.is_empty() {
        Err(anyhow!("Could not find config file for alias {}", &alias))
    } else {
        let config = paths
            .choose(&mut rand::thread_rng())
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

    if content.contains("[Interface]") {
        Ok(Protocol::Wireguard)
    } else {
        // TODO: Don't always assume OpenVPN
        Ok(Protocol::OpenVpn)
    }
}

pub fn get_firewall() -> anyhow::Result<Firewall> {
    if which("nft").is_ok() {
        Ok(Firewall::NfTables)
    } else if which("iptables").is_ok() {
        Ok(Firewall::IpTables)
    } else {
        Err(anyhow!("Neither nftables nor iptables is installed!"))
    }
}

pub fn get_lock_namespaces() -> anyhow::Result<HashMap<String, Vec<Lockfile>>> {
    let mut dir = config_dir()?;
    dir.push("vopono");
    dir.push("locks");

    let mut namespaces: HashMap<String, Vec<Lockfile>> = HashMap::new();
    WalkDir::new(dir)
        .into_iter()
        .filter(|x| x.is_ok() && x.as_ref().unwrap().path().is_file())
        .map(|x| x.unwrap())
        .try_for_each(|x| -> anyhow::Result<()> {
            let lockfile = File::open(x.path())?;
            let lock: Lockfile = ron::de::from_reader(lockfile)?;
            namespaces
                .entry(lock.ns.name.clone())
                .or_default()
                .push(lock);
            Ok(())
        })?;
    Ok(namespaces)
}
