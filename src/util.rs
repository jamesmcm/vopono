use anyhow::{anyhow, Context};
use directories_next::BaseDirs;
use log::debug;
use regex::Regex;
use std::path::{Path, PathBuf};
use std::process::Command;
use users::{get_current_uid, get_user_by_uid};
use walkdir::WalkDir;

pub fn config_dir() -> anyhow::Result<PathBuf> {
    let mut pathbuf = PathBuf::new();
    let _res: () = if let Some(base_dirs) = BaseDirs::new() {
        pathbuf.push(base_dirs.config_dir());
        Ok(())
    // Ok((*base_dirs.config_dir()))
    } else if let Some(user) = get_user_by_uid(get_current_uid()) {
        let confpath = format!("/home/{}/.config", user.name().to_str().unwrap());
        let path = Path::new(&confpath);
        if path.exists() {
            pathbuf.push(path);
            Ok(())
        } else {
            Err(anyhow!("Could not find valid config directory!"))
        }
    } else {
        Err(anyhow!("Could not find valid config directory!"))
    }?;
    Ok(pathbuf)
}

// TODO: Create struct for holding IPv4 addresses and use FromStr and Eq with that
pub fn get_allocated_ip_addresses() -> anyhow::Result<Vec<String>> {
    let output = Command::new("sudo")
        .args(&["ip", "addr", "show", "type", "veth"])
        .output()?
        .stdout;
    let output = std::str::from_utf8(&output)?;
    debug!("Existing interfaces: {}", output);

    let re = Regex::new(r"inet\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})").unwrap();
    let mut ips = Vec::new();
    for caps in re.captures_iter(output) {
        ips.push(String::from(&caps["ip"]));
    }
    debug!("Assigned IPs: {:?}", &ips);
    Ok(ips)
}

pub fn get_existing_namespaces() -> anyhow::Result<Vec<String>> {
    let output = Command::new("sudo")
        .args(&["ip", "netns", "list"])
        .output()?
        .stdout;
    let output = std::str::from_utf8(&output)?
        .split("\n")
        .into_iter()
        .map(|x| x.split_whitespace().nth(0))
        .filter(|x| x.is_some())
        .map(|x| String::from(x.unwrap()))
        .collect();
    debug!("Existing namespaces: {:?}", output);

    Ok(output)
}

pub fn check_process_running(pid: u32) -> anyhow::Result<bool> {
    let output = Command::new("ps")
        .args(&["-p", &pid.to_string(), "-o", "pid:1", "--no-headers"])
        .output()?
        .stdout;
    let output = std::str::from_utf8(&output)?.split("\n").into_iter().next();
    // debug!("pid: {}, output: {:?}", pid, &output);
    if let Some(x) = output {
        Ok(x.trim() == pid.to_string())
    } else {
        Ok(false)
    }
}

pub fn get_all_running_pids() -> anyhow::Result<Vec<u32>> {
    let output = Command::new("ps")
        .args(&["a", "-o", "pid:1", "--no-headers"])
        .output()?
        .stdout;
    std::str::from_utf8(&output)?
        .split("\n")
        .into_iter()
        .map(|x| x.trim())
        .filter(|x| x.len() > 0)
        .map(|x| match x.parse::<u32>() {
            Ok(x) => Ok(x),
            Err(_) => Err(anyhow!("Could not parse PID to u32: {:?}", x)),
        })
        .collect()
}

pub fn get_target_subnet() -> anyhow::Result<u8> {
    // TODO clean this up
    let assigned_ips = get_allocated_ip_addresses()?;
    let mut target_ip = 1;
    loop {
        let ip = format!("10.200.{}.1/24", target_ip);
        if assigned_ips.contains(&ip) {
            target_ip += 1;
        } else {
            return Ok(target_ip);
        }
    }
}

pub fn sudo_command(command: &[&str]) -> anyhow::Result<()> {
    debug!("sudo {}", command.join(" "));
    let exit_status = Command::new("sudo")
        .args(command)
        .status()
        .with_context(|| format!("Failed to run command: sudo {}", command.join(" ")))?;

    if exit_status.success() {
        Ok(())
    } else {
        Err(anyhow!("Command failed: sudo {}", command.join(" ")))
    }
}

// TODO: Clean this up (can we combine maps and filters?)
pub fn clean_dead_locks() -> anyhow::Result<()> {
    debug!("Cleaning dead lock files...");
    let running_processes = get_all_running_pids()?;
    let mut lockfile_path = config_dir()?;
    lockfile_path.push("vopono/locks");

    // Delete files if their PIDs are no longer running
    std::fs::create_dir_all(&lockfile_path)?;
    WalkDir::new(&lockfile_path)
        .into_iter()
        .filter(|x| x.is_ok())
        .map(|x| x.unwrap())
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
        .filter(|x| x.1 == true)
        .map(|x| {
            debug!("Removing lockfile: {}", x.0.path().display());
            std::fs::remove_file(x.0.path())
        })
        .collect::<Result<(), _>>()?;

    // Delete subdirectories if they contain no locks (ignore errors)
    WalkDir::new(&lockfile_path)
        .into_iter()
        .filter(|x| x.is_ok())
        .map(|x| x.unwrap())
        .filter(|x| x.path().is_dir())
        .map(|x| std::fs::remove_dir(x.path()))
        .collect::<Result<(), _>>()
        .ok();
    Ok(())
}
