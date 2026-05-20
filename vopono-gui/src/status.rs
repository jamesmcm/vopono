use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use vopono_core::config::providers::VpnProvider;
use vopono_core::config::vpn::Protocol;
use walkdir::WalkDir;

#[derive(Clone, Debug, Default)]
pub struct StatusSnapshot {
    pub namespaces: Vec<NamespaceStatus>,
    pub error: Option<String>,
}

impl StatusSnapshot {
    pub fn active_count(&self) -> usize {
        self.namespaces.len()
    }

    pub fn tray_text(&self) -> String {
        if let Some(error) = &self.error {
            return format!("vopono status unavailable: {error}");
        }
        if self.namespaces.is_empty() {
            return "vopono: no active namespaces".to_string();
        }

        let mut lines = vec![format!(
            "vopono: {} active namespace{}",
            self.namespaces.len(),
            if self.namespaces.len() == 1 { "" } else { "s" }
        )];
        lines.extend(self.namespaces.iter().take(4).map(|ns| {
            format!(
                "{}: {} {} / {} app{}",
                ns.name,
                ns.provider,
                ns.protocol,
                ns.applications.len(),
                if ns.applications.len() == 1 { "" } else { "s" }
            )
        }));
        lines.join("\n")
    }
}

#[derive(Clone, Debug)]
pub struct NamespaceStatus {
    pub name: String,
    pub provider: String,
    pub protocol: String,
    pub uptime: String,
    pub applications: Vec<ApplicationStatus>,
}

#[derive(Clone, Debug)]
pub struct ApplicationStatus {
    pub command: String,
    pub uptime: String,
}

pub fn read_status() -> StatusSnapshot {
    match read_status_inner() {
        Ok(snapshot) => snapshot,
        Err(error) => StatusSnapshot {
            namespaces: Vec::new(),
            error: Some(error.to_string()),
        },
    }
}

fn read_status_inner() -> anyhow::Result<StatusSnapshot> {
    let namespaces = read_lock_namespaces()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut snapshot = StatusSnapshot::default();

    let mut names = namespaces.keys().cloned().collect::<Vec<_>>();
    names.sort();

    for name in names {
        let Some(locks) = namespaces.get(&name) else {
            continue;
        };
        let Some(first_lock) = locks.first() else {
            continue;
        };
        let start = locks.iter().map(|lock| lock.start).min().unwrap_or(now);
        let mut applications = locks
            .iter()
            .map(|lock| ApplicationStatus {
                command: lock.command.clone(),
                uptime: format_duration(now.saturating_sub(lock.start)),
            })
            .collect::<Vec<_>>();
        applications.sort_by(|a, b| a.command.cmp(&b.command));

        snapshot.namespaces.push(NamespaceStatus {
            name,
            provider: first_lock.ns.provider.to_string(),
            protocol: first_lock.ns.protocol.to_string(),
            uptime: format_duration(now.saturating_sub(start)),
            applications,
        });
    }

    Ok(snapshot)
}

#[derive(Debug, Deserialize)]
struct StatusLockfile {
    ns: StatusNamespace,
    start: u64,
    command: String,
}

#[derive(Debug, Deserialize)]
struct StatusNamespace {
    name: String,
    provider: VpnProvider,
    protocol: Protocol,
}

fn read_lock_namespaces() -> anyhow::Result<HashMap<String, Vec<StatusLockfile>>> {
    let mut dir = vopono_core::util::config_dir()?;
    dir.push("vopono");
    dir.push("locks");

    let mut namespaces: HashMap<String, Vec<StatusLockfile>> = HashMap::new();
    WalkDir::new(dir)
        .into_iter()
        .filter(|entry| entry.is_ok() && entry.as_ref().unwrap().path().is_file())
        .map(|entry| entry.unwrap())
        .try_for_each(|entry| -> anyhow::Result<()> {
            let lockfile = File::open(entry.path())?;
            let lock: StatusLockfile = ron::de::from_reader(lockfile)?;
            namespaces
                .entry(lock.ns.name.clone())
                .or_default()
                .push(lock);
            Ok(())
        })?;
    Ok(namespaces)
}

fn format_duration(seconds: u64) -> String {
    let duration = Duration::from_secs(seconds);
    let total = duration.as_secs();
    let days = total / 86_400;
    let hours = (total % 86_400) / 3_600;
    let minutes = (total % 3_600) / 60;
    let seconds = total % 60;

    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_lockfile_deserializes_only_inert_status_fields() {
        let raw = r#"(
            ns: (
                name: "vopono_mullvad_se",
                veth_pair: None,
                dns_config: None,
                openvpn: None,
                wireguard: None,
                host_masquerade: None,
                firewall_exception: None,
                shadowsocks: None,
                veth_pair_ips: None,
                openconnect: None,
                openfortivpn: None,
                warp: None,
                provider: Mullvad,
                protocol: Wireguard,
                firewall: NfTables,
                predown: None,
                predown_user: None,
                predown_group: None,
                config_file: None,
                trojan: None,
            ),
            start: 123,
            command: "firefox --private-window",
        )"#;

        let lock: StatusLockfile = ron::from_str(raw).expect("status lockfile should parse");
        assert_eq!(lock.ns.name, "vopono_mullvad_se");
        assert_eq!(lock.ns.provider, VpnProvider::Mullvad);
        assert_eq!(lock.ns.protocol, Protocol::Wireguard);
        assert_eq!(lock.start, 123);
        assert_eq!(lock.command, "firefox --private-window");
    }
}
