use super::firewall::Firewall;
use super::network_interface::NetworkInterface;
use crate::util::sudo_command;
use anyhow::{Context, bail};
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Serialize, Deserialize, Debug)]
pub struct HostMasquerade {
    ipv4_mask: Option<String>,
    ipv6_mask: Option<String>,
    interface: NetworkInterface,
    firewall: Firewall,
    #[serde(skip)]
    cleanup_enabled: bool,
}

impl HostMasquerade {
    pub(crate) fn interface_name(&self) -> &str {
        &self.interface.name
    }

    pub(crate) fn recover_interface(
        &mut self,
        interface: NetworkInterface,
    ) -> anyhow::Result<bool> {
        let interface_changed = self.interface.name != interface.name;
        // Create the replacement first so a failure leaves the working rule in
        // place. Then remove exactly the old generation before swapping it out.
        let mut replacement = Self::add_masquerade_rule(
            self.ipv4_mask.clone(),
            self.ipv6_mask.clone(),
            interface,
            self.firewall,
        )?;
        // Recovery also operates on inert snapshots. Only the owning
        // namespace guard may remove the replacement when it is dropped.
        replacement.set_cleanup_enabled(self.cleanup_enabled);
        if interface_changed {
            let _nft_guard = host_nft_lock();
            self.remove_rules();
        }
        self.set_cleanup_enabled(false);
        *self = replacement;
        Ok(interface_changed)
    }

    fn nft_comment(ipv4_mask: Option<&str>, ipv6_mask: Option<&str>, interface: &str) -> String {
        format!(
            "vopono-nat_{}_{}_{}",
            nft_token(ipv4_mask.unwrap_or("-")),
            nft_token(ipv6_mask.unwrap_or("-")),
            nft_token(interface)
        )
    }

    /// Remove this generation's rules without touching other namespaces.
    fn remove_rules(&self) {
        match self.firewall {
            Firewall::IpTables => {
                if let Some(ref mask) = self.ipv4_mask {
                    delete_firewall_rule(
                        &[
                            "iptables",
                            "-t",
                            "nat",
                            "-D",
                            "POSTROUTING",
                            "-s",
                            mask,
                            "-o",
                            &self.interface.name,
                            "-j",
                            "MASQUERADE",
                        ],
                        "iptables masquerade rule",
                    );
                }
                if let Some(ref mask) = self.ipv6_mask {
                    delete_firewall_rule(
                        &[
                            "ip6tables",
                            "-t",
                            "nat",
                            "-D",
                            "POSTROUTING",
                            "-s",
                            mask,
                            "-o",
                            &self.interface.name,
                            "-j",
                            "MASQUERADE",
                        ],
                        "ip6tables masquerade rule",
                    );
                }
            }
            Firewall::NfTables => {
                let comment = Self::nft_comment(
                    self.ipv4_mask.as_deref(),
                    self.ipv6_mask.as_deref(),
                    &self.interface.name,
                );
                if let Err(error) = delete_nft_rules_with_comment("vopono_nat", &comment) {
                    warn!("Failed to remove old nftables masquerade rules: {error:#}");
                }
            }
        }
    }

    /// Add masquerade rule to route traffic from network namespace to active network interface
    pub fn add_masquerade_rule(
        ipv4_mask: Option<String>,
        ipv6_mask: Option<String>,
        interface: NetworkInterface,
        firewall: Firewall,
    ) -> anyhow::Result<Self> {
        match firewall {
            Firewall::IpTables => {
                let add_rule = |program, mask: Option<&str>| {
                    mask.map_or(Ok(false), |mask| {
                        ensure_iptables_rule(
                            program,
                            Some("nat"),
                            "POSTROUTING",
                            &["-s", mask, "-o", &interface.name, "-j", "MASQUERADE"],
                        )
                    })
                };
                let added_ipv4 = add_rule("iptables", ipv4_mask.as_deref())?;
                if let Err(error) = add_rule("ip6tables", ipv6_mask.as_deref()) {
                    if added_ipv4 && let Some(mask) = ipv4_mask.as_deref() {
                        delete_firewall_rule(
                            &[
                                "iptables",
                                "-t",
                                "nat",
                                "-D",
                                "POSTROUTING",
                                "-s",
                                mask,
                                "-o",
                                &interface.name,
                                "-j",
                                "MASQUERADE",
                            ],
                            "partially installed IPv4 masquerade rule",
                        );
                    }
                    return Err(error);
                }
            }
            Firewall::NfTables => {
                let comment =
                    Self::nft_comment(ipv4_mask.as_deref(), ipv6_mask.as_deref(), &interface.name);
                let rules = [("ip", &ipv4_mask), ("ip6", &ipv6_mask)]
                    .into_iter()
                    .filter_map(|(family, mask)| {
                        let mask = mask.as_ref()?;
                        Some(mask.parse::<ipnet::IpNet>().map(|mask| {
                            format!(
                                "oifname \"{}\" {family} saddr {mask} counter masquerade",
                                interface.name
                            )
                        }))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                replace_nft_rules(
                    "vopono_nat",
                    "postrouting",
                    "{ type nat hook postrouting priority 100; }",
                    &comment,
                    &rules,
                )?;
            }
        }
        Ok(Self {
            ipv4_mask,
            ipv6_mask,
            interface,
            firewall,
            cleanup_enabled: true,
        })
    }
}

impl Drop for HostMasquerade {
    fn drop(&mut self) {
        if !self.cleanup_enabled {
            return;
        }
        let _nft_guard = host_nft_lock();
        self.remove_rules();
        if self.firewall == Firewall::NfTables && nft_table_has_no_rules("vopono_nat") {
            // Delete the shared table only when zero rules remain across all
            // namespaces and users, never based on a single user's lock dir.
            sudo_command(&["nft", "delete", "table", "inet", "vopono_nat"])
                .unwrap_or_else(|e| log::warn!("Failed to delete nftables table vopono_nat: {e}"));
        }
    }
}

impl HostMasquerade {
    pub(crate) fn set_cleanup_enabled(&mut self, enabled: bool) {
        self.cleanup_enabled = enabled;
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FirewallException {
    host_interface: NetworkInterface,
    ns_interface: NetworkInterface,
    firewall: Firewall,
    disable_ipv6: bool,
    #[serde(default)]
    docker_user_ipv4: bool,
    #[serde(default)]
    docker_user_ipv6: bool,
    #[serde(default)]
    ufw_forward_ipv4: bool,
    #[serde(default)]
    ufw_forward_ipv6: bool,
    #[serde(skip)]
    cleanup_enabled: bool,
}

impl FirewallException {
    pub(crate) fn recover_interface(
        &mut self,
        interface: NetworkInterface,
        veth: &str,
    ) -> anyhow::Result<bool> {
        let current_host = if self.ns_interface.name == veth {
            &self.host_interface
        } else {
            &self.ns_interface
        };
        if current_host.name == interface.name {
            self.ensure_rules()?;
            return Ok(false);
        }
        let (first, second) = if self.ns_interface.name == veth {
            (self.ns_interface.clone(), interface)
        } else {
            (interface, self.host_interface.clone())
        };
        let mut replacement =
            Self::add_firewall_exception(first, second, self.firewall, self.disable_ipv6)?;
        replacement.set_cleanup_enabled(self.cleanup_enabled);
        {
            let _nft_guard = host_nft_lock();
            self.remove_rules();
        }
        self.set_cleanup_enabled(false);
        *self = replacement;
        Ok(true)
    }

    fn nft_comment(host_interface: &str, ns_interface: &str) -> String {
        format!(
            "vopono-bridge_{}_{}",
            nft_token(host_interface),
            nft_token(ns_interface)
        )
    }

    /// Remove this generation's rules. Interface-specific rules are safe to
    /// remove even while other vopono namespaces are active.
    fn remove_rules(&self) {
        if self.docker_user_ipv4 {
            delete_docker_user_exception("iptables", &self.host_interface, &self.ns_interface);
        }
        if self.docker_user_ipv6 {
            delete_docker_user_exception("ip6tables", &self.host_interface, &self.ns_interface);
        }
        if self.ufw_forward_ipv4 {
            delete_forward_chain_exception(
                "iptables",
                "ufw-before-forward",
                &self.host_interface,
                &self.ns_interface,
            );
        }
        if self.ufw_forward_ipv6 {
            delete_forward_chain_exception(
                "ip6tables",
                "ufw6-before-forward",
                &self.host_interface,
                &self.ns_interface,
            );
        }
        match self.firewall {
            Firewall::IpTables => {
                delete_firewall_rule(
                    &[
                        "iptables",
                        "-D",
                        "FORWARD",
                        "-o",
                        &self.host_interface.name,
                        "-i",
                        &self.ns_interface.name,
                        "-j",
                        "ACCEPT",
                    ],
                    "iptables host output rule",
                );
                delete_firewall_rule(
                    &[
                        "iptables",
                        "-D",
                        "FORWARD",
                        "-i",
                        &self.host_interface.name,
                        "-o",
                        &self.ns_interface.name,
                        "-j",
                        "ACCEPT",
                    ],
                    "iptables host input rule",
                );
                if !self.disable_ipv6 {
                    delete_firewall_rule(
                        &[
                            "ip6tables",
                            "-D",
                            "FORWARD",
                            "-o",
                            &self.host_interface.name,
                            "-i",
                            &self.ns_interface.name,
                            "-j",
                            "ACCEPT",
                        ],
                        "ip6tables host output rule",
                    );
                    delete_firewall_rule(
                        &[
                            "ip6tables",
                            "-D",
                            "FORWARD",
                            "-i",
                            &self.host_interface.name,
                            "-o",
                            &self.ns_interface.name,
                            "-j",
                            "ACCEPT",
                        ],
                        "ip6tables host input rule",
                    );
                }
            }
            Firewall::NfTables => {
                let comment = Self::nft_comment(&self.host_interface.name, &self.ns_interface.name);
                if let Err(error) = delete_nft_rules_with_comment("vopono_bridge", &comment) {
                    warn!("Failed to remove old nftables bridge rules: {error:#}");
                }
            }
        }
    }

    /// Add firewall exception for network namespace to host and vice versa (in case of ufw
    /// running)
    pub fn add_firewall_exception(
        ns_interface: NetworkInterface,
        host_interface: NetworkInterface,
        firewall: Firewall,
        disable_ipv6: bool,
    ) -> anyhow::Result<Self> {
        let mut guard = Self {
            host_interface,
            ns_interface,
            firewall,
            disable_ipv6,
            docker_user_ipv4: false,
            docker_user_ipv6: false,
            ufw_forward_ipv4: false,
            ufw_forward_ipv6: false,
            cleanup_enabled: false,
        };
        guard.cleanup_enabled = true;
        guard.ensure_rules()?;
        Ok(guard)
    }

    fn ensure_rules(&mut self) -> anyhow::Result<()> {
        let (host, ns) = (&self.host_interface, &self.ns_interface);
        match self.firewall {
            Firewall::IpTables => {
                add_forward_chain_exception("iptables", "FORWARD", host, ns)?;
                if !self.disable_ipv6 {
                    add_forward_chain_exception("ip6tables", "FORWARD", host, ns)?;
                }
            }
            Firewall::NfTables => {
                let comment = Self::nft_comment(&host.name, &ns.name);
                let rules = [
                    format!(
                        "iifname \"{}\" oifname \"{}\" counter accept",
                        host.name, ns.name
                    ),
                    format!(
                        "iifname \"{}\" oifname \"{}\" counter accept",
                        ns.name, host.name
                    ),
                ];
                replace_nft_rules(
                    "vopono_bridge",
                    "forward",
                    "{ type filter hook forward priority filter - 10; }",
                    &comment,
                    &rules,
                )?;
                if docker_user_chain_active("iptables") {
                    self.docker_user_ipv4 =
                        add_forward_chain_exception("iptables", "DOCKER-USER", host, ns)?;
                }
                if !self.disable_ipv6 && docker_user_chain_active("ip6tables") {
                    self.docker_user_ipv6 =
                        add_forward_chain_exception("ip6tables", "DOCKER-USER", host, ns)?;
                }
            }
        }
        // An accept in vopono_bridge is not final across later nft base chains.
        // Maintain the corresponding exceptions in active UFW chains, too.
        self.ufw_forward_ipv4 |= add_ufw_forward_exception("iptables", host, ns)?;
        if !self.disable_ipv6 {
            self.ufw_forward_ipv6 |= add_ufw_forward_exception("ip6tables", host, ns)?;
        }
        Ok(())
    }
}

impl Drop for FirewallException {
    fn drop(&mut self) {
        if !self.cleanup_enabled {
            return;
        }
        let _nft_guard = host_nft_lock();
        self.remove_rules();
        if self.firewall == Firewall::NfTables && nft_table_has_no_rules("vopono_bridge") {
            // Delete the shared table only when zero rules remain across all
            // namespaces and users, never based on a single user's lock dir.
            delete_firewall_rule(
                &["nft", "delete", "table", "inet", "vopono_bridge"],
                "nftables namespace bridge table",
            );
        }
    }
}

struct HostNftLockGuard {
    _mutex: std::sync::MutexGuard<'static, ()>,
    _flock_file: Option<std::fs::File>,
}

impl Drop for HostNftLockGuard {
    fn drop(&mut self) {
        if let Some(ref file) = self._flock_file {
            use std::os::fd::AsRawFd;
            unsafe {
                libc::flock(file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

fn host_nft_lock() -> HostNftLockGuard {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    let mutex = LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let flock_file = acquire_cross_process_nft_flock();
    HostNftLockGuard {
        _mutex: mutex,
        _flock_file: flock_file,
    }
}

fn acquire_cross_process_nft_flock() -> Option<std::fs::File> {
    use std::os::fd::AsRawFd;
    let dir = std::path::Path::new("/run/vopono");
    if std::fs::create_dir_all(dir).is_err() {
        return None;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(dir.join("host-nft.lock"))
        .ok()?;
    loop {
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc == 0 {
            return Some(file);
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return None;
        }
    }
}

fn nft_table_has_no_rules(table: &str) -> bool {
    let Ok(listing) = Command::new("nft")
        .args(["-j", "list", "table", "inet", table])
        .output()
    else {
        return false;
    };
    if !listing.status.success() {
        return false;
    }
    let Ok(ruleset) = serde_json::from_slice::<serde_json::Value>(&listing.stdout) else {
        return false;
    };
    let Some(items) = ruleset["nftables"].as_array() else {
        return false;
    };
    !items.iter().any(|item| item.get("rule").is_some())
}

impl FirewallException {
    pub(crate) fn set_cleanup_enabled(&mut self, enabled: bool) {
        self.cleanup_enabled = enabled;
    }
}

fn nft_token(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

/// Delete rules carrying an exact comment from one of vopono's shared tables.
///
/// Comments include the namespace-specific masks/interfaces, so recovery can
/// remove only the old generation without disturbing other namespaces.
fn nft_rule_deletions(table: &str, comment: &str) -> anyhow::Result<String> {
    let listing = Command::new("nft")
        .args(["-j", "list", "table", "inet", table])
        .output()
        .with_context(|| format!("Failed to list nftables table {table}"))?;
    if !listing.status.success() {
        let stderr = String::from_utf8_lossy(&listing.stderr);
        if stderr.contains("No such file or directory")
            || stderr.contains("does not exist")
            || stderr.contains("No such file")
        {
            return Ok(String::new());
        }
        bail!("Failed to list nftables table {table}: {}", stderr.trim());
    }
    let ruleset: serde_json::Value = serde_json::from_slice(&listing.stdout)
        .with_context(|| format!("Invalid nftables JSON for {table}"))?;
    let mut batch = String::new();
    for item in ruleset["nftables"]
        .as_array()
        .with_context(|| format!("Invalid nftables listing for {table}"))?
    {
        let Some(rule) = item.get("rule") else {
            continue;
        };
        if rule["comment"].as_str() != Some(comment) {
            continue;
        }
        let chain = rule["chain"].as_str().context("Missing nftables chain")?;
        ensure_shared_chain(chain)?;
        let handle = rule["handle"].as_u64().context("Missing nftables handle")?;
        batch.push_str(&format!(
            "delete rule inet {table} {chain} handle {handle}\n"
        ));
    }
    Ok(batch)
}

fn delete_nft_rules_with_comment(table: &str, comment: &str) -> anyhow::Result<()> {
    apply_nft_batch(table, &nft_rule_deletions(table, comment)?)
}

fn replace_nft_rules(
    table: &str,
    chain: &str,
    chain_definition: &str,
    comment: &str,
    rules: &[String],
) -> anyhow::Result<()> {
    let _guard = host_nft_lock();
    let deletions = nft_rule_deletions(table, comment)?;
    let mut batch = format!(
        "add table inet {table}\nadd chain inet {table} {chain} {chain_definition}\n{deletions}"
    );
    for rule in rules {
        batch.push_str(&format!(
            "add rule inet {table} {chain} {rule} comment \"{comment}\"\n"
        ));
    }
    // Publish the whole generation in one transaction. Refreshing rules on the
    // same uplink never creates an interval with partially installed policy.
    apply_nft_batch(table, &batch)
}

fn apply_nft_batch(table: &str, batch: &str) -> anyhow::Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let mut file = tempfile::NamedTempFile::new_in("/run")?;
    file.write_all(batch.as_bytes())?;
    let path = file
        .path()
        .to_str()
        .context("Invalid nftables runtime path")?;
    let outcome = Command::new("nft")
        .args(["-f", path])
        .output()
        .context("Failed to apply nftables rule batch")?;
    if !outcome.status.success() {
        bail!(
            "Failed to update nftables rules in {table}: {}",
            String::from_utf8_lossy(&outcome.stderr).trim()
        );
    }
    Ok(())
}

fn ensure_shared_chain(chain: &str) -> anyhow::Result<()> {
    if ["postrouting", "forward"].contains(&chain) {
        Ok(())
    } else {
        bail!("Refusing to delete nftables rule from unexpected chain '{chain}'")
    }
}

/// Delete a firewall rule, treating already-absent rules as success.
///
/// Concurrent teardowns (`vopono stop` racing the session that owns the
/// namespace, or two sessions sharing a host interface) can remove a rule
/// before this Drop runs; iptables/nft report that as a plain failure, which
/// previously surfaced as scary error-level noise during routine cleanup.
fn delete_firewall_rule(command: &[&str], description: &str) {
    let Some((program, args)) = command.split_first() else {
        return;
    };
    let outcome = std::process::Command::new(program).args(args).output();
    match outcome {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let normalized = stderr.to_ascii_lowercase();
            if normalized.contains("bad rule")
                || normalized.contains("matching rule exist")
                || normalized.contains("no such file or directory")
            {
                debug!("Firewall rule already absent during teardown: {description}");
            } else {
                log::warn!("Failed to delete {description}: {}", stderr.trim());
            }
        }
        Err(error) => {
            log::warn!("Failed to run cleanup for {description}: {error}");
        }
    }
}

fn docker_user_chain_active(iptables_cmd: &str) -> bool {
    forward_chain_active(iptables_cmd, "DOCKER-USER")
}

fn ufw_forward_chain(iptables_cmd: &str) -> &str {
    if iptables_cmd == "ip6tables" {
        "ufw6-before-forward"
    } else {
        "ufw-before-forward"
    }
}

fn ufw_forward_chain_active(iptables_cmd: &str) -> bool {
    forward_chain_active(iptables_cmd, ufw_forward_chain(iptables_cmd))
}

fn forward_chain_active(iptables_cmd: &str, chain: &str) -> bool {
    let chain_status = Command::new(iptables_cmd)
        .args(["-S", chain])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !matches!(chain_status, Ok(status) if status.success()) {
        return false;
    }

    let forward = Command::new(iptables_cmd)
        .args(["-S", "FORWARD"])
        .stderr(Stdio::null())
        .output();
    match forward {
        Ok(output) if output.status.success() => {
            let jump = format!("-A FORWARD -j {chain}");
            String::from_utf8_lossy(&output.stdout).contains(&jump)
        }
        _ => false,
    }
}

fn delete_docker_user_exception(
    iptables_cmd: &str,
    host_interface: &NetworkInterface,
    ns_interface: &NetworkInterface,
) {
    sudo_command(&[
        iptables_cmd,
        "-D",
        "DOCKER-USER",
        "-o",
        &host_interface.name,
        "-i",
        &ns_interface.name,
        "-j",
        "ACCEPT",
    ])
    .unwrap_or_else(|e| {
        warn!(
            "Failed to delete {iptables_cmd} DOCKER-USER output rule, host interface: {}, namespace interface: {}: {e}",
            host_interface.name, ns_interface.name
        )
    });

    sudo_command(&[
        iptables_cmd,
        "-D",
        "DOCKER-USER",
        "-i",
        &host_interface.name,
        "-o",
        &ns_interface.name,
        "-j",
        "ACCEPT",
    ])
    .unwrap_or_else(|e| {
        warn!(
            "Failed to delete {iptables_cmd} DOCKER-USER input rule, host interface: {}, namespace interface: {}: {e}",
            host_interface.name, ns_interface.name
        )
    });
}

fn add_ufw_forward_exception(
    iptables_cmd: &str,
    host_interface: &NetworkInterface,
    ns_interface: &NetworkInterface,
) -> anyhow::Result<bool> {
    let chain = ufw_forward_chain(iptables_cmd);
    if !ufw_forward_chain_active(iptables_cmd) {
        return Ok(false);
    }

    add_forward_chain_exception(iptables_cmd, chain, host_interface, ns_interface)
}

fn add_forward_chain_exception(
    iptables_cmd: &str,
    chain: &str,
    host_interface: &NetworkInterface,
    ns_interface: &NetworkInterface,
) -> anyhow::Result<bool> {
    let input = [
        "-i",
        &host_interface.name,
        "-o",
        &ns_interface.name,
        "-j",
        "ACCEPT",
    ];
    let output = [
        "-o",
        &host_interface.name,
        "-i",
        &ns_interface.name,
        "-j",
        "ACCEPT",
    ];
    let added_input = ensure_iptables_rule(iptables_cmd, None, chain, &input)?;
    if let Err(error) = ensure_iptables_rule(iptables_cmd, None, chain, &output) {
        if added_input {
            let mut command = vec![iptables_cmd, "-D", chain];
            command.extend(input);
            delete_firewall_rule(&command, "partially installed forwarding exception");
        }
        return Err(error);
    }
    Ok(true)
}

fn ensure_iptables_rule(
    program: &str,
    table: Option<&str>,
    chain: &str,
    rule: &[&str],
) -> anyhow::Result<bool> {
    let mut command = vec![program];
    if let Some(table) = table {
        command.extend(["-t", table]);
    }
    let operation = command.len();
    command.extend(["-C", chain]);
    command.extend(rule);
    let output = Command::new(program).args(&command[1..]).output()?;
    if output.status.success() {
        return Ok(false);
    }
    anyhow::ensure!(
        output.status.code() == Some(1),
        "Could not check {program} rule in {chain}: {}",
        String::from_utf8_lossy(&output.stderr).trim(),
    );
    command[operation] = "-I";
    sudo_command(&command)?;
    Ok(true)
}

fn delete_forward_chain_exception(
    iptables_cmd: &str,
    chain: &str,
    host_interface: &NetworkInterface,
    ns_interface: &NetworkInterface,
) {
    sudo_command(&[
        iptables_cmd,
        "-D",
        chain,
        "-o",
        &host_interface.name,
        "-i",
        &ns_interface.name,
        "-j",
        "ACCEPT",
    ])
    .unwrap_or_else(|e| {
        warn!(
            "Failed to delete {iptables_cmd} {chain} output rule, host interface: {}, namespace interface: {}: {e}",
            host_interface.name, ns_interface.name
        )
    });

    sudo_command(&[
        iptables_cmd,
        "-D",
        chain,
        "-i",
        &host_interface.name,
        "-o",
        &ns_interface.name,
        "-j",
        "ACCEPT",
    ])
    .unwrap_or_else(|e| {
        warn!(
            "Failed to delete {iptables_cmd} {chain} input rule, host interface: {}, namespace interface: {}: {e}",
            host_interface.name, ns_interface.name
        )
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nft_comments_are_generation_specific() {
        assert_eq!(
            HostMasquerade::nft_comment(Some("10.200.1.0/24"), None, "eth0"),
            "vopono-nat_10_200_1_0_24_-_eth0"
        );
        assert_ne!(
            HostMasquerade::nft_comment(Some("10.200.1.0/24"), None, "eth0"),
            HostMasquerade::nft_comment(Some("10.200.1.0/24"), None, "eth1")
        );
        assert_eq!(
            FirewallException::nft_comment("eth0", "vopono_a_d"),
            "vopono-bridge_eth0_vopono_a_d"
        );
    }

    #[test]
    fn shared_rule_deletion_is_limited_to_known_chains() {
        assert!(ensure_shared_chain("postrouting").is_ok());
        assert!(ensure_shared_chain("forward").is_ok());
        assert!(ensure_shared_chain("output").is_err());
    }
}
