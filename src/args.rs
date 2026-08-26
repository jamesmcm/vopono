use clap::ValueEnum;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize}; // Import serde traits
use std::fmt::{Debug, Display}; // Import Debug
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use strum::IntoEnumIterator;
use vopono_core::config::providers::VpnProvider;
use vopono_core::config::vpn::Protocol;
use vopono_core::network::firewall::Firewall;
use vopono_core::network::network_interface::NetworkInterface;
use vopono_core::network::trojan::TrojanHost;
use vopono_core::util::hostname_to_ip;

#[derive(Clone, Debug)]
pub struct WrappedArg<T: IntoEnumIterator + Clone + Display> {
    variant: T,
}

// Manual implementation of Serialize/Deserialize to act as a transparent wrapper.
impl<T> Serialize for WrappedArg<T>
where
    T: IntoEnumIterator + Clone + Display + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.variant.serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for WrappedArg<T>
where
    T: IntoEnumIterator + Clone + Display + Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(|variant| WrappedArg { variant })
    }
}

impl<T: IntoEnumIterator + Clone + Display> WrappedArg<T> {
    pub fn new(variant: T) -> Self {
        Self { variant }
    }

    pub fn to_variant(&self) -> T {
        self.variant.clone()
    }
}

impl<T: IntoEnumIterator + Clone + Display> ValueEnum for WrappedArg<T> {
    fn from_str(input: &str, ignore_case: bool) -> core::result::Result<Self, String> {
        let use_input = input.trim().to_string();
        let found = if ignore_case {
            T::iter().find(|x| x.to_string().eq_ignore_ascii_case(&use_input))
        } else {
            T::iter().find(|x| x.to_string() == use_input)
        };
        if let Some(f) = found {
            Ok(WrappedArg { variant: f })
        } else {
            Err(format!("Invalid argument: {input}"))
        }
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        let name: &'static str = Box::leak(self.variant.to_string().into_boxed_str());
        Some(clap::builder::PossibleValue::new(name))
    }

    fn value_variants<'a>() -> &'a [Self] {
        Box::leak(Box::new(
            T::iter()
                .map(|x| WrappedArg { variant: x })
                .collect::<Vec<Self>>(),
        ))
    }
}

#[derive(Parser, Debug)]
#[clap(
    name = "vopono",
    about = "Launch applications in a temporary VPN network namespace",
    version,
    author
)]
pub struct App {
    /// Verbose output
    #[clap(short = 'v', long = "verbose", global = true)]
    pub verbose: bool,

    /// Suppress all output including application output.
    #[clap(long = "silent", global = true)]
    pub silent: bool,

    /// read sudo password from program specified in SUDO_ASKPASS environment variable
    #[clap(short = 'A', long = "askpass", global = true)]
    pub askpass: bool,

    #[clap(subcommand)]
    pub cmd: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    #[clap(
        name = "daemon",
        about = "Run or inspect the privileged root vopono daemon"
    )]
    Daemon(DaemonCommand),
    #[clap(
        name = "exec",
        about = "Execute an application with the given VPN connection"
    )]
    Exec(ExecCommand),
    #[clap(
        name = "check",
        about = "Check network connectivity of a running namespace"
    )]
    Check(CheckCommand),
    #[clap(
        name = "__connectivity-probe",
        about = "Internal TCP probe executed inside a network namespace",
        hide = true
    )]
    Probe(ProbeCommand),
    #[clap(
        name = "__write-user-file",
        about = "Internal dropped-privilege filesystem write helper",
        hide = true
    )]
    WriteUserFile,
    #[clap(
        name = "list",
        about = "List running vopono namespaces and applications"
    )]
    List(ListCommand),
    #[clap(name = "status", about = "Show active namespaces and applications")]
    Status(StatusCommand),
    #[clap(
        name = "providers",
        about = "List provider capabilities and configuration state"
    )]
    Providers(ProvidersCommand),
    #[clap(name = "provider", about = "Inspect a provider")]
    Provider(ProviderCommand),
    #[clap(name = "stop", about = "Stop a running application or namespace")]
    Stop(StopCommand),
    #[clap(
        name = "sync",
        about = "Synchronise local server lists with VPN providers"
    )]
    Synch(SynchCommand),
    #[clap(
        name = "servers",
        about = "List possible server configs for VPN provider, beginning with prefix"
    )]
    Servers(ServersCommand),
}

#[derive(Parser, Debug)]
pub struct DaemonCommand {
    #[clap(subcommand)]
    pub command: Option<DaemonSubcommand>,
}

#[derive(Subcommand, Debug)]
pub enum DaemonSubcommand {
    #[clap(
        name = "start",
        about = "Start the privileged vopono daemon (requires root)"
    )]
    Start,
    #[clap(name = "status", about = "Show daemon health")]
    Status(JsonCommand),
}

#[derive(Parser, Debug, Clone, Copy)]
pub struct JsonCommand {
    /// Emit versioned JSON instead of human-readable output.
    #[clap(long = "json")]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct StatusCommand {
    /// Emit versioned JSON instead of human-readable output.
    #[clap(long = "json")]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct ProvidersCommand {
    /// Emit versioned JSON instead of human-readable output.
    #[clap(long = "json")]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct ProviderCommand {
    #[clap(subcommand)]
    pub command: ProviderSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum ProviderSubcommand {
    #[clap(name = "status", about = "Show provider configuration state")]
    Status(ProviderStatusCommand),
}

#[derive(Parser, Debug)]
pub struct ProviderStatusCommand {
    /// VPN provider.
    #[clap(value_enum, ignore_case = true)]
    pub vpn_provider: WrappedArg<VpnProvider>,

    /// Emit versioned JSON instead of human-readable output.
    #[clap(long = "json")]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct StopCommand {
    #[clap(subcommand)]
    pub target: StopTarget,
}

#[derive(Subcommand, Debug)]
pub enum StopTarget {
    #[clap(name = "application", about = "Stop an application by PID")]
    Application(StopIdCommand),
    #[clap(name = "namespace", about = "Stop a namespace and its applications")]
    Namespace(StopIdCommand),
}

#[derive(Parser, Debug)]
pub struct StopIdCommand {
    /// Application PID or namespace ID.
    pub id: String,

    /// Emit versioned JSON instead of human-readable output.
    #[clap(long = "json")]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct SynchCommand {
    /// VPN Provider - will launch interactive menu if not provided
    #[clap(value_enum, ignore_case = true)]
    pub vpn_provider: Option<WrappedArg<VpnProvider>>,

    /// VPN Protocol (if not given will try to sync both)
    #[clap(value_enum, long = "protocol", short = 'c', ignore_case = true)]
    pub protocol: Option<WrappedArg<Protocol>>,

    /// Emit a versioned JSON result after the interactive sync completes.
    #[clap(long = "json")]
    pub json: bool,
}

#[derive(Parser, Clone, Serialize, Deserialize, Debug)]
pub struct ExecCommand {
    /// VPN Provider (must be given unless using custom config)
    #[clap(value_enum, long = "provider", short = 'p', ignore_case = true)]
    pub provider: Option<WrappedArg<VpnProvider>>,

    /// VPN Protocol (if not given will use default)
    #[clap(value_enum, long = "protocol", short = 'c', ignore_case = true)]
    pub protocol: Option<WrappedArg<Protocol>>,

    /// Network Interface (if not given, will use first active network interface)
    #[clap(long = "interface", short = 'i', ignore_case = true)]
    pub interface: Option<NetworkInterface>,

    /// VPN Server prefix (must be given unless using custom config)
    #[clap(long = "server", short = 's')]
    pub server: Option<String>,

    /// Application to run (should be on PATH or full path to binary)
    pub application: String,

    /// User with which to run the application (default is current user)
    #[clap(long = "user", short = 'u')]
    pub user: Option<String>,

    /// Group with which to run the application
    #[clap(long = "group", short = 'g')]
    pub group: Option<String>,

    /// Working directory in which to run the application (default is current working directory)
    #[clap(long = "working-directory", short = 'w')]
    pub working_directory: Option<String>,

    /// Custom VPN Provider - OpenVPN or Wireguard config file (will override other settings)
    #[clap(long = "custom")]
    pub custom: Option<PathBuf>,

    /// DNS Server (will override provider's DNS server)
    #[clap(long = "dns", short = 'd')]
    pub dns: Option<Vec<IpAddr>>,

    /// List of /etc/hosts entries for the network namespace (e.g. "10.0.1.10 webdav.server01.lan","10.0.1.10 vaultwarden.server01.lan"). For a local host you should also provide the open-hosts option.
    #[clap(long = "hosts", use_value_delimiter = true)]
    pub hosts: Option<Vec<String>>,

    /// List of hostnames or IP addresses to open on the network namespace (comma separated)
    /// hostnames will be resolved locally to IP addresses
    #[clap(
        long = "open-hosts",
        use_value_delimiter = true,
        value_parser(parse_hosts_or_ips)
    )]
    pub open_hosts: Option<Vec<IpAddr>>,

    /// Disable killswitch
    #[clap(long = "no-killswitch")]
    pub no_killswitch: bool,

    /// Keep-alive - do not close network namespace when launched process terminates
    #[clap(long = "keep-alive", short = 'k')]
    pub keep_alive: bool,

    /// List of ports to open on network namespace (to allow port forwarding through the tunnel,
    /// e.g. for BitTorrent, etc.)
    #[clap(long = "open-ports", short = 'o')]
    pub open_ports: Option<Vec<u16>>,

    /// List of ports to forward from network namespace to host - useful for running servers and daemons
    #[clap(long = "forward", short = 'f')]
    pub forward: Option<Vec<u16>>,

    /// Disable proxying to host machine when forwarding ports
    #[clap(long = "no-proxy")]
    pub no_proxy: bool,

    /// Firewall to use
    #[clap(value_enum, long = "firewall", ignore_case = true)]
    pub firewall: Option<WrappedArg<Firewall>>,

    /// Block all IPv6 traffic
    #[clap(long = "disable-ipv6")]
    pub disable_ipv6: bool,

    /// Path or alias to executable PostUp script or binary for commands to run on the host after
    /// bringing up the namespace
    #[clap(long = "postup")]
    pub postup: Option<String>,

    /// Path or alias to executable PreDown script or binary for commands to run on the host after
    /// before shutting down the namespace
    #[clap(long = "predown")]
    pub predown: Option<String>,

    /// Path to vopono config TOML file (will be created if it does not exist)
    /// Default: ~/.config/vopono/config.toml
    #[clap(long = "vopono-config")]
    pub vopono_config: Option<PathBuf>,

    /// Attach to an existing network namespace by name (e.g. vo_ar_romania)
    /// instead of creating a new connection. Namespaces created by vopono are
    /// used as-is; foreign namespaces are attached without modifying them and
    /// are left running on exit. Provider, protocol, server and custom config
    /// options are ignored.
    #[clap(
        long = "existing-netns",
        conflicts_with_all = &["provider", "protocol", "server", "custom", "custom_netns_name"]
    )]
    pub existing_netns: Option<String>,

    /// Custom name for the generated network namespace
    /// Will use this network namespace directly if it exists
    #[clap(long = "custom-netns-name")]
    pub custom_netns_name: Option<String>,
    /// Allow access to host from network namespace
    /// Useful for accessing services on the host locally
    #[clap(long = "allow-host-access")]
    pub allow_host_access: bool,

    /// Enable port forwarding for if supported
    #[clap(long = "port-forwarding")]
    pub port_forwarding: bool,

    /// Port forwarding implementation to use for custom config file with --custom-config
    #[clap(long = "custom-port-forwarding", ignore_case = true)]
    pub custom_port_forwarding: Option<WrappedArg<VpnProvider>>,

    /// Path or alias to executable script or binary to be called with the port as an argumnet
    /// when the port forwarding is refreshed (PIA only)
    #[clap(long = "port-forwarding-callback")]
    pub port_forwarding_callback: Option<String>,

    /// Only create network namespace (does not run application)
    #[clap(long = "create-netns-only")]
    pub create_netns_only: bool,

    /// Trojan server address - hostname or IP, will not verify SSL if IP address is given.
    /// Port is optional (default is 443).
    #[clap(long = "trojan-host")]
    pub trojan_host: Option<TrojanHost>,

    /// Trojan server password
    /// Set this in ~/.config/vopono/vopono.toml or use --trojan-config
    /// to avoid setting this in the command line
    #[clap(long = "trojan-password")]
    pub trojan_password: Option<String>,

    /// Disable SSL verification for Trojan server
    #[clap(long = "trojan-no-verify")]
    pub trojan_no_verify: bool,

    /// Trojan config file (will override other settings)
    #[clap(long = "trojan-config")]
    pub trojan_config: Option<PathBuf>,

    /// Local SOCKS5 port for SSH dynamic forwarding
    #[clap(long = "ssh-proxy-port")]
    pub ssh_proxy_port: Option<u16>,

    /// Username for the remote SSH server
    #[clap(long = "ssh-user")]
    pub ssh_user: Option<String>,

    /// Port of the remote SSH server
    #[clap(long = "ssh-port")]
    pub ssh_port: Option<u16>,

    /// Emit a machine-readable launch report (namespace, PID, forwarded port)
    /// as the first line on stdout.
    #[clap(long = "json")]
    pub json: bool,

    /// Suppress the application's output when executed through the daemon.
    /// Set client-side in `forward_to_daemon`; not a CLI flag of its own.
    #[clap(skip)]
    #[serde(default)]
    pub silent: bool,
}

#[derive(Parser, Debug)]
pub struct CheckCommand {
    /// Network namespace ID (as shown by `vopono status`)
    pub id: String,

    /// TCP port used for both family checks
    #[clap(long = "port", default_value_t = crate::check::DEFAULT_CHECK_PORT)]
    pub port: u16,

    /// Connection timeout in milliseconds per family
    #[clap(long = "timeout-ms", default_value_t = crate::check::DEFAULT_TIMEOUT_MS)]
    pub timeout_ms: u64,

    /// IPv4 target to connect to
    #[clap(long = "v4-host")]
    pub v4_host: Option<String>,

    /// IPv6 target to connect to
    #[clap(long = "v6-host")]
    pub v6_host: Option<String>,

    /// Skip the IPv4 connectivity check
    #[clap(long = "skip-ipv4")]
    pub skip_ipv4: bool,

    /// Skip the IPv6 connectivity check
    #[clap(long = "skip-ipv6")]
    pub skip_ipv6: bool,

    /// Hostname resolved via the namespace's own DNS configuration
    #[clap(long = "dns-host")]
    pub dns_host: Option<String>,

    /// Skip the DNS resolution check
    #[clap(long = "skip-dns")]
    pub skip_dns: bool,

    /// Emit versioned JSON instead of human-readable output.
    #[clap(long = "json")]
    pub json: bool,
}

/// Hidden helper executed inside a network namespace by the connectivity
/// check. Probes each enabled address family plus optional DNS resolution and
/// exits 0/1.
#[derive(Parser, Debug)]
pub struct ProbeCommand {
    #[clap(long = "v4-host")]
    pub v4_host: Option<String>,

    #[clap(long = "v6-host")]
    pub v6_host: Option<String>,

    #[clap(long = "port")]
    pub port: u16,

    #[clap(long = "timeout-ms")]
    pub timeout_ms: u64,

    #[clap(long = "dns-host")]
    pub dns_host: Option<String>,

    #[clap(long = "skip-ipv4")]
    pub skip_ipv4: bool,

    #[clap(long = "skip-ipv6")]
    pub skip_ipv6: bool,

    #[clap(long = "skip-dns")]
    pub skip_dns: bool,
}

#[derive(Parser, Debug)]
pub struct ListCommand {
    /// VPN Provider
    #[clap(value_enum)]
    pub list_type: Option<ListType>,

    /// Emit versioned JSON instead of human-readable output.
    #[clap(long = "json")]
    pub json: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ListType {
    Namespaces,
    Applications,
}

#[derive(Parser, Debug)]
pub struct ServersCommand {
    /// VPN Provider
    #[clap(value_enum, ignore_case = true)]
    pub vpn_provider: WrappedArg<VpnProvider>,

    /// VPN Protocol (if not given will list all)
    #[clap(value_enum, long = "protocol", short = 'c', ignore_case = true)]
    pub protocol: Option<WrappedArg<Protocol>>,

    /// VPN Server prefix
    #[clap(long = "prefix", short = 's')]
    pub prefix: Option<String>,

    /// Optional country code/name filter.
    #[clap(long = "country")]
    pub country: Option<String>,

    /// Emit versioned JSON instead of human-readable output.
    #[clap(long = "json")]
    pub json: bool,
}

fn parse_host_or_ip(arg: &str) -> anyhow::Result<IpAddr> {
    if let Ok(ip) = IpAddr::from_str(arg) {
        return Ok(ip);
    }

    Ok(hostname_to_ip(arg)?
        .into_iter()
        .next()
        .expect("Failed to resolve hostname"))
}

/// Parse a list of hosts/IPs separated by comma
fn parse_hosts_or_ips(arg: &str) -> anyhow::Result<IpAddr> {
    parse_host_or_ip(arg.trim()).map_err(|e| anyhow::anyhow!("Failed to parse host or IP: {}", e))
}

#[cfg(test)]
mod tests {
    use super::{App, Command, DaemonSubcommand, ListType};
    use clap::Parser;
    use vopono_core::config::vpn::Protocol;

    #[test]
    fn parses_ssh_dynamic_proxy_options() {
        let app = App::try_parse_from([
            "vopono",
            "exec",
            "--protocol",
            "ssh",
            "--server",
            "work-proxy",
            "--ssh-proxy-port",
            "9080",
            "--ssh-user",
            "gopostal",
            "--ssh-port",
            "2222",
            "curl example.com",
        ])
        .unwrap();

        let Command::Exec(command) = app.cmd.unwrap() else {
            panic!("expected exec command");
        };
        assert_eq!(command.protocol.unwrap().to_variant(), Protocol::Ssh);
        assert_eq!(command.server.as_deref(), Some("work-proxy"));
        assert_eq!(command.ssh_proxy_port, Some(9080));
        assert_eq!(command.ssh_user.as_deref(), Some("gopostal"));
        assert_eq!(command.ssh_port, Some(2222));
    }

    #[test]
    fn daemon_without_subcommand_is_the_daemon_start_command() {
        let app = App::try_parse_from(["vopono", "daemon"]).unwrap();
        let Command::Daemon(command) = app.cmd.unwrap() else {
            panic!("expected daemon command");
        };
        assert!(command.command.is_none());
    }

    #[test]
    fn daemon_status_is_a_subcommand() {
        let app = App::try_parse_from(["vopono", "daemon", "status", "--json"]).unwrap();
        let Command::Daemon(command) = app.cmd.unwrap() else {
            panic!("expected daemon command");
        };
        assert!(matches!(
            command.command,
            Some(DaemonSubcommand::Status(status)) if status.json
        ));
    }

    #[test]
    fn daemon_start_is_an_explicit_alias_for_the_bare_command() {
        let app = App::try_parse_from(["vopono", "daemon", "start"]).unwrap();
        let Command::Daemon(command) = app.cmd.unwrap() else {
            panic!("expected daemon command");
        };
        assert!(matches!(command.command, Some(DaemonSubcommand::Start)));
    }

    #[test]
    fn list_type_is_typed() {
        let app = App::try_parse_from(["vopono", "list", "namespaces", "--json"]).unwrap();
        let Command::List(command) = app.cmd.unwrap() else {
            panic!("expected list command");
        };
        assert!(matches!(command.list_type, Some(ListType::Namespaces)));
        assert!(command.json);
    }

    #[test]
    fn existing_netns_rejects_connection_settings() {
        for extra in [
            vec!["--provider", "mullvad"],
            vec!["--protocol", "wireguard"],
            vec!["--server", "se"],
            vec!["--custom", "/tmp/foo.conf"],
            vec!["--custom-netns-name", "vo_x"],
        ] {
            let mut argv = vec!["vopono", "exec", "--existing-netns", "vo_ar_romania"];
            argv.extend(extra);
            argv.push("firefox");
            assert!(
                App::try_parse_from(argv).is_err(),
                "expected conflict error"
            );
        }
    }

    #[test]
    fn existing_netns_parses_standalone() {
        let app = App::try_parse_from([
            "vopono",
            "exec",
            "--existing-netns",
            "vo_ar_romania",
            "firefox",
        ])
        .unwrap();
        let Command::Exec(command) = app.cmd.unwrap() else {
            panic!("expected exec command");
        };
        assert_eq!(command.existing_netns.as_deref(), Some("vo_ar_romania"));
        assert!(command.provider.is_none());
        assert!(command.protocol.is_none());
    }

    #[test]
    fn check_defaults_and_json() {
        let app = App::try_parse_from(["vopono", "check", "vo_ar_romania", "--json"]).unwrap();
        let Command::Check(command) = app.cmd.unwrap() else {
            panic!("expected check command");
        };
        assert_eq!(command.id, "vo_ar_romania");
        assert_eq!(command.v4_host, None);
        assert_eq!(command.v6_host, None);
        assert!(!command.skip_ipv4);
        assert!(!command.skip_ipv6);
        assert_eq!(command.port, crate::check::DEFAULT_CHECK_PORT);
        assert_eq!(command.timeout_ms, crate::check::DEFAULT_TIMEOUT_MS);
        assert_eq!(command.dns_host, None);
        assert!(!command.skip_dns);
        assert!(command.json);
    }

    #[test]
    fn provider_values_parse_case_insensitively() {
        for spelling in ["airvpn", "AirVPN", "AIRVPN", "aIrVpN"] {
            let app =
                App::try_parse_from(["vopono", "exec", "-p", spelling, "-c", "None", "x"]).unwrap();
            let Command::Exec(command) = app.cmd.unwrap() else {
                panic!("expected exec command");
            };
            assert_eq!(
                command.provider.unwrap().to_variant(),
                vopono_core::config::providers::VpnProvider::AirVPN
            );
        }
    }
}
