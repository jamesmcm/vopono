use super::netns::NetworkNamespace;
use super::util::{config_dir, sudo_command};
use super::vpn::VpnProvider;
use anyhow::anyhow;
use log::{debug, info, warn};
use rand::seq::SliceRandom;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use walkdir::WalkDir;

#[derive(Serialize, Deserialize)]
pub struct Wireguard {
    ns_name: String,
    config_file: PathBuf,
}

// MTU, PRE_UP, PRE_DOWN, POST_UP, POST_DOWN, TABLE
// Only need interface section

// Wireguard UP:
// PRE_UP hooks
// add_if
// sudo ip link add INTERFACE type wireguard
// set_config
// wg setconf INTERFACE < config
// add_addr
// ip -4 (or -6) address add ADDRESS dev INTERFACE
// set_mtu_up
// if MTU: ip link set mtu MTU up dev INTERFACE
// set_dns
// write to netns resolv.conf
// add_route (from allowed IPs for interface)
// if TABLE: ip -4 route add IP dev INTERFACE table TABLE
// elif */0:  add_default: nftcmd
// POST_UP hooks

// [#] ip link add mullvad-se16 type wireguard
// [#] wg setconf mullvad-se16 /dev/fd/63
// [#] ip -4 address add 10.67.24.207/32 dev mullvad-se16
// [#] ip -6 address add fc00:bbbb:bbbb:bb01::4:18ce/128 dev mullvad-se16
// [#] ip link set mtu 1420 up dev mullvad-se16
// [#] resolvconf -a mullvad-se16 -m 0 -x
// [#] wg set mullvad-se16 fwmark 51820
// [#] ip -6 route add ::/0 dev mullvad-se16 table 51820
// [#] ip -6 rule add not fwmark 51820 table 51820
// [#] ip -6 rule add table main suppress_prefixlength 0
// [#] nft -f /dev/fd/63
// [#] ip -4 route add 0.0.0.0/0 dev mullvad-se16 table 51820
// [#] ip -4 rule add not fwmark 51820 table 51820
// [#] ip -4 rule add table main suppress_prefixlength 0
// [#] sysctl -q net.ipv4.conf.all.src_valid_mark=1
// [#] nft -f /dev/fd/63

// Wireguard DOWN:
// PRE_DOWN hooks
// del_if
// unset_dns
// remove_firewall
// POST_DOWN hooks

impl Wireguard {
    pub fn run(namespace: &mut NetworkNamespace, config_file: PathBuf) -> anyhow::Result<Self> {
        let config_string = std::fs::read_to_string(&config_file)?;
        // Create temp conf file
        {
            let skip_keys = vec![
                "Address",
                "DNS",
                "MTU",
                "Table",
                "PreUp",
                "PreDown",
                "PostUp",
                "PostDown",
                "SaveConfig",
            ];

            let mut f = std::fs::File::create("/tmp/vopono_nft.conf")?;
            write!(
                f,
                "{}",
                config_string
                    .clone()
                    .split("\n")
                    .into_iter()
                    .filter(|x| !skip_keys
                        .contains(&x.split_whitespace().into_iter().nth(0).unwrap_or("")))
                    .collect::<Vec<&str>>()
                    .join("\n")
            )?;
        }
        let re = Regex::new(r"(?P<key>[^\s]+) = (?P<value>[^\s]+)")?;
        let mut config_string = re
            .replace_all(&config_string, "$key = \"$value\"")
            .to_string();
        config_string.push('\n');
        let config: WireguardConfig = toml::from_str(&config_string)?;
        debug!("TOML config: {:?}", config);
        namespace.exec(&["ip", "link", "add", &namespace.name, "type", "wireguard"])?;

        namespace.exec(&["wg", "setconf", &namespace.name, "/tmp/vopono_nft.conf"])?;
        std::fs::remove_file("/tmp/vopono_nft.conf")?;
        // Extract addresses
        for address in config.interface.address.split(",") {
            if address.contains(":") {
                // IPv6
                namespace.exec(&[
                    "ip",
                    "-6",
                    "address",
                    "add",
                    address,
                    "dev",
                    &namespace.name,
                ])?;
            } else {
                // IPv4
                namespace.exec(&[
                    "ip",
                    "-4",
                    "address",
                    "add",
                    address,
                    "dev",
                    &namespace.name,
                ])?;
            }
        }

        // TODO: Handle custom MTU
        namespace.exec(&[
            "ip",
            "link",
            "set",
            "mtu",
            "1420",
            "up",
            "dev",
            &namespace.name,
        ])?;

        namespace.dns_config(&vec![config.interface.dns])?;
        let fwmark = "51820";
        namespace.exec(&["wg", "set", &namespace.name, "fwmark", fwmark])?;
        // IPv6
        namespace.exec(&[
            "ip",
            "-6",
            "route",
            "add",
            "::/0",
            "dev",
            &namespace.name,
            "table",
            fwmark,
        ])?;
        namespace.exec(&[
            "ip", "-6", "rule", "add", "not", "fwmark", fwmark, "table", fwmark,
        ])?;
        namespace.exec(&[
            "ip",
            "-6",
            "rule",
            "add",
            "table",
            "main",
            "suppress_prefixlength",
            "0",
        ])?;

        // nft ipv6
        let nftable = format!("vopono_{}", &namespace.name);
        let pf = "ip6";
        let mut nftcmd: Vec<String> = Vec::with_capacity(16);
        nftcmd.push(format!("add table {} {}", pf, &nftable));
        nftcmd.push(format!(
            "add chain {} {} preraw {{ type filter hook prerouting priority -300; }}",
            pf, &nftable
        ));
        nftcmd.push(format!(
            "add chain {} {} premangle {{ type filter hook prerouting priority -150; }}",
            pf, &nftable
        ));
        nftcmd.push(format!(
            "add chain {} {} postmangle {{ type filter hook prerouting priority -150; }}",
            pf, &nftable
        ));
        for address in config.interface.address.split(",") {
            if address.contains(":") {
                nftcmd.push(format!(
                "add rule {} {} preraw iifname != \"{}\" {} daddr {} fib saddr type != local drop",
                pf, &nftable, &namespace.name, pf, address
            ));
            }
        }
        nftcmd.push(format!(
            "add rule {} {} postmangle meta l4proto udp mark {} ct mark set mark",
            pf, &nftable, fwmark
        ));
        nftcmd.push(format!(
            "add rule {} {} premangle meta l4proto udp meta mark set ct mark",
            pf, &nftable
        ));

        let nftcmd = nftcmd.join("\n");
        {
            let mut f = std::fs::File::create("/tmp/vopono_nft.sh")?;
            write!(f, "{}", nftcmd)?;
        }

        namespace.exec(&["nft", "-f", "/tmp/vopono_nft.sh"])?;
        std::fs::remove_file("/tmp/vopono_nft.sh")?;
        // printf -v nftcmd '%sadd table %s %s\n' "$nftcmd" "$pf" "$nftable"
        // printf -v nftcmd '%sadd chain %s %s preraw { type filter hook prerouting priority -300; }\n' "$nftcmd" "$pf" "$nftable"
        // printf -v nftcmd '%sadd chain %s %s premangle { type filter hook prerouting priority -150; }\n' "$nftcmd" "$pf" "$nftable"
        // printf -v nftcmd '%sadd chain %s %s postmangle { type filter hook postrouting priority -150; }\n' "$nftcmd" "$pf" "$nftable"
        // while read -r line; do
        // 	[[ $line =~ .*inet6?\ ([0-9a-f:.]+)/[0-9]+.* ]] || continue
        // 	printf -v restore '%s-I PREROUTING ! -i %s -d %s -m addrtype ! --src-type LOCAL -j DROP %s\n' "$restore" "$INTERFACE" "${BASH_REMATCH[1]}" "$marker"
        // 	printf -v nftcmd '%sadd rule %s %s preraw iifname != "%s" %s daddr %s fib saddr type != local drop\n' "$nftcmd" "$pf" "$nftable" "$INTERFACE" "$pf" "${BASH_REMATCH[1]}"
        // done < <(ip -o $proto addr show dev "$INTERFACE" 2>/dev/null)
        // printf -v restore '%sCOMMIT\n*mangle\n-I POSTROUTING -m mark --mark %d -p udp -j CONNMARK --save-mark %s\n-I PREROUTING -p udp -j CONNMARK --restore-mark %s\nCOMMIT\n' "$restore" $table "$marker" "$marker"
        // printf -v nftcmd '%sadd rule %s %s postmangle meta l4proto udp mark %d ct mark set mark \n' "$nftcmd" "$pf" "$nftable" $table
        // printf -v nftcmd '%sadd rule %s %s premangle meta l4proto udp meta mark set ct mark \n' "$nftcmd" "$pf" "$nftable"

        // IPv4
        namespace.exec(&[
            "ip",
            "-4",
            "route",
            "add",
            "0.0.0.0/0",
            "dev",
            &namespace.name,
            "table",
            fwmark,
        ])?;
        namespace.exec(&[
            "ip", "-4", "rule", "add", "not", "fwmark", fwmark, "table", fwmark,
        ])?;
        namespace.exec(&[
            "ip",
            "-4",
            "rule",
            "add",
            "table",
            "main",
            "suppress_prefixlength",
            "0",
        ])?;
        sudo_command(&["sysctl", "-q", "net.ipv4.conf.all.src_valid_mark=1"])?;

        //nft ipv4  -TODO: DRY
        let nftable = format!("vopono_{}", &namespace.name);
        let pf = "ip";
        let mut nftcmd: Vec<String> = Vec::with_capacity(16);
        nftcmd.push(format!("add table {} {}", pf, &nftable));
        nftcmd.push(format!(
            "add chain {} {} preraw {{ type filter hook prerouting priority -300; }}",
            pf, &nftable
        ));
        nftcmd.push(format!(
            "add chain {} {} premangle {{ type filter hook prerouting priority -150; }}",
            pf, &nftable
        ));
        nftcmd.push(format!(
            "add chain {} {} postmangle {{ type filter hook prerouting priority -150; }}",
            pf, &nftable
        ));
        for address in config.interface.address.split(",") {
            // TODO: Better split ipv4 and ipv6 cases
            if address.contains(".") {
                nftcmd.push(format!(
                "add rule {} {} preraw iifname != \"{}\" {} daddr {} fib saddr type != local drop",
                pf, &nftable, &namespace.name, pf, address
            ));
            }
        }
        nftcmd.push(format!(
            "add rule {} {} postmangle meta l4proto udp mark {} ct mark set mark",
            pf, &nftable, fwmark
        ));
        nftcmd.push(format!(
            "add rule {} {} premangle meta l4proto udp meta mark set ct mark",
            pf, &nftable
        ));

        let nftcmd = nftcmd.join("\n");
        {
            let mut f = std::fs::File::create("/tmp/vopono_nft.sh")?;
            write!(f, "{}", nftcmd)?;
        }

        namespace.exec(&["nft", "-f", "/tmp/vopono_nft.sh"])?;
        std::fs::remove_file("/tmp/vopono_nft.sh")?;
        Ok(Self {
            config_file,
            ns_name: namespace.name.clone(),
        })
    }
}

impl Drop for Wireguard {
    fn drop(&mut self) {
        // TODO: Handle case of only ipv4
        match sudo_command(&[
            "ip",
            "netns",
            "exec",
            &self.ns_name,
            "ip",
            "link",
            "del",
            &self.ns_name,
        ]) {
            Ok(_) => {}
            Err(e) => warn!("Failed to delete ip link {}: {:?}", &self.ns_name, e),
        };

        match sudo_command(&[
            "ip",
            "netns",
            "exec",
            &self.ns_name,
            "nft",
            "delete",
            "table",
            "ip",
            &format!("vopono_{}", self.ns_name),
        ]) {
            Ok(_) => {}
            Err(e) => warn!(
                "Failed to delete nft ipv4 table: vopono_{}: {:?}",
                self.ns_name, e
            ),
        };

        match sudo_command(&[
            "ip",
            "netns",
            "exec",
            &self.ns_name,
            "nft",
            "delete",
            "table",
            "ip6",
            &format!("vopono_{}", self.ns_name),
        ]) {
            Ok(_) => {}
            Err(e) => warn!(
                "Failed to delete nft ipv6 table: vopono_{}: {:?}",
                self.ns_name, e
            ),
        };
    }
}

pub fn get_config_from_alias(provider: &VpnProvider, alias: &str) -> anyhow::Result<PathBuf> {
    let mut list_path = config_dir()?;
    list_path.push(format!("vopono/{}/wireguard", provider.alias()));
    let paths = WalkDir::new(&list_path)
        .into_iter()
        .filter(|x| x.is_ok())
        .map(|x| x.unwrap())
        .filter(|x| {
            x.path().is_file()
                && x.path().extension().is_some()
                && x.path().extension().expect("No file extension") == "conf"
        })
        .map(|x| {
            (
                x.clone(),
                x.file_name()
                    .to_str()
                    .expect("No filename")
                    .split("-")
                    .into_iter()
                    .nth(1)
                    .expect("No - in filename")
                    .to_string(),
            )
        })
        .filter(|x| x.1.starts_with(alias))
        .map(|x| PathBuf::from(x.0.path()))
        .collect::<Vec<PathBuf>>();

    if paths.len() == 0 {
        Err(anyhow!(
            "Could not find Wireguard config file for alias {}",
            &alias
        ))
    } else {
        let config = paths
            .choose(&mut rand::thread_rng())
            .expect("Could not find Wireguard config");

        info!("Chosen Wireguard config: {}", config.display());
        Ok(config.clone())
    }
}

// TODO: Do we ever have multiple DNS servers?
#[derive(Deserialize, Debug)]
struct WireguardInterface {
    #[serde(rename = "PrivateKey")]
    private_key: String,
    #[serde(rename = "Address")]
    address: String, // TODO Handle IP with mask
    #[serde(rename = "DNS")]
    dns: IpAddr,
}

#[derive(Deserialize, Debug)]
struct WireguardPeer {
    #[serde(rename = "PublicKey")]
    public_key: String,
    #[serde(rename = "AllowedIPs")]
    allowed_ips: String,
    #[serde(rename = "Endpoint")]
    endpoint: SocketAddr,
}

#[derive(Deserialize, Debug)]
pub struct WireguardConfig {
    #[serde(rename = "Interface")]
    interface: WireguardInterface,
    #[serde(rename = "Peer")]
    peer: WireguardPeer,
}
