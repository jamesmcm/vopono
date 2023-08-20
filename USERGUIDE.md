# vopono User Guide

## asciinema example

[![asciicast](https://asciinema.org/a/369367.png)](https://asciinema.org/a/369367)

## Usage

Applications will be run as the current user by default (you can use
`vopono exec sudo -u USERNAME program` as the command to run as another user).

vopono will call sudo if required, it is recommended to run as the
current user and let vopono call sudo so that the configuration
directories are correctly inferred and the final command is not run as
root.

Note that child processes of the application will also be spawned inside
the network namespace and so use the same VPN connection, so you can run
entire shell sessions inside vopono.

Note that the order of command-line arguments matters, as the `--dns`
argument can take a list of DNS servers for example.

### Configuration file

You can save default configuration options in the config file
`~/.config/vopono/config.toml` (or in the respective `$XDG_CONFIG/vopono/`
directory).

Here is an example:

```toml
firewall = "NfTables"
provider = "Mullvad"
protocol = "Wireguard"
server = "usa-us22"
postup = "/home/archie/postup.sh"
predown = "/home/archie/predown.sh"
user = "archie"
dns = "8.8.8.8"
# custom_config = "/home/user/vpn/mycustomconfig.ovpn"
```

Note that the values are case-sensitive. If you use a custom config file
then you should not set the provider or server (setting the protocol is
also optional).

The current network namespace name is provided to the PostUp and PreDown
scripts in the environment variable `$VOPONO_NS`. It is temporarily set
when running these scripts only.

Similarly, the network namespace IP address is provided via `$VOPONO_NS_IP`,
and is available to the PostUp and PreDown scripts, and the application to
run itself. `$VOPONO_NS_IP` is useful if you'd like to configure a server
running within the network namespace to listen on its local IP address only
(see below, for more information on that).

The application to run within the namespace also has access to
`$VOPONO_HOST_IP`, to get the IP address of the host.

Note: These environment variables are currently only available from within
the application/script to run, not on the command line. So the following
doesn't work:

`vopono exec {other Vopono options} 'echo "HOST IP: $VOPONO_HOST_IP"'`

Output: `HOST IP: $VOPONO_HOST_IP` (the environ variable wasn't expanded).

A work around is to create a executable script, that executes the 
application you'd like to run:

```bash
#!/bin/bash

echo "=> NETWORK NAMESPACE IP: $VOPONO_NS_IP"
echo "=> HOST IP: $VOPONO_HOST_IP"
```

Execution: `vopono exec {other Vopono options} '/path/to/the/above/script.sh'`

Output:

```
=> NETWORK NAMESPACE IP: 10.200.1.2
=> HOST IP: 10.200.1.1
```

### Host scripts

Host scripts to run just after a network namespace is created and just before it is destroyed,
can be provided with the `postup` and `predown` arguments (or in the `config.toml`).

Note these scripts run on the host (outside the network namespace), using the current working directory,
and with the same user as the final application itself (which can be set
with the `user` argument or config file entry).

Script arguments (e.g. `script.sh arg1 arg1`), are currently not possible, resulting in an error:

```
$ vopono exec {other Vopono options} --postup 'echo POSTUP' ls
[...]
sudo: echo POSTUP: command not found
[...]
```

### Wireguard

Install vopono and use `vopono sync` to
create the Wireguard configuration files (and generate a keypair if
necessary):

```bash
$ yay -S vopono-git
$ vopono sync
```

Run vopono:

```bash
$ vopono exec --provider mullvad --server sweden --protocol wireguard "transmission-gtk"
```

The server prefix will be searched against available servers (and
country names) and a random one will be chosen (and reported in the terminal).

Note that vopono expects the `AllowedIPs` setting to allow all traffic,
since all traffic in the vopono network namespace will be forced through
this tunnel (traffic via the host is deliberately blocked to enforce the
killswitch). e.g. it should be `AllowedIPs = 0.0.0.0/0,::/0`

#### Custom Settings

The sync menu will prompt you for any custom settings (i.e. ports used,
and connection protocol for OpenVPN, etc.)

Valid ports for Mullvad Wireguard are: 53, 4000-33433, 33565-51820 and 52000-60000.
The same is true for MozillaVPN since it is mostly a wrapper around Mullvad's
Wireguard services.

### OpenVPN

Install vopono and use `vopono sync` to
create the OpenVPN configuration files and server lists.

```bash
$ yay -S vopono-git
$ vopono sync
```

Run vopono:

```bash
$ vopono exec --provider privateinternetaccess --server poland "curl ifconfig.co/country"
Poland
```

You can also launch graphical applications like `firefox`,
`transmission-gtk`, etc. - the network namespace will be cleaned up when
the application is terminated. Note you may need to run them as your own
user:

```bash
$ vopono exec --provider privateinternetaccess --server mexico "firefox"
```

The server prefix will be searched against available servers (both
server names and aliases in the provider's configuration files) and a
random one will be chosen (and reported in the terminal).

The sync process will save your credentials to a file in the
config directory of the provider, so it can be passed to OpenVPN.
If it is missing you will be prompted for your credentials.

For PrivateInternetAccess, HMA (HideMyAss) and AzireVPN these should be the same as your account
credentials.

For Mullvad your OpenVPN credentials are your account code as your username, and `m` as the password.

For ProtonVPN you can view your OpenVPN credentials [online on your account dashboard](https://account.protonvpn.com/account#openvpn).
The OpenVPN credentials are **not** the same as your ProtonVPN account credentials.

For AirVPN the OpenVPN connection uses a key embedded in the config
files, however you will need to provide your AirVPN API key and enable
API access in [the client area webpage](https://airvpn.org/apisettings/) when running `vopono sync`.
Note that ports for forwarding must also be added in [the client area webpage](https://airvpn.org/ports/), 
and it is also possible to configure the VPN tunnel [DNS settings there](https://airvpn.org/dns/).

#### Connection / hostname resolution issues

If you face issues with OpenVPN resolving the remote host, try generating the VPN provider config files with IP addresses instead.

e.g. the error may appear as follows:

```
2023-01-06 13:19:18 RESOLVE: Cannot resolve host address: ro-buh-ovpn-002.mullvad.net:1197 (Name or service not known)
```

#### TCP support and custom ports

By default vopono uses the UDP configuration of the VPN providers.

You can use the TCP configurations by running `vopono sync` and choosing
that option from the provider configuration.

For Mullvad, valid ports are: 1300, 1301, 1302, 1194, 1195, 1196, 1197, or 53 for UDP, and
80 or 443 for TCP,

For PrivateInternetAccess valid ports are 1198 for UDP and 502 for TCP.

#### Shadowsocks socks-proxy

Mullvad supports proxying via Shadowsocks, if that configuration is
chosen with `vopono sync`. Note you must use a TCP connection on port
443 in this case.

Respond with `Y` when asked `Connect via a bridge?` during the `vopono sync` configuration for Mullvad OpenVPN to enable this configuration. It
is not used by default.

If you are using a custom provider config file, you must run the socks
proxy server yourself (i.e. `ss-local`) if using a socks-proxy.

### Custom Providers

If you use another commercial VPN provider, please open a Pull Request here with
the necessary configuration and serverlist.

For private VPN connections, you can use a custom provider, by passing
the complete configuration file to vopono (i.e. an OpenVPN .ovpn config
file or a Wireguard wg-quick .conf file).

```bash
$ vopono -v exec --custom ~/custom_wireguard.conf --protocol wireguard "firefox"
```

```bash
$ vopono -v exec --custom ./custom_openvpn.ovpn --protocol openvpn "firefox"
```
> To use a custom provider which requires a username and password, supply an authentication file with the username and password.
> Reference the authentication file in the ovpn configuration file with `auth-user-pass auth.txt` appended to the top of the file.

Note that in the OpenVPN case the vopono will execute OpenVPN from the same
directory as the config file itself. So any accompanying files (CA certificates, authentication
files, etc.) must be in the same directory with the file if using
relative paths in the config file.



### OpenFortiVPN

OpenFortiVPN is supported as a custom provider, allowing you to connect
to Fortinet VPN servers.

To use it, first create an [OpenFortiVPN](https://github.com/adrienverge/openfortivpn) config file for your
connection, such as:

`myvpn.conf`:
```
host = vpn.company.net
port = 443
username = myuser
password = mypassword
set-dns = 0
pppd-use-peerdns = 0
pppd-log = /tmp/pppd.log
```

You must set `set-dns` and `pppd-use-peerdns` to `0` so that
OpenFortiVPN does not try to change the global DNS settings (vopono will
set them within the network namespace). You __must__ include the line:
`pppd-log = /tmp/pppd.log` as vopono uses this to read the pppd output
directly.

Then run vopono using this as the custom config file and specifying
`OpenFortiVPN` as the protocol. Note that if you do not specify your
password in the OpenFortiVPN config file then you must enter it when it
is waiting to connect (you will not be prompted).

```bash
vopono -v exec --protocol OpenFortiVPN --custom /home/user/myvpn.conf firefox
```

### Firefox

Note if running multiple Firefox sessions, they need to run separate
profiles in order to force Firefox to run them as separate processes.

Trying to run Firefox normally when there is already an instance running
will result in a silent error.

You should also disable DNS over HTTPS as this will send all DNS
requests to Cloudflare by default. Firefox Options > General >
Network settings > Settings, then deselect `Enable DNS over HTTPS`.

You may also wish to disable WebRTC - see
[Mullvad's guide](https://mullvad.net/en/help/webrtc/) for more details.

Similar issues apply to Chromium and Google Chrome, where you must provide a 
different `user-data-dir` in order to force it to use a separate process:

```bash
$ chromium --user-data-dir=/tmp/profile-2
```

### Daemons and servers

If running servers and daemons inside of vopono, you can you use the
`-f $PORT` argument to allow incoming connections to a TCP port inside the namespace, by default this
port will also be proxied to your host machine at the same port number.
Note for same daemons you may need to use the `-k` keep-alive option in
case the process ID changes (you will then need to manually kill the
daemon after finishing).

#### transmission-daemon

For example, to launch `transmission-daemon` that is externally
accessible at `127.0.0.1:9091` (with outward connections via AzireVPN with Wireguard and a VPN server in Norway):

```bash
$ vopono -v exec -k -f 9091 --provider azirevpn --server norway "transmission-daemon -a *.*.*.*"
```

Note in the case of `transmission-daemon` the `-a *.*.*.*` argument is
required to allow external connections to the daemon's web portal (your
host machine will now count as external to the network namespace).

Instead of listening on `*.*.*.*` you also can listen on `$VOPONO_NS_IP`,
to listen on an IP address that is only reachable from the same machine,
the network namespace runs on.

When finished with vopono, you must manually kill the
`transmission-daemon` since the PID changes (i.e. use `killall`).

#### Jackett

The same approach also works for [Jackett](https://github.com/Jackett/Jackett), e.g. with the setup from
the [AUR PKGBUILD](https://aur.archlinux.org/packages/jackett-bin) (a separate `jackett` user and hosting on port `9117`):

```bash
$ vopono -v exec -u jackett "/usr/lib/jackett/jackett --NoRestart --NoUpdates --DataFolder /var/lib/jackett" -f 9117
```

You can then access the web UI on the host machine at `http://127.0.0.1:9117/UI/Dashboard`, but all of Jackett's connections will go via the VPN.

#### Proxy to host

By default, vopono runs a small TCP proxy to proxy the ports on your
host machine to the ports on the network namespace - if you do not want
this to run use the `--no-proxy` flag.

In this case, you can read the IP of the network namespace from the
terminal, or use `$VOPONO_NS_IP` to get it (e.g. to use it in a script).

#### systemd service

For the above you may want to run vopono as a systemd service. If your
user has passwordless sudo access you can use a user service, such as:

`/etc/systemd/user/vopono.service`:
```
[Service]
ExecStart=/usr/bin/vopono -v exec -k -f 9091 --protocol wireguard --provider mullvad --server romania "transmission-daemon -a *.*.*.*"
```

And then start it with (no sudo):
```
systemctl start --user vopono
```

If you do not have passwordless sudo access (i.e. privilege escalation
requires entering the password) then you could use a root service and
set up vopono on the root account. But note [this issue](https://github.com/jamesmcm/vopono/issues/84) currently
makes this problematic for forwarding ports.

#### Privoxy

A popular use case is to run a proxy server like Privoxy inside the
namespace with vopono, and then just configure Firefox, etc. to use that
(so it connects via the VPN). This saves having to use Docker or LXC,
etc. to do this otherwise.

Here is an example using AzireVPN and Wireguard (where the privoxy user
was already created in the normal installation process):

```bash
$ vopono -v exec --provider azirevpn -k -u root -f 8118 --server norway  "privoxy --chroot --user privoxy /etc/privoxy/config"
```

Note we need to specify `-u root` so that privoxy has the permissions to
chroot later.

Port 8118 is then forwarded to the local host, so you can use the proxy
server normal. Note that just like with the transmission-daemon example
above, Privoxy **must** be configured to allow remote connections,
specifically in the config file you must **not** specify an IP address in
the `listen-address`:

```
listen-address :8118
```

Note that since the daemon forks to a new PID and does not set the
parent PID, you must use the `-k` option to keep vopono alive and then
manually kill Privoxy when finished with `sudo killall privoxy`.

If you have a better solution for handling the PIDs of daemons please
create an issue / Pull Request!

### Listing running namespaces and applications

The `vopono list` command lists running applications and namespaces, as
a tab separated table:

```bash
$ vopono list namespaces
namespace       provider        protocol        num_applications        uptime
vopono_tig_us_losangeles        TigerVpn        OpenVpn 2       28s

$ vopono list applications
namespace       provider        protocol        application     uptime
vopono_tig_us_losangeles        TigerVpn        OpenVpn firefox 36s
vopono_tig_us_losangeles        TigerVpn        OpenVpn lynx    15s
```

### Listing possible servers

The `--server` argument is actually a prefix,
and you can see all possibilities for a given prefix and provider with:

```bash
$ vopono servers mullvad --prefix usa
provider        protocol        config_file
Mullvad openvpn usa-us.ovpn
Mullvad wireguard       usa-us40.conf
Mullvad wireguard       usa-us145.conf
Mullvad wireguard       usa-us52.conf
...
```

## VPN Provider specific details

Mullvad users can use [mullvad.net/en/check](https://mullvad.net/en/check/) to
check the security of their browser's connection. This was used with the
Mullvad configuration to verify that there is no DNS leaking or
BitTorrent leaking for both the OpenVPN and Wireguard configurations.

AzireVPN users can use [their security check page](https://www.azirevpn.com/check)
for the same (note the instructions on disabling WebRTC). I noticed that
when using IPv6 with OpenVPN it incorrectly states you are not connected
via AzireVPN though (Wireguard works correctly).

ProtonVPN users must log-in to the dashboard via a web browser during
the `vopono sync` process in order to copy the `AUTH-*` cookie to
access the OpenVPN configuration files, and the OpenVPN specific
credentials to use them.

### VPN Provider limitations

#### ProtonVPN

Due to the way Wireguard configuration is handled, this should be
generated online and then used as a custom configuration, e.g.:

```bash
$ vopono -v exec --provider custom --custom testwg-UK-17.conf --protocol wireguard firefox-developer-edition
```

Note that port forwarding is currently not supported for ProtonVPN.

#### PrivateInternetAccess

Wireguard support for PrivateInternetAccess (PIA) requires the use of a
user token to get the latest servers at time of use. See [issue 9](https://github.com/jamesmcm/vopono/issues/9) for details,
and PIA's [official script for Wireguard access](https://github.com/pia-foss/manual-connections/blob/master/connect_to_wireguard_with_token.sh).

So if you encounter connection issues, first try re-running `vopono sync`.

#### MozillaVPN

There is no easy way to delete MozillaVPN devices (Wireguard keypairs),
unlike Mullvad this _cannot_ be done on the webpage.
I recommend using [MozWire](https://github.com/NilsIrl/MozWire) to manage this.

#### iVPN

iVPN Wireguard keypairs must be uploaded manually, as the Client Area is
behind a captcha login.

#### NordVPN
Starting 27 June 2023, the required user credentials are no longer your NordVPN login details but need to be generated in the user control panel, under Services → NordVPN. Scroll down and locate the Manual Setup tab, then click on Set up NordVPN manually and follow instructions. Copy your service credentials and re-sync NordVPN configuration inside Vopono.

### Tunnel Port Forwarding

Some providers allow port forwarding inside the tunnel, so you can open
some ports inside the network namespace which can be accessed via the
Wireguard/OpenVPN tunnel (this can be important for BitTorrent
connectivity, etc.).

For iVPN port forwarding also works the same way, however it is **only
supported for OpenVPN** on iVPN's side. So remember to pass
`--protocol openvpn -o PORTNUMBER` when trying it! Enable port
forwarding in the [Port Forwarding page in the iVPN client area](https://www.ivpn.net/clientarea/vpn/273887).

For AirVPN you must enable the port in [the client area webpage](https://airvpn.org/ports/),
and then use `--protocol openvpn -o PORTNUMBER` as for iVPN.

## Dependencies

At the moment, either iptables or nftables is required (the firewall
choice can be chosen with the `--firewall` argument).

OpenVPN must be installed for using OpenVPN providers, and wireguard-tools must be
installed for using Wireguard providers.

shadowsocks-libev must be installed for Shadowsocks support (Mullvad OpenVPN bridges).

## Troubleshooting

If you have any issues please create a Github issue with details of the
problem.

If the issue is networking related, please include the output of the
following commands. On the host machine:

```bash
ip addr
ip link
ping 10.200.1.2
sudo nft list tables
sudo nft list table nat
sudo iptables -t nat -L
```

And on the network namespace, replacing `vopono_*` with your specific generated
namespace name e.g. `vopono_azire_norway`:

```bash
sudo ip netns exec vopono_* ip addr
sudo ip netns exec vopono_* ip link
sudo ip netns exec vopono_* nft list tables
sudo ip netns exec vopono_* nft list table vopono_*
sudo ip netns exec vopono_* iptables -L
sudo ip netns exec ping 10.200.1.1
sudo ip netns exec ping 8.8.8.8
```

See issues #40, #24, #2, and #1 for previous troubleshooting of issues.

### DNS / name resolution issues

When encountering issues in name resolution (e.g. with OpenVPN resolving remote host names), please
first try generating the VPN provider config files with IP addresses instead to see whether the issue
is connection/firewall related or solely a DNS / hostname resolution issue.
