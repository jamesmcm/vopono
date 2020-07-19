# vopono

vopono is a tool to run applications through VPN tunnels via temporary
network namespaces. This allows you to run only a handful of
applications through different VPNs simultaneously, whilst keeping your main connection
as normal.

vopono includes built-in killswitches for both Wireguard and OpenVPN.

Currently only Mullvad, TigerVPN and
PrivateInternetAccess are supported directly, with custom configuration files
also supported with the `--custom` argument.

Mullvad users can use [am.i.mullvad.net](https://am.i.mullvad.net/) to
check the security of their browser's connection. This was used with the
Mullvad configuration to verify that there is no DNS leaking or
BitTorrent leaking for both the OpenVPN and Wireguard configurations.

Mullvad port forwarding works for both Wireguard and OpenVPN. You will
need to enable the ports in your [Mullvad account](https://mullvad.net/en/account/#/ports).

At the moment, both iptables and nftables are required.

## Screenshot

Screenshot showing an example with firefox, google-chrome-stable and
lynx all running through different VPN connections:

![Screenshot](screenshot.png)

## Supported Providers

| Provider              | OpenVPN support | Wireguard support | 
|-----------------------|-----------------|-------------------|
| Mullvad               | ✅              | ✅                |
| PrivateInternetAccess | ✅              | ❌                |
| TigerVPN              | ✅              | ❌                |

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
$ vopono exec --provider mullvad --server se --protocol wireguard "transmission-gtk"
```

The server prefix will be searched against available servers (and
country names) and a random one will be chosen (and reported in the terminal).

#### Custom Port

Note you can set a custom port in the Wireguard configuration by running
`vopono sync` with the `--port` argument:

```bash
$ vopono sync --protocol wireguard --port 31337
```

Valid ports for Mullvad Wireguard are: 53, 4000-33433, 33565-51820 and 52000-60000.

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
server names and aliases in the provider's `serverlist.csv`) and a
random one will be chosen (and reported in the terminal).

Place your username and password in
`~/.config/vopono/pia/openvpn/auth.txt` - the username on the first
line, and the password on the second (with a newline). Otherwise you
will be prompted for your credentials.

For PrivateInternetAccess these should be the same as your account
credentials.

For TigerVPN you can view your OpenVPN credentials [online on the "geeks" dashboard](https://www.tigervpn.com/dashboard/geeks).
The OpenVPN credentials are **not** the same as your TigerVPN account credentials.

For Mullvad your OpenVPN credentials are your account code as your username, and `m` as the password.

#### TCP support and custom ports

By default vopono uses the UDP configuration of the VPN providers.

You can use the TCP configurations by running `vopono sync` with the
`--port` argument where the port is a valid TCP port for this provider:

```bash
$ vopono sync --protocol openvpn --port 443 mullvad
```

For Mullvad, valid ports are: 1300, 1301, 1302, 1194, 1195, 1196, 1197, or 53 for UDP, and 
80 or 443 for TCP,

For PrivateInternetAccess valid ports are 1198 for UDP and 502 for TCP.

For TigerVPN valid ports are 1194 for UDP or 443 for TCP.

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

Note that in the OpenVPN case the command must be executed in the same
directory as any accompanying files (CA certificates, authentication
files, etc.) and the user authentication must be by file (OpenVPN will
fail to request user and password otherwise, due to being launched in
the background).

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

Similar issues apply to Chromium and Google Chrome.


## Installation

### AUR (Arch Linux)

Install the `vopono-git` package with your favourite AUR helper.

```bash
$ yay -S vopono-git
$ vopono sync
```

Alternatively use the `vopono-bin` package if you don't want to compile
from source.

### Debian + Ubuntu

Install the deb package provided on the releases page.

### Fedora + OpenSUSE

Install the rpm package provided on the release page (choose the correct
version).

### Other Linux

Either use the compiled binaries on the release page, or install from
source with Cargo as documented below.

### From this repository (with Cargo)

Run the install script provided: `install.sh` - this will `cargo
install` the repository and copy over the configuration files to
`~/.config/vopono/`

Note the minimum supported Rust version is 1.43. You can check your
version with:

```bash
$ rustc --version
```

## Known issues

* OpenVPN credentials are always stored in plaintext in configuration - may add
  option to not store credentials, but it seems OpenVPN needs them
  provided in plaintext.
* Configuration of OpenVPN connection is limited - support may be added for
  different keylengths, etc. in the future, for now this can be done by
  directly editing the generated config files in `~/.config/vopono`

## License

vopono is licensed under the GPL Version 3.0 (or above), see the LICENSE
file or https://www.gnu.org/licenses/gpl-3.0.en.html

## Etymology

vopono is the pronunciation of the letters VPN in Esperanto.

Se vi ankaŭ parolas Esperanton, bonvolu serĉi min en la kanalo de
Discord de Rust Programming Language Community.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, will be licensed under the GPLv3 (or
above), without any additional terms or conditions.
