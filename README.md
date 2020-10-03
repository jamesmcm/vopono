# vopono

vopono is a tool to run applications through VPN tunnels via temporary
network namespaces. This allows you to run only a handful of
applications through different VPNs simultaneously, whilst keeping your main connection
as normal.

vopono includes built-in killswitches for both Wireguard and OpenVPN.

Currently Mullvad, AzireVPN, MozillaVPN, TigerVPN, ProtonVPN and
PrivateInternetAccess are supported directly, with custom configuration files
also supported with the `--custom` argument.

Mullvad users can use [mullvad.net/en/check](https://mullvad.net/en/check/) to
check the security of their browser's connection. This was used with the
Mullvad configuration to verify that there is no DNS leaking or
BitTorrent leaking for both the OpenVPN and Wireguard configurations.

AzireVPN users can use [their security check page](https://www.azirevpn.com/check)
for the same (note the instructions on disabling WebRTC). I noticed that
when using IPv6 with OpenVPN it incorrectly states you are not connected
via AzireVPN though (Wireguard works correctly).

Mullvad port forwarding works for both Wireguard and OpenVPN. You will
need to enable the ports in your [Mullvad account](https://mullvad.net/en/account/#/ports).

At the moment, both iptables and nftables are required. OpenVPN must be
installed for using OpenVPN providers, and wireguard-tools must be
installed for using Wireguard providers. shadowsocks-libev must be
installed for Shadowsocks support (Mullvad OpenVPN bridges).

## Screenshot

Screenshot showing an example with firefox, google-chrome-stable and
lynx all running through different VPN connections:

![Screenshot](screenshot.png)

## Supported Providers

| Provider              | OpenVPN support | Wireguard support | 
|-----------------------|-----------------|-------------------|
| Mullvad               | ✅              | ✅                |
| AzireVPN              | ✅              | ✅                |
| PrivateInternetAccess | ✅              | ❌                |
| TigerVPN              | ✅              | ❌                |
| ProtonVPN             | ✅              | ❌                |
| MozillaVPN            | ❌              | ✅                |

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
$ vopono exec --provider mullvad --server sweden --protocol wireguard "transmission-gtk"
```

The server prefix will be searched against available servers (and
country names) and a random one will be chosen (and reported in the terminal).

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

For PrivateInternetAccess and AzireVPN these should be the same as your account
credentials.

For TigerVPN you can view your OpenVPN credentials [online on the "geeks" dashboard](https://www.tigervpn.com/dashboard/geeks).
The OpenVPN credentials are **not** the same as your TigerVPN account credentials.

For Mullvad your OpenVPN credentials are your account code as your username, and `m` as the password.

For ProtonVPN you can view your OpenVPN credentials [online on your account dashboard](https://account.protonvpn.com/account#openvpn).
The OpenVPN credentials are **not** the same as your ProtonVPN account credentials.

#### TCP support and custom ports

By default vopono uses the UDP configuration of the VPN providers.

You can use the TCP configurations by running `vopono sync` and choosing
that option from the provider configuration.

For Mullvad, valid ports are: 1300, 1301, 1302, 1194, 1195, 1196, 1197, or 53 for UDP, and 
80 or 443 for TCP,

For PrivateInternetAccess valid ports are 1198 for UDP and 502 for TCP.

For TigerVPN valid ports are 1194 for UDP or 443 for TCP.

#### Shadowsocks socks-proxy

Mullvad supports proxying via Shadowsocks, if that configuration is
chosen with `vopono sync`. Note you must use a TCP connection on port
443 in this case.

Respond with `Y` when asked `Connect via a bridge?` during the `vopono
sync` configuration for Mullvad OpenVPN to enable this configuration. It
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

Note that in the OpenVPN case the vopono will execute OpenVPN from the same
directory as the config file itself. So any accompanying files (CA certificates, authentication
files, etc.) must be in the same directory with the file if using
relative paths in the config file.

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

### Raspberry Pi (Raspbian)

Download and install the `vopono_x.y.z_armhf.deb` package from the
releases page:

```bash
$ sudo dpkg -i vopono_0.2.1_armhf.deb
```

You will need to install OpenVPN (available in the Raspbian repos):

```bash
$ sudo apt install openvpn
```

You can then use vopono as above (note that the Chromium binary is
`chromium-browser`):

```bash
$ vopono sync --protocol openvpn mullvad
$ vopono exec --provider mullvad --server sweden chromium-browser
```

Screenshot of vopono with OpenVPN running on Raspbian:

![Raspbian Screenshot](rpi_screen.png)

Note Wireguard is not in the Raspbian repositories, so installing it is
not trivial. You can follow [this guide](https://www.sigmdel.ca/michel/ha/wireguard/wireguard_02_en.html) to attempt it, but note that
not only do you need to install Wireguard and `wireguard-tools` to have `wg`
available, but also the `linux-headers` to ensure it works correctly
(i.e. you don't just get `Protocol not supported` errors when trying to
establish a connection).

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
* ProtonVPN DNS servers do not reliably connect, so Google's DNS is used
  for now (you can override this with the `--dns` argument.
* There is no easy way to delete MozillaVPN devices (Wireguard
  keypairs) - unlike Mullvad this _cannot_ be done on the webpage. I recommend using [MozWire](https://github.com/NilsIrl/MozWire) to manage this.

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

Many thanks to NilIrl's [MozWire](https://github.com/NilsIrl/MozWire)
for the investigation of the MozillaVPN API.
