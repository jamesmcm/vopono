![vopono logo](logos/vopono_banner_transparent.png)

vopono is a tool to run applications through VPN tunnels via temporary
network namespaces. This allows you to run only a handful of
applications through different VPNs simultaneously, whilst keeping your main connection
as normal.

vopono includes built-in killswitches for both Wireguard and OpenVPN.

Currently Mullvad, AzireVPN, MozillaVPN, ProtonVPN, iVPN,
NordVPN, AirVPN, and PrivateInternetAccess are supported directly, with custom
configuration files also supported with the `--custom` argument.
Cloudflare Warp is also supported.

For custom connections the OpenConnect and OpenFortiVPN protocols are
also supported (e.g. for enterprise VPNs). See the [vopono User Guide](USERGUIDE.md) for more details.

## Screenshot

Screenshot showing an example with firefox, google-chrome-stable and
lynx all running through different VPN connections:

![Screenshot](screenshot.png)

## Supported Providers

| Provider                      | OpenVPN support | Wireguard support |
| ----------------------------- | --------------- | ----------------- |
| Mullvad                       | ✅              | ✅                |
| AzireVPN                      | ❌              | ✅                |
| iVPN                          | ✅              | ✅                |
| PrivateInternetAccess         | ✅              | ✅\*              |
| ProtonVPN                     | ✅\*\*          | ✅\*\*\*          |
| MozillaVPN                    | ❌              | ✅                |
| NordVPN                       | ✅              | ❌                |
| AirVPN                        | ✅              | ❌                |
| Cloudflare Warp\*\*\*\*       | ❌              | ❌                |
| Self host (--custom)          | ✅              | ✅                |
| ~~HMA (HideMyAss)~~\*\*\*\*\* | ❌              | ❌                |

\* Port forwarding supported with the `--port-forwarding` option and `--port-forwarding-callback` to run a command when the port is refreshed.

\*\* See the [User Guide](USERGUIDE.md) for authentication instructions for generating the OpenVPN config files via `vopono sync`. You must copy the authentication header of the form `AUTH-xxx=yyy` where `yyy` is the value of the `x-pm-uid` header in the same request when logged in, in your web browser.

\*\*\* For ProtonVPN you can generate and download specific Wireguard config
files, and use them as a custom provider config. See the [User Guide](USERGUIDE.md)
for details. [Port Forwarding](https://protonvpn.com/support/port-forwarding-manual-setup/) is supported with the `--port-forwarding` argument for both OpenVPN and Wireguard.
Note for using a custom config with Wireguard, the port forwarding implementation to be used should be specified with `--custom-port-forwarding`
(i.e. with `--provider custom --custom xxx.conf --protocol wireguard --custom-port-forwarding protonvpn` ). `natpmpc` must be installed.
Note for OpenVPN you must generate the OpenVPN config files appending `+pmp` to your OpenVPN username, and you must choose servers which support this feature
(e.g. at the time of writing, the Romania servers do). The assigned port is then printed to the terminal where vopono was launched - this should then be set in any applications that require it.
The port can also be passed to a custom script that will be executed
within the network namespace via the `--port-forwarding-callback`
argument.

\*\*\*\* Cloudflare Warp uses its own protocol. Set both the provider and
protocol to `warp`. Note you must first register with `sudo warp-cli registration new` and then run it once with `sudo warp-svc` and `sudo warp-cli connect` and `sudo warp-cli debug connectivity-check disable` outside of vopono - then kill `sudo warp-svc` without running `sudo warp-cli disconnect` so it will auto-connect when run.
Please verify this works first before trying it with vopono. 

\*\*\*\*\* HideMyAss [no longer supports Linux](https://www.hidemyass.com/en-us/installation-files) nor usage outside of their
proprietary applications. Switch to another VPN provider.

## Usage

Set up VPN provider configuration files:

```bash
$ vopono sync
```

Note when creating and uploading new Wireguard keypairs there may be a slight delay
until they are usable (about 30-60 seconds on Mullvad for example).

Run Firefox through an AzireVPN Wireguard connection to a server in
Norway:

```bash
$ vopono exec --provider azirevpn --server norway firefox
```

You should run vopono as your own user (not using sudo) as it will
handle privilege escalation where necessary. For more details around
running as a systemd service, etc. see the [User Guide](USERGUIDE.md).

### Daemon Mode

For a smoother experience, run the privileged root daemon and keep using `vopono` as your normal user. The CLI automatically forwards `exec` requests to the daemon if it’s running.

- Start once at boot via systemd: `sudo systemctl enable --now vopono-daemon`
- Or run manually as root: `sudo vopono daemon`
- Then use vopono normally as your user: `vopono exec --provider mullvad --server se firefox`

See [USERGUIDE.md](USERGUIDE.md) for a ready‑to‑copy systemd unit.

vopono can handle up to 255 separate network namespaces (i.e. different VPN server
connections - if your VPN provider allows it). Commands launched with
the same server prefix and VPN provider will share the same network
namespace.

Default configuration options can be saved in the `~/.config/vopono/config.toml`
file, for example:

```toml
firewall = "NfTables"
provider = "Mullvad"
protocol = "Wireguard"
server = "usa-us22"
```

Note that the values are case-sensitive.

See the [vopono User Guide](USERGUIDE.md) for much more detailed usage instructions
(including handling daemons and servers).

## Installation

### AUR (Arch Linux)

Install the `vopono-git` package with your favourite AUR helper.

```bash
$ paru -S vopono-git
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

Check the [User Guide](USERGUIDE.md) for details on port forwarding and
using vopono with daemons and servers, in case you want to use your
Raspberry Pi to run privoxy or transmission-daemon, etc.

### Debian + Ubuntu

Install the deb package provided on the releases page.

### Fedora + OpenSUSE

Install the rpm package provided on the release page (choose the correct
version).

### Gentoo Linux

Install `vopono` from the main repository.

```bash
$ emerge -av net-vpn/vopono
```

### Other Linux

Either use the compiled binaries on the release page, or install from
source with Cargo as documented below.

### From this repository (with Cargo)

Run the install script provided: `install.sh` - this will `cargo install` the repository and copy over the configuration files to
`~/.config/vopono/`

Note the minimum supported Rust version is 1.43. You can check your
version with:

```bash
$ rustc --version
```

## Known issues

- When launching a new application in an existing vopono namespace, any
  modifications to the firewall rules (i.e. forwarding and opening
  ports) will not be applied (they are only used when creating the
  namespace). The same applies for port forwarding.
- OpenVPN credentials are always stored in plaintext in configuration - may add
  option to not store credentials, but it seems OpenVPN needs them
  provided in plaintext.
- There is no easy way to delete MozillaVPN devices (Wireguard
  keypairs) - unlike Mullvad this _cannot_ be done on the webpage. I recommend using [MozWire](https://github.com/NilsIrl/MozWire) to manage this.
- `gnome-terminal` will not run in the network namespace due to the
  client-server model - see issue [#48](https://github.com/jamesmcm/vopono/issues/48)
- Port forwarding from inside the network namespace to the host (e.g.
  for running `transmission-daemon`) does not work correctly when vopono
  is run as root - see issue [#84](https://github.com/jamesmcm/vopono/issues/84)

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

Many thanks to NilsIrl's [MozWire](https://github.com/NilsIrl/MozWire)
for the investigation of the MozillaVPN API.
